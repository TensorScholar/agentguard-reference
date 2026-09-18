import hashlib
import hmac
import math
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from ..audit import ZERO_HEAD, AuditLog, is_digest, valid_key
from ..domain import Action, Authorization, Decision, ExecutionResult, Policy, canonical, identity


class ReplayStore:
    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, authorization_id: str) -> bool:
        with self._lock:
            if authorization_id in self._consumed:
                return False
            self._consumed.add(authorization_id)
            return True


class Guard:
    def __init__(self, *, policy: Policy, key: bytes, replay_store: ReplayStore | None = None,
                 audit: AuditLog | None = None, clock: Callable[[], float] = time.time,
                 nonce_factory: Callable[[], str] = lambda: uuid.uuid4().hex) -> None:
        valid_key(key)
        if not isinstance(policy, Policy) or not callable(clock) or not callable(nonce_factory):
            raise ValueError("invalid guard configuration")
        self._policy = policy
        self._key = key
        self._replay = replay_store if replay_store is not None else ReplayStore()
        self.audit = audit if audit is not None else AuditLog(key)
        self._clock = clock
        self._nonce = nonce_factory

    def _now(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid clock")
        return float(value)

    def _sign(self, authorization: Authorization) -> str:
        payload = canonical(authorization.payload()).encode("ascii")
        return hmac.new(self._key, b"agentguard-reference:authorization:v1\0" + payload,
                        hashlib.sha256).hexdigest()

    def _event(self, event: str, identifier: str, action_digest: str, reason: str) -> bool:
        try:
            self.audit.append(event, identifier, action_digest, reason)
            return True
        except Exception:
            return False

    def authorize(self, action: Action) -> Decision:
        action_digest = ZERO_HEAD
        try:
            if type(action) is not Action:
                raise ValueError("invalid action")
            action_digest = action.digest
            reason = self._policy.evaluate(action)
        except Exception:
            reason = "policy.invalid_action"
        if reason != "policy.allowed":
            if not self._event("decision.denied", "", action_digest, reason):
                reason = "audit.unavailable"
            return Decision(False, reason)
        try:
            now = self._now()
            identifier = self._nonce()
            identity(identifier)
            expires = now + self._policy.ttl_seconds
            if not math.isfinite(expires) or expires <= now:
                raise ValueError("invalid expiry")
            authorization = Authorization(identifier, action_digest, now, expires,
                                          self._policy.fingerprint, self._policy.revision, "")
            authorization = replace(authorization, signature=self._sign(authorization))
        except Exception:
            self._event("decision.denied", "", action_digest, "authorization.issuance_failed")
            return Decision(False, "authorization.issuance_failed")
        if not self._event("decision.allowed", identifier, action_digest, "policy.allowed"):
            return Decision(False, "audit.unavailable")
        return Decision(True, "policy.allowed", authorization)

    def execute(self, action: Action, authorization: Authorization | None,
                executor: Callable[[dict[str, Any]], Any]) -> ExecutionResult:
        identifier = ""
        action_digest = ZERO_HEAD

        def deny(reason: str) -> ExecutionResult:
            if not self._event("execution.denied", identifier, action_digest, reason):
                reason = "audit.unavailable"
            return ExecutionResult("denied", reason, False, identifier)

        try:
            if type(action) is not Action or type(authorization) is not Authorization:
                return deny("execution.invalid_input")
            identity(authorization.id)
            identifier = authorization.id
            action_digest = action.digest
            if (not is_digest(authorization.signature)
                    or not hmac.compare_digest(self._sign(authorization), authorization.signature)):
                return deny("authorization.invalid_signature")
            if (authorization.policy_fingerprint != self._policy.fingerprint
                    or authorization.policy_revision != self._policy.revision):
                return deny("authorization.policy_changed")
            if authorization.action_digest != action_digest:
                return deny("authorization.action_mismatch")
            reason = self._policy.evaluate(action)
            if reason != "policy.allowed":
                return deny(reason)
            now = self._now()
            if (type(authorization.issued_at) not in (float, int)
                    or type(authorization.expires_at) not in (float, int)
                    or not math.isfinite(authorization.issued_at)
                    or not math.isfinite(authorization.expires_at)
                    or not authorization.issued_at <= now < authorization.expires_at
                    or authorization.expires_at - authorization.issued_at
                    > self._policy.ttl_seconds):
                return deny("authorization.invalid_time")
            if not callable(executor):
                return deny("execution.invalid_executor")
            arguments = action.arguments
            if not self._replay.consume(identifier):
                return deny("authorization.replayed")
        except Exception:
            return deny("execution.invalid_input")
        if not self._event("execution.admitted", identifier, action_digest, "execution.admitted"):
            return ExecutionResult("denied", "audit.unavailable", False, identifier)
        try:
            executor(arguments)
        except Exception:
            self._event("execution.unknown", identifier, action_digest, "executor.raised")
            return ExecutionResult("unknown", "executor.raised", True, identifier)
        if not self._event("execution.succeeded", identifier, action_digest, "executor.returned"):
            return ExecutionResult("unknown", "audit.unavailable", True, identifier)
        return ExecutionResult("succeeded", "executor.returned", True, identifier)
