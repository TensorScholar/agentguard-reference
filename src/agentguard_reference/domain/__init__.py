import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def identity(value: str) -> None:
    if (type(value) is not str or not value or value != value.strip() or len(value) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("identity must be a nonempty string of at most 256 characters")


def validate_json(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise ValueError("JSON nesting exceeds 16")
    if type(value) is dict:
        if len(value) > 1024:
            raise ValueError("too many object members")
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON keys must be strings")
            validate_json(item, depth + 1)
    elif type(value) is list:
        if len(value) > 1024:
            raise ValueError("too many array members")
        for item in value:
            validate_json(item, depth + 1)
    elif value is not None and type(value) not in (str, int, bool):
        raise ValueError("only JSON strings, integers, booleans, null and containers are supported")


@dataclass(frozen=True)
class Action:
    principal: str
    name: str
    audience: str
    arguments_json: str

    def __post_init__(self) -> None:
        for value in (self.principal, self.name, self.audience):
            identity(value)
        if type(self.arguments_json) is not str or len(self.arguments_json) > 65536:
            raise ValueError("arguments exceed 65536 characters")
        data = json.loads(self.arguments_json)
        if type(data) is not dict:
            raise ValueError("arguments must be an object")
        validate_json(data)
        if type(data.get("amount_minor")) is bool:
            raise ValueError("amount must not be boolean")
        if canonical(data) != self.arguments_json:
            raise ValueError("arguments must be canonical JSON")

    @classmethod
    def create(cls, *, principal: str, name: str, audience: str,
               arguments: dict[str, Any]) -> "Action":
        validate_json(arguments)
        return cls(principal, name, audience, canonical(arguments))

    @property
    def arguments(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(self.arguments_json)
        return value

    @property
    def digest(self) -> str:
        return digest({"principal": self.principal, "name": self.name,
                       "audience": self.audience, "arguments": self.arguments})


@dataclass(frozen=True)
class Policy:
    allowed_actions: tuple[str, ...] = ("refund.create",)
    audience: str = "refund-demo"
    max_amount_minor: int = 10000
    ttl_seconds: int = 60
    revision: str = "reference-v1"

    def __post_init__(self) -> None:
        identity(self.audience)
        identity(self.revision)
        if type(self.allowed_actions) is not tuple:
            raise ValueError("allowed_actions must be an immutable tuple")
        for action in self.allowed_actions:
            identity(action)
        for value in (self.max_amount_minor, self.ttl_seconds):
            if type(value) is not int or not 0 < value <= 2**53:
                raise ValueError("policy limits must be positive bounded integers")

    @property
    def fingerprint(self) -> str:
        return digest({"actions": self.allowed_actions, "audience": self.audience,
                       "max_amount_minor": self.max_amount_minor,
                       "ttl_seconds": self.ttl_seconds, "revision": self.revision})

    def evaluate(self, action: Action) -> str:
        if action.name not in self.allowed_actions:
            return "policy.unknown_action"
        if action.audience != self.audience:
            return "policy.audience_mismatch"
        amount = action.arguments.get("amount_minor")
        if type(amount) is not int or not 0 < amount <= self.max_amount_minor:
            return "policy.invalid_amount"
        untrusted = action.arguments.get("untrusted", False)
        if type(untrusted) is not bool or untrusted:
            return "policy.untrusted_input"
        return "policy.allowed"


@dataclass(frozen=True)
class Authorization:
    id: str
    action_digest: str
    issued_at: float
    expires_at: float
    policy_fingerprint: str
    policy_revision: str
    signature: str

    def payload(self) -> dict[str, Any]:
        return {"id": self.id, "action_digest": self.action_digest, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "policy_fingerprint": self.policy_fingerprint,
                "policy_revision": self.policy_revision}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    authorization: Authorization | None = None


@dataclass(frozen=True)
class ExecutionResult:
    status: Literal["denied", "succeeded", "unknown"]
    reason: str
    executor_called: bool = False
    authorization_id: str = ""
