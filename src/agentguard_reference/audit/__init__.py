import hashlib
import hmac
import threading
from typing import Any

from ..domain import canonical

ZERO_HEAD = "0" * 64
EVENTS = frozenset({"decision.allowed", "decision.denied", "execution.admitted",
                    "execution.denied", "execution.succeeded", "execution.unknown"})
FIELDS = {"sequence", "previous", "event", "authorization_id", "action_digest", "reason", "mac"}


def valid_key(key: bytes) -> None:
    if type(key) is not bytes or len(key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")


def is_digest(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def record_mac(payload: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, b"agentguard-reference:audit:v1\0" + canonical(payload).encode("ascii"),
                    hashlib.sha256).hexdigest()


def record_head(record: dict[str, Any]) -> str:
    return hashlib.sha256(b"agentguard-reference:chain:v1\0"
                          + canonical(record).encode("ascii")).hexdigest()


class AuditLog:
    def __init__(self, key: bytes) -> None:
        valid_key(key)
        self._key = key
        self._records: list[dict[str, Any]] = []
        self._head = ZERO_HEAD
        self._lock = threading.Lock()

    @property
    def head(self) -> str:
        with self._lock:
            return self._head

    def append(self, event: str, authorization_id: str, action_digest: str, reason: str) -> None:
        if (event not in EVENTS or type(authorization_id) is not str
                or len(authorization_id) > 256 or not is_digest(action_digest)
                or type(reason) is not str or not 0 < len(reason) <= 256):
            raise ValueError("invalid audit event")
        with self._lock:
            record = {"sequence": len(self._records) + 1, "previous": self._head,
                      "event": event, "authorization_id": authorization_id,
                      "action_digest": action_digest, "reason": reason}
            record["mac"] = record_mac(record, self._key)
            head = record_head(record)
            self._records.append(record)
            self._head = head

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(record) for record in self._records]


def verify_records(records: list[dict[str, Any]], key: bytes, *,
                   expected_head: str | None = None) -> bool:
    try:
        valid_key(key)
        if (type(records) is not list
                or (expected_head is not None and not is_digest(expected_head))):
            return False
        previous = ZERO_HEAD
        for index, record in enumerate(records, 1):
            if type(record) is not dict or set(record) != FIELDS:
                return False
            if (type(record["sequence"]) is not int or record["sequence"] != index
                    or record["previous"] != previous or record["event"] not in EVENTS
                    or type(record["authorization_id"]) is not str
                    or len(record["authorization_id"]) > 256
                    or not is_digest(record["action_digest"])
                    or type(record["reason"]) is not str or not 0 < len(record["reason"]) <= 256
                    or not is_digest(record["mac"])):
                return False
            payload = {name: value for name, value in record.items() if name != "mac"}
            if not hmac.compare_digest(record_mac(payload, key), record["mac"]):
                return False
            previous = record_head(record)
        return expected_head is None or hmac.compare_digest(previous, expected_head)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return False
