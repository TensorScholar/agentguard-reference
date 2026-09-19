import hashlib
import hmac
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agentguard_reference import AuditLog, verify_records
from agentguard_reference.audit import ZERO_HEAD, record_mac
from agentguard_reference.domain import canonical

KEY = b"audit-unit-test-key-not-secret!!!" * 2


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = AuditLog(KEY)
        self.digest = "a" * 64
        for event, reason in (
            ("decision.allowed", "policy.allowed"),
            ("execution.admitted", "execution.admitted"),
            ("execution.succeeded", "executor.returned"),
        ):
            self.audit.append(event, "local-authorization", self.digest, reason)

    def test_valid_chain_and_expected_head(self) -> None:
        records = self.audit.snapshot()
        self.assertTrue(verify_records(records, KEY))
        self.assertTrue(verify_records(records, KEY, expected_head=self.audit.head))
        self.assertFalse(verify_records(records, KEY, expected_head=ZERO_HEAD))
        self.assertEqual([record["sequence"] for record in records], [1, 2, 3])
        self.assertEqual(records[0]["previous"], ZERO_HEAD)

    def test_wrong_key(self) -> None:
        self.assertFalse(verify_records(self.audit.snapshot(), b"other-audit-test-key" * 3))

    def test_tamper_each_field(self) -> None:
        changes = {
            "sequence": 9, "previous": "b" * 64, "event": "execution.unknown",
            "authorization_id": "different", "action_digest": "b" * 64,
            "reason": "different.reason", "mac": "0" * 64,
        }
        for index in range(3):
            for field, value in changes.items():
                with self.subTest(index=index, field=field):
                    records = self.audit.snapshot()
                    records[index][field] = value
                    self.assertFalse(verify_records(records, KEY))
                    self.assertFalse(verify_records(records, KEY, expected_head=self.audit.head))

    def test_reorder_and_remove_middle(self) -> None:
        records = self.audit.snapshot()
        for modified in (records[::-1], [records[1], records[0], records[2]], records[::2]):
            with self.subTest(modified=modified):
                self.assertFalse(verify_records(modified, KEY))
                self.assertFalse(verify_records(modified, KEY, expected_head=self.audit.head))

    def test_prefix_removal_fails(self) -> None:
        for count in (1, 2):
            with self.subTest(count=count):
                records = self.audit.snapshot()[count:]
                self.assertFalse(verify_records(records, KEY))
                self.assertFalse(verify_records(records, KEY, expected_head=self.audit.head))

    def test_suffix_removal_requires_trusted_head(self) -> None:
        for count in (1, 2, 3):
            with self.subTest(count=count):
                records = self.audit.snapshot()[:-count]
                self.assertTrue(verify_records(records, KEY))
                self.assertFalse(verify_records(records, KEY, expected_head=self.audit.head))

    def test_strict_schema_rejects_missing_and_extra_fields(self) -> None:
        for field in self.audit.snapshot()[0]:
            with self.subTest(field=field):
                records = self.audit.snapshot()
                del records[0][field]
                self.assertFalse(verify_records(records, KEY))
        records = self.audit.snapshot()
        records[0]["extra"] = "not-in-schema"
        payload = {key: value for key, value in records[0].items() if key != "mac"}
        records[0]["mac"] = record_mac(payload, KEY)
        self.assertFalse(verify_records(records, KEY))

    def test_malformed_values_even_with_valid_mac(self) -> None:
        cases: dict[str, list[Any]] = {
            "sequence": [True, 1.0, "1", 0, -1, None],
            "previous": [None, 0, [], {}, "", "g" * 64],
            "event": [None, 1, [], {}, "unknown", ""],
            "authorization_id": [None, 1, True, [], "x" * 257],
            "action_digest": [None, 1, [], "", "a" * 63, "A" * 64],
            "reason": [None, 1, True, [], "", "x" * 257],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    record = self.audit.snapshot()[0]
                    record[field] = value
                    payload = {key: item for key, item in record.items() if key != "mac"}
                    record["mac"] = record_mac(payload, KEY)
                    self.assertFalse(verify_records([record], KEY))

    def test_malformed_macs(self) -> None:
        values: list[Any] = [None, 1, [], {}, "", "a" * 63, "A" * 64]
        for value in values:
            with self.subTest(value=value):
                records = self.audit.snapshot()
                records[0]["mac"] = value
                self.assertFalse(verify_records(records, KEY))

    def test_malformed_record_collections(self) -> None:
        values: list[Any] = [None, {}, (), "records", [None], [[]], [1], ["record"]]
        for records in values:
            with self.subTest(records=records):
                self.assertFalse(verify_records(records, KEY))

    def test_invalid_expected_heads(self) -> None:
        values: list[Any] = [True, 1, [], {}, "", "g" * 64, "a" * 63, "A" * 64]
        for head in values:
            with self.subTest(head=head):
                self.assertFalse(verify_records(self.audit.snapshot(), KEY, expected_head=head))
                self.assertFalse(verify_records([], KEY, expected_head=head))

    def test_empty_chain(self) -> None:
        audit = AuditLog(KEY)
        self.assertEqual(audit.snapshot(), [])
        self.assertEqual(audit.head, ZERO_HEAD)
        self.assertTrue(verify_records([], KEY))
        self.assertTrue(verify_records([], KEY, expected_head=ZERO_HEAD))
        self.assertFalse(verify_records([], KEY, expected_head="a" * 64))

    def test_invalid_keys_rejected_even_for_empty_chain(self) -> None:
        keys: list[Any] = [None, "x" * 32, b"", b"x" * 31, bytearray(b"x" * 32)]
        for key in keys:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    AuditLog(key)
                self.assertFalse(verify_records([], key))
                self.assertFalse(verify_records(self.audit.snapshot(), key))

    def test_snapshot_isolation(self) -> None:
        original = self.audit.snapshot()
        head = self.audit.head
        changed = self.audit.snapshot()
        changed[0]["reason"] = "tampered"
        changed[1].clear()
        changed.pop()
        changed.append({"extra": []})
        self.assertEqual(self.audit.snapshot(), original)
        self.assertEqual(self.audit.head, head)
        self.audit.append("execution.denied", "another", self.digest, "authorization.replayed")
        self.assertEqual(len(original), 3)
        self.assertTrue(verify_records(original, KEY, expected_head=head))
        self.assertEqual(len(self.audit.snapshot()), 4)
        self.assertTrue(verify_records(self.audit.snapshot(), KEY, expected_head=self.audit.head))

    def test_invalid_append_does_not_change_chain(self) -> None:
        baseline = self.audit.snapshot()
        head = self.audit.head
        cases: list[tuple[Any, Any, Any, Any]] = [
            ("invalid", "id", self.digest, "reason"),
            ([], "id", self.digest, "reason"),
            ("decision.denied", None, self.digest, "reason"),
            ("decision.denied", "x" * 257, self.digest, "reason"),
            ("decision.denied", "id", "not-a-digest", "reason"),
            ("decision.denied", "id", self.digest, ""),
            ("decision.denied", "id", self.digest, None),
            ("decision.denied", "id", self.digest, "x" * 257),
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises((ValueError, TypeError)):
                    self.audit.append(*arguments)
                self.assertEqual(self.audit.snapshot(), baseline)
                self.assertEqual(self.audit.head, head)

    def test_concurrent_appends_form_one_chain(self) -> None:
        audit = AuditLog(KEY)

        def append(index: int) -> None:
            audit.append("decision.denied", f"local-{index}", self.digest, "policy.unknown_action")

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(append, range(256)))
        records = audit.snapshot()
        self.assertEqual(len(records), 256)
        self.assertEqual([record["sequence"] for record in records], list(range(1, 257)))
        self.assertEqual(
            {record["authorization_id"] for record in records},
            {f"local-{index}" for index in range(256)},
        )
        self.assertTrue(verify_records(records, KEY, expected_head=audit.head))

    def test_authorization_domain_separator_is_not_audit_mac(self) -> None:
        payload = {
            "sequence": 1, "previous": ZERO_HEAD, "event": "decision.denied",
            "authorization_id": "local", "action_digest": self.digest,
            "reason": "policy.unknown_action",
        }
        authorization_mac = hmac.new(
            KEY, b"agentguard-reference:authorization:v1\0" + canonical(payload).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        self.assertNotEqual(record_mac(payload, KEY), authorization_mac)
        record = {**payload, "mac": authorization_mac}
        self.assertFalse(verify_records([record], KEY))
