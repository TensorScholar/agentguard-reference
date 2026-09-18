import io
import json
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import call, patch

from agentguard_reference import AuditLog
from agentguard_reference.cli import demo, main

KEY = b"cli-test-external-key-not-secret!" * 2


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        audit = AuditLog(KEY)
        audit.append("decision.allowed", "cli-test", "a" * 64, "policy.allowed")
        self.records = audit.snapshot()
        self.head = audit.head
        self.argv = ["verify", "audit.json", "--key-file", "verification.key",
                     "--expected-head", self.head]
        self.read_text = self.enterContext(patch.object(
            Path, "read_text", autospec=True, return_value=json.dumps(self.records)
        ))
        self.read_bytes = self.enterContext(patch.object(
            Path, "read_bytes", autospec=True, return_value=KEY
        ))
        self.stat = self.enterContext(patch.object(
            Path, "stat", autospec=True, return_value=SimpleNamespace(st_size=256)
        ))

    def invoke(self, argv: list[str] | None = None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(self.argv if argv is None else argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_invalid_input(self) -> None:
        self.assertEqual(self.invoke(), (
            1, "", "verification failed: invalid or unreadable input\n"
        ))

    def test_demo_repeated_is_deterministic(self) -> None:
        first = self.invoke(["demo"])
        self.assertEqual(first, self.invoke(["demo"]))
        self.assertEqual(first[0], 0)
        self.assertEqual(first[2], "")
        document = json.loads(first[1])
        self.assertEqual(document, demo())
        self.assertTrue(document["verified"])
        self.assertTrue(document["decision"]["allowed"])
        self.assertEqual(document["executor_calls"], 1)
        self.assertEqual([result["status"] for result in document["results"]],
                         ["succeeded", "denied"])
        self.assertEqual(document["results"][1]["reason"], "authorization.replayed")
        self.stat.assert_not_called()
        self.read_text.assert_not_called()
        self.read_bytes.assert_not_called()

    def test_demo_failure_exit_status(self) -> None:
        for changes in ({"verified": False}, {"executor_calls": 0}, {"executor_calls": 2}):
            with self.subTest(changes=changes):
                document = demo()
                document.update(changes)
                with patch("agentguard_reference.cli.demo", return_value=document):
                    status, output, error = self.invoke(["demo"])
                self.assertEqual(status, 1)
                self.assertEqual(json.loads(output), document)
                self.assertEqual(error, "")

    def test_verify_valid_array_and_document_external_key_and_head(self) -> None:
        for document in (self.records, {"records": self.records, "head": "0" * 64}):
            with self.subTest(document=document):
                self.read_text.return_value = json.dumps(document)
                self.assertEqual(self.invoke(), (0, '{"verified": true}\n', ""))
        self.read_text.assert_called_with(Path("audit.json"), encoding="utf-8")
        self.read_bytes.assert_called_with(Path("verification.key"))
        self.assertEqual(self.stat.call_args_list, [
            call(Path("audit.json")), call(Path("verification.key")),
            call(Path("audit.json")), call(Path("verification.key")),
        ])

    def test_verify_wrong_key_and_head(self) -> None:
        for key, head in ((b"wrong-external-key" * 3, self.head), (KEY, "0" * 64),
                          (KEY, "not-a-head"), (b"short", self.head)):
            with self.subTest(key=key, head=head):
                self.read_bytes.return_value = key
                self.assertEqual(self.invoke([*self.argv[:-1], head]),
                                 (1, '{"verified": false}\n', ""))

    def test_verify_tampered_and_missing_record_fields(self) -> None:
        changes: dict[str, Any] = {
            "sequence": 2, "previous": "b" * 64, "event": "execution.denied",
            "authorization_id": "changed", "action_digest": "b" * 64,
            "reason": "changed", "mac": "0" * 64,
        }
        for field, value in changes.items():
            for remove in (False, True):
                with self.subTest(field=field, remove=remove):
                    record = dict(self.records[0])
                    if remove:
                        del record[field]
                    else:
                        record[field] = value
                    self.read_text.return_value = json.dumps([record])
                    self.assertEqual(self.invoke(), (1, '{"verified": false}\n', ""))

    def test_verify_missing_records_and_invalid_document_shapes(self) -> None:
        for document in ({}, {"records": None}, {"records": {}}, None, True, 1, "records"):
            with self.subTest(document=document):
                self.read_text.return_value = json.dumps(document)
                self.assert_invalid_input()
        self.read_bytes.assert_not_called()

    def test_verify_malformed_json(self) -> None:
        for text in ("", "{", "[", '{"records": []', "[] trailing"):
            with self.subTest(text=text):
                self.read_text.return_value = text
                self.assert_invalid_input()
        self.read_bytes.assert_not_called()

    def test_verify_unreadable_files(self) -> None:
        for operation in (self.stat, self.read_text, self.read_bytes):
            for error in (FileNotFoundError("missing"), PermissionError("denied"),
                          OSError("unreadable")):
                with self.subTest(operation=operation, error=type(error)):
                    operation.side_effect = error
                    try:
                        self.assert_invalid_input()
                    finally:
                        operation.side_effect = None
        self.stat.side_effect = [SimpleNamespace(st_size=256), PermissionError("key stat")]
        self.assert_invalid_input()

    def test_verify_size_caps_reject_before_reading(self) -> None:
        for sizes in ((10 * 1024 * 1024 + 1, 32), (256, 4097)):
            with self.subTest(sizes=sizes):
                self.stat.side_effect = [SimpleNamespace(st_size=size) for size in sizes]
                self.assert_invalid_input()
        self.read_text.assert_not_called()
        self.read_bytes.assert_not_called()

    def test_verify_size_caps_are_inclusive(self) -> None:
        self.stat.side_effect = [SimpleNamespace(st_size=10 * 1024 * 1024),
                                 SimpleNamespace(st_size=4096)]
        self.assertEqual(self.invoke(), (0, '{"verified": true}\n', ""))

    def test_verify_requires_external_key_file_and_expected_head(self) -> None:
        for argv, missing in (
            (["verify", "audit.json", "--expected-head", self.head], "--key-file"),
            (["verify", "audit.json", "--key-file", "verification.key"], "--expected-head"),
            (["verify", "audit.json"], "--key-file"),
        ):
            with self.subTest(argv=argv):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        main(argv)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(missing, stderr.getvalue())
                self.assertIn("required", stderr.getvalue())
        self.stat.assert_not_called()
        self.read_text.assert_not_called()
        self.read_bytes.assert_not_called()

    def test_embedded_key_cannot_override_external_key(self) -> None:
        for external, embedded, status in (
            (b"wrong-external-key" * 3, KEY, 1),
            (KEY, b"wrong-embedded-key" * 3, 0),
        ):
            with self.subTest(status=status):
                self.read_text.return_value = json.dumps({
                    "records": self.records, "head": self.head,
                    "key": embedded.decode("ascii"), "key_hex": embedded.hex(),
                })
                self.read_bytes.return_value = external
                self.assertEqual(self.invoke(), (
                    status, json.dumps({"verified": status == 0}) + "\n", ""
                ))

    def test_module_propagates_cli_exit_status(self) -> None:
        for status in (0, 1, 2):
            with self.subTest(status=status):
                with patch("agentguard_reference.cli.main", return_value=status) as entrypoint:
                    with self.assertRaises(SystemExit) as raised:
                        runpy.run_module("agentguard_reference", run_name="__main__")
                self.assertEqual(raised.exception.code, status)
                entrypoint.assert_called_once_with()
