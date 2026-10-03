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
from agentguard_reference.cli import demo_document, main

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
        document = json.loads(self.invoke(["demo", "--json"])[1])
        self.assertEqual(document, demo_document())
        self.assertTrue(document["all_properties_held"])
        self.assertEqual(
            [scenario["id"] for scenario in document["scenarios"]],
            ["mutation", "expiry", "replay", "unknown", "tamper"],
        )
        self.stat.assert_not_called()
        self.read_text.assert_not_called()
        self.read_bytes.assert_not_called()

    def test_demo_failure_exit_status(self) -> None:
        broken = {
            "all_properties_held": False,
            "self_check": False,
        }
        for change in broken:
            with self.subTest(change=change):
                document = demo_document()
                if change == "all_properties_held":
                    document["all_properties_held"] = False
                else:
                    document["audit"]["self_check_under_public_demo_key"] = False
                with patch("agentguard_reference.cli.demo_document", return_value=document):
                    status, _output, _error = self.invoke(["demo"])
                self.assertEqual(status, 1)

    def test_demo_documents_every_required_property(self) -> None:
        document = demo_document()
        by_id = {scenario["id"]: scenario for scenario in document["scenarios"]}
        self.assertEqual(sorted(by_id), ["expiry", "mutation", "replay", "tamper", "unknown"])

        mutation = by_id["mutation"]["observed"]
        self.assertEqual(mutation["execution"]["reason"], "authorization.action_mismatch")
        self.assertIs(mutation["execution"]["executor_called"], False)
        self.assertEqual(mutation["callback_invocations"], 0)
        self.assertNotEqual(mutation["approved_action_digest"],
                            mutation["presented_action_digest"])

        expiry = by_id["expiry"]["observed"]
        self.assertEqual(expiry["at_exact_expiry"]["reason"], "authorization.invalid_time")
        self.assertEqual(expiry["callback_invocations_at_boundary"], 0)
        self.assertEqual(expiry["inside_window"]["status"], "succeeded")
        self.assertTrue(expiry["refusal_survived_clock_reset"])
        self.assertEqual(expiry["expires_at"], expiry["issued_at"] + 60)

        replay = by_id["replay"]["observed"]
        self.assertEqual(replay["first"]["status"], "succeeded")
        self.assertEqual(replay["second"]["reason"], "authorization.replayed")
        self.assertEqual(replay["third"]["reason"], "authorization.replayed")
        self.assertEqual(replay["callback_invocations"], 1)

        unknown = by_id["unknown"]["observed"]
        self.assertEqual(unknown["execution"]["status"], "unknown")
        self.assertEqual(unknown["execution"]["reason"], "executor.raised")
        self.assertIs(unknown["execution"]["executor_called"], True)
        self.assertEqual(unknown["retry"]["reason"], "authorization.replayed")

        tamper = by_id["tamper"]["observed"]
        self.assertTrue(tamper["tampered_record_rejected"])
        self.assertTrue(tamper["wrong_key_rejected"])
        self.assertTrue(tamper["valid_prefix_accepted_without_trusted_head"])
        self.assertTrue(tamper["valid_prefix_rejected_with_trusted_head"])

        for scenario in document["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                self.assertTrue(scenario["property_held"])
                self.assertTrue(scenario["claim"])
                self.assertTrue(scenario["lines"])

    def test_demo_narrates_each_property_and_states_it_is_not_core(self) -> None:
        status, output, error = self.invoke(["demo"])
        self.assertEqual(status, 0)
        for marker in (
            "not AgentGuard Core",
            "not a newer version of Core",
            "authorization.action_mismatch",
            "authorization.invalid_time",
            "authorization.replayed",
            "executor.raised",
            "Callback invocations so far: 0",
            "not permission to retry",
            "tautology",
            "expected head",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, output)
        self.assertIn("HELD", output)
        self.assertEqual(output.count("property HELD"), 5)

    def test_demo_never_claims_a_bare_verification_result(self) -> None:
        """The demo must not present a self-check under a published key as evidence."""
        status, output, error = self.invoke(["demo"])
        self.assertEqual(status, 0)
        self.assertNotIn('"verified"', output)
        self.assertNotIn("verified: true", output)
        document = json.loads(self.invoke(["demo", "--json"])[1])
        self.assertNotIn("verified", document)
        self.assertIn("self_check_under_public_demo_key", document["audit"])
        self.assertIn("not a secret", error)
        self.assertIn("is not evidence", error)
        self.assertEqual(error.count("\n"), 1)

    def test_no_argument_invocation_runs_the_guided_demo(self) -> None:
        with_argv = self.invoke(["demo"])
        without_argv = self.invoke([])
        self.assertEqual(without_argv, with_argv)
        self.assertEqual(without_argv[0], 0)
        self.assertIn("guided demo", without_argv[1])

    def test_demo_json_and_narrative_are_both_deterministic(self) -> None:
        self.assertEqual(self.invoke(["demo", "--json"]), self.invoke(["demo", "--json"]))
        self.assertEqual(self.invoke(["demo"]), self.invoke(["demo"]))

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
