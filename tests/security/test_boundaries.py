import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import Mock

from agentguard_reference import Action, AuditLog, Guard, Policy, ReplayStore, verify_records
from agentguard_reference.audit import ZERO_HEAD

KEY = b"boundary-test-key-not-secret!!!!!" * 2


class FailingAudit(AuditLog):
    def __init__(self, key: bytes, failed_event: str) -> None:
        super().__init__(key)
        self.failed_event = failed_event

    def append(self, event: str, authorization_id: str, action_digest: str, reason: str) -> None:
        if event == self.failed_event:
            raise RuntimeError("synthetic audit failure")
        super().append(event, authorization_id, action_digest, reason)


class BoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action = Action.create(
            principal="local-principal-sensitive-marker",
            name="refund.create",
            audience="refund-demo",
            arguments={"amount_minor": 100, "note": "local-argument-sensitive-marker"},
        )
        self.callback = Mock()

    def test_authorization_audit_failure_withholds_authorization(self) -> None:
        for event, action in (
            ("decision.allowed", self.action),
            (
                "decision.denied",
                Action.create(
                    principal="local", name="unknown", audience="refund-demo",
                    arguments={"amount_minor": 100},
                ),
            ),
        ):
            with self.subTest(event=event):
                audit = FailingAudit(KEY, event)
                guard = Guard(policy=Policy(), key=KEY, audit=audit, clock=lambda: 1000)
                decision = guard.authorize(action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "audit.unavailable")
                self.assertIsNone(decision.authorization)
                result = guard.execute(action, decision.authorization, self.callback)
                self.assertEqual(result.status, "denied")
                self.assertFalse(result.executor_called)
                self.callback.assert_not_called()
                self.assertTrue(verify_records(audit.snapshot(), KEY, expected_head=audit.head))

    def test_admission_audit_failure_denies_and_retains_replay(self) -> None:
        audit = FailingAudit(KEY, "execution.admitted")
        guard = Guard(policy=Policy(), key=KEY, audit=audit, clock=lambda: 1000)
        authorization = guard.authorize(self.action).authorization
        self.assertIsNotNone(authorization)
        result = guard.execute(self.action, authorization, self.callback)
        self.assertEqual((result.status, result.reason), ("denied", "audit.unavailable"))
        self.assertFalse(result.executor_called)
        self.callback.assert_not_called()
        audit.failed_event = ""
        retry = guard.execute(self.action, authorization, self.callback)
        self.assertEqual((retry.status, retry.reason), ("denied", "authorization.replayed"))
        self.assertFalse(retry.executor_called)
        self.callback.assert_not_called()
        self.assertEqual(
            [record["event"] for record in audit.snapshot()],
            ["decision.allowed", "execution.denied"],
        )
        self.assertTrue(verify_records(audit.snapshot(), KEY, expected_head=audit.head))

    def test_success_outcome_audit_failure_is_unknown_and_consumed(self) -> None:
        audit = FailingAudit(KEY, "execution.succeeded")
        guard = Guard(policy=Policy(), key=KEY, audit=audit, clock=lambda: 1000)
        authorization = guard.authorize(self.action).authorization
        result = guard.execute(self.action, authorization, self.callback)
        self.assertEqual((result.status, result.reason), ("unknown", "audit.unavailable"))
        self.assertTrue(result.executor_called)
        self.callback.assert_called_once_with(self.action.arguments)
        retry = guard.execute(self.action, authorization, self.callback)
        self.assertEqual((retry.status, retry.reason), ("denied", "authorization.replayed"))
        self.assertFalse(retry.executor_called)
        self.callback.assert_called_once()
        self.assertTrue(verify_records(audit.snapshot(), KEY, expected_head=audit.head))

    def test_exception_outcome_audit_failure_is_unknown_and_consumed(self) -> None:
        audit = FailingAudit(KEY, "execution.unknown")
        guard = Guard(policy=Policy(), key=KEY, audit=audit, clock=lambda: 1000)
        authorization = guard.authorize(self.action).authorization
        failing = Mock(side_effect=RuntimeError("synthetic callback failure"))
        result = guard.execute(self.action, authorization, failing)
        self.assertEqual((result.status, result.reason), ("unknown", "executor.raised"))
        self.assertTrue(result.executor_called)
        failing.assert_called_once_with(self.action.arguments)
        retry = guard.execute(self.action, authorization, self.callback)
        self.assertEqual((retry.status, retry.reason), ("denied", "authorization.replayed"))
        self.assertFalse(retry.executor_called)
        self.callback.assert_not_called()
        self.assertTrue(verify_records(audit.snapshot(), KEY, expected_head=audit.head))

    def test_denial_audit_failure_still_never_calls_executor(self) -> None:
        audit = FailingAudit(KEY, "execution.denied")
        guard = Guard(policy=Policy(), key=KEY, audit=audit, clock=lambda: 1000)
        result = guard.execute(self.action, None, self.callback)
        self.assertEqual((result.status, result.reason), ("denied", "audit.unavailable"))
        self.assertFalse(result.executor_called)
        self.callback.assert_not_called()

    def test_replay_sixteen_threads_single_winner(self) -> None:
        replay = ReplayStore()
        audit = AuditLog(KEY)
        guards = [
            Guard(policy=Policy(), key=KEY, replay_store=replay, audit=audit, clock=lambda: 1000)
            for _ in range(16)
        ]
        authorization = guards[0].authorize(self.action).authorization
        self.assertIsNotNone(authorization)
        barrier = threading.Barrier(16)
        lock = threading.Lock()
        calls: list[dict[str, Any]] = []

        def callback(arguments: dict[str, Any]) -> None:
            with lock:
                calls.append(arguments)

        def execute(index: int) -> Any:
            barrier.wait(timeout=10)
            return guards[index].execute(self.action, authorization, callback)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(execute, range(16)))
        self.assertEqual(sum(result.status == "succeeded" for result in results), 1)
        self.assertEqual(sum(result.executor_called for result in results), 1)
        denied = [result for result in results if result.status == "denied"]
        self.assertEqual(len(denied), 15)
        self.assertTrue(all(result.reason == "authorization.replayed" for result in denied))
        self.assertEqual(calls, [self.action.arguments])
        records = audit.snapshot()
        self.assertEqual(sum(record["event"] == "execution.admitted" for record in records), 1)
        self.assertEqual(sum(record["event"] == "execution.succeeded" for record in records), 1)
        self.assertTrue(verify_records(records, KEY, expected_head=audit.head))

    def test_mutable_original_and_callback_cannot_change_authorized_snapshot(self) -> None:
        original: dict[str, Any] = {"amount_minor": 100, "metadata": {"roles": ["reader"]}}
        action = Action.create(
            principal="local", name="refund.create", audience="refund-demo", arguments=original
        )
        guard = Guard(policy=Policy(), key=KEY, clock=lambda: 1000)
        decision = guard.authorize(action)
        self.assertTrue(decision.allowed)
        authorization = decision.authorization
        assert authorization is not None
        authorized_digest = action.digest
        original["amount_minor"] = 999999
        original["metadata"]["roles"].append("administrator")
        exposed = action.arguments
        exposed["metadata"]["roles"].append("owner")
        observed: list[dict[str, Any]] = []

        def callback(arguments: dict[str, Any]) -> None:
            observed.append(json.loads(json.dumps(arguments)))
            arguments["amount_minor"] = 999999
            arguments["metadata"]["roles"].append("administrator")

        result = guard.execute(action, authorization, callback)
        self.assertEqual(result.status, "succeeded")
        expected = {"amount_minor": 100, "metadata": {"roles": ["reader"]}}
        self.assertEqual(observed, [expected])
        self.assertEqual(action.arguments, expected)
        self.assertEqual(action.digest, authorized_digest)
        self.assertEqual(authorization.action_digest, authorized_digest)
        changed = Action.create(
            principal="local", name="refund.create", audience="refund-demo", arguments=original
        )
        result = guard.execute(changed, authorization, self.callback)
        self.assertEqual(
            (result.status, result.reason), ("denied", "authorization.action_mismatch")
        )
        self.assertFalse(result.executor_called)
        self.callback.assert_not_called()

    def test_audit_contains_no_raw_arguments_principal_or_exception(self) -> None:
        guard = Guard(policy=Policy(), key=KEY, clock=lambda: 1000)
        authorization = guard.authorize(self.action).authorization
        self.assertEqual(
            guard.execute(self.action, authorization, self.callback).status, "succeeded"
        )
        self.assertEqual(
            guard.execute(self.action, authorization, self.callback).reason,
            "authorization.replayed",
        )
        authorization = guard.authorize(self.action).authorization
        failing = Mock(side_effect=RuntimeError("local-exception-sensitive-marker"))
        self.assertEqual(guard.execute(self.action, authorization, failing).status, "unknown")
        denied_action = Action.create(
            principal=self.action.principal, name=self.action.name, audience=self.action.audience,
            arguments={**self.action.arguments, "untrusted": True},
        )
        self.assertFalse(guard.authorize(denied_action).allowed)
        self.assertEqual(guard.execute(denied_action, None, self.callback).status, "denied")
        records = guard.audit.snapshot()
        serialized = json.dumps(records)
        for marker in (
            self.action.principal, "local-argument-sensitive-marker",
            "local-exception-sensitive-marker", "amount_minor", "arguments", "principal",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, serialized)
        fields = {
            "sequence", "previous", "event", "authorization_id", "action_digest", "reason", "mac"
        }
        self.assertTrue(all(set(record) == fields for record in records))
        self.assertEqual(
            {record["action_digest"] for record in records},
            {self.action.digest, denied_action.digest, ZERO_HEAD},
        )
        self.assertTrue(verify_records(records, KEY, expected_head=guard.audit.head))
        self.callback.assert_called_once_with(self.action.arguments)

    def test_action_constructor_rejects_invalid_input(self) -> None:
        cases: list[tuple[Any, Any, Any, Any]] = [
            (None, "refund.create", "refund-demo", '{"amount_minor":1}'),
            ("local", 1, "refund-demo", '{"amount_minor":1}'),
            ("local", "refund.create", [], '{"amount_minor":1}'),
            ("local", "refund.create", "refund-demo", {"amount_minor": 1}),
            ("local", "refund.create", "refund-demo", '{"amount_minor":true}'),
            ("local", "refund.create", "refund-demo", '{"amount_minor":1.0}'),
            ("local", "refund.create", "refund-demo", '{"amount_minor": 1}'),
            ("local", "refund.create", "refund-demo", '{"amount_minor":Infinity}'),
            ("local", "refund.create", "refund-demo", '"not-an-object"'),
            ("local", "refund.create", "refund-demo", '{"unfinished":'),
        ]
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    Action(*values)
        self.callback.assert_not_called()

    def test_admission_samples_clock_inside_claim(self) -> None:
        events: list[str] = []
        clock_during_claim: list[bool] = []

        class TracingStore(ReplayStore):
            def claim(self, authorization_id: str, admit: Any) -> Any:
                events.append("enter")

                def wrapped() -> bool:
                    clock_during_claim.append("enter" in events and "exit" not in events)
                    return bool(admit())

                result = ReplayStore.claim(self, authorization_id, wrapped)
                events.append("exit")
                return result

        store = TracingStore()
        guard = Guard(policy=Policy(), key=KEY, replay_store=store, clock=lambda: 1000.0)
        authorization = guard.authorize(self.action).authorization
        events.clear()
        clock_during_claim.clear()
        result = guard.execute(self.action, authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(events, ["enter", "exit"])
        self.assertEqual(clock_during_claim, [True])
        self.callback.assert_called_once_with(self.action.arguments)

    def test_rejected_claim_does_not_consume(self) -> None:
        store = ReplayStore()
        guard = Guard(policy=Policy(), key=KEY, replay_store=store, clock=lambda: 1000.0)
        authorization = guard.authorize(self.action).authorization
        assert authorization is not None
        self.assertEqual(store.claim(authorization.id, lambda: False), "rejected")
        result = guard.execute(self.action, authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        self.callback.assert_called_once_with(self.action.arguments)
