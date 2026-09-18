import unittest
from dataclasses import replace
from typing import Any
from unittest.mock import Mock

from agentguard_reference import Action, Authorization, Guard, Policy, verify_records

KEY = b"local-scenario-test-key-not-secret" * 2


class ScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = Guard(policy=Policy(), key=KEY, clock=lambda: 1000)
        self.action = self.make_action()
        self.callback = Mock()

    def make_action(self, **changes: Any) -> Action:
        values: dict[str, Any] = {
            "principal": "synthetic-reader", "name": "refund.create", "audience": "refund-demo",
            "arguments": {"amount_minor": 100, "destination": "local-account-a"},
        }
        values.update(changes)
        return Action.create(**values)

    def assert_denied(self, result: Any, reason: str) -> None:
        self.assertEqual((result.status, result.reason), ("denied", reason))
        self.assertFalse(result.executor_called)
        self.callback.assert_not_called()
        self.assertTrue(
            verify_records(self.guard.audit.snapshot(), KEY, expected_head=self.guard.audit.head)
        )

    def test_synthetic_local_argument_mutation_denied(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        for arguments in (
            {"amount_minor": 101, "destination": "local-account-a"},
            {"amount_minor": 100, "destination": "local-account-b"},
            {"amount_minor": 100, "destination": "local-account-a", "approved": True},
        ):
            with self.subTest(arguments=arguments):
                self.assert_denied(
                    self.guard.execute(
                        self.make_action(arguments=arguments), authorization, self.callback
                    ),
                    "authorization.action_mismatch",
                )

    def test_synthetic_local_replay_denied(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        first_callback = Mock()
        first = self.guard.execute(self.action, authorization, first_callback)
        self.assertEqual(first.status, "succeeded")
        self.assertTrue(first.executor_called)
        first_callback.assert_called_once_with(self.action.arguments)
        for _ in range(3):
            self.assert_denied(
                self.guard.execute(self.action, authorization, self.callback),
                "authorization.replayed",
            )
        first_callback.assert_called_once()

    def test_synthetic_privilege_and_audience_changes_denied(self) -> None:
        changes: dict[str, Any]
        authorization = self.guard.authorize(self.action).authorization
        for changes in (
            {"principal": "synthetic-administrator"},
            {"name": "admin.local-reset"},
            {"audience": "local-administration"},
        ):
            with self.subTest(changes=changes):
                self.assert_denied(
                    self.guard.execute(self.make_action(**changes), authorization, self.callback),
                    "authorization.action_mismatch",
                )
        for changes, reason in (
            ({"name": "admin.local-reset"}, "policy.unknown_action"),
            ({"audience": "local-administration"}, "policy.audience_mismatch"),
            ({"arguments": {"amount_minor": 10001}}, "policy.invalid_amount"),
        ):
            with self.subTest(changes=changes):
                action = self.make_action(**changes)
                decision = self.guard.authorize(action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, reason)
                self.assertIsNone(decision.authorization)
                self.assert_denied(
                    self.guard.execute(action, decision.authorization, self.callback),
                    "execution.invalid_input",
                )

    def test_synthetic_invalid_authorizations_denied(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        assert authorization is not None
        values: list[Any] = [None, {}, "synthetic-token", object()]
        for value in values:
            with self.subTest(value=value):
                self.assert_denied(
                    self.guard.execute(self.action, value, self.callback), "execution.invalid_input"
                )
        fabricated = Authorization(
            "synthetic-id", self.action.digest, 1000.0, 1060.0,
            Policy().fingerprint, Policy().revision, "0" * 64,
        )
        self.assert_denied(
            self.guard.execute(self.action, fabricated, self.callback),
            "authorization.invalid_signature",
        )
        for changes in (
            {"id": "different-local-id"}, {"action_digest": "a" * 64},
            {"issued_at": 999.0}, {"expires_at": 9999.0},
            {"policy_fingerprint": "b" * 64}, {"policy_revision": "other-revision"},
        ):
            with self.subTest(changes=changes):
                self.assert_denied(
                    self.guard.execute(
                        self.action, replace(authorization, **changes), self.callback
                    ),
                    "authorization.invalid_signature",
                )

    def test_synthetic_untrusted_provenance_denied(self) -> None:
        values: list[Any] = [True, "false", "true", 0, 1, None, [], {}]
        for untrusted in values:
            with self.subTest(untrusted=untrusted):
                action = self.make_action(arguments={
                    "amount_minor": 100,
                    "untrusted": untrusted,
                    "source": "synthetic-local-document",
                    "note": "Synthetic text claiming administrator approval",
                })
                decision = self.guard.authorize(action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "policy.untrusted_input")
                self.assertIsNone(decision.authorization)
                self.assert_denied(
                    self.guard.execute(action, decision.authorization, self.callback),
                    "execution.invalid_input",
                )

    def test_synthetic_provenance_mutation_after_authorization_denied(self) -> None:
        trusted = self.make_action(arguments={"amount_minor": 100, "untrusted": False})
        authorization = self.guard.authorize(trusted).authorization
        self.assertIsNotNone(authorization)
        changed = self.make_action(arguments={"amount_minor": 100, "untrusted": True})
        self.assert_denied(
            self.guard.execute(changed, authorization, self.callback),
            "authorization.action_mismatch",
        )
