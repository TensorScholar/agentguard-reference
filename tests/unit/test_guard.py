import json
import unittest
from dataclasses import FrozenInstanceError, replace
from typing import Any, cast
from unittest.mock import Mock

from agentguard_reference import Action, Guard, Policy

KEY = b"unit-test-signing-key-not-secret!" * 2


class GuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now: Any = 1000.0
        self.policy = Policy()
        self.guard = Guard(policy=self.policy, key=KEY, clock=lambda: self.now)
        self.action = self.make_action()
        self.callback = Mock()

    def make_action(self, **changes: Any) -> Action:
        values: dict[str, Any] = {
            "principal": "local-user",
            "name": "refund.create",
            "audience": "refund-demo",
            "arguments": {"amount_minor": 100},
        }
        values.update(changes)
        return Action.create(**values)

    def assert_denied(self, result: Any, reason: str) -> None:
        self.assertEqual(result.status, "denied")
        self.assertEqual(result.reason, reason)
        self.assertFalse(result.executor_called)
        self.callback.assert_not_called()

    def test_action_canonical_snapshot(self) -> None:
        original = {"z": [1, {"text": "caf\u00e9"}], "amount_minor": 100}
        action = self.make_action(arguments=original)
        equivalent = self.make_action(
            arguments={"amount_minor": 100, "z": [1, {"text": "caf\u00e9"}]}
        )
        self.assertEqual(
            action.arguments_json, '{"amount_minor":100,"z":[1,{"text":"caf\\u00e9"}]}'
        )
        self.assertEqual(action.digest, equivalent.digest)
        original["z"] = [999]
        snapshot = action.arguments
        snapshot["z"][1]["text"] = "changed"
        self.assertEqual(action.arguments, equivalent.arguments)
        self.assertEqual(action.digest, equivalent.digest)
        with self.assertRaises(FrozenInstanceError):
            cast(Any, action).principal = "other"

    def test_policy_empty_actions_denies(self) -> None:
        guard = Guard(policy=Policy(allowed_actions=()), key=KEY)
        decision = guard.authorize(self.action)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "policy.unknown_action")
        self.assertIsNone(decision.authorization)
        self.assert_denied(
            guard.execute(self.action, decision.authorization, self.callback),
            "execution.invalid_input",
        )

    def test_policy_invalid_limits(self) -> None:
        for field in ("max_amount_minor", "ttl_seconds"):
            for value in (0, -1, True, 1.5, "60", None, 2**53 + 1):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        limits: dict[str, Any] = {field: value}
                        Policy(**limits)
        self.callback.assert_not_called()

    def test_policy_requires_immutable_valid_actions(self) -> None:
        values: list[Any] = [["refund.create"], "refund.create", ("",), (1,)]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Policy(allowed_actions=value)

    def test_amount_zero_negative_over_ceiling_missing_and_nonstrict_types(self) -> None:
        amounts: list[Any] = [0, -1, 10001, "100", None, [], {}]
        for amount in amounts:
            with self.subTest(amount=amount):
                action = self.make_action(arguments={"amount_minor": amount})
                decision = self.guard.authorize(action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "policy.invalid_amount")
                self.assertIsNone(decision.authorization)
                self.assert_denied(
                    self.guard.execute(action, decision.authorization, self.callback),
                    "execution.invalid_input",
                )
        self.assertEqual(
            self.guard.authorize(self.make_action(arguments={})).reason, "policy.invalid_amount"
        )

    def test_amount_at_ceiling_executes(self) -> None:
        action = self.make_action(arguments={"amount_minor": self.policy.max_amount_minor})
        decision = self.guard.authorize(action)
        self.assertTrue(decision.allowed)
        result = self.guard.execute(action, decision.authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.executor_called)
        self.callback.assert_called_once_with(action.arguments)

    def test_bool_float_and_non_json_arguments_rejected(self) -> None:
        for value in (True, False, 1.0, float("nan"), float("inf"), object(), {1, 2}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.make_action(arguments={"amount_minor": value})
        with self.assertRaises(ValueError):
            self.make_action(arguments={1: "not-a-string-key"})
        self.callback.assert_not_called()

    def test_nonstring_identities_rejected(self) -> None:
        values: list[Any] = [
            None, True, 1, [], "", "   ", " ident", "ident ", "ident\n",
            "ident\x00", "ident\t", "x" * 257,
        ]
        for field in ("principal", "name", "audience"):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        self.make_action(**{field: value})
        self.callback.assert_not_called()

    def test_malformed_noncanonical_and_nonobject_json_rejected(self) -> None:
        values: list[Any] = [
            "{", "[]", "null", "true", "1", '{"amount_minor": 100}',
            '{"amount_minor":100,"amount_minor":100}', '{"amount_minor":NaN}',
            '{"amount_minor":1.5}', '{"amount_minor":true}', None, 100,
        ]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Action("local-user", "refund.create", "refund-demo", value)
        self.callback.assert_not_called()

    def test_depth_boundary(self) -> None:
        nested: Any = "leaf"
        for _ in range(15):
            nested = [nested]
        action = self.make_action(arguments={"amount_minor": 1, "nested": nested})
        self.assertTrue(self.guard.authorize(action).allowed)
        for arguments in (
            {"amount_minor": 1, "nested": [nested]},
        ):
            with self.assertRaises(ValueError):
                self.make_action(arguments=arguments)
            with self.assertRaises(ValueError):
                Action(
                    "local-user", "refund.create", "refund-demo",
                    json.dumps(arguments, sort_keys=True, separators=(",", ":")),
                )
        self.callback.assert_not_called()

    def test_argument_size_and_container_limits(self) -> None:
        for arguments in (
            {"amount_minor": 1, "text": "x" * 65536},
            {"amount_minor": 1, "items": [0] * 1025},
            {str(index): index for index in range(1025)},
        ):
            with self.subTest(size=len(arguments)):
                with self.assertRaises(ValueError):
                    self.make_action(arguments=arguments)

    def test_ttl_is_bound_to_issuance(self) -> None:
        decision = self.guard.authorize(self.action)
        self.assertTrue(decision.allowed)
        authorization = decision.authorization
        self.assertIsNotNone(authorization)
        assert authorization is not None
        self.assertEqual(authorization.issued_at, 1000.0)
        self.assertEqual(authorization.expires_at, 1060.0)
        self.now = 1059.999
        result = self.guard.execute(self.action, authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        self.callback.assert_called_once_with(self.action.arguments)

    def test_exact_expiry_and_after_expiry_deny(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        for now in (1060.0, 1060.001, 2000):
            with self.subTest(now=now):
                self.now = now
                self.assert_denied(
                    self.guard.execute(self.action, authorization, self.callback),
                    "authorization.invalid_time",
                )

    def test_before_issuance_denies(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        self.now = 999.999
        self.assert_denied(
            self.guard.execute(self.action, authorization, self.callback),
            "authorization.invalid_time",
        )

    def test_wrong_key_and_signature_deny(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        assert authorization is not None
        other = Guard(policy=self.policy, key=b"different-test-key" * 3, clock=lambda: self.now)
        self.assert_denied(
            other.execute(self.action, authorization, self.callback),
            "authorization.invalid_signature",
        )
        signatures: list[Any] = ["0" * 64, "", "G" * 64, None, 123]
        for signature in signatures:
            with self.subTest(signature=signature):
                self.assert_denied(
                    self.guard.execute(
                        self.action, replace(authorization, signature=signature), self.callback
                    ),
                    "authorization.invalid_signature",
                )

    def test_changed_action_fields_deny(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        for changes in (
            {"principal": "other-user"}, {"name": "admin.delete"},
            {"audience": "other-service"}, {"arguments": {"amount_minor": 101}},
        ):
            with self.subTest(changes=changes):
                self.assert_denied(
                    self.guard.execute(self.make_action(**changes), authorization, self.callback),
                    "authorization.action_mismatch",
                )
        self.assertEqual(
            self.guard.execute(self.action, authorization, self.callback).status, "succeeded"
        )
        self.callback.assert_called_once_with(self.action.arguments)

    def test_changed_policy_same_revision_denies(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        for changes in (
            {"max_amount_minor": 20000}, {"ttl_seconds": 61},
            {"allowed_actions": ("refund.create", "admin.delete")},
            {"audience": "other-service"},
        ):
            with self.subTest(changes=changes):
                policy = replace(self.policy, **changes)
                self.assertEqual(policy.revision, self.policy.revision)
                self.assertNotEqual(policy.fingerprint, self.policy.fingerprint)
                guard = Guard(policy=policy, key=KEY, clock=lambda: self.now)
                self.assert_denied(
                    guard.execute(self.action, authorization, self.callback),
                    "authorization.policy_changed",
                )

    def test_unknown_callback_outcome_retains_replay(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        failing = Mock(side_effect=RuntimeError("synthetic callback failure"))
        result = self.guard.execute(self.action, authorization, failing)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.reason, "executor.raised")
        self.assertTrue(result.executor_called)
        failing.assert_called_once_with(self.action.arguments)
        self.assert_denied(
            self.guard.execute(self.action, authorization, self.callback), "authorization.replayed"
        )

    def test_noncallable_denies_without_consuming_authorization(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        executors: list[Any] = [None, 0, "callback", {}, object()]
        for executor in executors:
            with self.subTest(executor=executor):
                self.assert_denied(
                    self.guard.execute(self.action, authorization, executor),
                    "execution.invalid_executor",
                )
        self.assertEqual(
            self.guard.execute(self.action, authorization, self.callback).status, "succeeded"
        )
        self.callback.assert_called_once_with(self.action.arguments)

    def test_invalid_clock_fails_issuance_and_execution(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        for value in (True, None, "1000", -1, float("nan"), float("inf"), -float("inf")):
            with self.subTest(value=value):
                self.now = value
                decision = self.guard.authorize(self.action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "authorization.issuance_failed")
                self.assertIsNone(decision.authorization)
                self.assert_denied(
                    self.guard.execute(self.action, authorization, self.callback),
                    "execution.invalid_input",
                )

    def test_raising_clock_fails_closed(self) -> None:
        guard = Guard(policy=self.policy, key=KEY, clock=Mock(side_effect=RuntimeError("clock")))
        self.assertEqual(guard.authorize(self.action).reason, "authorization.issuance_failed")
        authorization = self.guard.authorize(self.action).authorization
        self.assert_denied(
            guard.execute(self.action, authorization, self.callback), "execution.invalid_input"
        )

    def test_invalid_action_and_authorization_fail_closed(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        values: list[Any] = [None, {}, "action", object()]
        for value in values:
            with self.subTest(value=value):
                decision = self.guard.authorize(value)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "policy.invalid_action")
                self.assertIsNone(decision.authorization)
                self.assert_denied(
                    self.guard.execute(value, authorization, self.callback),
                    "execution.invalid_input",
                )
                self.assert_denied(
                    self.guard.execute(self.action, value, self.callback), "execution.invalid_input"
                )

    def test_policy_revision_change_denies(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        policy = replace(self.policy, revision="reference-v2")
        self.assertEqual(policy.allowed_actions, self.policy.allowed_actions)
        self.assertNotEqual(policy.fingerprint, self.policy.fingerprint)
        guard = Guard(policy=policy, key=KEY, clock=lambda: self.now)
        self.assert_denied(
            guard.execute(self.action, authorization, self.callback),
            "authorization.policy_changed",
        )

    def test_expiry_does_not_consume_authorization(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        self.now = 1060.0
        self.assert_denied(
            self.guard.execute(self.action, authorization, self.callback),
            "authorization.invalid_time",
        )
        self.now = 1000.0
        result = self.guard.execute(self.action, authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(result.executor_called)
        self.callback.assert_called_once_with(self.action.arguments)

    def test_guard_rejects_invalid_configuration(self) -> None:
        keys: list[Any] = [None, "x" * 32, b"", b"x" * 31, bytearray(b"x" * 32)]
        for key in keys:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    Guard(policy=self.policy, key=key, clock=lambda: self.now)
        with self.assertRaises(ValueError):
            Guard(policy=cast(Any, "policy"), key=KEY, clock=lambda: self.now)
        self.callback.assert_not_called()

    def test_padded_nonce_fails_issuance(self) -> None:
        for nonce in ("", "   ", " nonce", "nonce ", "nonce\n"):
            with self.subTest(nonce=nonce):
                guard = Guard(
                    policy=self.policy, key=KEY, clock=lambda: self.now,
                    nonce_factory=lambda value=nonce: value,
                )
                decision = guard.authorize(self.action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "authorization.issuance_failed")
                self.assertIsNone(decision.authorization)
        self.callback.assert_not_called()

    def test_keyboardinterrupt_records_unknown_and_consumes(self) -> None:
        authorization = self.guard.authorize(self.action).authorization
        failing = Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.guard.execute(self.action, authorization, failing)
        failing.assert_called_once_with(self.action.arguments)
        self.assert_denied(
            self.guard.execute(self.action, authorization, self.callback),
            "authorization.replayed",
        )
        events = [record["event"] for record in self.guard.audit.snapshot()]
        self.assertIn("execution.unknown", events)
        self.assertEqual(
            [record["reason"] for record in self.guard.audit.snapshot()
             if record["event"] == "execution.unknown"],
            ["executor.interrupted"],
        )

    def test_duplicate_nonce_second_ticket_is_replay(self) -> None:
        guard = Guard(
            policy=self.policy, key=KEY, clock=lambda: self.now,
            nonce_factory=lambda: "fixed-authorization-id",
        )
        first = guard.authorize(self.action)
        second = guard.authorize(self.action)
        self.assertTrue(first.allowed and second.allowed)
        assert first.authorization is not None and second.authorization is not None
        self.assertEqual(first.authorization.id, second.authorization.id)
        result = guard.execute(self.action, first.authorization, self.callback)
        self.assertEqual(result.status, "succeeded")
        other = Mock()
        replayed = guard.execute(self.action, second.authorization, other)
        self.assertEqual((replayed.status, replayed.reason), ("denied", "authorization.replayed"))
        self.assertFalse(replayed.executor_called)
        other.assert_not_called()
        self.callback.assert_called_once_with(self.action.arguments)
