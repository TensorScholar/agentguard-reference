"""Executable evidence for the hazards named in the threat model.

Each test here locks a documented claim. If the implementation changes such that a
hazard no longer holds, the corresponding documentation is wrong and this fails.

These are demonstrations of what the package does NOT protect against. They are not
defect reports; see docs/threat-model.md for why each is acceptable for a
single-process reference.
"""

import threading
import unittest
from typing import Any
from unittest.mock import Mock

from agentguard_reference import Action, AuditLog, Guard, Policy, ReplayStore

KEY = b"hazard-test-key-not-a-secret!!!!!" * 2


def build_action(amount_minor: int = 100) -> Action:
    return Action.create(principal="hazard-user", name="refund.create",
                         audience="refund-demo", arguments={"amount_minor": amount_minor})


class CrossStoreReplayTests(unittest.TestCase):
    """H1: single-use state belongs to a store, not to a ticket."""

    def test_h1_consumed_ticket_is_replayable_through_a_second_store(self) -> None:
        first = Guard(policy=Policy(), key=KEY, clock=lambda: 1000.0,
                      nonce_factory=lambda: "hazard-ticket")
        action = build_action()
        authorization = first.authorize(action).authorization
        assert authorization is not None
        first_calls: list[Any] = []
        self.assertEqual(
            first.execute(action, authorization, first_calls.append).status, "succeeded")

        second = Guard(policy=Policy(), key=KEY, clock=lambda: 1000.0,
                       nonce_factory=lambda: "hazard-ticket")
        second_calls: list[Any] = []
        replayed = second.execute(action, authorization, second_calls.append)
        self.assertEqual(replayed.status, "succeeded")
        self.assertEqual(replayed.reason, "executor.returned")
        self.assertEqual(len(first_calls), 1)
        self.assertEqual(len(second_calls), 1)

    def test_h1_single_use_still_holds_within_one_store(self) -> None:
        """The counterweight: the guarantee that does hold is not weakened by H1."""
        guard = Guard(policy=Policy(), key=KEY, clock=lambda: 1000.0,
                      nonce_factory=lambda: "hazard-ticket")
        action = build_action()
        authorization = guard.authorize(action).authorization
        assert authorization is not None
        calls: list[Any] = []
        self.assertEqual(
            guard.execute(action, authorization, calls.append).status, "succeeded")
        second = guard.execute(action, authorization, calls.append)
        self.assertEqual((second.status, second.reason), ("denied", "authorization.replayed"))
        self.assertEqual(len(calls), 1)

    def test_h2_independent_store_copies_admit_the_same_ticket(self) -> None:
        """H2's mechanism, without forking.

        `fork()` copies memory, so parent and child begin from identical
        pre-consumption state and each can claim once. Copying the store directly is
        the same situation expressed in one process: two stores that share no
        admission state both admit the same ticket. Forking is not exercised here
        because a forking test in a threaded suite is a flaky release gate.
        """
        authorization = Guard(policy=Policy(), key=KEY, clock=lambda: 1000.0,
                              nonce_factory=lambda: "hazard-ticket"
                              ).authorize(build_action()).authorization
        assert authorization is not None
        action = build_action()
        dispatched: list[str] = []

        stores = [ReplayStore(), ReplayStore()]
        for index, store in enumerate(stores):
            guard = Guard(policy=Policy(), key=KEY, replay_store=store,
                          clock=lambda: 1000.0)
            result = guard.execute(action, authorization,
                                   lambda arguments, tag=index: dispatched.append(tag))
            self.assertEqual(result.status, "succeeded", f"store {index}")
        self.assertEqual(sorted(dispatched), [0, 1])


class StoreLockTests(unittest.TestCase):
    """H3: the clock is sampled under a lock that cannot be re-entered."""

    def test_h3_store_lock_is_not_reentrant(self) -> None:
        """Locks H3's precondition without deadlocking the suite.

        The deadlock itself is not exercised: it would hang the run with no recovery.
        Asserting the lock is non-reentrant is what makes the hazard statement true,
        and `test_admission_samples_clock_inside_claim` separately proves the clock is
        in fact invoked while that lock is held.
        """
        store = ReplayStore()
        self.assertIsInstance(store._lock, type(threading.Lock()))
        self.assertFalse(hasattr(store._lock, "_count"))
        acquired = threading.Event()

        def probe() -> None:
            acquired.set()
            store.claim("hazard-probe", lambda: True)

        thread = threading.Thread(target=probe)
        thread.start()
        self.assertTrue(acquired.wait(timeout=5))
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


class UnboundedGrowthTests(unittest.TestCase):
    """H4: neither store evicts, and denied traffic still grows the audit log."""

    def test_h4_denied_authorize_traffic_grows_the_audit_log(self) -> None:
        guard = Guard(policy=Policy(), key=KEY, clock=lambda: 1000.0,
                      nonce_factory=lambda: "hazard-ticket")
        for _ in range(25):
            decision = guard.authorize("not-an-action")
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "policy.invalid_action")
        self.assertEqual(len(guard.audit.snapshot()), 25)

    def test_h4_consumed_ids_and_records_never_shrink(self) -> None:
        store = ReplayStore()
        counter = iter(f"hazard-ticket-{index}" for index in range(20))
        guard = Guard(policy=Policy(), key=KEY, replay_store=store, clock=lambda: 1000.0,
                      nonce_factory=lambda: next(counter))
        for _ in range(20):
            action = build_action()
            self.assertEqual(
                guard.execute(action, guard.authorize(action).authorization,
                              Mock()).status, "succeeded")
        self.assertEqual(len(store._consumed), 20)
        self.assertEqual(len(guard.audit.snapshot()), 60)
        self.assertEqual(guard.audit.snapshot(), guard.audit.snapshot())

    def test_h4_audit_log_has_no_bound_or_eviction_api(self) -> None:
        for removed in ("evict", "rotate", "flush", "truncate", "clear", "pop"):
            with self.subTest(removed=removed):
                self.assertFalse(hasattr(AuditLog, removed))
                self.assertFalse(hasattr(ReplayStore, removed))


if __name__ == "__main__":
    unittest.main()