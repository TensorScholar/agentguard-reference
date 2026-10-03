"""Minimal API walkthrough: the three ideas, on one page.

Run the guided demo for the full narrated walkthrough, including replay and audit
tampering:

    python -m agentguard_reference

The HMAC key used here is published in this package's source. It is not a secret, so
the verification assertion at the end is a self-check under a public key and is not
evidence about anything.
"""

from agentguard_reference import Action, Guard, Policy, verify_records
from agentguard_reference.cli import DEMO_KEY


def build_guard(clock):
    return Guard(policy=Policy(), key=DEMO_KEY, clock=clock,
                 nonce_factory=lambda: "quickstart-ticket")


def main() -> None:
    action = Action.create(principal="synthetic-user", name="refund.create",
                           audience="refund-demo",
                           arguments={"amount_minor": 8500, "order_id": "synthetic-order"})
    dispatched: list[dict] = []

    # 1. authorize is not execute. It returns a ticket and calls nothing.
    now = [1000.0]
    guard = build_guard(lambda: now[0])
    decision = guard.authorize(action)
    print("authorize ->", decision.reason, "| executor called:", len(dispatched))

    # 2. A changed argument cannot reuse that ticket.
    tampered = Action.create(principal="synthetic-user", name="refund.create",
                             audience="refund-demo",
                             arguments={"amount_minor": 9800, "order_id": "synthetic-order"})
    mutated = guard.execute(tampered, decision.authorization, dispatched.append)
    print("mutation  ->", mutated.status, "/", mutated.reason,
          "| executor called:", mutated.executor_called)

    # 3. At exactly expires_at the ticket is refused, and refusal does not consume it.
    assert decision.authorization is not None
    now[0] = decision.authorization.expires_at
    at_expiry = guard.execute(action, decision.authorization, dispatched.append)
    print("expiry    ->", at_expiry.status, "/", at_expiry.reason,
          "| executor called:", at_expiry.executor_called)

    # 4. Inside the window the same ticket still works: it was refused, not spent.
    now[0] = 1000.0
    accepted = guard.execute(action, decision.authorization, dispatched.append)
    print("in-window ->", accepted.status, "/", accepted.reason,
          "| executor called:", accepted.executor_called)

    # 5. A consumed ticket cannot be replayed.
    replay = guard.execute(action, decision.authorization, dispatched.append)
    print("replay    ->", replay.status, "/", replay.reason)

    # 6. After dispatch, a failing callback is unknown, never success.
    def failing(arguments: dict) -> None:
        dispatched.append(arguments)
        raise RuntimeError("synthetic downstream failure")

    now[0] = 2000.0
    second = build_guard(lambda: now[0])
    ticket = second.authorize(action).authorization
    assert ticket is not None
    unknown = second.execute(action, ticket, failing)
    print("unknown   ->", unknown.status, "/", unknown.reason,
          "| executor called:", unknown.executor_called)
    print("            unknown means dispatch happened, outcome unconfirmed,")
    print("            and it is not permission to retry this ticket.")

    # 7. Self-check under the published key. Not evidence.
    records = guard.audit.snapshot()
    consistent = verify_records(records, DEMO_KEY, expected_head=guard.audit.head)
    print(f"\naudit chain: {len(records)} records under the published demo key")
    print("self-check under a public key ->", consistent, "(not evidence)")


if __name__ == "__main__":
    main()