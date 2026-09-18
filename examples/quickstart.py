from agentguard_reference import Action, Guard, Policy, verify_records
from agentguard_reference.cli import DEMO_KEY


def main() -> None:
    guard = Guard(policy=Policy(), key=DEMO_KEY)
    action = Action.create(principal="synthetic-user", name="refund.create", audience="refund-demo",
                           arguments={"amount_minor": 8500, "order_id": "synthetic-order"})
    decision = guard.authorize(action)
    first = guard.execute(action, decision.authorization, lambda arguments: print(arguments))
    replay = guard.execute(action, decision.authorization, lambda arguments: print(arguments))
    assert first.status == "succeeded"
    assert replay.status == "denied"
    assert verify_records(guard.audit.snapshot(), DEMO_KEY, expected_head=guard.audit.head)
    print(first.status, replay.reason)


if __name__ == "__main__":
    main()
