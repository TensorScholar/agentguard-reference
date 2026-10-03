import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .. import Action, AuditLog, Guard, Policy, __version__, verify_records

DEMO_KEY = b"public-demo-key-not-for-real-use!!"
DEMO_SCHEMA = "agentguard-reference-demo-v2"

KEY_WARNING = (
    "The HMAC key used by this demo is published in the package source. It is not a "
    "secret. Any verification result shown here is a self-check under that public key "
    "and is not evidence about anything."
)
NOT_CORE = (
    "This package is a reference implementation. It is not AgentGuard Core and it is "
    "not a newer version of Core."
)


def _action(amount_minor: int = 8500, **changes: Any) -> Action:
    values: dict[str, Any] = {
        "principal": "synthetic-user",
        "name": "refund.create",
        "audience": "refund-demo",
        "arguments": {"amount_minor": amount_minor, "order_id": "synthetic-order"},
    }
    values.update(changes)
    return Action.create(**values)


def _result(status: str, reason: str) -> dict[str, Any]:
    return {"status": status, "reason": reason}


def scenario_mutation(audit: AuditLog) -> dict[str, Any]:
    """A changed argument after approval must not reach the callback."""
    guard = Guard(policy=Policy(), key=DEMO_KEY, audit=audit, clock=lambda: 1000.0,
                  nonce_factory=lambda: "synthetic-ticket-mutation")
    approved = _action()
    decision = guard.authorize(approved)
    changed = _action(amount_minor=9800)
    calls: list[dict[str, Any]] = []
    outcome = guard.execute(changed, decision.authorization, calls.append)
    return {
        "id": "mutation",
        "title": "Argument mutation is blocked",
        "claim": (
            "Authorization is bound to one immutable action snapshot. Changing any bound "
            "field after approval denies dispatch and never calls the callback."
        ),
        "lines": [
            "Approve a refund of 8500 minor units for order synthetic-order.",
            "Then change the amount to 9800 and present the same approval.",
            f"Result: {outcome.status} / {outcome.reason}",
            f"Callback invocations: {len(calls)}",
        ],
        "observed": {
            "approved_action_digest": approved.digest,
            "presented_action_digest": changed.digest,
            "execution": asdict(outcome),
            "executor_called": outcome.executor_called,
            "callback_invocations": len(calls),
        },
        "property_held": (
            outcome.status == "denied"
            and outcome.reason == "authorization.action_mismatch"
            and outcome.executor_called is False
            and len(calls) == 0
            and approved.digest != changed.digest
        ),
    }


def scenario_expiry(audit: AuditLog) -> dict[str, Any]:
    """At exactly expires_at the ticket is refused, and refusal does not consume it."""
    now = [1000.0]
    guard = Guard(policy=Policy(), key=DEMO_KEY, audit=audit, clock=lambda: now[0],
                  nonce_factory=lambda: "synthetic-ticket-expiry")
    action = _action()
    decision = guard.authorize(action)
    authorization = decision.authorization
    assert authorization is not None
    calls: list[dict[str, Any]] = []

    now[0] = authorization.expires_at
    at_boundary = guard.execute(action, authorization, calls.append)
    calls_at_boundary = len(calls)

    now[0] = authorization.issued_at
    in_window = guard.execute(action, authorization, calls.append)

    return {
        "id": "expiry",
        "title": "Exact expiry denies without consuming the ticket",
        "claim": (
            "A ticket is valid only while issued_at <= now < expires_at. Exactly at the "
            "boundary it is refused, and a refused ticket is not consumed: the same "
            "ticket still works once the clock is valid again."
        ),
        "lines": [
            f"Approve at t={authorization.issued_at}. Expires at "
            f"t={authorization.expires_at} (TTL 60s).",
            f"Move the clock to exactly expires_at ({authorization.expires_at}) and "
            "present the ticket.",
            f"Result: {at_boundary.status} / {at_boundary.reason}",
            f"Callback invocations so far: {calls_at_boundary} - the callback never ran.",
            f"Move the clock back inside the window to t={authorization.issued_at} and "
            "present the same ticket.",
            f"Result: {in_window.status} / {in_window.reason}",
            "The refusal above did not consume the ticket. That is the difference "
            "between an expired ticket and a spent one.",
        ],
        "observed": {
            "issued_at": authorization.issued_at,
            "expires_at": authorization.expires_at,
            "at_exact_expiry": asdict(at_boundary),
            "inside_window": asdict(in_window),
            "callback_invocations_at_boundary": calls_at_boundary,
            "refusal_survived_clock_reset": (
                at_boundary.status == "denied" and in_window.status == "succeeded"
            ),
        },
        "property_held": (
            at_boundary.status == "denied"
            and at_boundary.reason == "authorization.invalid_time"
            and at_boundary.executor_called is False
            and in_window.status == "succeeded"
            and calls_at_boundary == 0
            and len(calls) == 1
        ),
    }


def scenario_replay(audit: AuditLog) -> dict[str, Any]:
    """A consumed ticket cannot be dispatched a second time."""
    now = [1000.0]
    guard = Guard(policy=Policy(), key=DEMO_KEY, audit=audit, clock=lambda: now[0],
                  nonce_factory=lambda: "synthetic-ticket-replay")
    action = _action()
    authorization = guard.authorize(action).authorization
    assert authorization is not None
    calls: list[dict[str, Any]] = []
    first = guard.execute(action, authorization, calls.append)
    second = guard.execute(action, authorization, calls.append)
    third = guard.execute(action, authorization, calls.append)
    return {
        "id": "replay",
        "title": "Replay is blocked",
        "claim": (
            "Single-use authority is claimed atomically before the callback runs, inside "
            "the same in-memory store in the same process. A consumed ticket is refused "
            "every later time and is never released."
        ),
        "lines": [
            "Dispatch the ticket once. It succeeds and the identifier is consumed.",
            "Present the identical ticket twice more.",
            f"Second: {second.status} / {second.reason}",
            f"Third:  {third.status} / {third.reason}",
            f"Callback invocations across all three attempts: {len(calls)}",
            "Scope: this guarantee is the same store in the same process. A restart, a "
            "second process, or a separate store is outside it.",
        ],
        "observed": {
            "first": asdict(first),
            "second": asdict(second),
            "third": asdict(third),
            "callback_invocations": len(calls),
        },
        "property_held": (
            first.status == "succeeded"
            and second.status == "denied"
            and third.status == "denied"
            and second.reason == "authorization.replayed"
            and third.reason == "authorization.replayed"
            and len(calls) == 1
        ),
    }


def scenario_unknown(audit: AuditLog) -> dict[str, Any]:
    """A callback that fails after dispatch is unknown, not success and not a retry."""
    guard = Guard(policy=Policy(), key=DEMO_KEY, audit=audit, clock=lambda: 1000.0,
                  nonce_factory=lambda: "synthetic-ticket-unknown")
    action = _action()
    authorization = guard.authorize(action).authorization
    assert authorization is not None
    calls: list[dict[str, Any]] = []

    def failing_callback(arguments: dict[str, Any]) -> None:
        calls.append(arguments)
        raise RuntimeError("synthetic downstream failure")

    outcome = guard.execute(action, authorization, failing_callback)
    retry = guard.execute(action, authorization, calls.append)
    return {
        "id": "unknown",
        "title": "unknown means dispatch happened and the outcome is unconfirmed",
        "claim": (
            "When the callback has already been dispatched and then fails, or outcome "
            "auditing fails, the result is unknown. Unknown is not success. It is also "
            "not evidence that nothing happened, and it is not permission to retry the "
            "same ticket."
        ),
        "lines": [
            "Dispatch a ticket whose callback raises after being called.",
            f"Result: {outcome.status} / {outcome.reason}",
            f"executor_called: {'true' if outcome.executor_called else 'false'} - the "
            "callback did run, so an external effect may already exist.",
            "Present the same ticket again.",
            f"Result: {retry.status} / {retry.reason}",
            "This package has no reconciliation path. An unknown outcome must be resolved "
            "out of band; reusing the ticket is refused.",
        ],
        "observed": {
            "execution": asdict(outcome),
            "retry": asdict(retry),
            "callback_invocations": len(calls),
        },
        "property_held": (
            outcome.status == "unknown"
            and outcome.reason == "executor.raised"
            and outcome.executor_called is True
            and retry.status == "denied"
            and retry.reason == "authorization.replayed"
        ),
    }


def scenario_tamper(audit: AuditLog) -> dict[str, Any]:
    """What the audit chain detects, and the one thing it cannot."""
    records = audit.snapshot()
    head = audit.head
    self_check = verify_records(records, DEMO_KEY, expected_head=head)

    tampered = [dict(record) for record in records]
    target = tampered[len(tampered) // 2]
    target["reason"] = "policy.allowed" if target["reason"] != "policy.allowed" else "tampered"
    tampered_rejected = verify_records(tampered, DEMO_KEY, expected_head=head)

    prefix = records[:-1]
    prefix_without_head = verify_records(prefix, DEMO_KEY)
    prefix_with_head = verify_records(prefix, DEMO_KEY, expected_head=head)

    wrong_key = verify_records(records, b"a-different-key-entirely--------")
    yes, no = "true", "false"

    return {
        "id": "tamper",
        "title": "Tampering is detected; completeness is not implied",
        "claim": (
            "Each audit record is MAC'd and chained to the previous one, so an edited, "
            "reordered, or forged record is rejected under the right key. A valid prefix "
            "is still a valid prefix: only a trusted expected head establishes that the "
            "chain is complete."
        ),
        "lines": [
            f"Chain length under the public demo key: {len(records)} records.",
            "Self-check, untampered chain, external key plus trusted expected head: "
            f"{yes if self_check else no}. This is a tautology: the key is published in "
            "this file, so it proves internal consistency and nothing else.",
            "Edit one record's reason field: verification returns "
            f"{yes if tampered_rejected else no}.",
            f"Verify with a different key: {yes if wrong_key else no}.",
            "Drop the last record and verify with no expected head: "
            f"{yes if prefix_without_head else no} - the shortened chain is still "
            "internally consistent.",
            "Verify the same shortened chain against the trusted head: "
            f"{yes if prefix_with_head else no}.",
            "So an expected head obtained through a trusted channel is what makes "
            "truncation detectable. Without one, a shorter chain still looks valid.",
        ],
        "observed": {
            "record_count": len(records),
            "self_check_under_public_demo_key": self_check,
            "tampered_record_rejected": tampered_rejected is False,
            "wrong_key_rejected": wrong_key is False,
            "valid_prefix_accepted_without_trusted_head": prefix_without_head,
            "valid_prefix_rejected_with_trusted_head": prefix_with_head is False,
        },
        "property_held": (
            self_check
            and tampered_rejected is False
            and wrong_key is False
            and prefix_without_head
            and prefix_with_head is False
        ),
    }


def demo_document() -> dict[str, Any]:
    """Run every scenario against one shared audit chain and return the result."""
    audit = AuditLog(DEMO_KEY)
    scenarios = [
        scenario_mutation(audit),
        scenario_expiry(audit),
        scenario_replay(audit),
        scenario_unknown(audit),
        scenario_tamper(audit),
    ]
    records = audit.snapshot()
    head = audit.head
    return {
        "schema": DEMO_SCHEMA,
        "package_version": __version__,
        "identity": NOT_CORE,
        "key": "published in source; not a secret",
        "scenarios": scenarios,
        "all_properties_held": all(item["property_held"] for item in scenarios),
        "audit": {
            "record_count": len(records),
            "head": head,
            "self_check_under_public_demo_key": verify_records(records, DEMO_KEY,
                                                               expected_head=head),
            "records": records,
        },
    }


def demo() -> dict[str, Any]:
    return demo_document()


def _rule(char: str = "=") -> str:
    return char * 78


def render_demo(document: dict[str, Any]) -> str:
    lines = [
        _rule(),
        f" AgentGuard Reference {document['package_version']} - guided demo",
        _rule(),
        "",
        " " + "\n ".join(_wrap(document["identity"], 76)),
        "",
        " One idea: an authorized structured action is bound to ONE guarded callback",
        " dispatch, and the evidence for that can be checked offline with a key and a",
        " head you already trust.",
        "",
        " " + "\n ".join(_wrap("NOT EVIDENCE: " + KEY_WARNING, 76)),
        "",
    ]
    total = len(document["scenarios"])
    for index, scenario in enumerate(document["scenarios"], 1):
        lines += [
            _rule("-"),
            f" {index}/{total}  {scenario['title']}",
            _rule("-"),
            " Property",
        ]
        lines += ["   " + text for text in _wrap(scenario["claim"], 74)]
        lines += ["", " What happened"]
        for text in scenario["lines"]:
            lines += ["   " + row for row in _wrap(text, 74)]
        verdict = "HELD" if scenario["property_held"] else "NOT HELD"
        lines += ["", f"   -> property {verdict}", ""]
    audit = document["audit"]
    lines += [
        _rule("-"),
        " Audit chain produced by this run",
        _rule("-"),
        f"   records: {audit['record_count']}",
        f"   head:    {audit['head']}",
        "",
        " Event sequence:",
    ]
    for record in audit["records"]:
        lines.append(
            f"   {record['sequence']:>2}. {record['event']:<20} {record['reason']}"
        )
    lines += [
        "",
        "Every field above is deterministic and synthetic. No refund is issued "
        "and no provider is contacted.",
        "",
        "Read next: docs/limitations.md for what this package does NOT guarantee,",
        "and docs/threat-model.md for its assumptions.",
        "",
    ]
    if document["all_properties_held"]:
        lines += [f"All {total} demonstrated properties held.", ""]
    else:
        lines += ["At least one demonstrated property did NOT hold. Treat this run as a "
                  "failure.", ""]
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    rows: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            rows.append(current)
            current = word
        else:
            current = candidate
    if current:
        rows.append(current)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentguard-reference",
        description="AgentGuard Reference: a guarded-callback boundary reference. "
                    "Not AgentGuard Core.",
        epilog="With no arguments, runs the guided demo.",
    )
    subcommands = parser.add_subparsers(dest="command")
    demo_parser = subcommands.add_parser(
        "demo", help="narrate the five properties this reference enforces")
    demo_parser.add_argument("--json", action="store_true",
                             help="emit the raw machine-readable document instead")
    verify = subcommands.add_parser("verify", help="verify an audit record array or demo document")
    verify.add_argument("file", type=Path)
    verify.add_argument("--key-file", required=True, type=Path)
    verify.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)

    if args.command in (None, "demo"):
        document = demo_document()
        print(KEY_WARNING, file=sys.stderr)
        if getattr(args, "json", False):
            print(json.dumps(document, sort_keys=True, indent=2))
        else:
            print(render_demo(document))
        held = bool(document["all_properties_held"])
        checked = bool(document["audit"]["self_check_under_public_demo_key"])
        return 0 if held and checked else 1

    try:
        if args.file.stat().st_size > 10 * 1024 * 1024 or args.key_file.stat().st_size > 4096:
            raise ValueError("input too large")
        document = json.loads(args.file.read_text(encoding="utf-8"))
        records = document.get("records") if isinstance(document, dict) else document
        if not isinstance(records, list):
            raise ValueError("records must be an array")
        verified = verify_records(records, args.key_file.read_bytes(),
                                  expected_head=args.expected_head)
    except (OSError, ValueError, TypeError, RecursionError):
        print("verification failed: invalid or unreadable input", file=sys.stderr)
        return 1
    print(json.dumps({"verified": verified}, sort_keys=True))
    return 0 if verified else 1