import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .. import Action, Guard, Policy, __version__, verify_records

DEMO_KEY = b"public-demo-key-not-for-real-use!!"


def demo() -> dict[str, Any]:
    guard = Guard(policy=Policy(), key=DEMO_KEY, clock=lambda: 1000.0,
                  nonce_factory=lambda: "synthetic-refund-001")
    action = Action.create(principal="synthetic-user", name="refund.create", audience="refund-demo",
                           arguments={"amount_minor": 8500})
    decision = guard.authorize(action)
    calls: list[dict[str, Any]] = []
    first = guard.execute(action, decision.authorization, calls.append)
    replay = guard.execute(action, decision.authorization, calls.append)
    records = guard.audit.snapshot()
    return {"schema": "agentguard-reference-demo-v1", "package_version": __version__,
            "key_warning": "public illustrative key",
            "decision": asdict(decision), "results": [asdict(first), asdict(replay)],
            "executor_calls": len(calls), "records": records, "head": guard.audit.head,
            "verified": verify_records(records, DEMO_KEY, expected_head=guard.audit.head)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard-reference")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("demo", help="run deterministic synthetic execution and replay denial")
    verify = subcommands.add_parser("verify", help="verify an audit record array or demo document")
    verify.add_argument("file", type=Path)
    verify.add_argument("--key-file", required=True, type=Path)
    verify.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    if args.command == "demo":
        result = demo()
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["verified"] and result["executor_calls"] == 1 else 1
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
