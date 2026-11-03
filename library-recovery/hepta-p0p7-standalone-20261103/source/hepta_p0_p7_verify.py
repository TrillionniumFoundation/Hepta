"""Fail-closed structural validation for Hepta P0-P7 program ledger.

A passing structural check NEVER verifies model science, independent attestations,
CI provenance, or production authority. Use --require-closed for release preflight.
"""
import argparse
import json
import re
import sys
from pathlib import Path

STAGES = tuple(f"P{i}" for i in range(8))
OPEN_STATES = frozenset(("OPEN", "PATCHED_PENDING_CI", "LIMITED_RESEARCH_EVIDENCE", "FAILED_GATE"))
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def validate(data):
    """Return a normalized summary, raising ValueError for inconsistent claims."""
    if type(data) is not dict or data.get("schema") != "hepta.nextgen.p0-p7.blockers.v1":
        raise ValueError("unknown P0-P7 ledger schema")
    if not HEX40.fullmatch(str(data.get("main_head", ""))):
        raise ValueError("main head is not an exact SHA")
    items = data.get("stages")
    if type(items) is not list or [x.get("id") for x in items if type(x) is dict] != list(STAGES):
        raise ValueError("must contain all eight unique ordered stages")
    closed = set()
    rows = []
    for index, item in enumerate(items):
        if type(item) is not dict or item.get("id") != STAGES[index]:
            raise ValueError("invalid stage")
        expected_dependencies = [] if index == 0 else [STAGES[index - 1]]
        if item.get("depends_on") != expected_dependencies:
            raise ValueError(f"{item['id']}: invalid dependency ordering")
        if item.get("status") not in ("BLOCKED", "CLOSED"):
            raise ValueError(f"{item['id']}: invalid stage status")
        blockers = item.get("blockers")
        if type(blockers) is not list or not blockers:
            raise ValueError(f"{item['id']}: missing blocker list")
        seen = set()
        open_count = 0
        for blocker in blockers:
            if type(blocker) is not dict:
                raise ValueError("invalid blocker object")
            key = blocker.get("id")
            if type(key) is not str or not key.startswith(item['id'] + "-") or key in seen:
                raise ValueError(f"{item['id']}: bad/duplicate blocker identifier")
            seen.add(key)
            state = blocker.get("status")
            if state not in OPEN_STATES | {"CLOSED"}:
                raise ValueError(f"{key}: invalid status")
            if not isinstance(blocker.get("closure_test"), str) or not blocker["closure_test"].strip():
                raise ValueError(f"{key}: missing testable closure condition")
            if type(blocker.get("source_refs")) is not list or not blocker["source_refs"]:
                raise ValueError(f"{key}: missing source references")
            if not all(isinstance(v, str) and (v.startswith("https://github.com/") or v.startswith("https://raw.githubusercontent.com/")) for v in blocker["source_refs"]):
                raise ValueError(f"{key}: unsupported source reference")
            attestations = blocker.get("closure_attestations")
            if type(attestations) is not list:
                raise ValueError(f"{key}: missing attestation field")
            if state == "CLOSED":
                if len(attestations) < 2:
                    raise ValueError(f"{key}: no independent evidence pair")
                roles = set()
                auditors = set()
                sources = set()
                for proof in attestations:
                    if type(proof) is not dict or not HEX40.fullmatch(str(proof.get("source_sha", ""))) or not HEX64.fullmatch(str(proof.get("artifact_sha256", ""))):
                        raise ValueError(f"{key}: malformed pinned proof")
                    if not isinstance(proof.get("auditor"), str) or not proof["auditor"].strip():
                        raise ValueError(f"{key}: missing independent auditor identity")
                    roles.add(proof.get("role"))
                    auditors.add(proof["auditor"])
                    sources.add(proof["source_sha"])
                if len(roles) < 2 or roles != {"execution", "independent_evaluation"} or len(sources) != 1 or len(auditors) != 2:
                    raise ValueError(f"{key}: unpaired or mixed-source proofs")
            else:
                open_count += 1
                if attestations:
                    raise ValueError(f"{key}: incomplete blocker must not carry closure attestations")
        if item['status'] == "CLOSED":
            if open_count or any(dep not in closed for dep in expected_dependencies):
                raise ValueError(f"{item['id']}: premature stage closure")
            closed.add(item['id'])
        elif open_count == 0:
            raise ValueError(f"{item['id']}: stage marked BLOCKED with every blocker closed")
        rows.append({"stage": item['id'], "status": item['status'], "open_blockers": open_count,
                     "total_blockers": len(blockers)})
    is_closed = len(closed) == len(STAGES)
    if data.get("all_blockers_closed") is not is_closed:
        raise ValueError("global closure claim contradicts stage evidence")
    if data.get("authority") != "DENY_ALL":
        raise ValueError("structural ledger never grants production authority")
    return {"structural_check": "PASS", "all_blockers_closed": is_closed,
            "authority": data['authority'], "stages": rows,
            "open_blockers": sum(row['open_blockers'] for row in rows)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--require-closed", action="store_true",
                        help="release preflight; exit 2 while any blocker remains")
    args = parser.parse_args(argv)
    try:
        if args.ledger.is_symlink() or args.ledger.stat().st_size > 1024 * 1024:
            raise ValueError("ledger must be a bounded non-symlink file")
        data = json.loads(args.ledger.read_text(encoding="utf-8"))
        summary = validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"structural_check": "FAIL", "error": str(error)}, ensure_ascii=False))
        return 3
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 2 if args.require_closed and not summary['all_blockers_closed'] else 0


if __name__ == "__main__":
    sys.exit(main())
