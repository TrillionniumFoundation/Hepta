#!/usr/bin/env python3
"""Fail-closed exact-SHA Hepta qualification inventory checker.

This is an offline audit helper, NOT a CI runner, GitHub attestation,
cryptographic signature verifier, or production release authority.

Usage:
  python3 hepta_exact_head_gate.py --snapshot hepta_blocker_snapshot_20261023.json
  python3 hepta_exact_head_gate.py --self-test
  python3 hepta_exact_head_gate.py --snapshot ... --worktree /path/to/hepta-private-ci

A verdict of BLOCKED means this snapshot does not prove that every required
gate completed successfully at the exact same source SHA. Old successful
runs, cancelled jobs, skipped jobs and empty evidence are never substituted.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import unittest

HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED = ("blocking-ci", "Hepta architecture convergence", "v8-canary")

def inspect(candidate: dict) -> dict:
    sha = candidate.get("sha")
    if not isinstance(sha, str) or not HEX40.fullmatch(sha):
        return {"name": candidate.get("name"), "status": "BLOCKED", "reason": "invalid exact SHA"}
    per_name = {}
    for run in candidate.get("runs", []):
        name, status, conclusion = run.get("name"), run.get("status"), run.get("conclusion")
        # This snapshot stores only runs explicitly fetched by commit SHA.
        if run.get("sha") != sha or not isinstance(name, str):
            return {"name": candidate.get("name"), "status": "BLOCKED", "reason": "run-source identity mismatch"}
        state = "PASS" if status == "completed" and conclusion == "success" else "BLOCKED"
        # Multiple same-name runs do not make cancellation a pass. Only the
        # latest observed attempt could qualify if all other gates pass.
        per_name[name] = state
    needed = candidate.get("required", list(REQUIRED))
    if not isinstance(needed, list) or not needed or not all(isinstance(x, str) for x in needed):
        return {"name": candidate.get("name"), "status": "BLOCKED", "reason": "invalid required-gate declaration"}
    missing = [n for n in needed if per_name.get(n) != "PASS"]
    evidence = candidate.get("external_evidence", {})
    unqualified = [k for k, v in evidence.items() if v is not True]
    good = not missing and not unqualified
    return {"name": candidate.get("name"), "sha": sha, "status": "PASS_SCOPED" if good else "BLOCKED", "required_gates": per_name, "missing_or_unverified": missing, "unqualified_external_evidence": unqualified}

def local_probe(worktree: str | None) -> dict:
    out = {"worktree_supplied": bool(worktree), "tools": {c: shutil.which(c) for c in ("git", "cargo", "rustc", "rustfmt", "just", "bazel")}}
    if not worktree:
        out["status"] = "UNAVAILABLE: no source worktree selected"
        return out
    root = pathlib.Path(worktree)
    try:
        r = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, capture_output=True, timeout=10, check=True)
        out["head"] = r.stdout.strip()
        p = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], text=True, capture_output=True, timeout=10, check=True)
        out["worktree_clean"] = not bool(p.stdout.strip())
    except (OSError, subprocess.SubprocessError) as exc:
        out["status"] = "UNAVAILABLE: " + str(exc)
        return out
    out["status"] = "AVAILABLE_FOR_LOCAL_CHECKS" if out["worktree_clean"] else "BLOCKED: local modifications require reconciliation"
    return out

class GateTests(unittest.TestCase):
    def setUp(self):
        self.good = {"name": "fixture", "sha": "a" * 40, "required": list(REQUIRED), "runs": [{"name": n, "sha": "a" * 40, "status": "completed", "conclusion": "success"} for n in REQUIRED], "external_evidence": {"model": True}}
    def test_exact_sha_success(self):
        self.assertEqual(inspect(self.good)["status"], "PASS_SCOPED")
    def test_old_sha_cannot_qualify(self):
        self.good["runs"][0]["sha"] = "b" * 40
        self.assertEqual(inspect(self.good)["reason"], "run-source identity mismatch")
    def test_cancelled_or_skipped_are_not_passes(self):
        for conclusion in ("cancelled", "skipped", "failure", None):
            with self.subTest(conclusion=conclusion):
                self.good["runs"][1]["conclusion"] = conclusion
                self.assertEqual(inspect(self.good)["status"], "BLOCKED")
    def test_absent_required_gate_is_blocked(self):
        self.good["runs"].pop()
        self.assertEqual(inspect(self.good)["status"], "BLOCKED")
    def test_external_evidence_is_independent(self):
        self.good["external_evidence"]["independent_observer"] = None
        self.assertIn("independent_observer", inspect(self.good)["unqualified_external_evidence"])
    def test_invalid_required_gates_cannot_pass(self):
        self.good["required"] = []
        self.assertEqual(inspect(self.good)["status"], "BLOCKED")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", type=pathlib.Path)
    ap.add_argument("--worktree")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(GateTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if not args.snapshot:
        ap.error("--snapshot is required unless --self-test")
    content = json.loads(args.snapshot.read_text(encoding="utf-8"))
    rows = [inspect(x) for x in content["candidates"]]
    report = {"schema": "hepta.offline.exact-head.gate-audit.v1", "snapshot_time": content.get("observed_at"), "source": "snapshot supplied by caller, not live GitHub verification", "candidates": rows, "local_probe": local_probe(args.worktree), "global_verdict": "BLOCKED" if any(r["status"] != "PASS_SCOPED" for r in rows) else "PASS_SCOPED_NOT_PRODUCTION_AUTHORITY"}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2 if report["global_verdict"] == "BLOCKED" else 0

if __name__ == "__main__":
    sys.exit(main())
