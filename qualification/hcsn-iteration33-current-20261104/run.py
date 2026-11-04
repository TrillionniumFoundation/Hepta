#!/usr/bin/env python3
"""Run the unchanged iteration-33 research commands with exact source binding.

This qualification never grants scientific admission or production activation.
It preserves the original report, including its old test-source fingerprint.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MODULES = (
    "research.hcsn.test_p2_markov_defective_firsthit",
    "research.hcsn.test_p2_defective_first_hit_clock",
    "research.hcsn.test_p2_first_hit_renewal_falsification",
    "research.hcsn.test_p2_physical_hazard_clock",
)
PHASES = {f"P{i}" for i in range(7)}
MAX_RETAINED_STREAM = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def parse(raw):
    def nonfinite(_):
        raise RuntimeError("NONFINITE_JSON")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def git(*args):
    completed = subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=ROOT, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60,
    )
    require(completed.returncode == 0, "GIT_COMMAND_FAILED")
    return completed.stdout


def regular_file(path):
    require(stat.S_ISREG(path.lstat().st_mode), "SOURCE_NOT_REGULAR")
    for ancestor in path.parents:
        if ancestor == ROOT:
            break
        require(not ancestor.is_symlink(), "SOURCE_ANCESTOR_SYMLINK")
    return path.read_bytes()


def snapshot(config):
    require(git("rev-parse", "HEAD:research/hcsn").decode().strip() == config["original_hcsn_tree"],
            "ORIGINAL_RESEARCH_TREE_CHANGED")
    raw = git("ls-tree", "-rz", "--full-tree", "HEAD", "--", "research/hcsn",
              "qualification/hcsn-iteration33-current-20261104",
              ".github/workflows/hepta-hcsn-iteration33-current.yml")
    records = {}
    total = 0
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        meta, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        path = raw_path.decode("utf-8")
        require(mode in {"100644", "100755"} and kind == "blob", "NONREGULAR_GIT_INPUT")
        data = regular_file(ROOT / path)
        total += len(data)
        require(total <= MAX_SOURCE_BYTES, "SOURCE_BYTE_BUDGET")
        require(git_blob(data) == oid and git("cat-file", "blob", oid) == data,
                "WORKTREE_DIFFERS_FROM_GIT")
        require(path not in records, "DUPLICATE_SOURCE_PATH")
        records[path] = {"git_blob_sha": oid, "sha256": sha(data), "bytes": len(data), "mode": mode}
    require(len(records) > 100, "INCOMPLETE_RESEARCH_SNAPSHOT")
    require(not git("diff", "--name-only", "HEAD", "--"), "TRACKED_SOURCE_DIRTY")
    return records


def inventory():
    cases = []
    for module in MODULES:
        path = ROOT / (module.replace(".", "/") + ".py")
        tree = ast.parse(regular_file(path), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [ast.unparse(base) for base in node.bases]
            if "unittest.TestCase" not in bases:
                continue
            for method in node.body:
                if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"):
                    cases.append(module + "." + node.name + "." + method.name)
    require(len(cases) == len(set(cases)) == 38, "ORIGINAL_38_CASE_INVENTORY_CHANGED")
    return sorted(cases)


def inspect_tests(raw, expected):
    text = raw.decode("utf-8").replace("\r\n", "\n")
    observed = re.findall(
        r"^test_[^\s(]+ \(([A-Za-z_][A-Za-z0-9_.]+)\) \.\.\. ok$", text, re.M
    )
    require(len(observed) == len(set(observed)) == len(expected)
            and set(observed) == set(expected), "CASE_SET")
    summaries = re.findall(r"^Ran (\d+) tests? in ([0-9.]+)s$", text, re.M)
    require(len(summaries) == 1 and int(summaries[0][0]) == len(expected), "SUMMARY")
    require(re.search(r"\nOK\n?\Z", text) is not None, "OK_TRAILER")
    require(not re.search(r"\.\.\. (?:skipped|FAIL|ERROR)|^FAILED\b", text, re.M), "CASE_FAILURE")
    return {"passed": len(observed), "failed": 0, "errors": 0, "skipped": 0,
            "exact_cases": sorted(observed), "scope": "Only the original four iteration-33 modules."}


def validate_raw(report, expected_sources):
    require(report.get("schema") == "hcsn.p2.iteration33.markov-defective.v1", "RAW_SCHEMA")
    require(report.get("scientific_admission") is False
            and report.get("production_activation") is False
            and report.get("gates") == {p: "OPEN" for p in PHASES}, "RESEARCH_BOUNDARY")
    require(report.get("sha256_sources") == expected_sources, "SOURCE_DIGESTS")
    require(type(report.get("num_samples_per_seed_and_transition")) is int
            and report["num_samples_per_seed_and_transition"] == 45000
            and report.get("seeds") == [11, 23, 37], "SAMPLE_BUDGET")
    scenarios = report.get("scenarios")
    require(isinstance(scenarios, list) and len(scenarios) == 2
            and {x["scenario"] for x in scenarios} == {"stay", "alternate"}, "SCENARIOS")
    for scenario in scenarios:
        rows = scenario["per_seed_rank"]
        require(len(rows) == 9
                and {(r["seed"], r["rank"]) for r in rows}
                == {(seed, rank) for seed in (11, 23, 37) for rank in (1, 2, 3)}
                and all(r["sample_paths"] == 45000 and r["finite_horizon_s"] == 8.0 for r in rows),
                "PANEL_BUDGET")
    return {"source_digests_match_current_bytes": True, "independent_seed_transition_panels": 6,
            "sample_paths_per_panel": 45000, "synthetic_trajectories": 270000,
            "scientific_admission": False, "production_activation": False}


def validate_gate(report):
    require(report.get("full_closure") is False
            and report.get("production_activation") is False
            and report.get("independent_attestation_verified") is False
            and set(report.get("gates", {})) == PHASES, "EMPTY_GATE_BOUNDARY")
    require(all(row.get("status") == "OPEN" and row.get("production_ready") is False
                for row in report["gates"].values()), "EMPTY_GATE_PHASES")


def execute(argv, name, out, commands, expected_exit=0):
    start = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=False, timeout=600)
        exit_code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code, stdout, stderr = None, error.stdout or b"", error.stderr or b""
    row = {"name": name, "argv": argv, "exit_code": exit_code, "timed_out": timed_out,
           "expected_exit_code": expected_exit, "seconds": time.monotonic() - start}
    commands.append(row)
    for suffix, raw in (("stdout", stdout), ("stderr", stderr)):
        require(len(raw) <= MAX_RETAINED_STREAM, "RETAINED_STREAM_TOO_LARGE")
        (out / (name + "." + suffix)).write_bytes(raw)
        row[suffix] = {"bytes": len(raw), "sha256": sha(raw)}
        if raw:
            print(raw.decode("utf-8"), end="", flush=True)
    require(not timed_out, "ORIGINAL_COMMAND_TIMEOUT")
    require(exit_code == expected_exit, "ORIGINAL_COMMAND_EXIT")
    return stdout + stderr


def self_test():
    names = ["p.T.test_one", "p.T.test_two"]
    good = (b"test_one (p.T.test_one) ... ok\n"
            b"test_two (p.T.test_two) ... ok\n\nRan 2 tests in 0.001s\n\nOK\n")
    checks = []
    require(inspect_tests(good, names)["passed"] == 2, "CONTROL_POSITIVE")
    checks.append("complete exact case set accepted")

    def denied(name, callback, code):
        try:
            callback()
        except RuntimeError as error:
            require(str(error) == code, "CONTROL_WRONG_REJECTION")
        else:
            raise RuntimeError("CONTROL_FALSE_GREEN")
        checks.append(name)

    denied("missing case", lambda: inspect_tests(good.replace(b"test_two (p.T.test_two) ... ok\n", b""), names), "CASE_SET")
    denied("duplicate case", lambda: inspect_tests(good.replace(b"test_two (p.T.test_two)", b"test_one (p.T.test_one)"), names), "CASE_SET")
    denied("skipped case", lambda: inspect_tests(good.replace(b"test_two (p.T.test_two) ... ok", b"test_two (p.T.test_two) ... skipped 'fixture'"), names), "CASE_SET")
    denied("false summary count", lambda: inspect_tests(good.replace(b"Ran 2 tests", b"Ran 1 test"), names), "SUMMARY")
    denied("missing success trailer", lambda: inspect_tests(good.replace(b"\nOK\n", b"\nFAILED\n"), names), "OK_TRAILER")
    baseline = {"schema": "hcsn.p2.iteration33.markov-defective.v1",
                "scientific_admission": False, "production_activation": False,
                "gates": {p: "OPEN" for p in PHASES}, "sha256_sources": {"test.py": "old"}}
    denied("old source fingerprint", lambda: validate_raw(baseline, {"test.py": "current"}), "SOURCE_DIGESTS")
    denied("production admission", lambda: validate_raw({**baseline, "production_activation": True}, {"test.py": "old"}), "RESEARCH_BOUNDARY")
    denied("zero sample count", lambda: validate_raw({**baseline, "num_samples_per_seed_and_transition": 0, "seeds": [11, 23, 37]}, {"test.py": "old"}), "SAMPLE_BUDGET")
    print("HCSN_READER_CONTROLS=" + json.dumps({"passed": len(checks), "failed": 0,
          "synthetic_only": True, "checks": checks}, sort_keys=True), flush=True)


def main():
    require(__debug__, "OPTIMIZED_PYTHON")
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    require(args.out is not None, "OUTPUT_REQUIRED")
    out = args.out.resolve()
    require(not out.is_relative_to(ROOT), "OUTPUT_INSIDE_SOURCE")
    out.mkdir(parents=True, exist_ok=False)
    config = parse((HERE / "inputs.json").read_bytes())
    receipt = {"schema": "hcsn.iteration33.current-source-qualification.v1", "status": "failed",
               "commands": [], "scientific_admission": False, "production_activation": False,
               "gates": {p: "OPEN" for p in sorted(PHASES)},
               "scope": "New execution of the original four research test modules, original synthetic evidence command, and empty-bundle refusal. Not full HCSN qualification or historical native-log verification.",
               "historical_scipy_version_known": False, "original_report_modified": False}
    before = None
    failed = None
    try:
        head = git("rev-parse", "HEAD").decode().strip()
        require(head == os.environ.get("GITHUB_SHA"), "WORKFLOW_HEAD")
        require(git("merge-base", config["original_commit"], head).decode().strip()
                == config["original_commit"], "SOURCE_ANCESTRY")
        changed = set(git("diff", "--name-only", config["original_commit"], head, "--").decode().splitlines())
        require(changed <= set(config["qualification_paths"]), "CHANGES_OUTSIDE_QUALIFICATION")
        receipt.update({"source_commit": head, "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
                        "original_research_commit": config["original_commit"],
                        "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]})
        before = snapshot(config)
        (out / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
        import numpy
        import scipy
        versions = {"python": platform.python_version(), "numpy": numpy.__version__, "scipy": scipy.__version__}
        require(versions == config["software"], "SOFTWARE_VERSIONS")
        receipt["software"] = versions
        expected = inventory()
        (out / "test-inventory.json").write_text(json.dumps(expected, indent=2) + "\n")
        original_path = ROOT / config["original_report"]["path"]
        original_bytes = regular_file(original_path)
        require(sha(original_bytes) == config["original_report"]["sha256"], "ORIGINAL_REPORT_BYTES")
        original = parse(original_bytes)
        expected_sources = {name: before["research/hcsn/" + name]["sha256"] for name in config["source_names"]}
        require(expected_sources == config["current_source_sha256"], "SOURCE_MANIFEST")
        mismatch = {name: {"recorded": original["sha256_sources"].get(name), "current": value}
                    for name, value in expected_sources.items()
                    if original["sha256_sources"].get(name) != value}
        require(mismatch == config["original_source_mismatches"], "ORIGINAL_MISMATCH_CHANGED")
        receipt["original_report_source_mismatches"] = mismatch
        original_log = execute([sys.executable, "-m", "unittest", *MODULES, "-v"],
                               "original-four-modules", out, receipt["commands"])
        receipt["tests"] = inspect_tests(original_log, expected)
        generated_path = out / "current-markov-defective-raw.json"
        execute([sys.executable, "-m", "research.hcsn.p2_markov_defective_evidence",
                 "--samples", "45000", "--output", str(generated_path)],
                "original-evidence", out, receipt["commands"])
        generated_bytes = generated_path.read_bytes()
        generated = parse(generated_bytes)
        receipt["fresh_evidence"] = validate_raw(generated, expected_sources)
        receipt["fresh_evidence"].update({"sha256": sha(generated_bytes), "bytes": len(generated_bytes)})
        ignored_metadata = {"sha256_sources", "software"}
        receipt["new_vs_original_nonmetadata_changed_top_level_keys"] = sorted(
            key for key in set(original) | set(generated)
            if key not in ignored_metadata and original.get(key) != generated.get(key))
        empty = out / "empty-untrusted"
        empty.mkdir()
        gate_path = out / "strict-gate.json"
        execute([sys.executable, "-m", "research.hcsn.independent_gate", "--bundle", str(empty),
                 "--strict", "--output", str(gate_path)], "original-empty-bundle-gate",
                out, receipt["commands"], expected_exit=2)
        gate = parse(gate_path.read_bytes())
        validate_gate(gate)
        receipt["empty_gate"] = {"expected_exit_code": 2, "observed_exit_code": 2,
                                 "sha256": sha(gate_path.read_bytes()), "all_phases_open": True}
        require(regular_file(original_path) == original_bytes, "ORIGINAL_REPORT_CHANGED")
        receipt["status"] = "source-bound-research-commands-passed"
    except Exception as error:
        failed = error
        receipt["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            after = snapshot(config)
            (out / "source-after.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
            require(before is not None and after == before, "SOURCE_CHANGED_DURING_EXECUTION")
            receipt["source_unchanged"] = True
        except Exception as error:
            failed = failed or error
            receipt["source_check_error"] = {"type": type(error).__name__, "message": str(error)}
            receipt["source_unchanged"] = False
        if failed is not None:
            receipt["status"] = "failed"
        receipt["retained_outputs"] = {
            path.name: {"bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
            for path in sorted(out.iterdir()) if path.is_file() and path.name != "receipt.json"
        }
        rendered = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n"
        (out / "receipt.json").write_text(rendered)
        print("HCSN_CURRENT_SOURCE_RESULT=" + json.dumps(receipt, sort_keys=True, allow_nan=False), flush=True)
    if failed is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
