"""Run the retained hosted contract controls in a complete hosted source fixture.

The checked-in native contract remains unchanged and is validated separately.
The original test module, method IDs, assertions and budgets run unchanged.
A hosted fixture result never qualifies a native compiler or release.
"""
from __future__ import annotations
import os
import sys
if __name__ == "__main__" and (not sys.flags.isolated or sys.flags.optimize != 0):
    os.execv(sys.executable, [sys.executable, "-I", "-B", os.path.abspath(__file__), *sys.argv[1:]])

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

ORIGINAL_TEST = "tests/test_hia_selfhost_contract.py"
ORIGINAL_TEST_SHA256 = "c769b620d4a3e1186fdbda243ac76b5b9a1f74269646098561c7649acd5a00be"
SCOPE = "tests.test_hia_selfhost_contract.SelfhostContractTests"
EXPECTED_METHODS = 12


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("hosted source fixture requires a regular source: " + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
    if (len(raw) != before.st_size
            or any(getattr(before, name) != getattr(after, name) for name in fields)):
        raise ValueError("hosted source changed during capture: " + str(path))
    return raw


def original_ids(raw):
    if sha256(raw).hexdigest() != ORIGINAL_TEST_SHA256:
        raise ValueError("the complete original hosted contract test source changed")
    classes = [node for node in ast.parse(raw).body
               if isinstance(node, ast.ClassDef) and node.name == "SelfhostContractTests"]
    if len(classes) != 1:
        raise ValueError("the original hosted contract class changed")
    ids = sorted(SCOPE + "." + node.name for node in classes[0].body
                 if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))
    if len(ids) != EXPECTED_METHODS:
        raise ValueError("the complete original hosted contract method inventory changed")
    return ids


CHILD = r"""
import json, pathlib, sys, unittest
root, expected, result_path = pathlib.Path(sys.argv[1]), json.loads(sys.argv[2]), pathlib.Path(sys.argv[3])
sys.path.insert(0, str(root))
suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_hia_selfhost_contract.SelfhostContractTests")
def flatten(value):
    for item in value:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item.id()
ids = list(flatten(suite))
if ids != expected or suite.countTestCases() != len(expected):
    raise ValueError("loaded hosted controls differ from the complete original inventory")
result = unittest.TextTestRunner(verbosity=2).run(suite)
complete = result.testsRun == len(expected)
clean = not (result.errors or result.failures or result.skipped or result.expectedFailures or result.unexpectedSuccesses)
passed = complete and clean and result.wasSuccessful()
record = {"ordered_ids": ids, "expected": len(expected), "executed": result.testsRun,
          "errors": len(result.errors), "failures": len(result.failures),
          "skipped": len(result.skipped), "expected_failures": len(result.expectedFailures),
          "unexpected_successes": len(result.unexpectedSuccesses), "pass": passed,
          "isolated": sys.flags.isolated, "optimize": sys.flags.optimize}
result_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
raise SystemExit(0 if passed and sys.flags.isolated == 1 and sys.flags.optimize == 0 else 1)
"""


def source_names(source, hosted):
    names = set(hosted["source_identity"]["files"])
    names.update(path.relative_to(source).as_posix()
                 for path in (source / "tools").glob("build_hia*.py"))
    names.add(ORIGINAL_TEST)
    names.update(name for name in ("tests/__init__.py", "tools/__init__.py")
                 if (source / name).is_file())
    return names


def qualify(source, evidence):
    from tools.hia_selfhost_contract import CONTRACT_PATH, support_contract
    from tools.hia_release_contract import source_domain, validate_release_contract
    source = Path(source).resolve(strict=True)
    evidence = Path(evidence).absolute()
    evidence.mkdir(parents=True, exist_ok=False)
    declared = validate_release_contract(source)
    declared_raw = regular(source / CONTRACT_PATH)
    originals = regular(source / ORIGINAL_TEST)
    ids = original_ids(originals)
    hosted = support_contract(source)
    names = source_names(source, hosted)
    captured = {name: regular(source / name) for name in sorted(names)}
    stage = evidence / "hosted-source"
    stage.mkdir()
    for name, raw in captured.items():
        expected = hosted["source_identity"]["files"].get(name)
        if expected is not None and sha256(raw).hexdigest() != expected:
            raise ValueError("hosted source identity changed before staging: " + name)
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    if support_contract(stage) != hosted:
        raise ValueError("the complete hosted fixture differs from actual current source bytes")
    hosted_raw = (json.dumps(hosted, sort_keys=True, indent=2) + "\n").encode()
    (stage / CONTRACT_PATH).write_bytes(hosted_raw)
    if source_domain(validate_release_contract(stage)) != "hosted":
        raise ValueError("the isolated hosted fixture has the wrong source domain")
    command = [sys.executable, "-I", "-B", "-c", CHILD, str(stage),
               json.dumps(ids), str(evidence / "original-results.json")]
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("PYTHON", "HEPTA_HIA_"))}
    report = {"schema": "hepta.hia.hosted-contract-controls.v1",
              "status": "FAILED", "scope": SCOPE, "original_ordered_ids": ids,
              "driver_isolated": sys.flags.isolated, "driver_optimize": sys.flags.optimize,
              "original_test_source": pin(originals),
              "actual_release_domain": source_domain(declared),
              "actual_release_contract": pin(declared_raw),
              "hosted_fixture_contract": pin(hosted_raw),
              "current_source_pins": {name: pin(raw) for name, raw in captured.items()},
              "whole_native_delivery_qualified": False}
    with (evidence / "stdout").open("wb") as out, (evidence / "stderr").open("wb") as err:
        done = subprocess.run(command, cwd=stage, env=environment,
                              stdout=out, stderr=err, timeout=1800)
    report["returncode"] = done.returncode
    result_path = evidence / "original-results.json"
    if result_path.is_file():
        report["original_results"] = json.loads(result_path.read_bytes())
    for name, raw in captured.items():
        if regular(source / name) != raw or regular(stage / name) != raw:
            raise ValueError("hosted source inputs changed during original controls: " + name)
    if (regular(source / CONTRACT_PATH) != declared_raw
            or regular(stage / CONTRACT_PATH) != hosted_raw
            or validate_release_contract(source) != declared):
        raise ValueError("release or hosted fixture contract changed during original controls")
    if (support_contract(source) != hosted or support_contract(stage) != hosted
            or source_names(source, hosted) != set(captured)
            or source_names(stage, hosted) != set(captured)):
        raise ValueError("the complete hosted source or builder inventory changed during controls")
    report["terminal_complete_inventory_unchanged"] = True
    report["terminal_inputs_unchanged"] = True
    result = report.get("original_results", {})
    if (done.returncode == 0 and result.get("pass") is True
            and result.get("ordered_ids") == ids
            and result.get("expected") == result.get("executed") == EXPECTED_METHODS
            and result.get("isolated") == 1 and result.get("optimize") == 0
            and all(result.get(key) == 0 for key in
                    ("errors", "failures", "skipped", "expected_failures", "unexpected_successes"))):
        report["status"] = "PASS"
    (evidence / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": SCOPE,
                      "original_methods": EXPECTED_METHODS, "evidence": str(evidence)}))
    return 0 if report["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    return qualify(args.source_root, args.evidence)


if __name__ == "__main__":
    raise SystemExit(main())
