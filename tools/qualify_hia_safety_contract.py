#!/usr/bin/env python3
"""Run the safety contract's existing boundary regressions against this source.

The frozen matrix is an implementation contract, never an admission receipt or
a soundness theorem. Registry drift, unresolved entrypoints, missing tests,
skips, failures and source drift fail this qualification. Native dependencies
must actually be available; an absent tool is not counted as positive evidence.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_schema import schema_registry

CONTRACT = ROOT / "docs/HIA_SAFETY_CONTRACT.json"
# This is the reviewed qualification protocol, not a program admission receipt.
# Pin it independently of the JSON supplied to validate_contract: otherwise a
# caller can remove capabilities/tests and still obtain the same qualification
# status for a weaker matrix. Deliberate protocol changes must review and update
# this identity together with the contract and its boundary tests.
REVIEWED_CONTRACT_SHA256 = "fac4e12c5385128e33a36aae2611abcfebf261c1264b0861fda942d742cdf999"
_UNPROVED = frozenset({"whole_language_soundness_proved", "source_to_core_refinement_proved",
    "core_to_native_refinement_proved", "global_optimality_proved", "absolute_resource_safety_proved",
    "general_concurrent_memory_safety_proved", "native_process_memory_bound_proved",
    "rust_performance_superiority_proved"})
_GUARANTEES = frozenset({"checked_on_every_admission", "checked_source_and_reverified_core",
    "checked_elaboration_and_reverified_core", "finite_execution_evidence", "stopped_ledger_no_unwind",
    "explicit_cooperative_protocol", "unknown_or_reject_outside_finite_profile", "recomputed_from_actual_core",
    "independent_finite_comparison_only", "proved_only_within_declared_solver_profile",
    "host_enforced_scoped_admission", "uncertain_release_quarantined_no_numeric_retry",
    "checked_translation_with_foreign_obligations", "reviewed_qualification_protocol"})


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def resolve(name):
    parts = name.split(".")
    for index in range(len(parts) - 1, 0, -1):
        module = ".".join(parts[:index])
        try:
            value = importlib.import_module(module)
        except ModuleNotFoundError as error:
            if error.name != module:
                raise
            continue
        for attribute in parts[index:]:
            value = getattr(value, attribute)
        if not callable(value):
            raise ValueError("E_SAFETY_ENTRYPOINT: callable required: " + name)
        return value
    raise ValueError("E_SAFETY_ENTRYPOINT: unresolved: " + name)


def validate_contract(contract):
    """Check the review boundary and executable references; do not admit Core."""
    try:
        canonical = wire(contract)
        identity = sha256(canonical).hexdigest()
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise ValueError("E_SAFETY_PROTOCOL: canonical reviewed contract required") from error
    if identity != REVIEWED_CONTRACT_SHA256:
        raise ValueError("E_SAFETY_PROTOCOL: reviewed capability, test and assumption matrix changed")
    # Continue from the bytes that were checked. Public Python callers can pass
    # stateful list/dict subclasses; iterating the caller's object again could
    # otherwise select fewer regressions after its full matrix was hashed.
    contract = json.loads(canonical)
    # The generated catalog uses immutable tuple fields in memory; JSON carries
    # those arrays as lists. Compare the complete canonical wire bytes exactly.
    if (type(contract) is not dict or contract.get("schema") != "hepta.hia.safety-contract.v1"
            or contract.get("status") != "implementation_contract_with_finite_regression_evidence"
            or wire(contract.get("registry")) != wire(schema_registry())):
        raise ValueError("E_SAFETY_REGISTRY: exact reviewed schema/profile registry required")
    claims = contract.get("unproved_claims", {})
    if set(claims) != _UNPROVED or any(value is not False for value in claims.values()):
        raise ValueError("E_SAFETY_CLAIM: finite regressions cannot promote an unproved universal claim")
    authority = contract.get("authority", {})
    if (authority.get("admission") != "hepta.hia_program.verify_program"
            or authority.get("external_receipts_grant_admission") is not False
            or authority.get("metadata_grants_admission") is not False):
        raise ValueError("E_SAFETY_AUTHORITY: only actual Core admission is authoritative")
    if set(contract.get("boundaries", {})) != {"normal", "error", "trap", "budget", "cancel", "crash", "recursive", "concurrent"}:
        raise ValueError("E_SAFETY_BOUNDARY: all eight execution boundaries must remain explicit")
    rows, identifiers, selectors = contract.get("capabilities"), set(), set()
    if type(rows) is not list or not rows:
        raise ValueError("E_SAFETY_MATRIX: nonempty capability matrix required")
    for row in rows:
        if (type(row) is not dict or type(row.get("id")) is not str or row["id"] in identifiers
                or row.get("guarantee") not in _GUARANTEES or not row.get("scope")
                or not row.get("exclusions") or not row.get("entrypoints")
                or not row.get("regression_selectors")):
            raise ValueError("E_SAFETY_MATRIX: exact scoped capability and evidence references required")
        identifiers.add(row["id"])
        for entrypoint in row["entrypoints"]:
            resolve(entrypoint)
        for selector in row["regression_selectors"]:
            if type(selector) is not str or not selector.startswith("tests."):
                raise ValueError("E_SAFETY_TEST: explicit existing test method required")
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(selector)
            if loader.errors or suite.countTestCases() != 1:
                raise ValueError("E_SAFETY_TEST: exactly one resolvable method required: " + selector)
            selectors.add(selector)
    if not contract.get("trusted_computing_base"):
        raise ValueError("E_SAFETY_TCB: trust assumptions must remain explicit")
    return sorted(selectors)


def source_inventory():
    tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"], timeout=30).decode().split("\0")
    prefixes = ("hepta/", "tests/", "tools/", "examples/", "benchmarks/", "rust/hia-core-shadow/")
    suffixes = {".py", ".json", ".hepta", ".rs", ".toml", ".lock", ".c", ".cpp", ".h", ".hpp"}
    paths = {ROOT / name for name in tracked if name.startswith(prefixes) and Path(name).suffix in suffixes}
    # Workflow argv, checkout attributes and upstream licenses/notices are
    # executable qualification inputs even when their suffix is not source code.
    paths.update(ROOT / name for name in tracked
                 if name == ".gitattributes" or name.startswith(
                     (".github/workflows/", "tests/fixtures/cpp_upgrade/")))
    # Selected regressions import benchmark/experiment code and read registered
    # protocols. Bind those actual code and configuration bytes as well;
    # historical run outputs must not stand in for their current inputs.
    paths.update(ROOT / name for name in tracked if name.startswith("experiments/")
                 and (Path(name).suffix in suffixes - {".json"}
                      or Path(name).suffix == ".json" and "PROTOCOL" in Path(name).name.upper()
                      or name.startswith("experiments/hia_agent_toolstudy_v11_20261030/provenance/")))
    # Include the new contract and runner even before the first local commit.
    paths.update({CONTRACT, Path(__file__), ROOT / "docs/HIA_SAFETY_CONTRACT.md"})
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}


def command(argv):
    child = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
    return {"argv": argv, "returncode": child.returncode, "stdout": child.stdout, "stderr": child.stderr}


def environment_identity():
    tools = {}
    for label, selector in (("clang", os.environ.get("CLANG", "clang")),
                            ("rustc", os.environ.get("RUSTC", "rustc")),
                            ("cargo", os.environ.get("CARGO", "cargo")),
                            ("lld", os.environ.get("HEPTA_LLD", "ld.lld")),
                            ("qemu_x86_64", os.environ.get("HEPTA_QEMU_X86_64", "qemu-x86_64"))):
        path = shutil.which(selector)
        tools[label] = ({"path": path, "sha256": digest(path), "version": command([path, "--version"])}
                        if path else {"path": None, "status": "missing"})
    try:
        import z3
        from hepta.hia_optimization import _solver_identity
        solver = _solver_identity(z3)
    except ImportError:
        solver = {"status": "missing"}
    return {"python": {"executable": sys.executable, "sha256": digest(sys.executable), "version": sys.version},
            "host": {"system": platform.system(), "machine": platform.machine()},
            "tools": tools, "solver": solver,
            "complete_transitive_toolchain_or_sysroot_closure_proved": False,
            "environment": {key: os.environ.get(key) for key in (
                "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LIBRARY_PATH", "CPATH",
                "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTFLAGS", "PYTHONPATH")}}


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = {}
        self.started = {}

    def startTest(self, test):
        super().startTest(test)
        self.started[test.id()] = time.monotonic_ns()
        self.records[test.id()] = {"status": "started"}

    def stopTest(self, test):
        self.records[test.id()]["wall_ns"] = time.monotonic_ns() - self.started[test.id()]
        super().stopTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.records[test.id()]["status"] = "passed"

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.records.setdefault(test.id(), {})["status"] = "failed"

    def addError(self, test, error):
        super().addError(test, error)
        self.records.setdefault(test.id(), {})["status"] = "error"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.records.setdefault(test.id(), {}).update(status="skipped", reason=reason)

    def addSubTest(self, test, subtest, error):
        super().addSubTest(test, subtest, error)
        if error is not None:
            self.records[test.id()]["status"] = "failed_subtest"


def qualify():
    started = time.monotonic_ns()
    contract = json.loads(CONTRACT.read_bytes())
    before = source_inventory()
    head_before = command(["git", "rev-parse", "HEAD"])
    status_before = command(["git", "status", "--porcelain"])
    selectors = validate_contract(contract)
    environment = environment_identity()
    captured = io.StringIO()
    runner = unittest.TextTestRunner(stream=captured, verbosity=2, resultclass=RecordedResult)
    result = runner.run(unittest.defaultTestLoader.loadTestsFromNames(selectors))
    after = source_inventory()
    head_after = command(["git", "rev-parse", "HEAD"])
    stable = before == after and head_before == head_after
    exact = set(result.records) == set(selectors) and result.testsRun == len(selectors)
    passed = stable and exact and result.wasSuccessful() and not result.skipped and all(
        row["status"] == "passed" for row in result.records.values())
    capabilities = [{"id": row["id"], "declared_contract": row["guarantee"],
        "regression_evidence_passed": all(result.records.get(test, {}).get("status") == "passed"
                                          for test in row["regression_selectors"]),
        "regression_selectors": row["regression_selectors"],
        "soundness_or_refinement_proof_established_by_this_run": False}
        for row in contract["capabilities"]]
    return {"schema": "hepta.hia.safety-contract-qualification.v1",
            "status": "passed" if passed else "failed", "contract": contract,
            "contract_sha256": sha256(wire(contract)).hexdigest(),
            "reviewed_contract_sha256": REVIEWED_CONTRACT_SHA256,
            "source_before": before, "source_after": after, "source_stable": stable,
            "head_before": head_before, "head_after": head_after, "status_before": status_before,
            "environment": environment, "tests_run": result.testsRun, "expected_tests": len(selectors),
            "tests": result.records, "log": captured.getvalue(), "capabilities": capabilities,
            "claims": {**contract["unproved_claims"], "metadata_grants_admission": False,
                       "all_selected_boundary_regressions_passed_without_skips": passed},
            "wall_ns": time.monotonic_ns() - started}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New JSON report path")
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must be a new path")
    report = qualify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("status", "tests_run", "expected_tests", "source_stable")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
