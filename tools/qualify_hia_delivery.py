"""Qualify one clean HIA delivery candidate, retaining every bounded command."""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest

from hepta.clang_capture import CaptureRejected, run_bounded

ROOT = Path(__file__).resolve().parents[1]
SUITES = (
    "tests.test_hia_compatibility", "tests.test_hia_candidate_release",
    "tests.test_hia_deliverable_controls", "tests.test_hia_delivery_gate",
    "tests.test_hia_schema_unification", "tests.test_hia_full_cost_gate", "tests.test_hia_paired_holdout",
    "tests.test_hia_opcode_catalog", "tests.test_hia_core_upgrade",
    "tests.test_hia_program_llvm",
    "tests.test_hia_composite_returned_loans.CompositeReturnedLoans",
    "tests.test_hia_composite_returned_loans.CompositeReturnedLoansNative",
)
CANDIDATE_EXTRA = frozenset({"pyproject.toml", "tools/build_hia_candidate.py", "tools/verify_hia_candidate.py",
    "examples/hia_program/counter.hia", "examples/hia_program/parameter_loan_return_v8.hia"})
QUOTA_SOURCES = frozenset({"hepta/apps/__init__.py", "hepta/apps/quota.py", "hepta/apps/quota_v1.hiaasm",
    "hepta/apps/quota_v2.hiaasm", "tests/test_hia_quota_application.py", "tools/qualify_hia_quota_application.py"})
AUDIT_SOURCES = frozenset({"experiments/hia_deliverable_controls_20261106/compute_oracle.py",
    "hepta/hia_ndu_stateful.py", "tools/qualify_hia_ndu_stateful.py", "tools/qualify_hia_ndu_costed.py",
    "tools/qualify_hia_ndu_stateful_reference.py"})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def git(*args, root=ROOT, binary=False):
    value = subprocess.check_output(["git", "-C", str(root), *args], timeout=30)
    return value if binary else value.decode().strip()


def file_record(path, *, git_blob=None):
    """Hash the actual bytes, including files hidden by Git's stat cache flags."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "source/evidence is not a regular file: " + str(path))
    content, blob = sha256(), sha1(b"blob " + str(before.st_size).encode() + b"\0")
    length = 0
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        opened = os.fstat(stream.fileno())
        while chunk := stream.read(1024 * 1024):
            length += len(chunk)
            content.update(chunk)
            blob.update(chunk)
        after = os.fstat(stream.fileno())
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    require(identity(before) == identity(opened) == identity(after) == identity(path.lstat())
            and length == before.st_size, "file changed while hashing: " + str(path))
    if git_blob is not None:
        require(blob.hexdigest() == git_blob, "tracked bytes differ from frozen Git tree: " + str(path))
    return {"sha256": content.hexdigest(), "size_bytes": length}


def source_snapshot(root=ROOT):
    """Check every tracked regular file against HEAD, not merely git status."""
    root = Path(root)
    require(not git("status", "--porcelain", "--untracked-files=all", root=root), "source checkout is dirty")
    commit, tree = git("rev-parse", "HEAD", root=root), git("rev-parse", "HEAD^{tree}", root=root)
    require(git("rev-parse", "--show-object-format", root=root) == "sha1", "unsupported Git object format")
    entries = git("ls-tree", "-r", "--full-tree", "-z", "HEAD", root=root, binary=True)
    files = []
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        name = raw_name.decode("utf-8")
        require(kind == "blob" and mode in {"100644", "100755"}, "unsupported tracked source mode: " + name)
        path = root / name
        require(path.resolve().is_relative_to(root.resolve()), "tracked source escapes checkout")
        files.append({"path": name, "mode": mode, "git_blob_sha1": blob,
                      **file_record(path, git_blob=blob)})
    require(files, "empty tracked source snapshot")
    require(git("rev-parse", "HEAD", root=root) == commit and git("rev-parse", "HEAD^{tree}", root=root) == tree
            and not git("status", "--porcelain", "--untracked-files=all", root=root),
            "source changed while freezing its full tracked inventory")
    return {"schema": "hepta.hia.delivery-source.v1", "source_commit": commit, "source_tree": tree,
            "files": files, "files_sha256": sha256(encoded(files)).hexdigest()}


def unchanged(snapshot, root=ROOT):
    require(source_snapshot(root) == snapshot, "tracked source snapshot changed during qualification")


def index(snapshot):
    return {row["path"]: row for row in snapshot["files"]}


def check_sources(observed, expected_names, snapshot):
    frozen = index(snapshot)
    require(type(observed) is dict and set(observed) == set(expected_names), "source identity roster differs")
    require(all(name in frozen and observed[name] == frozen[name]["sha256"] for name in expected_names),
            "child evidence names bytes outside the frozen source snapshot")


def test_ids(suite):
    result = []
    for child in suite:
        result.extend(test_ids(child) if isinstance(child, unittest.TestSuite) else [child.id()])
    return result


def check_test_summary(report, *, expected_suites=None):
    count = report.get("inventory")
    require(type(count) is int and count > 0 and type(report.get("tests_run")) is int
            and report["tests_run"] == count, "empty or incomplete test inventory")
    for name in ("failures", "errors", "skips", "expected_failures", "unexpected_successes"):
        require(type(report.get(name)) is int and report[name] == 0, "test outcome prevents qualification: " + name)
    if expected_suites is not None:
        by_suite = report.get("suite_inventory")
        require(type(by_suite) is dict and set(by_suite) == set(expected_suites), "required suite roster differs")
        require(all(type(value) is int and value > 0 for value in by_suite.values())
                and sum(by_suite.values()) == count, "required suite is empty or counted twice")
        registered, executed = report.get("test_ids"), report.get("executed_test_ids")
        require(type(registered) is list and len(registered) == count
                and all(type(name) is str for name in registered) and len(set(registered)) == count,
                "test inventory has duplicate or missing identities")
        require(executed == registered, "executed test identities differ from registered inventory")


class InventoryResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


def run_regressions(names, output):
    """A zero test count, any skip/xfail, or partial suite always exits nonzero."""
    suites = [unittest.defaultTestLoader.loadTestsFromName(name) for name in names]
    inventory = {name: suite.countTestCases() for name, suite in zip(names, suites)}
    suite = unittest.TestSuite(suites)
    registered = test_ids(suite)
    result = unittest.TextTestRunner(verbosity=2, resultclass=InventoryResult).run(suite)
    report = {"schema": "hepta.hia.delivery-regressions.v1", "source_commit": git("rev-parse", "HEAD"),
        "source_tree": git("rev-parse", "HEAD^{tree}"), "inventory": len(registered),
        "suite_inventory": inventory, "test_ids": registered, "executed_test_ids": result.executed_ids,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skips": len(result.skipped), "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses), "qualified": False}
    try:
        check_test_summary(report, expected_suites=names)
        require(result.wasSuccessful(), "test runner reported unsuccessful completion")
        report["qualified"] = True
    except ValueError as exc:
        report["failure"] = str(exc)
    with Path(output).open("xb") as stream:
        stream.write(encoded(report))
    return 0 if report["qualified"] else 1


def check_candidate(manifest, snapshot):
    require(manifest.get("source_commit") == snapshot["source_commit"]
            and manifest.get("source_tree") == snapshot["source_tree"]
            and manifest.get("worktree_dirty") is False, "candidate is not the frozen clean commit/tree")
    frozen = index(snapshot)
    required = {name for name in frozen if name in CANDIDATE_EXTRA or (
        name.startswith("hepta/") and "__pycache__" not in Path(name).parts
        and Path(name).suffix in {".py", ".json", ".hia", ".hiaasm"})}
    require(CANDIDATE_EXTRA <= required and QUOTA_SOURCES.intersection({"hepta/apps/__init__.py", "hepta/apps/quota.py",
        "hepta/apps/quota_v1.hiaasm", "hepta/apps/quota_v2.hiaasm"}) <= required,
        "frozen source lacks required candidate/application files")
    observed = manifest.get("source_files")
    require(type(observed) is list and len(observed) == len(required), "candidate source inventory differs")
    names = [row.get("path") for row in observed]
    require(all(type(name) is str for name in names) and len(set(names)) == len(names)
            and set(names) == required, "candidate omits or adds source files")
    for row in observed:
        name = row["path"]
        require(type(row.get("size_bytes")) is int and row["size_bytes"] == frozen[name]["size_bytes"]
                and row.get("sha256") == frozen[name]["sha256"], "candidate bytes differ from frozen source: " + name)
    require(manifest.get("source_manifest_sha256") == sha256(encoded(observed)).hexdigest(),
            "candidate source manifest digest differs")


def check_quota(report, snapshot, program_ids, implementation_sha256):
    require(report.get("schema") == "hepta.hia.quota-qualification.v1" and report.get("qualified") is True
            and report.get("source_unchanged") is True, "quota application did not qualify")
    check_test_summary(report)
    check_sources(report.get("source_sha256"), QUOTA_SOURCES, snapshot)
    require(report.get("program_sha256") == program_ids, "quota Core identity differs from frozen assembly")
    require(report.get("native_status") == "executed" and report.get("claims", {}).get("native_execution_tested") is True,
            "quota native execution is missing or was not requested")
    observations = report.get("observations")
    require(type(observations) is list and len(observations) == report["inventory"]
            and all(row.get("outcome") == "passed" and type(row.get("test")) is str for row in observations)
            and len({row["test"] for row in observations}) == report["inventory"],
            "quota per-test observations are incomplete or unsuccessful")
    receipts = report.get("native_build_receipts")
    require(type(receipts) is list and len(receipts) == 2
            and {row.get("core_sha256") for row in receipts} == set(program_ids.values()),
            "quota native receipts do not cover both exact Core versions")
    for row in receipts:
        require(row.get("ok") is True and row.get("implementation_sha256") == implementation_sha256
                and all(row.get("claims", {}).get(flag) is False for flag in ("rust_codegen_used", "c_codegen_used", "fallback_used")),
                "quota receipt uses different compiler bytes or an unqualified fallback")


def check_installed(report, manifest, manifest_sha256, wheel_sha256):
    require(report.get("schema") == "hepta.hia.candidate-installed-verification.v1"
            and report.get("status") == "passed" and report.get("worktree_dirty") is False,
            "installed verification did not pass cleanly")
    for name, expected in (("source_commit", manifest["source_commit"]),
                           ("source_manifest_sha256", manifest["source_manifest_sha256"]),
                           ("manifest_sha256", manifest_sha256), ("wheel_sha256", wheel_sha256)):
        require(report.get(name) == expected, "installed evidence identity differs: " + name)
    native = report.get("native", {})
    require(native.get("execution_qualified") is True and native.get("status") == "counter_executed",
            "installed native execution is absent")
    required = {"offline_wheel_install", "installed_layout", "installed_package_before", "installed_package_after",
                "installed_identity", "verify_counter.hia",
                "verify_parameter_loan_return_v8.hia", "interpret", "installed_console_script",
                "installed_quota_init", "installed_quota_reserve", "installed_quota_upgrade", "installed_quota_recover",
                "native_build", "native_execute"}
    required.update("emit_" + target for target in manifest["compatibility"]["abi"]["targets"])
    rows = report.get("observations")
    require(type(rows) is list and len(rows) == len(required)
            and {row.get("name") for row in rows} == required
            and all(type(row.get("returncode")) is int and row["returncode"] == 0 for row in rows),
            "installed observation inventory is incomplete or contains failed commands")
    package_files = [row for row in manifest["source_files"] if row["path"].startswith("hepta/")]
    package_digest = sha256(encoded(package_files)).hexdigest()
    by_name = {row["name"]: row for row in rows}
    for label in ("installed_package_before", "installed_package_after"):
        row = by_name[label]
        require(type(row.get("file_count")) is int and row["file_count"] == len(package_files) > 0
                and row.get("package_manifest_sha256") == package_digest,
                "installed package bytes do not match the complete frozen package inventory")


def check_value_controls(report, snapshot):
    require(report.get("schema") == "hepta.hia.deliverable-controls.run.v1"
            and report.get("new_agent_campaign_executed") is False
            and report.get("new_ndu_native_campaign_executed") is False, "value-control scope changed")
    audit = report.get("native_free_compute_audit", {})
    require(audit.get("status") == "passed" and audit.get("native_ndu_calls") == 0
            and audit.get("model_calls") == 0 and audit.get("ndu_advantage_established") is False,
            "offline compute audit did not pass in its declared scope")
    check_sources(audit.get("source_sha256"), AUDIT_SOURCES, snapshot)


def child_command(arguments, environment, cache):
    """-B alone reads old bytecode; both this child and its children need a cold prefix."""
    require(not cache.exists(), "child bytecode prefix must be fresh")
    env = dict(environment)
    env.pop("PYTHONOPTIMIZE", None)
    env.update(PYTHONPYCACHEPREFIX=str(cache), PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    return [sys.executable, "-B", "-X", "pycache_prefix=" + str(cache), *map(str, arguments)], env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--clang", required=True)
    args = parser.parse_args(argv)
    output = args.output_directory.absolute().resolve()
    if output.exists() or output.is_relative_to(ROOT):
        parser.error("use a new evidence directory outside the source checkout")
    if git("status", "--porcelain", "--untracked-files=all"):
        parser.error("commit the complete candidate before qualification")
    output.mkdir(parents=True)
    environment = dict(os.environ)
    environment.update(CLANG=args.clang, HEPTA_CLANG=args.clang, HEPTA_TEST_CLANG=args.clang,
                       HIA_COMPATIBILITY_REQUIRE_NATIVE="1", PYTHONDONTWRITEBYTECODE="1")
    commands = []
    report = {"schema": "hepta.hia.delivery-qualification.v1",
        "scope": "installable standalone HIA candidate and bounded quota application", "qualified": False,
        "commands": commands, "evidence_files": {},
        "claims": {"production_release_qualified": False, "whole_project_blockers_closed": False,
            "hia_agent_productivity_advantage": False, "ndu_net_advantage": False,
            "cross_target_machine_execution": False}}

    def retain(label, value):
        with (output / label).open("xb") as stream:
            stream.write(encoded(value))

    def run(label, arguments, timeout=300):
        argv, env = child_command(arguments, environment, output / ("cold-cache-" + label))
        started = time.perf_counter_ns()
        row = {"name": label, "argv": argv, "timeout_seconds": timeout}
        commands.append(row)
        print("Running " + label, flush=True)
        try:
            unchanged(frozen)
            row["source_snapshot_sha256_before"] = frozen["files_sha256"]
            observed = run_bounded(argv, cwd=ROOT, env=env, timeout=timeout,
                                   stdout_limit=4 * 1024 * 1024, stderr_limit=4 * 1024 * 1024)
            row.update(returncode=observed.returncode, stdout=observed.stdout, stderr=observed.stderr)
            require(observed.returncode == 0, label + " failed")
            unchanged(frozen)
            row["source_snapshot_sha256_after"] = frozen["files_sha256"]
        except CaptureRejected as exc:
            row.update(capture_error=exc.code, message=str(exc))
            if exc.capture:
                row.update(returncode=exc.capture.returncode,
                    stdout=exc.capture.stdout.decode("utf-8", "replace"),
                    stderr=exc.capture.stderr.decode("utf-8", "replace"),
                    stdout_total_bytes=exc.capture.stdout_total_bytes, stderr_total_bytes=exc.capture.stderr_total_bytes)
            raise
        except Exception as exc:
            row["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            row["wall_ns"] = time.perf_counter_ns() - started
            retain(label + ".command.json", row)

    def evidence(name):
        path = output / name
        identity = file_record(path)
        parsed = json.loads(path.read_bytes())
        require(file_record(path) == identity, "child evidence changed while reading")
        report["evidence_files"][name] = identity
        return parsed

    try:
        frozen = source_snapshot()
        retain("source-snapshot.json", frozen)
        report.update(source_commit=frozen["source_commit"], source_tree=frozen["source_tree"],
                      tracked_source_files=len(frozen["files"]), source_snapshot_sha256=frozen["files_sha256"])
        run("compatibility-drift", ["tools/check_hia_compatibility.py", "--check"])
        run("opcode-drift", ["tools/generate_hia_catalog.py", "--check"])
        test_code = ("import sys; from tools.qualify_hia_delivery import run_regressions; "
                     "raise SystemExit(run_regressions(sys.argv[2:], sys.argv[1]))")
        run("regressions", ["-c", test_code, output / "regression-summary.json", *SUITES], timeout=900)
        tests = evidence("regression-summary.json")
        check_test_summary(tests, expected_suites=SUITES)
        require(tests.get("qualified") is True and tests.get("source_commit") == frozen["source_commit"]
                and tests.get("source_tree") == frozen["source_tree"], "regression evidence source or verdict differs")
        run("quota-application", ["-m", "tools.qualify_hia_quota_application", "--clang", args.clang,
                                   "--output", output / "quota-qualification.json"], timeout=300)
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_llvm import _implementation_hash
        program_ids = {version: assemble_program((ROOT / f"hepta/apps/quota_{version}.hiaasm").read_bytes()).sha256
                       for version in ("v1", "v2")}
        check_quota(evidence("quota-qualification.json"), frozen, program_ids, _implementation_hash())
        run("value-controls", ["experiments/hia_deliverable_controls_20261106/controls.py",
                                "--output", output / "value-controls.json"])
        check_value_controls(evidence("value-controls.json"), frozen)
        from tools.verify_hia_candidate import validate_bundle
        candidates = []
        for suffix in ("a", "b"):
            directory = output / ("candidate-" + suffix)
            run("build-" + suffix, ["tools/build_hia_candidate.py", "--output-directory", directory])
            files = {p.name: file_record(p)["sha256"] for p in directory.iterdir()}
            manifest, _ = validate_bundle(directory, expected_manifest_sha256=files["candidate-manifest.json"])
            check_candidate(manifest, frozen)
            candidates.append((directory, files, manifest))
        left, hashes, manifest = candidates[0]
        require(hashes == candidates[1][1], "rebuild artifacts differ")
        report.update(rebuild_equal=True, candidate_files_sha256=hashes)
        run("installed-native", ["tools/verify_hia_candidate.py", "--candidate-directory", left,
            "--expected-manifest-sha256", hashes["candidate-manifest.json"], "--clang", args.clang,
            "--output", output / "installed-native.json"])
        check_installed(evidence("installed-native.json"), manifest,
                        hashes["candidate-manifest.json"], hashes[manifest["wheel"]])
        for directory, expected_hashes, _ in candidates:
            require({p.name: file_record(p)["sha256"] for p in directory.iterdir()} == expected_hashes,
                    "candidate bytes changed after qualification: " + directory.name)
        unchanged(frozen)
        report["qualified"] = True
    except Exception as exc:
        report["failure"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        retain("RESULT.json", report)
    print(json.dumps({"qualified": report["qualified"], "source_commit": report.get("source_commit"),
                      "evidence": str(output / "RESULT.json"), "commands": len(commands)}))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
