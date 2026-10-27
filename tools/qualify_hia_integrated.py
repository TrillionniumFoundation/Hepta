#!/usr/bin/env python3
"""Qualify the merged contracts once against one frozen, committed source tree.

The full Python discovery is mandatory and executes exactly once. Its critical
module coverage is a subset of that same run, never another test denominator.
Real tool, Linux seal, two distinct native NDU protocols, and Rust crate gates
are retained separately. Standalone historical performance/agent campaigns are
neither replayed nor promoted to measurements of this merged source revision.
Full regression still executes its existing native timing/budget controls.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.qualify_hia_ndu_pipeline import _write
from tools.qualify_hia_unified import _command, cargo_test_outcome, unittest_outcome
from tools.release_check import _read_regular_evidence

SCHEMA = "hepta.hia.integrated-contract-qualification.v1"
RECURSIVE_SOURCE = "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b"
CRITICAL_MODULES = {
    "wire_rejection": ("test_hia_inmemory_json_key_collisions", "test_hia_inmemory_surrogate_wire",
                       "test_hia_program_tools"),
    "cpp_lexical_ownership": ("test_cpp_scoped_ownership_migration", "test_cpp_composed_migrate"),
    "llvm_allocation_and_native_observables": ("test_hia_program_llvm", "test_hia_empty_owner_native",
                                               "test_hia_native_side_effects", "test_hia_native_pinning"),
    "acyclic_scalar_smt": ("test_hia_translation_validation",),
    "compositional_barrier_smt": ("test_hia_optimization",),
    "proof_profile_integration": ("test_hia_profile_integration",),
    "ranking_ndu": ("test_hia_ndu_bridge", "test_hia_ndu_optimizer"),
    "recursive_ndu": ("test_hia_ndu", "test_hia_ndu_loop"),
    "ndu_protocol_isolation": ("test_hia_ndu_bridge_isolation",),
    "native_runtime_lifecycles": ("test_hia_multiversion", "test_hia_background_optimizer", "test_hia_adaptive"),
    "cli_and_route_contracts": ("test_hia_optimization_cli", "test_hia_routes"),
    "finite_actions_and_instruction_grammar": ("test_hia_finite_actions", "test_hia_x86_search"),
    "rust_resource_execution": ("test_hia_rust_owned_vm", "test_hia_rust_owned_cfg", "test_hia_rust_migration"),
}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _git(*arguments, root=ROOT):
    return subprocess.check_output(["git", *map(str, arguments)], cwd=root)


def _digest_file(path):
    """Hash actual regular bytes, detecting replacement or mutation in the read."""
    path = Path(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require(stat.S_ISREG(opened.st_mode), "opened object is not a regular file: " + str(path))
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns),
                 "file changed before identity read: " + str(path))
        digest = sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after_fd = os.fstat(stream.fileno())
    after = path.lstat()
    signatures = {(v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                  for v in (before, opened, after_fd, after)}
    _require(len(signatures) == 1, "file changed during identity read: " + str(path))
    return digest.hexdigest()


def _inventory():
    names = _git("ls-files", "-z").decode().split("\0")
    return {name: _digest_file(ROOT / name) for name in sorted(set(names)) if name}


def _source_state():
    return {"head": _git("rev-parse", "HEAD").decode().strip(),
            "tree": _git("rev-parse", "HEAD^{tree}").decode().strip(),
            "status": _git("status", "--porcelain", "--untracked-files=all").decode(),
            "files": _inventory()}


def _resolve_tool(value):
    return str(Path(shutil.which(str(value)) or str(value)).resolve(strict=True))


@contextmanager
def _environment(options, output):
    clang = _resolve_tool(options.clang)
    cargo, rustc = _resolve_tool(options.cargo), _resolve_tool(options.rustc)
    updates = {
        "CLANG": clang, "HEPTA_CLANG": clang, "CLANGXX": str(Path(clang).with_name("clang++")),
        "RUSTC": rustc, "HEPTA_NDU_BRIDGE": str(options.ranking_bridge.resolve()),
        "HEPTA_NDU_BUILD": str(options.ranking_build_receipt.resolve().parent),
        "HEPTA_NDU_UPSTREAM": str(options.ranking_upstream.resolve()),
        "HEPTA_RECURSIVE_NDU_BRIDGE": str(options.recursive_bridge.resolve()),
        "HEPTA_RECURSIVE_NDU_IDENTITY": str(options.recursive_identity.resolve()),
        "CARGO_NET_OFFLINE": "true", "PYTHONDONTWRITEBYTECODE": "1",
        "CARGO_TARGET_DIR": str(output / "rust-target"),
        "PATH": os.pathsep.join([str(Path(clang).parent), str(Path(cargo).parent),
                                  str(Path(rustc).parent), os.environ.get("PATH", "")]),
        "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]),
    }
    previous = {key: os.environ.get(key) for key in updates}
    old_cwd = Path.cwd()
    try:
        os.environ.update(updates)
        os.chdir(ROOT)
        yield updates
    finally:
        os.chdir(old_cwd)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _tool_gate(options, output):
    import fcntl
    import z3
    from hepta.hia_native_differential import _pin_native_artifact
    from hepta.hia_optimization import PINNED_Z3_VERSION, _solver_identity

    _require(platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"},
             "this integrated native qualification requires the declared Linux x86-64 host")
    _require(z3.get_version_string() == PINNED_Z3_VERSION == "4.15.4", "the actual Z3 pin differs")
    selected = {
        "python": sys.executable,
        "clang": os.environ["CLANG"], "clangxx": os.environ["CLANGXX"],
        "cargo": options.cargo, "rustc": options.rustc, "gcc": "gcc", "gxx": "g++",
        "lld": os.environ.get("HEPTA_LLD", "ld.lld"),
        "llvm_readobj": os.environ.get("HEPTA_LLVM_READOBJ", "llvm-readobj"),
        "qemu_aarch64": os.environ.get("HEPTA_QEMU_AARCH64", "qemu-aarch64"),
        "qemu_riscv64": os.environ.get("HEPTA_QEMU_RISCV64", "qemu-riscv64"),
        "qemu_system_arm": "qemu-system-arm",
        "lean": os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean")),
    }
    tools = {}
    for name, value in selected.items():
        # Keep argv[0]: ld.lld and clang++ may select a driver flavor through
        # their symlink name. Hash the resolved executable separately.
        invocation = str(Path(shutil.which(str(value)) or str(value)).absolute())
        path = _resolve_tool(invocation)
        digest = _digest_file(path)
        arguments = [invocation]
        if name == "lld" and Path(invocation).name in {"lld", "rust-lld"}:
            arguments += ["-flavor", "gnu"]
        execution = _command([*arguments, "--version"], timeout=20)
        tools[name] = {"invocation_path": invocation, "path": path,
                       "sha256": digest, "execution": execution}
        _write(output / (name + "-tool-probe.json"), tools[name])
        _require(execution["returncode"] == 0 and (execution["stdout"] + execution["stderr"]).strip(),
                 "actual tool version command failed: " + name)
        _require(_digest_file(path) == digest, "tool changed during version probe: " + name)
    payload = b"integrated native pinning probe\x00\xff"
    probe = output / "seal-probe.bin"
    probe.write_bytes(payload)
    original, _, descriptor = _pin_native_artifact(probe)
    try:
        seals = fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034))
        _require(original == payload and seals & 0xF == 0xF, "actual required kernel seals absent")
        try:
            os.pwrite(descriptor, b"x", 0)
        except OSError as error:
            _require(error.errno == errno.EPERM, "unexpected sealed write error")
        else:
            raise ValueError("sealed bytes were writable")
        _require(os.pread(descriptor, len(payload) + 1, 0) == payload, "sealed readback differs")
    finally:
        os.close(descriptor)
    solver = _solver_identity(z3)
    return {"passed": True, "tools": tools, "solver": solver,
            "linux_seals": {"required_bits": 15, "actual_bits": seals,
                             "actual_write_rejected_errno": errno.EPERM, "exact_readback": True},
            "scope": "actual host tools and kernel capability; individual native tests still execute their own gates"}


def _checked_map(root, expected):
    _require(type(expected) is dict and bool(expected), "a nonempty source inventory is required")
    actual = {}
    for name, digest in expected.items():
        relative = Path(name)
        _require(type(name) is str and not relative.is_absolute() and ".." not in relative.parts,
                 "source inventory has an invalid relative path")
        _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid source digest")
        actual[name] = _digest_file(root / relative)
    _require(actual == expected, "recorded source/build inputs differ from actual files")
    return actual


def _git_inventory(checkout, commit, expected):
    observed = _git("rev-parse", commit + "^{commit}", root=checkout).decode().strip()
    _require(observed == commit, "upstream Git commit identity differs")
    archive = _git("archive", commit, "--", *sorted(expected), root=checkout)
    original = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        for entry in package:
            if entry.isdir():
                continue
            _require(entry.isfile(), "source archive contains a nonregular member")
            original[entry.name] = sha256(package.extractfile(entry).read()).hexdigest()
    _require(original == expected, "recorded source bytes differ from the exact upstream Git object")
    return observed


def _ranking_gate(options, output):
    from hepta.hia_ndu_optimizer import _bridge_identity, _native_rank

    bridge = {"binary": str(options.ranking_bridge), "build_receipt": str(options.ranking_build_receipt)}
    _, identity = _bridge_identity(bridge)
    raw, _ = _read_regular_evidence(options.ranking_build_receipt)
    _require(sha256(raw).hexdigest() == identity["build_receipt_sha256"], "ranking receipt changed during read")
    receipt = json.loads(raw)
    _checked_map(options.ranking_build_receipt.parent, receipt["build_inputs"])
    _git_inventory(options.ranking_upstream, identity["upstream_commit"], receipt["original_source_files"])
    _write(output / "ranking-build-receipt.json", receipt)
    def candidate(name, cost):
        return {"id": name, "cost_q32": cost, "uncertainty_q32": 0, "resource_q32": 0,
                "hard_violation": False, "support_sha256": sha256(name.encode()).hexdigest()}
    request = {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "11" * 32,
               "generation": 1, "resource_cap_q32": 10 << 32,
               "candidates": [candidate("abstain", 2 << 32), candidate("control", 1 << 32)]}
    response, observed = _native_rank(bridge, request, timeout_s=10)
    _require(observed == identity and response["advisory_recommendation"] == "control",
             "actual native ranking probe did not match its finite control")
    return {"passed": True, "identity": identity, "binary": str(options.ranking_bridge),
            "receipt": str(options.ranking_build_receipt), "build_inputs": receipt["build_inputs"],
            "original_source_files": receipt["original_source_files"], "request": request, "response": response,
            "scope": "one synthetic advisory protocol probe, not a program proof or performance trial"}


def _recursive_gate(options, output):
    from hepta.hia_ndu import NduBridge, Q32, REQUEST_SCHEMA, candidate, event

    bridge = NduBridge(options.recursive_bridge, options.recursive_identity)
    manifest = bridge.manifest
    raw, _ = _read_regular_evidence(options.recursive_identity)
    _require(json.loads(raw) == manifest, "recursive identity changed during read")
    receipt_digest = sha256(raw).hexdigest()
    _require(manifest["identity"]["source_commit"] == RECURSIVE_SOURCE, "wrong recursive upstream source pin")
    _require(manifest.get("authority") == "DENY_ALL" and manifest.get("safety_certificate") is False,
             "recursive manifest claimed authority")
    expected_tools = {"builder_sha256": _digest_file(ROOT / "tools/build_hia_recursive_ndu_bridge.py"),
                      "cargo_sha256": _digest_file(Path(_resolve_tool(options.cargo))),
                      "rustc_sha256": _digest_file(Path(_resolve_tool(options.rustc)))}
    _require(manifest["build_tools"] == expected_tools, "recursive builder/compiler bytes differ")
    _checked_map(options.recursive_upstream, manifest["native_sources"])
    _checked_map(options.recursive_upstream, manifest["bridge_sources"])
    _git_inventory(options.recursive_upstream, RECURSIVE_SOURCE,
                   {**manifest["native_sources"], **manifest["bridge_sources"]})
    for field, digest_field in (("native_sources", "source_digest"), ("bridge_sources", "bridge_digest")):
        digest = sha256(json.dumps(manifest[field], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _require(digest == manifest["identity"][digest_field], "recursive embedded inventory digest differs")
    _write(output / "recursive-build-identity.json", manifest)
    def plan(name, utility):
        digest = sha256(name.encode()).hexdigest()
        step = event(identity="integrated-probe:" + name, instant_q32=utility, preference_digest=digest)
        return candidate(candidate_id=name, verified=True, verification_digest=digest,
                         support_digest=digest, events=[step], terminal_q32=0)
    request = {"schema": REQUEST_SCHEMA, "objective_digest": "22" * 32, "snapshot_digest": "33" * 32,
               "generation": 1, "utility_unit": "normalized-net-benefit", "resource_unit": "modeled-work",
               "risk_unit": "probability", "resource_budget_q32": 10 * Q32, "risk_ceiling_q32": Q32 // 4,
               "candidates": [plan("abstain", 0), plan("control", Q32)]}
    response = bridge.evaluate(request)
    _require(response["advisory_candidate_id"] == "control", "actual native recursive probe differs")
    _require(_digest_file(options.recursive_bridge) == manifest["binary_sha256"],
             "recursive binary changed during actual invocation")
    _require(_digest_file(options.recursive_identity) == receipt_digest,
             "recursive identity changed during actual invocation")
    return {"passed": True, "identity": manifest["identity"], "binary": str(options.recursive_bridge),
            "binary_sha256": manifest["binary_sha256"], "receipt": str(options.recursive_identity),
            "receipt_sha256": receipt_digest,
            "native_sources": manifest["native_sources"], "bridge_sources": manifest["bridge_sources"],
            "request": request, "response": response,
            "scope": "one synthetic advisory protocol probe; verified input flags confer no code admission authority"}


def _coverage(execution, outcome):
    identifiers = re.findall(r"(?m)^test\w+ \(((?:tests\.)?test_[^\s)]+)\)", execution["stderr"])
    normalized = [name.removeprefix("tests.") for name in identifiers]
    rows = {}
    for group, modules in CRITICAL_MODULES.items():
        rows[group] = {module: sorted(name for name in normalized if name.startswith(module + "."))
                       for module in modules}
    missing = [module for group in rows.values() for module, tests in group.items() if not tests]
    complete = (outcome["passed"] and len(normalized) == len(set(normalized)) == outcome["tests_run"] and not missing)
    return {"passed": complete, "subsets_of_full_regression_only": True, "groups": rows,
            "missing_modules": sorted(set(missing)), "verbose_method_records": len(normalized),
            "unique_method_records": len(set(normalized)),
            "denominator_policy": "group membership is coverage of the one full run; never add it to full tests or Rust tests"}


def _external_inventory(options, gates):
    paths = {Path(sys.executable).resolve(), options.ranking_bridge, options.ranking_build_receipt,
             options.recursive_bridge, options.recursive_identity}
    by_name = {row["name"]: row for row in gates}
    tools = by_name.get("actual_tools_and_linux_seals", {})
    for row in tools.get("tools", {}).values():
        _require(str(Path(row["invocation_path"]).resolve(strict=True)) == row["path"],
                 "tool invocation was retargeted since its actual version probe")
    paths.update(Path(row["path"]) for row in tools.get("tools", {}).values())
    if tools.get("solver"):
        import z3
        from hepta.hia_optimization import _solver_identity

        _require(_solver_identity(z3) == tools["solver"],
                 "complete Z3 binding/library identity changed since its actual identity gate")
        paths.add(Path(tools["solver"]["library_path"]))
        paths.update(Path(z3.__file__).parent.glob("*.py"))
    ranking = by_name.get("ranking_bridge_identity", {})
    paths.update(options.ranking_build_receipt.parent / name for name in ranking.get("build_inputs", {}))
    recursive = by_name.get("recursive_bridge_identity", {})
    for field in ("native_sources", "bridge_sources"):
        paths.update(options.recursive_upstream / name for name in recursive.get(field, {}))
    actual = {str(path): _digest_file(path) for path in sorted(paths)}
    expected = {row["path"]: row["sha256"] for row in tools.get("tools", {}).values()}
    if tools.get("solver"):
        expected[tools["solver"]["library_path"]] = tools["solver"]["library_sha256"]
    if ranking.get("passed"):
        expected[str(options.ranking_bridge)] = ranking["identity"]["binary_sha256"]
        expected[str(options.ranking_build_receipt)] = ranking["identity"]["build_receipt_sha256"]
        expected.update({str(options.ranking_build_receipt.parent / name): digest
                         for name, digest in ranking["build_inputs"].items()})
    if recursive.get("passed"):
        expected[str(options.recursive_bridge)] = recursive["binary_sha256"]
        expected[str(options.recursive_identity)] = recursive["receipt_sha256"]
        for field in ("native_sources", "bridge_sources"):
            expected.update({str(options.recursive_upstream / name): digest
                             for name, digest in recursive[field].items()})
    _require(all(actual.get(name) == digest for name, digest in expected.items()),
             "external inputs changed since their actual identity gate")
    return actual


def qualify(options):
    output = options.output_directory.resolve()
    _require(not output.is_relative_to(ROOT), "retain qualification output outside the frozen source worktree")
    _require(re.fullmatch(r"[0-9a-f]{40}", options.expected_head), "expected HEAD must be an exact full Git SHA")
    before = _source_state()
    _require(before["head"] == options.expected_head and not before["status"],
             "commit the complete integration and supply its exact clean HEAD before qualification")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "started_utc": datetime.now(timezone.utc).isoformat(),
              "source_before": before, "gates": [], "full_regression_requested": True,
              "historical_evidence_reused_as_current": False, "standalone_performance_campaigns_replayed": False,
              "native_timing_controls_in_full_regression": True,
              "scientific_incremental_advantage_established": False, "whole_language_soundness_proved": False,
              "global_optimality_established": False, "six_stages_closed": False,
              "scope": "merged finite contracts on the actual declared host; independent historical evidence keeps its own source and denominator"}
    with _environment(options, output) as configured:
        report["configured_environment"] = configured
        report["inherited_tool_environment"] = {name: os.environ.get(name) for name in (
            "CARGO_HOME", "LD_LIBRARY_PATH", "CPLUS_INCLUDE_PATH", "CPATH", "LEAN",
            "HEPTA_LLD", "HEPTA_LLVM_READOBJ", "HEPTA_QEMU_AARCH64", "HEPTA_QEMU_RISCV64")}
        commands = [
            ("rust_resource_crate", [str(options.cargo), "test", "--locked", "--offline", "--manifest-path",
                                     "rust/hia-core-shadow/Cargo.toml"], "cargo"),
            ("full_regression", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], "unittest"),
        ]
        _write(output / "frozen-plan.json", {"source_head": before["head"], "source_tree": before["tree"],
               "critical_modules": CRITICAL_MODULES, "configured_environment": configured,
               "commands": [{"name": name, "argv": argv} for name, argv, _ in commands],
               "native_identity_gates": ["actual_tools_and_linux_seals", "ranking_bridge_identity", "recursive_bridge_identity"],
               "historical_performance_denominators_combined": False})
        for name, function in (("actual_tools_and_linux_seals", _tool_gate),
                               ("ranking_bridge_identity", _ranking_gate),
                               ("recursive_bridge_identity", _recursive_gate)):
            print(json.dumps({"gate": name, "state": "running"}), flush=True)
            try:
                row = {"name": name, **function(options, output)}
            except Exception as error:
                row = {"name": name, "passed": False, "error": type(error).__name__ + ": " + str(error)}
            report["gates"].append(row)
            _write(output / (name + ".json"), row)
            print(json.dumps({"gate": name, "passed": row["passed"]}), flush=True)
        try:
            report["external_inventory_before"] = _external_inventory(options, report["gates"])
        except Exception as error:
            report["external_identity_error"] = type(error).__name__ + ": " + str(error)
        for name, argv, kind in commands:
            print(json.dumps({"gate": name, "state": "running"}), flush=True)
            execution = _command(argv, timeout=options.timeout)
            outcome = (cargo_test_outcome(execution["stdout"], execution["returncode"]) if kind == "cargo"
                       else unittest_outcome(execution["stderr"], execution["returncode"]))
            row = {"name": name, "execution": execution, **outcome}
            report["gates"].append(row)
            _write(output / (name + "-execution.json"), row)
            if kind == "unittest":
                coverage = {"name": "merge_and_profile_coverage", **_coverage(execution, outcome)}
                report["gates"].append(coverage)
                _write(output / "merge-and-profile-coverage.json", coverage)
            print(json.dumps({"gate": name, "passed": row["passed"], "seconds": execution["seconds"]}), flush=True)
        try:
            report["external_inventory_after"] = _external_inventory(options, report["gates"])
            report["external_inputs_unchanged"] = ("external_identity_error" not in report and
                report["external_inventory_before"] == report["external_inventory_after"])
        except Exception as error:
            report.update(external_inputs_unchanged=False, external_identity_error=type(error).__name__ + ": " + str(error))
        try:
            after = _source_state()
            report["source_after"] = after
            report["source_unchanged"] = before == after and not after["status"]
        except Exception as error:
            report.update(source_unchanged=False, source_identity_error=type(error).__name__ + ": " + str(error))
    report["ok"] = (report["source_unchanged"] and report.get("external_inputs_unchanged") is True
                    and len(report["gates"]) == 6 and all(row["passed"] for row in report["gates"]))
    report["status"] = "bounded_integrated_contracts_passed" if report["ok"] else "integration_qualification_failed"
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    _write(output / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--ranking-bridge", type=Path, required=True)
    parser.add_argument("--ranking-build-receipt", type=Path, required=True)
    parser.add_argument("--ranking-upstream", type=Path, required=True)
    parser.add_argument("--recursive-bridge", type=Path, required=True)
    parser.add_argument("--recursive-identity", type=Path, required=True)
    parser.add_argument("--recursive-upstream", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1800, help="timeout of each actual Rust/full regression gate")
    options = parser.parse_args(argv)
    for name in ("ranking_bridge", "ranking_build_receipt", "ranking_upstream", "recursive_bridge",
                 "recursive_identity", "recursive_upstream"):
        setattr(options, name, getattr(options, name).resolve())
    try:
        _require(1 <= options.timeout <= 7200, "gate timeout must be in 1..7200 seconds")
        result = qualify(options)
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__ + ": " + str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({key: result[key] for key in ("ok", "status", "source_unchanged", "external_inputs_unchanged")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
