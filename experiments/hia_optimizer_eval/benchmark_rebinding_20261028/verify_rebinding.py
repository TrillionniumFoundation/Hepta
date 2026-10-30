#!/usr/bin/env python3
"""Read-only, no-native-execution audit of the preserved benchmark.

Stream and hash the archive once; reconstruct Core/LLVM only in Python. No
solver is imported, no candidate is compiled/loaded, and no timing is replaced.
The output describes historical evidence, never deployment authority.
"""
from __future__ import annotations

import difflib
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
ORIGINAL = ROOT / "experiments/hia_optimizer_eval/next_20261028"
ARCHIVE = ORIGINAL / "benchmark-final-01.tar.xz"
MANIFEST = ORIGINAL / "benchmark-final-01.tar.manifest.json"
ARCHIVE_SHA = "0aa44299aabf4154f8cedc371309b4b4f2e33972986f795b4395af24a2e30e5a"
EXPECTED_CHANGED = {"hepta/hia_adaptive.py", "hepta/hia_stateful.py"}
EXPECTED_ADDED = {"hepta/native_mapping_identity.py"}
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True


def audit_event(event, arguments):
    if event in {"subprocess.Popen", "os.system", "os.fork", "os.exec", "ctypes.dlopen"}:
        raise RuntimeError("native execution is outside this audit: " + event)
    if event == "import" and (arguments[0] == "z3" or arguments[0].startswith("z3.")):
        raise RuntimeError("solver import/search is outside this audit")


sys.addaudithook(audit_event)

from hepta.elf_shared_abi import inspect_owned_shared_elf
from hepta.hia_guarded_optimization import (
    _compose, _freeze, guarded_checker_identity, propose_guarded_reduction,
)
from hepta.hia_optimization import checker_identity
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import _implementation_hash, emit_program_llvm
from hepta.hia_program_source import lower_source
from tools import qualify_hia_optimizer_bench as benchmark


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def require(value, explanation):
    if not value:
        raise RuntimeError(explanation)


def hash_file(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        hasher = sha256()
        for chunk in iter(lambda: stream.read(65536), b""):
            hasher.update(chunk)
        after = os.fstat(stream.fileno())
    fields = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    require(fields(before) == fields(after) == fields(path.stat()), "file changed while hashing: " + str(path))
    return {"path": str(path), "bytes": after.st_size, "sha256": hasher.hexdigest()}


def main():
    try:
        os.nice(10)
    except OSError:
        pass
    manifest_bytes = MANIFEST.read_bytes()
    manifest = json.loads(manifest_bytes)
    archive_before = hash_file(ARCHIVE)
    require(archive_before["sha256"] == manifest["archive_sha256"] == ARCHIVE_SHA,
            "historical archive identity mismatch")
    require(archive_before["bytes"] == manifest["archive_bytes"], "archive size mismatch")
    saved, checked_members = {}, {}
    # Stream mode avoids repeatedly decompressing the archive for random reads.
    # Large disassembly/Rust binary members are hashed without retaining them.
    with tarfile.open(ARCHIVE, "r|xz") as archive:
        for member in archive:
            require(member.isfile() and member.name not in checked_members,
                    "non-file or duplicate archive member")
            require(not Path(member.name).is_absolute() and ".." not in Path(member.name).parts,
                    "unexpected archive member path")
            expected = manifest["members"].get(member.name)
            require(expected is not None, "unregistered archive member: " + member.name)
            keep = (member.name.startswith("source_snapshot/") or
                    member.name.endswith((".json", ".hia", ".ll", ".c", ".cpp", ".rs", ".hepta", ".h")) or
                    member.name in {"hia_original.so", "hia_verified.so"})
            parts, hasher, size = [], sha256(), 0
            stream = archive.extractfile(member)
            for chunk in iter(lambda: stream.read(65536), b""):
                hasher.update(chunk)
                size += len(chunk)
                if keep:
                    parts.append(chunk)
            actual = {"bytes": size, "sha256": hasher.hexdigest()}
            require(actual == expected, "archive member hash/size mismatch: " + member.name)
            checked_members[member.name] = actual
            if keep:
                saved[member.name] = b"".join(parts)
    require(set(checked_members) == set(manifest["members"])
            and len(checked_members) == manifest["member_count"] == 260,
            "archive membership mismatch")

    def document(name):
        return json.loads(saved[name])

    plan, report = document("plan.json"), document("report.json")
    require(plan["source_bindings"] == report["source_bindings"], "plan/report source binding mismatch")
    old = report["source_bindings"]
    current_bytes = {name: (ROOT / name).read_bytes() for name in old}
    current_bytes.update({str(path.relative_to(ROOT)): path.read_bytes()
                          for path in sorted((ROOT / "hepta").glob("*.py"))})
    current = {name: sha256(raw).hexdigest() for name, raw in current_bytes.items()}
    for name, identity in old.items():
        require(sha256(saved["source_snapshot/" + name]).hexdigest() == identity,
                "archived source does not match its binding: " + name)
    changed = {name: {"archived": identity, "current": current.get(name)}
               for name, identity in old.items() if current.get(name) != identity}
    added = {name: identity for name, identity in current.items() if name not in old}
    require(set(changed) == EXPECTED_CHANGED and set(added) == EXPECTED_ADDED,
            "unexpected source delta outside the loaded-mapping repair")
    patch = []
    for name in sorted(changed | added):
        left = saved.get("source_snapshot/" + name, b"").decode().splitlines(keepends=True)
        right = current_bytes[name].decode().splitlines(keepends=True)
        patch.extend(difflib.unified_diff(left, right, fromfile="historical/" + name, tofile="current/" + name))

    require(plan["tools"] == report["tools"], "plan/report tool identities differ")
    tools = {}
    for name, item in plan["tools"].items():
        actual = hash_file(item["path"])
        require(actual == {key: item[key] for key in ("path", "bytes", "sha256")},
                "recorded compiler/tool executable changed: " + name)
        require(hash_file(item["version"]["argv"][0]) == actual,
                "tool alias no longer resolves to the recorded executable: " + name)
        tools[name] = {**actual, "historical_version_stdout": item["version"]["stdout"],
                       "new_version_process_executed": False}

    protocol = report["protocol"]
    require(protocol == plan["protocol"] == benchmark.next_protocol(), "registered benchmark protocol changed")
    require(digest(protocol) == report["protocol_sha256"] == plan["protocol_sha256"], "protocol digest mismatch")
    for name in ("kernels.hepta", "kernels.c", "kernels.cpp", "kernels.rs", "driver.c"):
        require(saved[name] == current_bytes["experiments/hia_optimizer_eval/" + name],
                "current benchmark fixture differs: " + name)
    require(saved["workload.h"] == benchmark.workload_header(protocol).encode(), "generated workload header changed")

    base = verify_program(saved["program.hia"])
    old_root = Path(manifest["source"])
    regenerated = lower_source(saved["kernels.hepta"].decode(), path=str(old_root / "kernels.hepta"),
                               module="optimizer_bench")
    require(regenerated.canonical_bytes == base.canonical_bytes
            and base.sha256 == report["core_sha256"], "baseline Core lowering changed")
    proposal = document("guarded-proposal.json")
    require(propose_guarded_reduction(base) == proposal, "deterministic proposal structure changed")
    # This reconstructs bytes, not a proof. No production proof gate is bypassed
    # for deployment, and no proposal is compiled or admitted by this audit.
    original, fast, frozen = _freeze(base, proposal)
    guarded = _compose(original, fast, frozen)
    archived_guarded = verify_program(saved["guarded-program.hia"])
    require(guarded.canonical_bytes == archived_guarded.canonical_bytes,
            "structurally reconstructed guarded Core changed")
    identities = {"ordinary_checker": checker_identity(), "guarded_checker": guarded_checker_identity(),
                  "native_implementation": _implementation_hash()}
    programs = {"hia_original": (base, "program.ll"), "hia_verified": (guarded, "guarded-program.ll")}
    candidates = {}
    for name, (program, llvm_member) in programs.items():
        build = report["builds"][name]
        native = build["receipt"] if name == "hia_original" else build["receipt"]["native"]
        llvm = emit_program_llvm(program)
        require(llvm.text.encode() == saved[llvm_member]
                and llvm.sha256 == native["llvm_ir_sha256"], "current emitted LLVM differs: " + name)
        require(program.sha256 == native["core_sha256"] == native["input_sha256"], "native/Core binding differs")
        require(llvm.implementation_sha256 == native["implementation_sha256"] == identities["native_implementation"],
                "native verifier/emitter identity changed")
        artifact = checked_members[name + ".so"]
        require(artifact["sha256"] == native["artifact_sha256"] and artifact["bytes"] == native["artifact_bytes"],
                "native receipt/artifact mismatch")
        require(inspect_owned_shared_elf(saved[name + ".so"], tuple(native["exports"])) == native["binary_inventory"],
                "preserved ELF inventory differs from native receipt")
        require(native["toolchain"]["sha256"] == tools["clang"]["sha256"], "native compiler executable mismatch")
        candidates[name] = {"core_sha256": program.sha256, "llvm_ir_sha256": llvm.sha256,
                            "artifact_sha256": artifact["sha256"], "artifact_bytes": artifact["bytes"],
                            "native_build_receipt_rechecked": True, "elf_inventory_rechecked_without_loading": True}

    receipt = document("guarded-native.json")
    require(receipt == report["builds"]["hia_verified"]["receipt"], "standalone/aggregate native receipt differs")
    historical_proofs = [document("guarded-verification.json"), receipt["verification"]]
    proof_rows, solver_identity = [], None
    for proof in historical_proofs:
        require(proof["status"] == "verified"
                and proof["checker_sha256"] == identities["guarded_checker"], "historical checker identity mismatch")
        require(proof["base_sha256"] == base.sha256 and proof["candidate_sha256"] == guarded.sha256
                and proof["fast_core_sha256"] == fast.sha256 and proof["proposal_sha256"] == digest(proposal),
                "historical proof/Core/proposal binding mismatch")
        require(digest({key: value for key, value in proof.items() if key != "verification_sha256"})
                == proof["verification_sha256"], "historical verification digest mismatch")
        for obligation in proof["obligations"]:
            require(sha256(obligation["smt2"].encode()).hexdigest() == obligation["smt2_sha256"]
                    and obligation["result"] == "unsat", "saved SMT obligation integrity mismatch")
        if solver_identity is None:
            solver_identity = proof["solver"]
        require(proof["solver"] == solver_identity, "historical solver identities differ")
        proof_rows.append({"verification_sha256": proof["verification_sha256"],
                           "historical_elapsed_ns": proof["elapsed_ns"],
                           "historical_obligations_rehashed": len(proof["obligations"]),
                           "new_solver_queries": 0})
    library = hash_file(solver_identity["library_path"])
    bindings = sha256()
    package = Path(solver_identity["library_path"]).parent.parent
    for path in sorted(package.glob("*.py")):
        bindings.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    require(library["sha256"] == solver_identity["library_sha256"]
            and bindings.hexdigest() == solver_identity["binding_sha256"], "recorded solver bytes changed")
    proof, native = receipt["verification"], receipt["native"]
    binding = {"base": proof["base_sha256"], "candidate": proof["candidate_sha256"],
               "verification": proof["verification_sha256"], "artifact": native["artifact_sha256"],
               "compiler": native["toolchain"]["sha256"], "target": native["target"]}
    require(digest(binding) == receipt["binding_sha256"], "guarded native/proof binding digest mismatch")

    artifacts = {}
    for name, item in report["artifacts_before"].items():
        relative = str(Path(item["path"]).relative_to(old_root))
        require(checked_members[relative] == {key: item[key] for key in ("bytes", "sha256")},
                "historical backend artifact mismatch: " + name)
        require(report["builds"][name]["status"] == "compiled", "backend was not successfully compiled")
        artifacts[name] = checked_members[relative]
    require(checked_members["driver"] == {key: report["driver_identity"][key] for key in ("bytes", "sha256")},
            "driver binary identity mismatch")
    schedule = [{"sample_index": index, "group": group, "kernel": kernel, "backend": backend}
                for index, (group, kernel, backend) in enumerate(benchmark.sample_order(protocol, tuple(report["backends"])))]
    require(schedule == plan["scheduled_samples"] == report["scheduled_samples"], "sample order differs from registration")
    require(len(report["raw_samples"]) == len(schedule) == 98, "scheduled measurements missing")
    for index, row in enumerate(report["raw_samples"]):
        require(document(f"sample-{index:03d}.json") == row, "individual/aggregate timing observation mismatch")
        require({key: row[key] for key in schedule[index]} == schedule[index], "sample ordering mismatch")
        require(row["status"] == "measured" and row["library_sha256"] == artifacts[row["backend"]]["sha256"],
                "sample artifact identity mismatch")
        execution = row["execution"]
        require(execution["status"] == "completed" and execution["returncode"] == 0
                and row["outer_wall_ns"] == execution["wall_ns"], "sample execution/timing disagreement")
        require(execution["argv"] == [str(old_root / "driver"), str(old_root / (row["backend"] + ".so")),
                                       row["kernel"], "holdout"], "sample executed unexpected command")
        require(all(row[key] == value for key, value in json.loads(execution["stdout"]).items()),
                "timing record differs from its actual retained stdout")
        require(row["checksum"] == benchmark.timed_checksum(row["kernel"], "holdout", protocol),
                "historical sample checksum mismatch")
    cases = benchmark.correctness_cases(protocol)
    observations = 0
    for value in report["correctness"].values():
        require(value["ok"] and value["observations"] == [{**case, "actual": case["expected"]} for case in cases],
                "finite historical correctness observation mismatch")
        observations += len(value["observations"])
    for row in report["training"]:
        require(row["split"] == "train" and row["measurement"]["checksum"]
                == benchmark.timed_checksum(row["kernel"], "train", protocol), "PGO training checksum mismatch")
    profiles = []
    for name in ("c_pgo_lto", "cpp_pgo_lto"):
        for item in [report["builds"][name]["training_profile"], *report["builds"][name]["profile_inputs"]]:
            relative = str(Path(item["path"]).relative_to(old_root))
            require(checked_members[relative] == {key: item[key] for key in ("bytes", "sha256")},
                    "retained PGO profile identity mismatch")
            profiles.append(relative)
    evaluation = benchmark.evaluate_samples(report["raw_samples"], protocol, tuple(report["backends"]), "hia_verified")
    require(evaluation == report["evaluation"], "current pure statistical evaluation differs")
    require(report["source_unchanged"] and report["tools_unchanged"] and report["artifacts_unchanged"]
            and report["quality_passed"] and not report["ok"] and not evaluation["noninferiority_passed"],
            "historical negative result incorrectly promoted")
    summary_bytes = (ORIGINAL / "benchmark-results.json").read_bytes()
    summary = json.loads(summary_bytes)
    require(summary["archive_sha256"] == ARCHIVE_SHA and summary["raw_report_sha256"] == sha256(saved["report.json"]).hexdigest(),
            "published summary does not identify the preserved raw report")
    for key in ("status", "builds", "search_cost", "source_bindings"):
        require(summary[key] == report[key], "published summary changes raw evidence: " + key)
    for key in ("summary", "comparisons", "quality_failures"):
        require(summary[key] == evaluation[key], "published statistical summary mismatch")
    require(summary["all_costs"] == report["costs"] and summary["samples"] == 98
            and summary["finite_checks"] == observations, "published cost/sample accounting mismatch")

    loaded_sources = {}
    for module in tuple(sys.modules.values()):
        location = getattr(module, "__file__", None)
        if not location:
            continue
        path = Path(location).resolve()
        if not path.is_relative_to(ROOT) or path.suffix != ".py" or path == Path(__file__).resolve():
            continue
        name = str(path.relative_to(ROOT))
        require(name in old and current[name] == old[name], "audit imported changed/unbound project code: " + name)
        loaded_sources[name] = current[name]
    for name, expected in current.items():
        require(sha256((ROOT / name).read_bytes()).hexdigest() == expected, "source changed during audit")
    require(hash_file(ARCHIVE) == archive_before and MANIFEST.read_bytes() == manifest_bytes
            and (ORIGINAL / "benchmark-results.json").read_bytes() == summary_bytes,
            "original evidence changed during audit")
    require("z3" not in sys.modules, "solver was unexpectedly imported")
    result = {
        "schema": "hepta.hia.benchmark-artifact-rebinding-audit.v1",
        "status": "historical_integrity_and_current_core_llvm_correspondence_verified",
        "archive_sha256": ARCHIVE_SHA, "archive_bytes": archive_before["bytes"],
        "manifest_sha256": sha256(manifest_bytes).hexdigest(), "archive_members_rechecked": len(checked_members),
        "raw_member_bytes_rechecked": sum(item["bytes"] for item in checked_members.values()),
        "old_report_sha256": sha256(saved["report.json"]).hexdigest(),
        "original_source_count": len(old), "unchanged_existing_source_count": len(old) - len(changed),
        "changed_sources": changed, "added_sources": added,
        "global_source_snapshot_identical": False, "original_source_inventory_digest": digest(old),
        "current_source_inventory_digest": digest(current), "current_source_inventory": current,
        "current_execution_dependencies_rechecked": loaded_sources,
        "current_codegen_and_checker_identities": identities, "core_llvm_correspondence": candidates,
        "recorded_tool_executables": tools, "recorded_tool_executable_bytes_match": True,
        "solver_bytes": {"library": library, "binding_sha256": bindings.hexdigest(),
                          "historical_reported_version": solver_identity["version"],
                          "fresh_version_query": False, "solver_loaded": False},
        "historical_proofs_rechecked": proof_rows, "optimized_native_binding_sha256": receipt["binding_sha256"],
        "native_backend_receipts_rechecked": 2, "backend_artifacts": artifacts,
        "driver_artifact": checked_members["driver"], "retained_profile_files_rechecked": profiles,
        "historical_samples_rechecked": 98, "historical_correctness_observations_rechecked": observations,
        "historical_training_observations_rechecked": len(report["training"]),
        "historical_quality_passed": report["quality_passed"], "historical_noninferiority_passed": evaluation["noninferiority_passed"],
        "historical_build_cost_ns": {name: row["wall_ns"] for name, row in report["builds"].items()},
        "historical_search_cost": report["search_cost"], "historical_other_costs": report["costs"],
        "historical_guarded_verification_wall_ns": report["guarded_verification_wall_ns"],
        "pure_statistics_recomputed_without_new_measurement": True,
        "new_solver_queries": 0, "new_compilations": 0, "candidate_native_libraries_loaded": 0,
        "new_performance_samples": 0, "new_workload_executions": 0,
        "old_timings_or_identities_modified": False, "fresh_proof_receipt_issued": False,
        "deployment_authority": False, "safety_certificate": False,
        "unestablished": {
            "all_implicit_toolchain_dependencies_identical": "unknown: the historical plan binds five tool executables, not every shared library, compiler-rt/sysroot or system-linker dependency",
            "fresh_native_binary_reproducibility": "unknown: no native compilation was performed; preserved artifact bytes and identical current emitted LLVM are separately established",
            "current_loaded_mapping_admission": "unknown/not attempted: this audit never dlopens preserved binaries",
            "fresh_solver_result": "unknown/not attempted: saved SMT bytes/results were rehashed, not solved again",
            "new_runtime_performance": "unknown/not measured: historical fresh-process C-driver timings are not measurements of the repaired adaptive/stateful runtime",
        },
        "deployment_requirement": "New deployment still requires current independent verification/build, a new bound receipt and applicable current artifact/mapping admission. Historical JSON and this audit grant no authority.",
        "scope": "The retained benchmark uses one ordinary-path dlopen per fresh C-driver process. The changed persistent adaptive/stateful numeric-fd loader is not its measured execution path. Exact archived machine-code observations and their old costs remain historical.",
    }
    return result, "".join(patch)


if __name__ == "__main__":
    try:
        result, patch = main()
    except Exception as error:
        print(json.dumps({"status": "unknown_audit_not_closed", "error": {"type": type(error).__name__, "message": str(error)},
                          "deployment_authority": False, "new_compilations": 0, "new_workload_executions": 0}, indent=2))
        raise SystemExit(1)
    # Only the separate audit directory is writable by this script.
    (HERE / "SOURCE_DELTA.patch").write_text(patch)
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
