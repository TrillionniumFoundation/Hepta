#!/usr/bin/env python3
"""Read-only audit of the preserved graph run against current implementation.

No solver search, optimization choice, compilation or workload timing is run.
Canonical Core and LLVM are deterministically regenerated; recorded executable
bytes are hash-checked, then their exports are bound to current sealed mappings
without calling the workload. This report is not deployment authority.
"""
from __future__ import annotations

import _ctypes
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from hepta.hia_adaptive import _identity as adaptive_identity
from hepta.hia_guarded_optimization import (
    _compose, _freeze, guarded_checker_identity, propose_guarded_reduction,
)
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_optimization import checker_identity, _solver_identity
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import _implementation_hash, emit_program_llvm
from hepta.hia_program_source import lower_source
from hepta.hia_stateful import _adapter_identity
from hepta.native_mapping_identity import verify_loaded_symbols
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_ndu_graph import DRIVER


ARCHIVE_SHA = "0b9d0824e59b8f07db67078996c8eebee02bcacb19b96c701f4a8fc89f736a1b"
EXPECTED_CHANGED = {"hepta/hia_adaptive.py", "hepta/hia_stateful.py"}
EXPECTED_ADDED = {"hepta/native_mapping_identity.py"}


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


def raw_hash(raw):
    return sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    directory = ROOT / "experiments/hia_ndu_graph"
    archive = directory / "run_20261028.tar.xz"
    manifest_bytes = (directory / "run_20261028.members.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    require(raw_hash(archive.read_bytes()) == ARCHIVE_SHA, "original archive changed")
    data, records = {}, {}
    with tarfile.open(archive) as handle:
        for member in handle.getmembers():
            require(member.isfile(), "unexpected non-file archive member")
            require(member.name.startswith("run_20261028/"), "unexpected archive prefix")
            relative = member.name.removeprefix("run_20261028/")
            require(relative not in data, "duplicate archive member")
            raw = handle.extractfile(member).read()
            actual = {"mode": member.mode, "sha256": raw_hash(raw), "size_bytes": len(raw)}
            require(actual == manifest["members"].get(relative), "archive member changed: " + relative)
            data[relative], records[relative] = raw, actual
    require(set(data) == set(manifest["members"]), "archive membership changed")

    def document(name):
        return json.loads(data[name])

    old = document("SOURCE_IDENTITY.json")
    current = {str(path.relative_to(ROOT)): raw_hash(path.read_bytes())
               for path in sorted((ROOT / "hepta").glob("*.py"))}
    current.update({name: raw_hash((ROOT / name).read_bytes())
                    for name in old if not name.startswith("hepta/")})
    for name, expected in old.items():
        require(raw_hash(data["sources/" + name]) == expected, "archived source hash mismatch")
    changed = {name: {"archived": old[name], "current": current.get(name)}
               for name in old if old[name] != current.get(name)}
    added = {name: current[name] for name in current if name not in old}
    require(set(changed) == EXPECTED_CHANGED, "unexpected current source drift")
    require(set(added) == EXPECTED_ADDED, "unexpected new implementation source")

    base = verify_program(document("BASE.json"))
    regenerated_base = lower_source((ROOT / "experiments/hia_optimizer_eval/kernels.hepta").read_text())
    require(base.canonical_bytes == regenerated_base.canonical_bytes, "source lowering changed")
    programs = {"base": base}
    protocol, bank, result = document("PROTOCOL.json"), document("BANK.json"), document("RESULT.json")
    require(digest({k: v for k, v in bank.items() if k != "bank_sha256"}) == bank["bank_sha256"],
            "candidate bank digest mismatch")
    require(digest(protocol) == result["protocol_sha256"], "protocol digest mismatch")
    require(bank["bank_sha256"] == result["bank_sha256"], "result bank identity mismatch")
    for name in ("guard-small", "guard-wide"):
        archived_proposal = document(name + ".proposal.json")
        proposal = propose_guarded_reduction(base, maximum=protocol["guard_limits"][name])
        require(proposal == archived_proposal, "guard proposal generation changed")
        # Structural reconstruction only. It is not a replacement for the
        # complete proof required by guarded_program/build_guarded_native.
        original, fast, frozen = _freeze(base, proposal)
        programs[name] = _compose(original, fast, frozen)

    import z3
    identities = {"ordinary_checker": checker_identity(), "guarded_checker": guarded_checker_identity(),
                  "native_implementation": _implementation_hash(), "solver": _solver_identity(z3)}
    candidate_rows = {}
    for name, program in programs.items():
        row, ir = bank["candidates"][name], emit_program_llvm(program)
        native, proof = row["receipt"]["native"], row["verification"]
        require(program.sha256 == row["source_sha256"] == proof["candidate_sha256"] == native["core_sha256"],
                "canonical Core identity mismatch: " + name)
        require(ir.sha256 == native["llvm_ir_sha256"], "current LLVM differs: " + name)
        require(ir.implementation_sha256 == native["implementation_sha256"] == identities["native_implementation"],
                "native compiler implementation changed")
        require(proof["checker_sha256"] == identities["ordinary_checker" if name == "base" else "guarded_checker"],
                "proof checker implementation changed")
        require(proof["solver"] == identities["solver"], "solver implementation changed")
        compiler = Path(native["toolchain"]["path"]).resolve(strict=True)
        require(digest_executable(compiler) == native["toolchain"]["sha256"], "compiler executable changed")
        binary = data[name + ".so"]
        require(raw_hash(binary) == native["artifact_sha256"], "native bytes differ from receipt")
        # No workload calls or clocks: bind the preserved bytes to actual
        # current mappings using the new gate and release every owned handle.
        with tempfile.TemporaryDirectory(prefix="hia-ndu-byte-audit-") as temporary:
            artifact = Path(temporary) / (name + ".so")
            artifact.write_bytes(binary)
            pinned, _, fd = _pin_native_artifact(artifact)
            library = None
            try:
                require(pinned == binary, "sealed audit snapshot differs")
                library = ctypes.CDLL("/proc/self/fd/" + str(fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
                mapping = verify_loaded_symbols(fd, {entry: getattr(library, entry) for entry in native["exports"]})
            finally:
                try:
                    if library is not None:
                        _ctypes.dlclose(library._handle)
                finally:
                    os.close(fd)
        candidate_rows[name] = {"core_sha256": program.sha256, "llvm_ir_sha256": ir.sha256,
            "artifact_sha256": native["artifact_sha256"], "historical_verification_sha256": proof["verification_sha256"],
            "historical_obligation_count": len(proof["obligations"]), "current_loaded_mapping": mapping,
            "current_workload_executed": False, "fresh_smt_proof_executed": False}

    receipts, samples, obligations = [], [], []
    def inspect_receipt(receipt, artifact):
        proof, native = receipt["verification"], receipt["native"]
        require(digest({k: v for k, v in proof.items() if k != "verification_sha256"}) == proof["verification_sha256"],
                "historical proof digest mismatch")
        require(raw_hash(data[artifact]) == native["artifact_sha256"], "receipt artifact mismatch")
        require(native["implementation_sha256"] == identities["native_implementation"], "receipt compiler mismatch")
        require(proof["candidate_sha256"] in {p.sha256 for p in programs.values()}, "unknown candidate Core")
        expected_checker = identities["ordinary_checker"] if proof["candidate_sha256"] == base.sha256 else identities["guarded_checker"]
        require(proof["checker_sha256"] == expected_checker, "receipt proof checker mismatch")
        require(proof["solver"] == identities["solver"], "receipt solver mismatch")
        for obligation in proof["obligations"]:
            require(raw_hash(obligation["smt2"].encode()) == obligation["smt2_sha256"], "SMT bytes mismatch")
            require(obligation["result"] == "unsat", "unexpected proved obligation result")
            obligations.append(obligation["smt2_sha256"])
        binding = {"base": proof["base_sha256"], "candidate": proof["candidate_sha256"],
                   "verification": proof["verification_sha256"], "artifact": native["artifact_sha256"],
                   "compiler": native["toolchain"]["sha256"], "target": native["target"]}
        require(digest(binding) == receipt["binding_sha256"], "native/proof receipt binding mismatch")
        receipts.append({"member": artifact, "artifact_sha256": native["artifact_sha256"],
                         "binding_sha256": receipt["binding_sha256"]})

    def inspect_sample(sample):
        relative = str(Path(sample["artifact_source_path"]).relative_to(manifest["original_root"]))
        actual = raw_hash(data[relative])
        require(actual == sample["artifact_sha256"] == sample["expected_artifact_sha256"], "executed bytes mismatch")
        require(sample["artifact_load"] == "sealed-memfd" and sample["loaded_snapshot_sealed"], "sample not sealed")
        require(sample["execution_attempted"] and sample["returncode"] == 0, "failed sample silently accepted")
        require(sample["checksum"] == sample["expected_checksum"], "historical output mismatch")
        samples.append({"member": relative, "artifact_sha256": actual})

    for name in programs:
        inspect_receipt(bank["candidates"][name]["receipt"], name + ".so")
        for sample in bank["candidates"][name]["samples"]:
            inspect_sample(sample)
    refusal = bank["candidates"]["refused-unguarded"]
    refused_program = verify_program(document("refused-unguarded.source.json"))
    refusal_proof = refusal["verification"]
    require(refusal["artifact"] is None and refusal["receipt"] is None, "refused candidate has a native artifact")
    require(refusal_proof["status"] == "rejected", "unguarded counterexample no longer recorded as refused")
    require(refused_program.sha256 == refusal["source_sha256"] == refusal_proof["candidate_sha256"],
            "refused candidate source mismatch")
    require(digest({k: v for k, v in refusal_proof.items() if k != "verification_sha256"}) == refusal_proof["verification_sha256"],
            "refusal proof digest mismatch")
    require(refusal_proof["checker_sha256"] == identities["ordinary_checker"]
            and refusal_proof["solver"] == identities["solver"], "refusal checker changed")
    for obligation in refusal_proof["obligations"]:
        require(raw_hash(obligation["smt2"].encode()) == obligation["smt2_sha256"], "refusal SMT bytes mismatch")
    require(refusal_proof["obligations"][-1]["result"] == "sat", "refusal lacks its saved counterexample")
    for episode in result["episodes"]:
        prefix = "episode-" + str(episode["group"]) + "-" + episode["arm"]
        raw_episode = document(prefix + "/RESULT.json")
        # The registered tool writes the raw admission result, then charges
        # that arm's observed serialization/write interval in the aggregate.
        # Reconstruct those exact top-level additions; all nested observations,
        # decisions, receipts and ledgers must remain byte-value identical.
        expected_episode = dict(raw_episode)
        outer = episode["episode_wall_ns"]
        require(outer >= raw_episode["episode_wall_ns"], "negative evidence write interval")
        expected_episode["admission_wall_ns"] = raw_episode["episode_wall_ns"]
        expected_episode["evidence_serialization_and_write_ns"] = outer - raw_episode["episode_wall_ns"]
        expected_episode["episode_wall_ns"] = expected_episode["net_cost_ns"] = outer
        expected_episode["actual_budget_passed"] = outer <= protocol["episode_budget_ns"]
        admitted = raw_episode["status"] == "completed" and expected_episode["actual_budget_passed"]
        expected_episode["completion_admitted"] = admitted
        expected_episode["net_utility_ns"] = (protocol["completion_value_ns"] if admitted else 0) - outer
        expected_episode["reported_cost_scope"] = "outer observed episode, including its full evidence encoding/write; this aggregate report's final write excluded"
        require(episode == expected_episode, "aggregate episode does not match its recorded accounting rule")
        inspect_receipt(episode["initial_receipt"], prefix + "/base.so")
        for transition in episode["transitions"]:
            name = prefix + "/transition-" + str(transition["batch"]) + "-" + transition["target"] + ".so"
            inspect_receipt(transition["receipt"], name)
        for sample in episode["observations"]:
            inspect_sample(sample)
    require(data["driver.c"] == DRIVER.encode(), "current fresh-process driver source changed")
    require(raw_hash(data["driver"]) == result["driver"]["sha256"], "archived driver binary mismatch")

    native_manifest = document("NATIVE_BUILD_IDENTITY.json")
    require(native_manifest == json.loads(Path(native_manifest["binary"]).parents[1].joinpath("identity.json").read_bytes()),
            "current NDU build identity changed")
    require(raw_hash(Path(native_manifest["binary"]).read_bytes()) == raw_hash(data["evidence/native/hepta-hia-ndu-bridge"])
            == native_manifest["binary_sha256"], "actual NDU executable changed")
    private_root = ROOT.parent / "hepta-ndu-source"
    private_files = {**native_manifest["native_sources"], **native_manifest["bridge_sources"]}
    for name, expected in private_files.items():
        require(raw_hash((private_root / name).read_bytes()) == expected, "current native source changed: " + name)

    old_runtime = digest({"runtime": old["hepta/hia_adaptive.py"],
        "pinning": old["hepta/hia_native_differential.py"], "optimization": identities["ordinary_checker"],
        "native": identities["native_implementation"]})
    old_adapter = digest({"adapter": old["hepta/hia_stateful.py"], "scalar_runtime": old_runtime})
    for name, expected in current.items():
        require(raw_hash((ROOT / name).read_bytes()) == expected, "source changed during audit")
    report = {"schema": "hepta.hia.ndu.loaded-mapping-rebinding-audit.v1", "authority": "DENY_ALL",
        "archive_sha256": ARCHIVE_SHA, "members_manifest_sha256": raw_hash(manifest_bytes),
        "original_raw_tree_sha256": manifest["raw_tree_sha256"], "members_rechecked": len(data),
        "original_source_manifest_sha256": raw_hash(data["SOURCE_IDENTITY.json"]),
        "unchanged_source_count": len(old) - len(changed), "changed_sources": changed, "added_sources": added,
        "original_inventory_digest": digest(old), "current_inventory_digest": digest(current),
        "current_identity_inventory": current, "identical_compiler_identities": identities,
        "runtime_identities": {"adaptive_old": old_runtime, "adaptive_current": adaptive_identity(),
                               "stateful_old": old_adapter, "stateful_current": _adapter_identity()},
        "candidates": candidate_rows, "native_receipts_rechecked": len(receipts), "native_receipts": receipts,
        "refused_candidate": {"core_sha256": refused_program.sha256,
                              "verification_sha256": refusal_proof["verification_sha256"],
                              "historical_obligations_rehashed": len(refusal_proof["obligations"]),
                              "historical_status": refusal_proof["status"], "native_artifact": None},
        "successful_historical_samples_rechecked": len(samples), "historical_smt_obligations_rehashed": len(obligations),
        "native_bridge": {"identity": native_manifest["identity"], "binary_sha256": native_manifest["binary_sha256"],
                          "current_source_files_rechecked": len(private_files)},
        "old_result_sha256": raw_hash(data["RESULT.json"]),
        "historical_median_episode_cost_ns": result["median_episode_cost_ns"],
        "historical_median_amortized_cost_ns": result["median_amortized_cost_ns"],
        "new_performance_samples": 0, "new_optimization_decisions": 0, "new_compilations": 0,
        "old_timings_or_identities_modified": False, "fresh_proof_receipt_issued": False,
        "current_mapping_only_admission_checks": len(candidate_rows), "workload_calls_during_audit": 0,
        "deployment_authority": False, "safety_certificate": False,
        "scope": "historical evidence integrity and unchanged compiler/output correspondence; current runtime identity is distinct",
        "deployment_requirement": "New deployment must independently verify/build and obtain a new receipt plus current sealed mapping admission; this audit and historical JSON do not authorize deployment.",
        "performance_scope": "Original fresh-process driver timings remain historical measurements of these exact bytes; no final adaptive/stateful runtime performance claim is transferred."}
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
