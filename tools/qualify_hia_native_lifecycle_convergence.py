#!/usr/bin/env python3
"""Finite C/Rust/LLVM state lifecycle and measured no-change qualification.

The existing runtime remains the only publication state machine. This retained
experiment has fixed inputs, sample pairs and costs; it never retries for a win.
Synthetic policy refusals are labelled controls, not performance observations.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_multiversion import (MEASUREMENT_SCHEMA, MultiversionRejected,
    PublicationCancellation, ScalarMultiversionRuntime, _admissible,
    _assess_measurement, _measurement_snapshot)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta import hia_program_llvm as llvm_backend
from hepta.hia_program_llvm import _implementation_hash, build_program_native, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from hepta.hia_scalar_state import (ScalarStateRejected, ScalarStateSession,
    ScalarTransitionCancellation, ScalarTransitionCancelled)
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from hepta.native_tool_identity import digest_executable

MASK = (1 << 64) - 1
DELTAS = (0, 1, MASK, 1 << 63, 17, 5, MASK - 3, 0, 9, 1 << 63, MASK, 23)
TIMING_VALUES = (0, 1, MASK, 1 << 63, 17, 5, MASK - 3, 23)
PROTOCOL = {
    "schema": "hepta.hia.native-lifecycle-convergence-protocol.v1",
    "initial_state": MASK - 5, "deltas": list(DELTAS),
    "code_transitions_before_step": {"3": "publish_commuted", "7": "rollback", "9": "publish_commuted"},
    "timing": {"pairs": 31, "calls_per_side_per_pair": 50000,
               "values": list(TIMING_VALUES), "candidate_delta_index": "(index+3)&7",
               "pair_order": "baseline first on even pairs, candidate first on odd pairs",
               "horizon_calls": 100_000_000, "maximum_search_ns": 60_000_000_000,
               "maximum_mad_ppm": 50_000, "minimum_gain_ppm": 20_000,
               "decision_reserve_ns": 2_000_000_000},
    "controls": ["identical_actual_artifact", "synthetic_noisy_samples", "synthetic_no_net_gain",
                 "stale_source", "forged_candidate_artifact", "behavior_changing_candidate"],
    "policy_controls_are_timings": False, "retries_or_sample_trimming": False,
    "performance_success_required": False, "physical_device_claim": False,
    "state_scope": "one host-owned u64 scalar; no heap/loan/stack migration or crash durability",
}
_BINDINGS = ("hepta/hia_multiversion.py", "hepta/hia_scalar_state.py", "hepta/hia_specialization.py",
             "hepta/hia_native_retirement.py", "hepta/native_mapping_identity.py",
             "hepta/hia_translation_validation.py", "hepta/hia_program.py", "hepta/hia_program_runtime.py",
             "hepta/hia_program_llvm.py", "tools/qualify_hia_native_lifecycle_convergence.py")


def transition_program(variant=0, *, version=7):
    parameters = [{"name": "state", "type": "u64"}, {"name": "delta", "type": "u64"}]
    args = ["state", "delta"] if variant != 1 else ["delta", "state"]
    ops = [{"op": "int.add.wrap", "args": args, "out": [{"name": "answer", "type": "u64"}], "attrs": {}}]
    result = "answer"
    if variant == 2:
        ops += [{"op": "const", "args": [], "out": [{"name": "one", "type": "u64"}], "attrs": {"value": 1}},
                {"op": "int.add.wrap", "args": ["answer", "one"], "out": [{"name": "wrong", "type": "u64"}], "attrs": {}}]
        result = "wrong"
    return {"schema": f"hepta.hia.program.v{version}", "module": "native_lifecycle_convergence",
            "functions": [{"name": "transition", "params": parameters, "returns": ["u64"], "effects": [],
            "entry": "entry", "blocks": [{"id": "entry", "params": copy.deepcopy(parameters), "ops": ops,
            "term": {"op": "ret", "values": [result]}}]}]}


def measurement_for(before, after, before_artifact, after_artifact, samples, *, search_cost_ns=0):
    return {"schema": MEASUREMENT_SCHEMA, "before_sha256": verify_program(before).sha256,
            "after_sha256": verify_program(after).sha256,
            "before_artifact_sha256": before_artifact, "after_artifact_sha256": after_artifact,
            "workload_sha256": sha256(_wire(PROTOCOL["timing"])).hexdigest(), "function": "transition",
            "calls_per_sample": PROTOCOL["timing"]["calls_per_side_per_pair"],
            "horizon_calls": PROTOCOL["timing"]["horizon_calls"],
            "search_cost_ns": search_cost_ns,
            "maximum_search_ns": PROTOCOL["timing"]["maximum_search_ns"], "samples": copy.deepcopy(samples)}


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


_DRIVER = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <dlfcn.h>
typedef uint64_t (*transition_fn)(uint64_t, uint64_t);
static const uint64_t values[8] = {0,1,UINT64_MAX,UINT64_C(9223372036854775808),17,5,UINT64_MAX-3,23};
static uint64_t now(void) {
    struct timespec stamp;
    if (clock_gettime(CLOCK_MONOTONIC, &stamp)) exit(11);
    return (uint64_t)stamp.tv_sec * UINT64_C(1000000000) + (uint64_t)stamp.tv_nsec;
}
static uint64_t measure(transition_fn fn, uint64_t *checksum) {
    uint64_t sum = 0, start = now();
    for (unsigned int i=0; i<50000; ++i) sum += fn(values[i&7], values[(i+3)&7]);
    uint64_t end = now();
    *checksum = sum;
    if (end <= start) exit(12);
    return end-start;
}
int main(int argc, char **argv) {
    if (argc != 3) return 13;
    void *first=dlopen(argv[1], RTLD_NOW|RTLD_LOCAL), *second=dlopen(argv[2], RTLD_NOW|RTLD_LOCAL);
    if (!first || !second) return 14;
    transition_fn baseline=(transition_fn)dlsym(first,"transition"), candidate=(transition_fn)dlsym(second,"transition");
    if (!baseline || !candidate) return 15;
    uint64_t expected=0;
    for (unsigned int i=0; i<50000; ++i) expected += values[i&7]+values[(i+3)&7];
    for (unsigned int pair=0; pair<31; ++pair) {
        uint64_t b,c,bs,cs;
        if (pair&1) { c=measure(candidate,&cs); b=measure(baseline,&bs); }
        else { b=measure(baseline,&bs); c=measure(candidate,&cs); }
        printf("{\"pair\":%u,\"baseline_ns\":%llu,\"candidate_ns\":%llu,\"baseline_checksum\":%llu,\"candidate_checksum\":%llu,\"expected_checksum\":%llu}\n",pair,(unsigned long long)b,(unsigned long long)c,(unsigned long long)bs,(unsigned long long)cs,(unsigned long long)expected);
        if (bs != expected || cs != expected) return 16;
    }
    if (dlclose(second) || dlclose(first)) return 17;
    return 0;
}
'''


def run(output, *, clang, rustc, expected_head=None):
    """Observe actual backend invocations without substituting any result.

    This single-process qualifier restores the backend hook even on failure;
    the production compiler and its publication path are unchanged.
    """
    output = Path(output).resolve()
    native_commands = []
    actual_run = llvm_backend.run_bounded

    def observe(argv, **kwargs):
        index = len(native_commands)
        label = f"native-command-{index:02d}"
        row = {"argv": list(argv), "cwd": str(kwargs.get("cwd") or Path.cwd()),
               "limits": {key: value for key, value in kwargs.items() if key != "cwd"}}
        for argument in argv:
            path = Path(argument)
            if path.suffix == ".ll" and path.is_file():
                retained = output / (label + ".ll")
                shutil.copyfile(path, retained)
                row["llvm_input"] = {"retained": retained.name, "sha256": _digest(retained)}
        native_commands.append(row)
        begin = time.perf_counter_ns()
        try:
            result = actual_run(argv, **kwargs)
            row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            if "-o" in argv:
                artifact = Path(argv[argv.index("-o") + 1])
                if artifact.is_file():
                    row["produced_artifact"] = {"path": str(artifact), "sha256": _digest(artifact),
                                                "bytes": artifact.stat().st_size}
            return result
        except BaseException as error:
            row["error"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            row["wall_ns"] = time.perf_counter_ns() - begin
            _write(output / "native-commands.json", native_commands)

    llvm_backend.run_bounded = observe
    try:
        return _run(output, clang=clang, rustc=rustc, expected_head=expected_head,
                    native_commands=native_commands)
    finally:
        llvm_backend.run_bounded = actual_run


def _run(output, *, clang, rustc, expected_head, native_commands):
    output = Path(output).resolve()
    output.mkdir(parents=True)
    started = time.perf_counter_ns()
    source = {name: _digest(ROOT / name) for name in _BINDINGS}
    implementation = _implementation_hash()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if expected_head is not None and (head != expected_head or status):
        raise ValueError("clean exact expected source commit required")
    clang, rustc = str(Path(clang).resolve()), str(Path(rustc).resolve())
    tools = {"clang": {"path": clang, "sha256": digest_executable(clang)},
             "rustc": {"path": rustc, "sha256": digest_executable(rustc)}}
    _write(output / "protocol.json", PROTOCOL)
    _write(output / "source-before.json", {"commit": head, "git_status": status, "files": source,
           "implementation_sha256": implementation, "tools": tools})
    commands = []

    def command(label, argv, *, pass_fds=()):
        begin = time.perf_counter_ns()
        process = subprocess.run(argv, cwd=output, capture_output=True, text=True, timeout=60, pass_fds=pass_fds)
        (output / (label + ".stdout")).write_text(process.stdout)
        (output / (label + ".stderr")).write_text(process.stderr)
        commands.append({"label": label, "argv": argv, "cwd": str(output), "pass_fds": list(pass_fds),
                         "returncode": process.returncode, "wall_ns": time.perf_counter_ns() - begin,
                         "stdout": label + ".stdout", "stderr": label + ".stderr"})
        _write(output / "commands.json", commands)
        if process.returncode:
            raise RuntimeError(f"{label} failed: {process.returncode}: {process.stderr}")
        return process.stdout

    command("clang-version", [clang, "--version"])
    command("rustc-version", [rustc, "--version", "--verbose"])
    (output / "reference.c").write_text("#include <stdint.h>\nuint64_t transition(uint64_t state,uint64_t delta){return state+delta;}\n")
    (output / "reference.rs").write_text('#[no_mangle]\npub extern "C" fn transition(state:u64,delta:u64)->u64{state.wrapping_add(delta)}\n')
    command("c-reference-build", [clang, "-std=c11", "-O2", "-shared", "-fPIC", "reference.c", "-o", "reference-c.so"])
    command("rust-reference-build", [rustc, "--edition=2021", "--crate-type=cdylib", "-C", "opt-level=2",
                                   "-C", "overflow-checks=yes", "-C", "panic=abort", "reference.rs", "-o", "reference-rust.so"])
    references = {}
    for language in ("c", "rust"):
        library = ctypes.CDLL(str(output / f"reference-{language}.so"))
        function = library.transition
        function.argtypes, function.restype = [ctypes.c_uint64, ctypes.c_uint64], ctypes.c_uint64
        references[language] = (library, function)
    (output / "timing-driver.c").write_text(_DRIVER)
    command("timing-driver-build", [clang, "-std=c11", "-O2", "timing-driver.c", "-ldl", "-o", "timing-driver"])

    before, after, wrong = transition_program(), transition_program(1), transition_program(2)
    for name, document in (("baseline", before), ("candidate", after), ("wrong", wrong)):
        _write(output / (name + ".hia.json"), document)
        (output / (name + ".ll")).write_text(emit_program_llvm(verify_program(document)).text)
    states, publications, controls, probes = [], [], [], []
    reference_states = {"c": PROTOCOL["initial_state"], "rust": PROTOCOL["initial_state"]}
    runtime = ScalarMultiversionRuntime(before, output, clang=clang)
    candidate_lease = None
    try:
        base_generation = runtime._states[0]
        shutil.copyfile(base_generation.artifact, output / "executed-baseline.so")
        probes.append(base_generation.info.as_dict())
        actual_prepare = runtime._prepare

        def retain_actual_preparation(*args, **kwargs):
            # Observe the actual existing method, including candidates later
            # rejected at the final gate. No result or receipt is substituted.
            prepared = actual_prepare(*args, **kwargs)
            try:
                probes.append(prepared.info.as_dict())
                retained_path = output / f"prepared-generation-{prepared.info.generation}.so"
                shutil.copyfile(prepared.artifact, retained_path)
                if _digest(retained_path) != prepared.info.artifact_sha256:
                    raise AssertionError("retained actual generation bytes changed")
            except BaseException as failure:
                # The observer has not returned this preparation to publish.
                # Transfer its complete ownership to the same runtime ledger;
                # never create a second owner or retry native release here.
                try:
                    runtime._dispose(prepared.info.generation, prepared.library,
                        prepared.functions, prepared.fd, prepared.artifact,
                        prepared.inode, prepared.identity_pin,
                        cause="qualification_retention_failed")
                except BaseException as cleanup_failure:
                    failure.add_note("runtime retention cleanup raised "
                        + type(cleanup_failure).__name__ + ": " + str(cleanup_failure))
                raise
            return prepared

        runtime._prepare = retain_actual_preparation
        with ScalarStateSession(runtime, "transition", PROTOCOL["initial_state"], max_native_calls=64) as state:
            expected = PROTOCOL["initial_state"]
            for index, delta in enumerate(DELTAS):
                action = PROTOCOL["code_transitions_before_step"].get(str(index))
                if action == "publish_commuted":
                    published = runtime.publish(after)
                    publications.append(published.as_dict())
                    if candidate_lease is None:
                        candidate_lease = runtime.lease()
                        shutil.copyfile(runtime._states[published.generation].artifact, output / "executed-candidate.so")
                elif action == "rollback":
                    runtime.rollback()
                expected = (expected + delta) & MASK
                for language, (_, native) in references.items():
                    reference_states[language] = native(reference_states[language], delta)
                observed = state.step([delta], expected_revision=index)
                if observed["state_after"] != expected or any(value != expected for value in reference_states.values()):
                    raise AssertionError("C/Rust/HIA state transition mismatch")
                states.append({"step": index, "delta": delta, "expected": expected,
                               "c": reference_states["c"], "rust": reference_states["rust"], "hia": observed})
            cancellation = ScalarTransitionCancellation()
            assert cancellation.cancel()
            try:
                state.step([1], expected_revision=len(DELTAS), cancellation=cancellation)
            except ScalarTransitionCancelled:
                controls.append({"kind": "pre-invocation-cancellation", "native_calls": 0})
            else:
                raise AssertionError("cancelled state transition committed")
            try:
                state.step([1], expected_revision=0)
            except ScalarStateRejected:
                controls.append({"kind": "stale-state-revision", "native_calls": 0})
            else:
                raise AssertionError("stale state transition committed")
            state_snapshot = state.snapshot()
        assert candidate_lease is not None
        runtime.rollback()
        selected_before = runtime.snapshot()
        retired_value = candidate_lease.call("transition", [MASK, 2])
        if retired_value != 1:
            raise AssertionError("retired leased native function changed")
        controls.append({"kind": "retired-generation-lease-call", "native_calls": 1, "result": retired_value})
        retained = runtime._states[candidate_lease.info.generation]
        raw = command("paired-native-samples", [str(output / "timing-driver"),
                      f"/proc/self/fd/{base_generation.fd}", f"/proc/self/fd/{retained.fd}"],
                      pass_fds=(base_generation.fd, retained.fd))
        rows = [json.loads(line) for line in raw.splitlines()]
        expected_checksum = sum((TIMING_VALUES[index & 7] + TIMING_VALUES[(index + 3) & 7]) & MASK
                                for index in range(50000)) & MASK
        if (len(rows) != 31 or [row["pair"] for row in rows] != list(range(31))
                or any(row[key] != expected_checksum for row in rows for key in
                       ("baseline_checksum", "candidate_checksum", "expected_checksum"))):
            raise AssertionError("paired C-loop calls did not meet the independent fixed checksum")
        pairs = [{key: row[key] for key in ("baseline_ns", "candidate_ns")} for row in rows]
        measurement = measurement_for(before, after, base_generation.info.artifact_sha256,
            retained.info.artifact_sha256, pairs, search_cost_ns=time.perf_counter_ns() - started)
        _write(output / "actual-measurement.json", measurement)
        measured_policy = _assess_measurement(_measurement_snapshot(measurement), prepare_ns=0)

        def refuse(label, document, evidence, expected_reason):
            snapshot = runtime.snapshot()
            token = PublicationCancellation()
            try:
                runtime.publish_if_current(document, snapshot["current_generation"],
                    expected_epoch=snapshot["selection_epoch"], max_prepare_ns=5_000_000_000,
                    cancellation=token, measurement=evidence)
            except MultiversionRejected as error:
                reason = str(error)
                if expected_reason not in reason:
                    raise AssertionError((label, expected_reason, reason)) from error
            else:
                raise AssertionError(label + " unexpectedly published")
            observed = runtime.snapshot()
            if (observed["current_generation"], observed["selection_epoch"]) != (snapshot["current_generation"], snapshot["selection_epoch"]):
                raise AssertionError("refusal changed the selected generation")
            if token.committed():
                raise AssertionError("refusal committed the cancellation token")
            controls.append({"kind": label, "outcome": "no_change", "reason": reason,
                             "measurement": evidence, "synthetic_policy_samples": label != "actual-measurement",
                             "before_generation": snapshot["current_generation"], "after_generation": observed["current_generation"]})

        # This equivalent pair is deliberately a no-improvement control. The
        # actual byte check is required; its result is never fabricated.
        if base_generation.info.artifact_sha256 != retained.info.artifact_sha256:
            raise AssertionError("fixed identical-artifact control unexpectedly produced different native bytes")
        refuse("actual-measurement", after, measurement, "identical_native_artifacts")
        synthetic = copy.deepcopy(measurement)
        synthetic.update(after_artifact_sha256="f" * 64, calls_per_sample=1, horizon_calls=1_000_000,
                         search_cost_ns=0, samples=[{"baseline_ns": 1_000_000, "candidate_ns": 1} for _ in range(31)])
        noisy = copy.deepcopy(synthetic)
        noisy["samples"] = [{"baseline_ns": (index % 3 + 1) * 1_000_000,
                             "candidate_ns": (index % 3 + 1) * 500_000} for index in range(31)]
        refuse("synthetic-noise-control", after, noisy, "timing_noise")
        no_gain = copy.deepcopy(synthetic)
        no_gain["horizon_calls"] = 1
        refuse("synthetic-no-net-gain-control", after, no_gain, "experiment_cost_not_recovered")
        stale = copy.deepcopy(synthetic)
        stale["before_sha256"] = "0" * 64
        refuse("stale-source-control", after, stale, "does not bind")
        refuse("forged-artifact-control", after, synthetic, "actual freshly built artifacts")
        bad_receipt = build_program_native(wrong, output / "wrong.so", clang=clang)
        _write(output / "wrong-native-build.json", bad_receipt)
        wrong_measurement = copy.deepcopy(synthetic)
        wrong_measurement.update(after_sha256=verify_program(wrong).sha256,
                                 after_artifact_sha256=bad_receipt["artifact_sha256"])
        refuse("wrong-semantics-control", wrong, wrong_measurement, "did not prove")
        runtime_after_controls = runtime.snapshot()
    finally:
        try:
            runtime.close()
        finally:
            try:
                if candidate_lease is not None:
                    candidate_lease.close()
            finally:
                after_close = runtime.snapshot()
                _write(output / "runtime-after-close.json", after_close)
    if (after_close["generations"]
            or after_close["cleanup"]["observed_closed_and_directory_absent"] is not True):
        raise AssertionError("native generations or cleanup ownership did not drain after close and lease release")
    v8 = transition_program(version=8)
    v8_proof = validate_translation(v8, v8, function="transition")
    if execute_program(v8, "transition", [7, 5])["result"] != 12 or v8_proof["status"] != "unknown":
        raise AssertionError("canonical v8 semantics or proof boundary changed")
    for action in (lambda: _admissible(v8), lambda: propose_guarded_specializations(v8,
            function="transition", assumptions=[{"parameter": "delta", "value": 0}])):
        try:
            action()
        except (MultiversionRejected, HIAProgramRejected):
            pass
        else:
            raise AssertionError("v8 escaped the scalar lifecycle/proposal version boundary")
    if source != {name: _digest(ROOT / name) for name in _BINDINGS} or implementation != _implementation_hash():
        raise AssertionError("source changed during lifecycle qualification")
    for tool in tools.values():
        if digest_executable(tool["path"]) != tool["sha256"]:
            raise AssertionError("compiler identity changed during execution")
    if expected_head is not None and (subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != expected_head
            or subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)):
        raise AssertionError("source commit or clean worktree changed during qualification")
    report = {"schema": "hepta.hia.native-lifecycle-convergence.v1", "ok": True,
        "created_at_utc": datetime.now(timezone.utc).isoformat(), "source_commit": head,
        "source_clean": not status, "expected_head": expected_head, "source_files": source, "tools": tools,
        "protocol_sha256": sha256(_wire(PROTOCOL)).hexdigest(), "commands": commands,
        "native_commands": native_commands,
        "state_transitions": states, "state_snapshot": state_snapshot, "publications": publications,
        "native_generation_probes": probes, "controls": controls, "actual_measurement_policy": measured_policy,
        "selected_before_controls": selected_before, "runtime_after_controls": runtime_after_controls,
        "runtime_after_close": after_close, "v8_proof": v8_proof,
        "denominators": {"state_calls_per_language": len(DELTAS), "c_state_calls": len(DELTAS),
            "rust_state_calls": len(DELTAS), "hia_state_calls": len(DELTAS),
            "retired_lease_calls": 1, "timing_pairs": 31, "timing_calls_per_side": 31 * 50000,
            "timing_total_native_calls": 2 * 31 * 50000,
            "automatic_generation_probe_calls": sum(row["native_probe_calls"] for row in probes),
            "probe_count_note": "All actual completed preparations, including the fresh generation rejected by the forged-artifact control; distinct from state calls and timing calls.",
            "test_methods_inferred": 0},
        "claims": {"one_publication_state_machine": True, "canonical_v8_execution_unchanged": True,
            "native_c_rust_llvm_state_results_compared": True, "performance_improvement_established": False,
            "physical_devices_qualified": False, "heap_or_loan_state_migration": False,
            "production_stage_closed": False},
        "elapsed_ns": time.perf_counter_ns() - started}
    report["retained_files"] = {str(path.relative_to(output)): _digest(path)
                                for path in sorted(output.rglob("*")) if path.is_file()}
    _write(output / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    args = parser.parse_args()
    clang, rustc = shutil.which(args.clang), shutil.which(args.rustc)
    if clang is None or rustc is None:
        raise SystemExit("actual Clang and Rust compilers are required")
    result = run(args.output_directory, clang=clang, rustc=rustc, expected_head=args.expected_head)
    print(json.dumps({"ok": result["ok"], "source_commit": result["source_commit"],
                      "denominators": result["denominators"], "measurement": result["actual_measurement_policy"]}, indent=2))


if __name__ == "__main__":
    main()
