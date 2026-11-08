"""Measure existing explicit machine plans on the actual Selfhost-Core compiler.

This is a native compiler workload qualification, not a model experiment or an
NDU value claim. Every original child request, result, failed plan and produced
byte buffer is retained. It never selects a new ISA feature from a microfixture.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import platform
import resource
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_machine_plan import MACHINE_V3, preservation_checks
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from tools.qualify_hia_selfhost import (CAPACITY, CHILD, INVALID, NO_SPACE, SAMPLE,
    SOURCE, checkout_identity, hash_reference, invalid_sources, invoke, source_manifest)

SCHEMA = "hepta.hia.agent.selfhost-machine-plans.v1"


def digest(raw):
    return sha256(raw).hexdigest()


def put(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_rejected_source(result, case):
    require(result["core_u32"] == INVALID, "invalid source accepted: " + case)
    require(result["output_unchanged"], "invalid source changed output: " + case)


def check_hash_observation(result, output, expected):
    require(result["core_u32"] == expected, "independent byte hash oracle mismatch")
    expected_byte = expected & 255
    require(output == bytes([expected_byte]) + b"\xa5" * (CAPACITY - 1),
            "independent byte hash output effects mismatch")
    header = {str(offset): expected_byte if offset == 0 else 0
              for offset in (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)}
    require(result["workspace_header"] == header,
            "independent byte hash workspace header mismatch")


def identities():
    paths = ("tools/qualify_hia_selfhost_machine_plans.py", "tools/qualify_hia_selfhost.py",
             "tools/hia_selfhost_child.py", "hepta/hia_machine_plan.py",
             "hepta/hia_program_native.py", "hepta/hia_agent_assembly.py",
             "hepta/hia_program.py")
    return {**source_manifest(), **{name: digest((ROOT / name).read_bytes()) for name in paths}}


def usage():
    parent = resource.getrusage(resource.RUSAGE_SELF)
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"parent_cpu_ns": int((parent.ru_utime + parent.ru_stime) * 1e9),
            "children_cpu_ns": int((child.ru_utime + child.ru_stime) * 1e9),
            "parent_highwater_kib": parent.ru_maxrss,
            "children_highwater_kib": child.ru_maxrss}


def compact_plan(checked, *, swapped=False):
    return {"schema": MACHINE_V3, "core_sha256": checked.sha256,
            "block_order": {}, "function_order": [fn["name"] for fn in checked.as_dict()["functions"]],
            "scratch_registers": {"r10": "r11", "r11": "r10"} if swapped else {"r10": "r10", "r11": "r11"},
            "instruction_selection": {"move_immediate": "mov32_if_exact",
                                      "alu_immediate": "imm8_if_exact", "scalar_select": "branch"},
            "function_alignment": 1, "value_registers": {}}


def verify(directory):
    directory = Path(directory).resolve()
    report = json.loads((directory / "RESULT.json").read_text())
    require(report["schema"] == SCHEMA, "unknown campaign schema")
    sealed = json.loads((directory / "SEALED.json").read_text())
    files = {p.relative_to(directory).as_posix(): p for p in directory.rglob("*") if p.is_file()}
    require(not any(p.is_symlink() for p in directory.rglob("*")), "symlink evidence is not accepted")
    require(set(files) - {"SEALED.json"} == set(sealed), "evidence file inventory changed")
    for name, expected in sealed.items():
        raw = files[name].read_bytes()
        require(len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "evidence bytes changed: " + name)
    require(report["source_identity"] == identities(), "qualification source identity changed")
    require(report["status"] == "passed", "qualification did not pass")
    require(report["ndu_incremental_value"] == "NOT_EVALUATED", "native workload cannot establish NDU value")
    return {"schema": SCHEMA, "status": "verified", "evidence_files": len(sealed),
            "native_invocations": len(report["native_invocations"]),
            "scope": "retained finite compiler workload; hashes are not model authorship attestations"}


def run(directory, repetitions=7):
    require(type(repetitions) is int and 3 <= repetitions <= 15, "use 3..15 repetitions")
    directory = Path(directory).resolve()
    require(not directory.is_relative_to(ROOT), "campaign evidence must be outside the source tree")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    started, initial_usage = time.monotonic_ns(), usage()
    report = {"schema": SCHEMA, "status": "started", "source_identity": identities(),
              "checkout": checkout_identity(), "host": {"system": platform.system(), "machine": platform.machine()},
              "python": {"path": str(Path(sys.executable).resolve()), "sha256": digest(Path(sys.executable).read_bytes()),
                         "version": sys.version}, "repetitions": repetitions,
              "phases": [], "attempts": [], "arms": {}, "native_invocations": [],
              "agent_model_calls": 0, "provider_usage": None, "monetary_cost": None,
              "ndu_incremental_value": "NOT_EVALUATED", "general_preservation_proved": False,
              "new_isa_or_register_classes": [],
              "cost_scope": "outer campaign includes setup, all builds, rejected plans, child launches, finite native checks and reporting; nested spans are not added to the outer span"}

    def checkpoint():
        temporary = directory / "RESULT.json.tmp"
        put(temporary, report)
        temporary.replace(directory / "RESULT.json")

    @contextmanager
    def phase(label):
        record = {"label": label, "started_monotonic_ns": time.monotonic_ns(), "status": "started"}
        before = usage()
        report["phases"].append(record)
        checkpoint()
        try:
            yield record
        except BaseException as exc:
            record.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
            raise
        else:
            record["status"] = "completed"
        finally:
            after = usage()
            record.update(finished_monotonic_ns=time.monotonic_ns())
            record["wall_ns"] = record["finished_monotonic_ns"] - record["started_monotonic_ns"]
            record["parent_cpu_ns"] = after["parent_cpu_ns"] - before["parent_cpu_ns"]
            record["children_cpu_ns"] = after["children_cpu_ns"] - before["children_cpu_ns"]
            checkpoint()

    def call(label, image, source, image_format="seed-shared", **kwargs):
        with phase("native/" + label):
            result, output = invoke(directory, label, image, source, image_format=image_format, **kwargs)
        report["native_invocations"].append(result)
        checkpoint()
        require(result.get("status") == "returned", "native child did not return: " + label)
        require(result["abi_status"] == 0, "native ABI status is nonzero: " + label)
        require(result["source_unchanged"] and not result["forbidden_compiler_modules_loaded"], "observer isolation/input changed: " + label)
        return result, output

    try:
        with phase("source_and_core_registration"):
            compiler_source, sample_source = SOURCE.read_bytes(), SAMPLE.read_bytes()
            checked = assemble_program(compiler_source)
            (directory / "compiler.hiaasm").write_bytes(compiler_source)
            (directory / "sample.hiaasm").write_bytes(sample_source)
            (directory / "compiler.core.json").write_bytes(checked.canonical_bytes)
            report["core_sha256"] = checked.sha256
            report["workload"] = {"compiler": {"sha256": digest(compiler_source), "bytes": len(compiler_source)},
                                  "sample": {"sha256": digest(sample_source), "bytes": len(sample_source)},
                                  "origin": "checked-in Selfhost-Core compiler and byte-hash example; actual compiler source workload"}
            plans = {"canonical": None, "compact_immediates": compact_plan(checked),
                     "compact_swapped_scratch": compact_plan(checked, swapped=True)}
            invalid = {}
            for name in ("stale_core", "forbidden_register", "resource_register", "scratch_alias"):
                invalid[name] = deepcopy(plans["compact_immediates"])
            invalid["stale_core"]["core_sha256"] = "0" * 64
            invalid["forbidden_register"]["value_registers"] = {"f0": {"v3": "rax"}}
            invalid["resource_register"]["value_registers"] = {"f0": {"v0": "r12"}}
            invalid["scratch_alias"]["scratch_registers"] = {"r10": "r10", "r11": "r10"}
            put(directory / "PLANS.json", {"valid": plans, "invalid": invalid})
        images = {}
        for name, plan in {**plans, **invalid}.items():
            attempt = {"name": name, "expected": "rejected" if name in invalid else "emitted", "status": "started", "commands": []}
            report["attempts"].append(attempt)
            checkpoint()
            if name in invalid:
                with phase("reject/" + name):
                    try:
                        emit_program_machine(checked, machine_plan=plan, foreign_buffer_exports=(("f0", CAPACITY),))
                    except ValueError as exc:
                        require(str(exc).startswith("E_HIA_MACHINE_PLAN:"), "wrong invalid-plan rejection")
                        attempt.update(status="rejected", error={"type": type(exc).__name__, "message": str(exc)})
                    else:
                        raise ValueError("invalid plan was accepted: " + name)
                continue
            with phase("emit/" + name):
                machine = emit_program_machine(checked, machine_plan=plan, foreign_buffer_exports=(("f0", CAPACITY),))
                (directory / (name + ".o")).write_bytes(machine.object_bytes)
            output = directory / (name + ".so")
            with phase("rederive_link/" + name):
                receipt = compile_program_machine(machine, program=checked, output=output, linker="ld", machine_plan=plan, command_log=attempt["commands"])
            images[name] = output
            attempt["status"] = "emitted"
            report["arms"][name] = {"plan": plan, "text_bytes": len(machine.text_bytes), "object_bytes": len(machine.object_bytes),
                "shared_bytes": output.stat().st_size, "shared_sha256": digest(output.read_bytes()), "receipt": receipt,
                "preservation_checks": [] if plan is None else preservation_checks(plan, checked), "timings_ns": {"compiler": [], "sample": []}}
            checkpoint()
        reference, produced = {}, {}
        names = list(images)
        for repeat in range(repetitions):
            # Deterministic Latin rotation, reversed on alternate rounds: every arm
            # occupies every position before a position is systematically repeated.
            order = names[repeat % len(names):] + names[:repeat % len(names)]
            if repeat % 2:
                order = list(reversed(order))
            for workload, source in (("compiler", compiler_source), ("sample", sample_source)):
                for name in order:
                    label = f"compile-{workload}-r{repeat}-{name}"
                    result, output = call(label, images[name], source)
                    require(0 < result["core_u32"] <= CAPACITY, "source compilation rejected: " + label)
                    result["produced_sha256"] = digest(output[:result["core_u32"]])
                    result["produced_bytes"] = result["core_u32"]
                    expectation = (result["core_u32"], digest(output))
                    require(workload not in reference or reference[workload] == expectation, "compiler output differs across exact plans or repetitions: " + label)
                    reference[workload] = expectation
                    report["arms"][name]["timings_ns"][workload].append(result["native_elapsed_ns"])
                    if repeat == 0:
                        image = directory / f"generated-{workload}-{name}.bin"
                        image.write_bytes(output[:result["core_u32"]])
                        produced[workload, name] = image
                    checkpoint()
        rejected_inputs = invalid_sources(sample_source)
        report["rejected_source_cases"] = ["unknown-opcode", "missing-end", "duplicate-ssa", "edge-type", "mutable-alias", "overflow-u32"]
        for case in report["rejected_source_cases"]:
            expected = None
            for name, image in images.items():
                result, output = call(f"reject-{case}-{name}", image, rejected_inputs[case])
                check_rejected_source(result, case)
                observed = digest(output)
                require(expected is None or expected == observed, "invalid-source effects differ across plans: " + case)
                expected = observed
        for name, image in images.items():
            result, output = call("short-output-" + name, image, sample_source, capacity=8)
            require(result["core_u32"] == NO_SPACE and result["output_unchanged"], "output limit not preserved")
            result, output = call("short-workspace-" + name, image, sample_source, workspace_size=8)
            require(result["core_u32"] == NO_SPACE and result["output_unchanged"], "workspace limit not preserved")
        observations = []
        for name in names:
            for index, value in enumerate((b"", b"\0", b"\xff", bytes(range(256)), bytes(range(256)) * 8)):
                result, output = call(f"independent-hash-{index}-{name}", produced["sample", name], value, "flat-x86-64")
                expected = hash_reference(value)
                check_hash_observation(result, output, expected)
                observations.append({"arm": name, "input_sha256": digest(value), "input_bytes": len(value),
                    "expected": expected, "actual": result["core_u32"], "complete_output_effects_match": True,
                    "workspace_header_match": True,
                    "workspace_scope": "all seventeen retained 8-byte header observations; full workspace tail is not observed"})
        report["independent_hash_observations"] = observations
        for row in report["arms"].values():
            row["median_native_ns"] = {name: statistics.median(values) for name, values in row["timings_ns"].items()}
            row["finite_preservation"] = "exact produced compiler/sample bytes across all plans/repetitions; transactional source rejection and capacity behavior; independent sample return/output oracle and sampled workspace header"
        report["extension_decision"] = "Existing exact compact-immediate and scratch-register choices measured on the real compiler. No new register class, instruction or target is justified by this workload-level observation; no function-level hotspot profile was collected."
        require(report["source_identity"] == identities(), "source identity changed during campaign")
        report["status"] = "passed"
    except BaseException as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
        raise
    finally:
        after = usage()
        report["campaign_cost"] = {"wall_ns": time.monotonic_ns() - started,
            "parent_cpu_ns": after["parent_cpu_ns"] - initial_usage["parent_cpu_ns"],
            "children_cpu_ns": after["children_cpu_ns"] - initial_usage["children_cpu_ns"],
            "parent_highwater_kib": after["parent_highwater_kib"], "children_highwater_kib": after["children_highwater_kib"],
            "excludes": "final inventory serialization; model interaction and economic cost are not measured"}
        checkpoint()
        inventory = {p.relative_to(directory).as_posix(): {"bytes": p.stat().st_size, "sha256": digest(p.read_bytes())}
                     for p in directory.rglob("*") if p.is_file() and p.name != "SEALED.json"}
        put(directory / "SEALED.json", inventory)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=7)
    args = parser.parse_args()
    result = verify(args.output) if args.mode == "verify" else run(args.output, args.repetitions)
    print(json.dumps({key: result[key] for key in ("schema", "status")}, sort_keys=True))


if __name__ == "__main__":
    main()
