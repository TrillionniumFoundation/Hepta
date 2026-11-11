#!/usr/bin/env python3
"""Qualify the exact original select upgrade on an explicit finite domain.

This separately versioned relation is not a new Agent proof claim. It executes
both original compiler versions, retains their raw observations, and composes
the existing copied-fragment proof without extending that proof's scope.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

SCHEMA = "hepta.hia.compiler-extension.finite-domain.v1"
PROFILE = "original-select.exact-sources-and-inputs.v1"
ARCHIVE_SHA256 = "0b18f5665657601141ada5fe67990ee192d91665eb5463f806b495d6240a2d3a"
ARCHIVE_BYTES = 4233093
ORIGINAL_REVISION = "d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6"
SAMPLE_SHA256 = "74bbcc3a6e0ac0962ec32017f4d8c971c91bca0f53c3de7846d65de6194ce4ae"
SAMPLE = ROOT / "tests/fixtures/hia_original_select_v1/bytesum.hiaasm"
INVALID, NO_SPACE = 0xffffffff, 0xfffffffe
OLD_INPUTS = (b"", b"\x00", b"\xff", b"\x00\xff", b"Hepta",
              bytes(range(256)), bytes(reversed(range(256))), b"HIA" * 257)


def digest(data):
    return sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def recover_original_inputs(archive, output):
    """Read only exact pinned members, never extract archive-supplied paths."""
    from tools.qualify_hia_original_select_fragments import HASHES
    require(archive.stat().st_size == ARCHIVE_BYTES, "original archive byte count differs")
    raw = archive.read_bytes()
    require(digest(raw) == ARCHIVE_SHA256, "original archive identity differs")
    found = {}
    with zipfile.ZipFile(BytesIO(raw)) as bundle:
        members = bundle.infolist()
        require(len(members) == 526, "original archive member inventory differs")
        for member in members:
            if member.is_dir() or not 0 < member.file_size <= 1 << 20:
                continue
            data = bundle.read(member)
            actual = digest(data)
            for key, expected in HASHES.items():
                if actual == expected:
                    require(key not in found or found[key] == data, "conflicting original members")
                    found[key] = data
    require(set(found) == set(HASHES), "original compiler inputs are absent from the archive")
    output.mkdir()
    paths = {}
    for name, data in found.items():
        target = output / (name + (".patch" if name == "patch" else ".hiaasm"))
        target.write_bytes(data)
        target.chmod(0o400)
        paths[name] = target
    save(output / "recovery.json", {"archive_sha256": ARCHIVE_SHA256,
        "archive_bytes": ARCHIVE_BYTES, "selected_member_sha256": HASHES,
        "paths_taken_from_archive": False})
    return paths


def select_input(case):
    return (bytes([int(case["condition"])]) + int(case["left"]).to_bytes(8, "little")
            + int(case["right"]).to_bytes(8, "little"))


def bytesum_reference(data):
    result = 5381
    for byte in data:
        result = ((result * 33) ^ byte) & 0xffffffff
    return result


def registered_domain(sample):
    from tools.hia_selfhost_select import select_source, select_cases
    from tools.qualify_hia_original_select_fragments import HASHES, WIDTHS
    require(digest(sample) == SAMPLE_SHA256, "registered old source bytes differ")
    new = []
    for typ, width in WIDTHS.items():
        cases = [case for case in select_cases() if case["type"] == typ]
        inputs = []
        for case in cases:
            expected = int(case["left"] if case["condition"] else case["right"]) & ((1 << width) - 1)
            require(expected == int(case["expected"]), "select oracle differs from integer mathematics")
            inputs.append({"input_hex": select_input(case).hex(), "expected_u64": expected})
        require(inputs, "empty new input domain")
        new.append({"id": typ, "source_sha256": digest(select_source(typ)), "inputs": inputs})
    return {"schema": "hepta.hia.compiler-extension.finite-domain-manifest.v1",
        "profile": PROFILE, "domain_kind": "exact-source-bytes-and-exact-input-bytes",
        "source_program_schema": "hepta.hia.program.v8",
        "historical_source_revision": ORIGINAL_REVISION,
        "historical_declared_support_profile": "selfhost-core-linux-x86_64-v6",
        "historical_support_declaration_is_complete_domain_proof": False,
        "old_sources": [
            {"id": "bytesum", "source_sha256": SAMPLE_SHA256,
             "inputs": [{"input_hex": data.hex(), "expected_u32": bytesum_reference(data)}
                        for data in OLD_INPUTS]},
            {"id": "compiler-c0", "source_sha256": HASHES["original"],
             "inputs": [{"input_sha256": SAMPLE_SHA256,
                         "expected": "exact bytesum image emitted by the original seed"}]}],
        "new_sources": new,
        "old_refusal_controls": [
            {"id": "unknown-opcode", "source_sha256": digest(sample.replace(b"int.mul.wrap", b"int.bad.wrap", 1)),
             "workspace_bytes": 1 << 20, "expected_u32": INVALID},
            {"id": "insufficient-workspace", "source_sha256": SAMPLE_SHA256,
             "workspace_bytes": 0, "expected_u32": NO_SPACE}],
        "observations": ["u32 return", "ABI status", "exact output bytes", "source bytes unchanged"],
        "excluded_quantification": ["other source bytes or runtime inputs", "all of the old grammar",
            "all newly valid select programs", "all workspace/capacity/resource states",
            "general compiler or complete generated-program machine refinement"]}


def native_observation(receipt, actual, *, image_sha256, input_sha256, expected_return, expected_output):
    require(receipt.get("status") == "returned" and receipt.get("abi_status") == 0
            and receipt.get("core_u32") == expected_return
            and receipt.get("source_unchanged") is True
            and receipt.get("forbidden_compiler_modules_loaded") == []
            and receipt.get("artifact_sha256") == image_sha256
            and receipt.get("input_sha256") == input_sha256
            and actual == expected_output
            and receipt.get("output_sha256") == digest(actual),
            "native observation differs from the registered exact obligation")


def equal_emitted_bytes(before, after):
    require(type(before) is bytes and type(after) is bytes and before
            and before == after, "old source output bytes changed")
    return digest(before)


def checker_identity(inventory):
    from hepta.hia_checker_identity import checker_source_identity, checker_native_selection
    selection = checker_native_selection()
    return {"schema": "hepta.hia.compiler-extension.checker-binding.v1",
        "source_inventory_sha256": digest(canonical(inventory)),
        "core_dependency_sha256": digest(canonical(checker_source_identity())),
        "native_selection_sha256": digest(canonical(selection)),
        "native_selection": selection,
        "python_sha256": digest(Path(sys.executable).resolve().read_bytes()),
        "python_version": sys.version,
        "historical_checker_reconstruction": False}


def check_coverage(domain, old_rows, new_rows, controls):
    require([row["id"] for row in old_rows] == [row["id"] for row in domain["old_sources"]]
            and [row["source_sha256"] for row in old_rows]
                == [row["source_sha256"] for row in domain["old_sources"]],
            "old-domain coverage is incomplete or substituted")
    for observed, registered in zip(old_rows, domain["old_sources"]):
        expected_inputs = [item.get("input_sha256") or digest(bytes.fromhex(item["input_hex"]))
                           for item in registered["inputs"]]
        expected = sorted((version, identity) for identity in expected_inputs
                          for version in ("before", "after"))
        actual = sorted((item["version"], item["input_sha256"]) for item in observed["observations"])
        require(actual == expected and observed["exact_emitted_bytes_equal"] is True,
                "old-domain runtime observations are incomplete or duplicated")
    require([row["type"] for row in new_rows] == [row["id"] for row in domain["new_sources"]]
            and [row["source_binding"]["source_sha256"] for row in new_rows]
                == [row["source_sha256"] for row in domain["new_sources"]],
            "new-domain coverage is incomplete or substituted")
    for observed, registered in zip(new_rows, domain["new_sources"]):
        require(observed["whole_generated_program_finite_calls"] == len(registered["inputs"])
                and observed["status"] == "smt_validated"
                and observed["agent_proof_receipt_issued"] is False,
                "new-domain observations or local fragment obligations are incomplete")
    require([row["id"] for row in controls] == [row["id"] for row in domain["old_refusal_controls"]],
            "registered refusal controls are incomplete")


def process_group_members(group):
    """Linux qualification ownership only; never inspect another session's group."""
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text(errors="replace").rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and int(fields[3]) == group:
                members.append({"pid": int(entry.name), "state": fields[0]})
        except (OSError, ValueError, IndexError):
            continue
    return members


def terminate_owned_group(group):
    """Bound cleanup to the session created by this qualifier's outer process."""
    started = time.monotonic()
    signals = []
    for signum in (signal.SIGTERM, signal.SIGKILL):
        live = [row for row in process_group_members(group) if row["state"] not in {"Z", "X"}]
        if not live:
            break
        try:
            os.killpg(group, signum)
            signals.append(int(signum))
        except ProcessLookupError:
            break
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if not any(row["state"] not in {"Z", "X"} for row in process_group_members(group)):
                break
            time.sleep(0.02)
    members = process_group_members(group)
    return {"process_group": group, "signals": signals,
        "remaining_live_pids": [row["pid"] for row in members if row["state"] not in {"Z", "X"}],
        "zombie_pids": [row["pid"] for row in members if row["state"] in {"Z", "X"}],
        "elapsed_seconds": time.monotonic() - started, "grace_budget_seconds": 2.0}


def run_retained(command, directory, label, timeout, *, env=None, allow_failure=False,
                 own_process_group=False):
    # Only the outer invocation creates a session. All nested qualification,
    # compiler, solver and replay children inherit it, so the outer owner can
    # terminate the complete job even if an intermediate process has exited.
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=own_process_group)
    status, termination = "completed", None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        if own_process_group:
            termination = terminate_owned_group(process.pid)
        else:
            # The outer owner reaps the entire inherited group when this worker
            # exits with failure. Do not create an unowned nested session.
            try:
                process.kill()
            except ProcessLookupError:
                pass
            termination = {"direct_child_killed": process.pid,
                           "descendant_cleanup_owner": "outer qualifier process group"}
        try:
            stdout, stderr = process.communicate(timeout=1.0)
        except subprocess.TimeoutExpired as tail:
            stdout, stderr = tail.stdout or stdout, tail.stderr or stderr
            for stream in (process.stdout, process.stderr):
                stream.close()
            termination["pipe_drain_timed_out"] = True
    if own_process_group and status == "completed":
        live = [row for row in process_group_members(process.pid) if row["state"] not in {"Z", "X"}]
        if live:
            termination = terminate_owned_group(process.pid)
            status = "unexpected_descendants_terminated"
    (directory / (label + ".stdout.log")).write_bytes(stdout)
    (directory / (label + ".stderr.log")).write_bytes(stderr)
    record = {"command": command, "status": status, "timeout_seconds": timeout,
        "returncode": process.returncode, "owned_process_group": process.pid if own_process_group else None,
        "termination": termination}
    save(directory / (label + ".process.json"), record)
    require(status == "completed", label + " timed out or left descendants; original output and termination are retained")
    require(allow_failure or process.returncode == 0,
            label + " failed; original process output is retained")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

def worker(args, output):
    prefix = output / "empty-bytecode-cache"
    require(sys.dont_write_bytecode and sys.pycache_prefix is not None
            and Path(sys.pycache_prefix).resolve() == prefix.resolve()
            and not list(prefix.rglob("*")), "fresh source-only qualification imports required")
    from tools.qualify_hia_original_select_fragments import HASHES, freeze_inputs, source_inventory
    from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke, checkout_identity
    from tools.hia_selfhost_select import select_source

    started = time.monotonic()
    inventory = source_inventory()
    save(output / "source-before.json", inventory)
    before_checker = checker_identity(inventory)
    paths = (recover_original_inputs(args.historical_archive.resolve(), output / "archive-inputs")
             if args.historical_archive is not None
             else {name: getattr(args, name).resolve() for name in HASHES})
    frozen = freeze_inputs(paths, output)
    sample = SAMPLE.read_bytes()
    domain = registered_domain(sample)
    save(output / "domain.json", domain)
    # This registry is fixed before any compiler outcome is observed.
    domain_sha256 = digest((output / "domain.json").read_bytes())
    before_dir = output / "before-compiler"
    before_dir.mkdir()
    before_seed, before_seed_receipt = build_seed(before_dir, frozen["original"])

    new_output = output / "new-domain"
    command = [sys.executable, "-B", str(ROOT / "tools/qualify_hia_original_select_fragments.py"),
               "--output", str(new_output), "--linker", args.linker]
    for name in HASHES:
        suffix = ".patch" if name == "patch" else ".hiaasm"
        command.extend(["--" + name, str(output / "frozen-inputs" / (name + suffix))])
    run_retained(command, output, "new-domain-qualification", 300)
    new_report = json.loads((new_output / "qualification.json").read_bytes())
    require(new_report["status"] == "PASS_SCOPED_COPIED_FRAGMENTS"
            and new_report["exact_frozen_input_sha256"] == HASHES
            and new_report["original_agent_four_claim_gate"] == "HOLD"
            and new_report["whole_compiler_or_original_agent_delta_proved"] is False,
            "copied-fragment result changed its scope or subjects")
    require(json.loads((new_output / "source-before.json").read_bytes()) == inventory,
            "new-domain checker/producer source differs from the old-domain runner")
    after_seed = new_output / "frozen-c1-seed/B0.so"
    after_seed_receipt = new_report["seed_receipt"]
    require(digest(after_seed.read_bytes()) == new_report["candidate_seed_image_sha256"]
            and after_seed_receipt["source_sha256"] == HASHES["candidate"],
            "candidate compiler image is not bound to the original frozen C1")
    seeds = {"before": before_seed, "after": after_seed}
    old_output = output / "old-domain"
    old_output.mkdir()
    old_rows, compiled = [], {}
    for name, source in (("bytesum", sample), ("compiler-c0", frozen["original"])):
        directory = old_output / name
        directory.mkdir()
        pair = {}
        for version, seed in seeds.items():
            image, receipt = compile_stage(directory, version, seed, source, image_format="seed-shared")
            pair[version] = (image, receipt)
        identity = equal_emitted_bytes(pair["before"][0].read_bytes(), pair["after"][0].read_bytes())
        compiled[name] = pair
        old_rows.append({"id": name, "source_sha256": digest(source), "emitted_image_sha256": identity,
            "exact_emitted_bytes_equal": True, "compiler_invocations": {
                version: receipt for version, (_, receipt) in pair.items()}, "observations": []})
    for index, data in enumerate(OLD_INPUTS):
        expected = bytesum_reference(data)
        for version, (image, _) in compiled["bytesum"].items():
            receipt, actual = invoke(old_output / "bytesum", version + "-input-" + str(index),
                                     image, data, capacity=1, workspace_size=1)
            native_observation(receipt, actual, image_sha256=digest(image.read_bytes()),
                input_sha256=digest(data), expected_return=expected,
                expected_output=bytes([expected & 255]))
            old_rows[0]["observations"].append({"version": version, "input_sha256": digest(data),
                "expected_u32": expected, "receipt": receipt})
    expected_bytesum = compiled["bytesum"]["before"][0].read_bytes()
    for version, (image, _) in compiled["compiler-c0"].items():
        generated, receipt = compile_stage(old_output / "compiler-c0", version + "-compile-bytesum",
                                           image, sample)
        require(generated.read_bytes() == expected_bytesum,
                "old compiler image does not reproduce its registered bytesum output")
        old_rows[1]["observations"].append({"version": version, "input_sha256": SAMPLE_SHA256,
            "emitted_image_sha256": digest(generated.read_bytes()), "receipt": receipt})

    controls = []
    control_dir = output / "refusal-controls"
    control_dir.mkdir()
    for registered in domain["old_refusal_controls"]:
        source = (sample.replace(b"int.mul.wrap", b"int.bad.wrap", 1)
                  if registered["id"] == "unknown-opcode" else sample)
        require(digest(source) == registered["source_sha256"], "refusal source differs")
        rows = []
        for version, seed in seeds.items():
            receipt, actual = invoke(control_dir, registered["id"] + "-" + version, seed, source,
                image_format="seed-shared", workspace_size=registered["workspace_bytes"])
            native_observation(receipt, actual, image_sha256=digest(seed.read_bytes()),
                input_sha256=digest(source), expected_return=registered["expected_u32"],
                expected_output=b"\xa5" * (1 << 20))
            rows.append({"version": version, "receipt": receipt})
        controls.append({"id": registered["id"], "observations": rows})
    admission_delta = []
    for registered in domain["new_sources"]:
        source = select_source(registered["id"])
        receipt, actual = invoke(control_dir, "c0-rejects-" + registered["id"], before_seed, source,
                                 image_format="seed-shared")
        native_observation(receipt, actual, image_sha256=digest(before_seed.read_bytes()),
            input_sha256=registered["source_sha256"], expected_return=INVALID,
            expected_output=b"\xa5" * (1 << 20))
        admission_delta.append({"id": registered["id"], "old_compiler": receipt,
                                "new_compiler": "new-domain/" + registered["id"] + "/result.json"})

    check_coverage(domain, old_rows, new_report["cases"], controls)
    fragment_manifest_sha256 = digest((new_output / "artifact-manifest.json").read_bytes())
    replay_dir = output / "fragment-replay"
    run_retained([sys.executable, "-B", str(ROOT / "tools/replay_hia_original_select_fragments.py"),
        "--input", str(new_output), "--expected-manifest-sha256", fragment_manifest_sha256,
        "--output", str(replay_dir)], output, "fragment-replay", 180)
    after_checker = checker_identity(source_inventory())
    require(before_checker == after_checker and source_inventory() == inventory,
            "checker implementation or selected native owner drifted")
    require(digest((output / "domain.json").read_bytes()) == domain_sha256,
            "registered source/input domain changed after execution began")
    for row in new_report["cases"]:
        validation = json.loads((new_output / row["type"] / "validation.json").read_bytes())
        require(validation["checker"]["native_selection"] == before_checker["native_selection"],
                "fragment checker selected different native owners")
    report = {"schema": SCHEMA, "status": "PASS_REGISTERED_FINITE_UPGRADE_DOMAIN",
        "profile": PROFILE, "property": "exact old-source output preservation and registered new-source observations",
        "domain_sha256": domain_sha256, "original_task_id": "selfhost-scalar-select-d1c97d22-20261108",
        "compiler_before": {"source_sha256": HASHES["original"],
            "image_sha256": digest(before_seed.read_bytes()), "seed_receipt": before_seed_receipt,
            "checker": before_checker},
        "compiler_after": {"source_sha256": HASHES["candidate"],
            "image_sha256": digest(after_seed.read_bytes()), "seed_receipt": after_seed_receipt,
            "checker": after_checker},
        "patch_sha256": HASHES["patch"], "patch_reconstruction_exact": True,
        "old_domain_results": old_rows, "new_domain_results": new_report["cases"],
        "refusal_controls": controls, "admission_delta": admission_delta,
        "copied_fragment_manifest_sha256": fragment_manifest_sha256,
        "copied_fragment_replay_directory": "fragment-replay",
        "counts": {"old_source_images_compared": len(old_rows),
            "old_native_runtime_observations": sum(len(row["observations"]) for row in old_rows),
            "old_refusal_observations": 2 * len(controls),
            "new_source_admission_deltas": len(admission_delta),
            "new_whole_program_finite_observations": sum(len(row["inputs"]) for row in domain["new_sources"]),
            "projected_fragment_native_observations": new_report["counts"]["native_calls"],
            "distinct_local_fragment_smt_obligations": new_report["counts"]["smt_obligations"]},
        "proof_boundary": {"finite_hardware_observations_are_formal_proofs": False,
            "local_fragment_proof_establishes_its_original_context": False,
            "whole_language_refinement_proved": False,
            "historical_original_checker_identified": False},
        "original_agent_four_claim_gate": "HOLD", "agent_proof_receipt_issued": False,
        "evaluation_performed": False, "adoption_authorized": False,
        "unproved_obligations": domain["excluded_quantification"] + [
            "historical checker implementation identity", "original strict Agent acceptance",
            "original provider transcript and complete costs"],
        "assumptions": ["the recorded native compiler seeds faithfully execute their frozen Core sources",
            "the existing Python/Core/ELF/ISA/solver assumptions of each local proof remain",
            "the host kernel, loader and isolated observation processes execute the recorded bytes"],
        "source_checkout": checkout_identity(), "elapsed_seconds": time.monotonic() - started}
    save(output / "worker-qualification.json", report)
    print(json.dumps({"status": report["status"], "counts": report["counts"],
        "original_agent_four_claim_gate": "HOLD", "domain_sha256": domain_sha256}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("original", "candidate", "patch"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--historical-archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    direct = [getattr(args, name) is not None for name in ("original", "candidate", "patch")]
    require((args.historical_archive is not None and not any(direct))
            or (args.historical_archive is None and all(direct)),
            "supply either the exact historical archive or all three original files")
    linker = shutil.which(args.linker)
    require(linker is not None, "linker is unavailable")
    args.linker = linker
    output = args.output.resolve()
    if args.worker:
        worker(args, output)
        return
    output.mkdir(parents=True, exist_ok=False)
    prefix = output / "empty-bytecode-cache"
    prefix.mkdir()
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--output", str(output),
               "--linker", linker]
    for name in ("original", "candidate", "patch", "historical_archive"):
        value = getattr(args, name)
        if value is not None:
            command.extend(["--" + name.replace("_", "-"), str(value.resolve())])
    try:
        process = run_retained(command, output, "worker", 600, allow_failure=True, own_process_group=True,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(prefix)))
        if process.returncode == 0:
            report = json.loads((output / "worker-qualification.json").read_bytes())
            report["process_owner"] = json.loads((output / "worker.process.json").read_bytes())
            save(output / "qualification.json", report)
    finally:
        save(output / "artifact-manifest.json", {path.relative_to(output).as_posix(): digest(path.read_bytes())
            for path in sorted(output.rglob("*")) if path.is_file() and path != output / "artifact-manifest.json"})
    print(process.stdout.decode(errors="replace"), end="")
    if process.returncode:
        print(process.stderr.decode(errors="replace"), end="", file=sys.stderr)
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
