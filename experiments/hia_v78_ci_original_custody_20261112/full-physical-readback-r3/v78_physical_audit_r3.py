"""Independently read existing v78 CI originals; never import or execute Hepta.

Fresh second read of the same official artifact after the previous executor was
lost. The immutable prior reader is used only as a byte/protocol audit library.
No historical overwritten-invocation allowance is inherited.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import time
import traceback
import zipfile

ARTIFACT = {
    "id": 13924594909, "run_id": 43178231433, "run_attempt": 1,
    "bytes": 67366366,
    "sha256": "c34df97917ae2eaf81385372b8771e8e0613274a5e4ed38239e106b284e2a23b",
    "checkout_commit": "d0e110e19f9433baaf202a0f605671c7205b4cff",
    "checkout_tree": "6381daf9beb11d873d4608c26facc0b9e5bc747f",
    "outer_files": 1736, "outer_unpacked_bytes": 334871730,
}
HELPER_PIN = (50236, "20428057a9c415b636759ff099bab7c612f8f41b9895eb35b4de157d950a906b")
PINS = {
    "hia-cold.json": (95281, "81933b63a27a7404baa7aaaf693613c8f62f3d3deaa44649c3abda93c05c23a6"),
    "hia-cold.cold/qualification.json": (53342479, "3e52a5751cc6c197d4572e05487e784d9d323fa891e7297ee53983f451140ec7"),
    "hia-cold.cold/qualification.evidence/phase-index.json": (18364, "63e585ad2f3f87cf854ecbf6f2685e44d73e4036d7160faaa3d344ff9946b367"),
}
SOURCE_PINS = {
    "tools/hia_selfhost_names.py": "991c77ce3981eadee219b4b64f2c4345019827051de8d45412b0ebfb31e4a942",
    "tests/test_hia_selfhost_names.py": "8a87379e153321a088b8f8c62364af2e72c823077f808a1f0d91d5336b52362a",
    "tools/qualify_hia_selfhost.py": "a1c76c165856927bfbaded5610568fa79456f15e1eb356dda7a8b882bb602c92",
    "tools/hia_evidence_archive.py": "f76cdeebb7dd7b4f4c49442e6c56631d9c99372715bd583b5df00952e80f1ebe",
    "tools/replay_hia_selfhost_cold.py": "732e93ce69fc997e9d9cb11aed89d015045f0a2f06c1962ea1134cc9359da38b",
}
SOURCE_MAP_SHA = "981e9df285f49879021a99d182746b45752d38e94cac89a91ef998dfbf561154"
FAMILIES = ("capacity", "cfg", "elf", "chain", "owned", "bulk", "loan", "resource",
            "tail", "select", "effects", "multi", "keyword", "signed", "scalar-casts",
            "explicit-traps", "cli", "names", "exports")
LABELS = ("original", "modified")
FIELDS = {
    "capacity": "expanded_capacity_observations", "cfg": "cfg_worklist_observations",
    "elf": "elf_object_observations", "owned": "owned_elf_observations",
    "bulk": "bulk_observations", "loan": "loan_observations", "resource": "resource_observations",
    "tail": "tail_call_observations", "select": "select_observations",
    "effects": "effect_observations", "multi": "multi_result_observations",
    "keyword": "keyword_observations", "signed": "signed_observations",
    "scalar-casts": "scalar_cast_observations", "explicit-traps": "explicit_trap_observations",
    "cli": "executable_cli_observations", "names": "function_name_observations",
    "exports": "explicit_export_observations",
}
REFERENCE_FIELDS = {
    "capacity": "independent_capacity_reference", "cfg": "independent_cfg_worklist_reference",
    "bulk": "independent_bulk_reference", "loan": "independent_loan_reference",
    "resource": "independent_resource_reference", "tail": "independent_tail_reference",
    "select": "independent_select_reference", "effects": "independent_effect_reference",
    "multi": "independent_multi_result_reference", "keyword": "independent_keyword_reference",
    "signed": "independent_signed_reference", "scalar-casts": "independent_scalar_cast_reference",
    "explicit-traps": "independent_explicit_trap_reference",
    "cli": "independent_executable_cli_reference", "names": "independent_function_name_reference",
    "exports": "independent_explicit_export_reference", "core": "independent_core_reference",
}
CHUNK = 1024 * 1024
TEMP = "/home/runner/work/_temp/"
EVIDENCE = "hia-cold.cold/qualification.evidence/"
SOURCE = "hia-cold.cold/source/"
PROFILE = "selfhost-core-linux-x86_64-v78-native-core-emitter-json-pretty-custody-development"
CONTRACT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"


def load_helper():
    path = Path(__file__).with_name("original_970_reader_r3.py")
    raw = path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != HELPER_PIN:
        raise ValueError("immutable audit helper bytes differ")
    spec = importlib.util.spec_from_file_location("v78_original_byte_audit_helper", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper, path, raw


def literal_assignment(raw, name):
    tree = ast.parse(raw)
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
    if len(rows) != 1:
        raise ValueError("fixed source literal not unique: " + name)
    return ast.literal_eval(rows[0])


def max_overlap(rows, start, end):
    events = []
    for row in rows:
        if not (type(row[start]) is int and type(row[end]) is int and row[start] <= row[end]):
            raise ValueError("invalid original timing interval")
        events.extend(((row[start], 1), (row[end], -1)))
    count = maximum = 0
    for _, delta in sorted(events):
        count += delta
        maximum = max(maximum, count)
    if count != 0:
        raise ValueError("unclosed timing intervals")
    return maximum


def owner_join(h, a, cold, get):
    raw = get("hia-cold.cold/process-owner.json")
    owner = h.document(raw)
    request_raw = get("hia-cold.cold/process-owner.json.request.json")
    request = h.document(request_raw)
    returned = cold["process_owner"]
    a.check(set(returned) == set(owner) | {"receipt_sha256", "supervisor_returncode"}
            and returned["receipt_sha256"] == h.digest(raw)
            and returned["supervisor_returncode"] == 0
            and {k: v for k, v in returned.items()
                 if k not in ("receipt_sha256", "supervisor_returncode")} == owner,
            "raw lifecycle and returned owner projection differ")
    a.check(owner["schema"] == request["schema"] == "hepta.hia.selfhost-process-owner.v1"
            and owner["implementation_sha256"] == request["implementation_sha256"] == h.OWNER_SHA
            and owner["request_sha256"] == h.digest(request_raw)
            and owner["qualification_seconds"] == request["qualification_seconds"] == 180
            and owner["cleanup_seconds"] == request["cleanup_seconds"] == 3,
            "original owner identity or budgets differ")
    a.check(owner["status"] == "OWNED_PROCESS_COMPLETED" and owner["returncode"] == 0
            and owner["timed_out"] is False and owner["exit_observed_before_deadline"] is True
            and owner["qualification_started"] is True and owner["subreaper_enabled"] is True
            and owner["event_overflow"] is False and owner["interrupted_signals"] == [],
            "original owner is not natural success")
    cleanup = owner["cleanup"]
    a.check(cleanup["attempted"] is True and cleanup["complete"] is True
            and cleanup["observed_echild"] is True and cleanup["leader_reaped"] is True
            and cleanup["remaining_direct_children"] == [] and cleanup["errors"] == []
            and cleanup["deadline_exceeded"] is False
            and 0 <= cleanup["elapsed_ns"] < 3_000_000_000,
            "original cleanup not complete natural ECHILD")
    events = owner["events"]
    a.check([e["kind"] for e in events] == [
        "qualification_started", "owned_child_observed", "qualification_exit_observed", "owned_child_reaped"],
        "owner lifecycle has extra/kill/overflow events")
    a.check(all(e["pid"] == owner["qualification_pid"] for e in events)
            and events[2]["si_status"] == events[3]["returncode"] == 0
            and events[0]["monotonic_ns"] <= events[2]["monotonic_ns"] <= request["deadline_ns"]
            and request["deadline_ns"] - request["started_ns"] == 180_000_000_000
            and events[3]["monotonic_ns"] >= events[2]["monotonic_ns"],
            "owner event identity or time order differs")
    a.check(request["command"][1:] == ["-I", "-S", "-B", TEMP + SOURCE + "tools/qualify_hia_selfhost.py",
             "--output", TEMP + "hia-cold.cold/qualification.json"]
            and request["cwd"] == TEMP + "hia-cold.cold/home"
            and request["receipt_path"] == TEMP + "hia-cold.cold/process-owner.json"
            and request["stdout_path"] == TEMP + "hia-cold.cold/stdout.log"
            and request["stderr_path"] == TEMP + "hia-cold.cold/stderr.log",
            "original owner command or paths differ")
    return {"raw_receipt_sha256": h.digest(raw), "raw_request_sha256": h.digest(request_raw),
            "qualification_seconds": 180, "cleanup_seconds": 3,
            "natural_event_kinds": [e["kind"] for e in events], "observed_echild": True,
            "historical_descendant_inventory_complete": owner["historical_descendant_inventory_complete"],
            "actual_command": request["command"], "qualification_pid": owner["qualification_pid"],
            "qualification_ns": events[2]["monotonic_ns"] - events[0]["monotonic_ns"],
            "raw_wrapper_projection_exact": True}, request


def names_custody(h, a, outer, infos, phase, ref):
    label = phase["compiler_label"]
    desc = phase["archive"]
    archive_name = desc["archive"][len(TEMP):]
    _, packed = h.read_member(outer, infos[archive_name], 128 * CHUNK, capture=True)
    with zipfile.ZipFile(io.BytesIO(packed)) as z:
        manifest = h.document(z.read(h.PHASE_MANIFEST))
        files = manifest["files"]
        def get(name):
            return h.read_member(z, z.getinfo(name), 16 * CHUNK, capture=True)[1]
        cases = ref["cases"]
        a.check(len(cases) == 106 and len({r["id"] for r in cases}) == 106
                and len({r["program"] for r in cases}) == 52, "names reference denominator differs")
        programs = {}
        for row in cases:
            programs.setdefault(row["program"], row)
        stems = {label + "-" + p + "-flat-build" for p in programs}
        object_stems = {label + "-" + p + "-object" for p in programs}
        auxiliary = {label + "-" + s for s in ("alpha-R1", "alpha-R2", "alpha-E1", "module-R1", "module-R2")}
        expected_compiles = stems | object_stems | auxiliary
        actual_compiles = {}
        for name in files:
            if not name.endswith(".receipt.json"):
                continue
            value = h.document(get(name))
            if "produced_image" in value:
                a.check(value["case"] not in actual_compiles, "duplicate names compilation case")
                actual_compiles[value["case"]] = value
        a.check(len(expected_compiles) == 109 and set(actual_compiles) == expected_compiles,
                "names full 109 compilation inventory differs")
        run_stems = {label + "-" + row["id"] + "-" + kind for row in cases for kind in ("flat", "elf")}
        a.check(len(run_stems) == 212 and not expected_compiles & run_stems,
                "compile and runtime label sets collide")
        companion_suffixes = (".request.json", ".input.bin", ".output.bin", ".receipt.json",
                              ".stdout.log", ".stderr.log")
        companions = {stem + suffix for stem in expected_compiles for suffix in companion_suffixes}
        a.check(len(companions) == 654 and companions <= files.keys(),
                "full compile companion inventory missing")
        physical_rows = []
        for program, row in programs.items():
            compile_stem = label + "-" + program + "-flat-build"
            build = actual_compiles[compile_stem]
            source = row["source"].encode()
            a.check(get(compile_stem + ".input.bin") == source
                    and build["input_sha256"] == h.digest(source)
                    and build["produced_image"] == desc["archive"][:-4] + "/" + compile_stem + ".image.bin",
                    "names compiled source/image path differs")
        for row in cases:
            for kind in ("flat", "elf"):
                stem = label + "-" + row["id"] + "-" + kind
                receipt = h.document(get(stem + ".receipt.json"))
                request = h.document(get(stem + ".request.json"))
                a.check(receipt["case"] == stem and receipt["status"] == "returned"
                        and receipt["abi_status"] == 0 and receipt["core_u32"] == row["expected_result"]
                        and receipt["source_unchanged"] is True
                        and get(stem + ".input.bin") == bytes.fromhex(row["source_hex"])
                        and get(stem + ".output.bin") == bytes.fromhex(row["expected_hex"])
                        and request["capacity"] == len(bytes.fromhex(row["initial_hex"]))
                        and request["workspace_size"] == 0
                        and request["output_initial_sha256"] == h.digest(bytes.fromhex(row["initial_hex"])),
                        "names actual runtime full bytes differ from fixed VM reference")
                if kind == "flat":
                    build = actual_compiles[label + "-" + row["program"] + "-flat-build"]
                    a.check(request["image"] == build["produced_image"]
                            and request["image_sha256"] == build["produced_sha256"],
                            "names runtime does not use separately retained compiled image")
        collisions = sorted(set(programs) & {r["id"] for r in cases})
        a.check(len(collisions) == 23, "prior names collision class denominator differs")
        for program in collisions:
            compile_stem = label + "-" + program + "-flat-build"
            runtime_stem = label + "-" + program + "-flat"
            a.check(compile_stem != runtime_stem
                    and all(compile_stem + s in files and runtime_stem + s in files for s in companion_suffixes),
                    "formerly colliding pair does not retain both complete companion sets")
            physical_rows.append({"program": program, "compile_stem": compile_stem, "runtime_stem": runtime_stem,
                "compile": {s: files[compile_stem + s] for s in companion_suffixes},
                "runtime": {s: files[runtime_stem + s] for s in companion_suffixes}})
        return {"compiler_label": label, "reference_cases": 106, "unique_programs": 52,
            "compilation_receipts": 109, "runtime_receipts": 212, "compile_companions": 654,
            "formerly_colliding_programs": 23, "all_separate_companions_present": True,
            "all_runtime_full_input_output_bytes_equal_fixed_reference": True, "pairs": physical_rows,
            "historical_970_originals_recovered": False}


def run(args):
    h, helper_path, helper_raw = load_helper()
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    a = h.Audit(output, expected_history_gaps={})
    started = time.monotonic_ns()
    own_raw = Path(__file__).read_bytes()
    report = {"schema": "hepta.hia.v78-independent-cold-original-physical-audit.v1",
        "status": "PHYSICAL_READBACK_HOLD", "errors": [], "artifact": ARTIFACT,
        "read_event": "NEW_SECOND_READ_OF_SAME_OFFICIAL_ZIP_AFTER_EXECUTOR_LOSS",
        "prior_unpublished_local_derived_report_recovered": False,
        "product_executed": False, "project_imported": False, "prior_product_outcomes_reclassified": False,
        "overall_v78_CI_status": "FAIL_FROM_SEPARATE_RESOURCE_EXPECTATIONS",
        "full_retained_5400_qualification_executed_by_this_audit": False,
        "old_970_46_history_gaps_whitelisted": False,
        "original_artifact_path": str(Path(args.archive).absolute()),
        "helper_sha256": HELPER_PIN[1], "reader_sha256": h.digest(own_raw)}
    try:
        with h.ordinary(args.archive, ARTIFACT["bytes"]) as (stream, before):
            actual_before = h.hash_stream(stream, before.st_size)
            a.equal_record(actual_before, ARTIFACT["bytes"], ARTIFACT["sha256"], "official original ZIP")
            report["input_identity_before"] = h.identity(before)
            report["original_before"] = actual_before
            with zipfile.ZipFile(stream) as outer:
                directory, infos, total = h.catalog(outer, before.st_size, 2000, 384 * CHUNK)
                a.check(len(infos) == ARTIFACT["outer_files"] and total == ARTIFACT["outer_unpacked_bytes"]
                        and all(not info.is_dir() for info in infos.values()), "fixed complete outer inventory differs")
                for name in sorted(infos):
                    record, _ = h.read_member(outer, infos[name])
                    a.outer_records[name] = record
                h.put(output / "outer-directory-readback.json", h.wire(
                    {"entries": directory, "records": a.outer_records, "all_complete_CRC_SHA256": True}))
                def get(name):
                    if name.startswith(TEMP):
                        name = name[len(TEMP):]
                    elif name.startswith(h.ORIGINAL_SOURCE):
                        name = SOURCE + name[len(h.ORIGINAL_SOURCE):]
                    return h.read_member(outer, infos[name], 64 * CHUNK, capture=True)[1]
                for name, pin in PINS.items():
                    a.equal_record(a.outer_records[name], *pin, name)
                cold = h.document(get("hia-cold.json"))
                q = h.document(get("hia-cold.cold/qualification.json"))
                index = h.document(get(EVIDENCE + "phase-index.json"))
                request = h.document(get("hia-cold.cold/request.json"))
                a.check(cold["schema"] == "hepta.hia.selfhost-cold-replay.v1"
                        and cold["status"] == "COLD_SELFHOST_REPLAY_PASS" and cold["returncode"] == 0
                        and len(cold["checks"]) == 11 and all(v is True for v in cold["checks"].values())
                        and cold["qualification_wall_limit_seconds"] == 180
                        and cold["cleanup_wall_limit_seconds"] == 3
                        and 0 < cold["wall_elapsed_ns"] == 91985578220 < 180_000_000_000,
                        "original cold status, checks or budget differs")
                a.check(q["schema"] == "hepta.hia.selfhost-qualification.v6"
                        and q["status"] == "SELF_HOSTED_FIXED_CORE_PASS" and len(q["checks"]) == 5051
                        and all(v is True for v in q["checks"].values())
                        and q["profile"] == cold["profile"] == PROFILE
                        and cold["nested_report"] == TEMP + "hia-cold.cold/qualification.json"
                        and cold["nested_report_sha256"] == PINS["hia-cold.cold/qualification.json"][1]
                        and q["checkout"] == {"identity_authority": "source_manifest", "kind": "source_export"},
                        "nested full original report differs")
                source_map = q["source_manifest"]
                a.check(len(source_map) == 798 and source_map == cold["source_manifest"] == request["source_manifest"]
                        and h.semantic_digest(source_map) == SOURCE_MAP_SHA,
                        "three original source maps differ")
                a.check({n[len(SOURCE):] for n in infos if n.startswith(SOURCE)} == set(source_map),
                        "physical source-only export inventory differs")
                source_rows = []
                for name, sha in sorted(source_map.items()):
                    a.check(a.outer_records[SOURCE + name]["sha256"] == sha, "cold copied source SHA differs: " + name)
                    with h.ordinary(Path(args.source) / name, a.outer_records[SOURCE + name]["bytes"]) as (s, st):
                        actual = h.hash_stream(s, st.st_size)
                    a.check(actual["sha256"] == sha and actual["bytes"] == a.outer_records[SOURCE + name]["bytes"],
                            "same-content current exact-v78 source differs: " + name)
                    source_rows.append({"path": name, **actual})
                for name, sha in SOURCE_PINS.items():
                    a.check(source_map[name] == sha, "fixed producer byte pin differs: " + name)
                contract = h.document(get(SOURCE + CONTRACT))
                a.check({**contract["source_identity"]["files"], CONTRACT: h.digest(get(SOURCE + CONTRACT))} == source_map
                        and contract["profile"] == PROFILE
                        and q["support_contract"] == {"path": CONTRACT, "sha256": source_map[CONTRACT]},
                        "original support contract is not exact complete source map")
                report["source"] = {"files": 798, "manifest_sha256": SOURCE_MAP_SHA,
                    "all_original_export_files_physically_read": True,
                    "independent_same_content_v78_copy_checked": True,
                    "original_checkout_inode_not_claimed": True, "support_contract_sha256": source_map[CONTRACT],
                    "producer_pins": SOURCE_PINS}
                h.put(output / "source-physical-joins.json", h.wire(source_rows))
                owner, owner_request = owner_join(h, a, cold, get)
                report["owner"] = owner
                a.check(request["schema"] == "hepta.hia.selfhost-cold-request.v1"
                        and request["command"] == owner_request["command"]
                        and request["source_root"] == TEMP + SOURCE[:-1]
                        and request["new_home"] == owner_request["cwd"]
                        and request["environment_keys"] == sorted(owner_request["env"])
                        and request["preexisting_generated_artifacts"] == [], "cold original request wiring differs")
                a.check(q["seed"]["python"]["isolated"] is True and q["seed"]["python"]["no_site"] is True,
                        "seed did not report original isolated no-site entry")
                b0 = h.document(get(EVIDENCE + "B0.receipt.json"))
                a.check(q["seed"] == b0 and b0["schema"] == "hepta.hia.program.direct-native.v1"
                        and b0["seed_only"] is True and cold["seed_sha256"] == b0["artifact_sha256"],
                        "original B0 seed receipt differs")
                a.equal_record(a.absolute_record(b0["output"]), b0["artifact_bytes"], b0["artifact_sha256"], "B0")
                root_names = sorted(n for n in infos if n.startswith(EVIDENCE)
                    and "/" not in n[len(EVIDENCE):] and n.endswith(".receipt.json"))
                a.check(len(root_names) == 87, "root original receipt denominator differs")
                for name in root_names:
                    if name == EVIDENCE + "B0.receipt.json":
                        continue
                    receipt = h.document(get(name))
                    child_request = h.document(get(name[:-len(".receipt.json")] + ".request.json"))
                    a.invocation(name, receipt, child_request, get)
                for field, labels in (("generations", ("B1", "B2", "B3")), ("modified_generations", ("M1", "M2", "M3"))):
                    rows = q[field]
                    a.check(len(rows) == 3 and [r["case"] for r in rows] == list(labels)
                            and cold["generation_sha256" if field == "generations" else "modified_generation_sha256"]
                                == [r["produced_sha256"] for r in rows], "original generation inventory differs")
                    for row in rows:
                        a.check(row == h.document(get(EVIDENCE + row["case"] + ".receipt.json")),
                                "embedded generation differs from original receipt")
                for observer in ("native", "linked"):
                    build = h.document(get(EVIDENCE + observer + "-observer-build.json"))
                    executable = get(EVIDENCE + observer + "-observer.elf")
                    emitted = get(EVIDENCE + observer + "-observer-emit.output.bin")
                    a.check(q[observer + "_observer_build"] == build
                            and h.digest(executable) == build["executable_sha256"]
                            and emitted[:len(executable)] == executable
                            and build["native_emission"]["core_u32"] == len(executable),
                            "observer build/ELF/full-output prefix differs")
                    a.check(q[observer + "_observer_reference"] ==
                            h.document(get(EVIDENCE + "independent-" + observer + "-observer-reference.json")),
                            "independent observer reference original differs")
                qualifier = get(SOURCE + "tools/qualify_hia_selfhost.py")
                a.check(literal_assignment(qualifier, "QUALIFICATION_FAMILIES") == FAMILIES,
                        "source family literal differs")
                reference_files = literal_assignment(qualifier, "PHASE_REFERENCE_FILES")
                reference_files["core"] = "independent-core-reference.json"
                schedule = q["qualification_scheduling"]
                refs = schedule["reference_processes"]
                a.check(len(refs) == 17 and {r["family"] for r in refs} == set(REFERENCE_FIELDS)
                        and len({r["worker_pid"] for r in refs}) == 17, "reference full fresh process denominator differs")
                for row in refs:
                    family = row["family"]
                    raw = get(EVIDENCE + "reference-" + family + ".worker.json")
                    worker = h.document(raw)
                    payload = h.document(get(EVIDENCE + reference_files[family]))
                    a.check(h.digest(raw) == row["report_sha256"] and row["returncode"] == 0
                            and row["source_manifest_sha256"] == SOURCE_MAP_SHA
                            and worker["schema"] == "hepta.hia.selfhost-independent-reference-process.v1"
                            and worker["family"] == family and worker["before_B0"] is True
                            and worker["worker_pid"] == row["worker_pid"]
                            and worker["source_manifest_sha256"] == SOURCE_MAP_SHA
                            and worker["reference"] == payload == q[REFERENCE_FIELDS[family]]
                            and h.semantic_digest(payload) == worker["reference_sha256"] == row["reference_sha256"]
                            and row["completed_monotonic_ns"] <= schedule["seed_started_monotonic_ns"],
                            "reference original envelope/payload/pre-B0 join differs: " + family)
                a.check(max_overlap(refs, "started_monotonic_ns", "completed_monotonic_ns") <= 2,
                        "original reference two-worker limit exceeded")
                a.check(schedule["maximum_host_oracle_workers"] == 2
                        and schedule["maximum_archive_workers"] == 1 and schedule["maximum_pending_archives"] == 2
                        and schedule["maximum_unsealed_phase_directories"] == 4
                        and schedule["native_child_processes_reused"] is False
                        and schedule["phase_completed_only_after_verified_archive"] is True
                        and schedule["fresh_seed_and_generation_chain_sequential"] is True
                        and schedule["independent_references_completed_before_B0"] is True,
                        "unchanged scheduling boundary differs")
                pairs = [(f, label) for f in FAMILIES for label in LABELS]
                processes = schedule["phases"]
                a.check(index["completed"] == 38 and index["exceptions"] == 0
                        and [(p["family"], p["compiler_label"]) for p in index["phases"]] == pairs
                        and [(p["family"], p["compiler_label"]) for p in processes] == pairs
                        and schedule["phase_inventory"] == [f + "-" + label for f, label in pairs],
                        "all original phase inventories differ")
                a.check(max_overlap(processes, "started_monotonic_ns", "completed_monotonic_ns") <= 2,
                        "original phase two-worker limit exceeded")
                phase_results, phase_objects, names_rows = [], {}, []
                all_phase_checks = {}
                inventory_path = output / "phase-member-readback.jsonl.gz"
                with inventory_path.open("xb") as raw_inventory:
                    with gzip.GzipFile(fileobj=raw_inventory, mode="wb", filename="", compresslevel=1, mtime=0) as compressed:
                        with io.TextIOWrapper(compressed, encoding="utf-8", newline="\n") as inventory:
                            for idx, proc in zip(index["phases"], processes, strict=True):
                                family, label = proc["family"], proc["compiler_label"]
                                stem = EVIDENCE + "phase-" + family + "-" + label
                                actual_proc = h.document(get(stem + ".process.json"))
                                phase_raw = get(stem + ".json")
                                phase_report = h.document(phase_raw)
                                phase_request = h.document(get(stem + ".request.json"))
                                a.check(actual_proc == proc
                                        and idx["process_receipt"] == TEMP + stem + ".process.json"
                                        and idx["report"] == TEMP + stem + ".json"
                                        and idx["request"] == TEMP + stem + ".request.json"
                                        and idx["state"] == "completed" and idx["report_status"] == "PASS",
                                        "actual process/index join differs: " + stem)
                                a.check(proc["schema"] == "hepta.hia.selfhost-phase-process.v1"
                                        and proc["returncode"] == 0 and proc["report_sha256"] == h.digest(phase_raw)
                                        and proc["completed_monotonic_ns"] - proc["started_monotonic_ns"] <= proc["wall_elapsed_ns"] <= proc["archive_completed_monotonic_ns"] - proc["started_monotonic_ns"]
                                        and proc["archive_completed_monotonic_ns"] >= proc["completed_monotonic_ns"],
                                        "phase process status/timing/hash differs")
                                a.check(proc["command"] == [owner_request["command"][0], "-I", "-S", "-B",
                                        TEMP + SOURCE + "tools/qualify_hia_selfhost.py", "--phase-request",
                                        TEMP + stem + ".request.json", "--output", TEMP + stem + ".json"],
                                        "phase command identity differs")
                                a.check(phase_report["schema"] == "hepta.hia.selfhost-phase.v1"
                                        and phase_report["status"] == "PASS"
                                        and phase_report["family"] == phase_request["family"] == family
                                        and phase_report["compiler_label"] == phase_request["compiler_label"] == label
                                        and phase_report["source_manifest_sha256"] == phase_request["source_manifest_sha256"] == SOURCE_MAP_SHA
                                        and phase_report["worker_pid"] == proc["worker_pid"]
                                        and phase_report["fresh_host_oracle_process"] is True
                                        and phase_report["successor_process_reuse"] is False
                                        and phase_report["python"] == {"dont_write_bytecode": True, "isolated": True, "no_site": True}
                                        and phase_report["checks"] and all(v is True for v in phase_report["checks"].values()),
                                        "phase full report/identity/checks differ")
                                a.check(phase_request["schema"] == "hepta.hia.selfhost-phase-request.v1"
                                        and phase_request["directory"] == proc["raw_artifacts"]["archive"][:-4],
                                        "phase request/archive root differs")
                                inputs = phase_request["inputs"]
                                a.check(set(inputs) == {"compiler", "source", "modified_source", "sample",
                                                         "native_observer", "linked_observer"} |
                                           ({"reference"} if family in reference_files else set()) |
                                           ({"sample_image"} if family == "elf" else set()),
                                        "phase exact input denominator differs")
                                for key, item in inputs.items():
                                    rec = a.absolute_record(item["path"])
                                    a.check(rec["sha256"] == item["sha256"] == phase_report["input_sha256"][key],
                                            "phase actual input SHA differs: " + key)
                                a.check(set(phase_report["input_sha256"]) == set(inputs),
                                        "phase report input partition differs")
                                for key, value in phase_report["checks"].items():
                                    a.check(q["checks"].get(key) is value and
                                            (key not in all_phase_checks or all_phase_checks[key] is value),
                                            "phase checks differ from full qualification")
                                    all_phase_checks[key] = value
                                phase = {"family": family, "compiler_label": label,
                                         "archive": proc["raw_artifacts"], "report": {"name": stem + ".json"}}
                                result = h.audit_phase(a, outer, infos, phase, inventory)
                                phase_results.append(result)
                                phase_objects[family, label] = phase_report["observations"]
                                if label == "modified":
                                    if family == "chain":
                                        for subkey, field in (("chain", "chain_elf_observations"),
                                                              ("allocator", "chain_allocator_observations")):
                                            a.check(phase_objects[family, "original"][subkey] +
                                                    phase_objects[family, "modified"][subkey] == q[field],
                                                    "chain complete observations differ from full report")
                                    else:
                                        a.check(phase_objects[family, "original"] + phase_objects[family, "modified"]
                                                == q[FIELDS[family]],
                                                "full phase observations differ from nested qualification: " + family)
                                    del phase_objects[family, "original"], phase_objects[family, "modified"]
                                if family == "names":
                                    names_rows.append(names_custody(h, a, outer, infos, phase,
                                                      q["independent_function_name_reference"]))
                                print(json.dumps({"stage": "phase-physical", "completed": len(phase_results),
                                    "family": family, "label": label, "files": result["files"],
                                    "history_gaps": len(a.history_gaps)}), flush=True)
                            inventory.flush()
                    raw_inventory.flush()
                    os.fsync(raw_inventory.fileno())
                totals = {"phases": len(phase_results), "member_files": sum(p["files"] for p in phase_results),
                    "unpacked_bytes": sum(p["unpacked_bytes"] for p in phase_results),
                    "packed_bytes": sum(p["packed_bytes"] for p in phase_results),
                    "physical_invocation_receipts": sum(p["physical_invocation_receipts"] for p in phase_results),
                    "embedded_observations": sum(p["embedded_invocation_observation_accounting"]["embedded_total"] for p in phase_results),
                    "exact_embedded_joins": sum(p["embedded_invocation_observation_accounting"]["exact_receipt_joins"] for p in phase_results),
                    "annotated_embedded_joins": len(a.annotation_joins)}
                a.check(totals["phases"] == 38 and totals["member_files"] == 42899
                        and totals["unpacked_bytes"] == 2447382806 and totals["packed_bytes"] == 67133059
                        and totals["embedded_observations"] == 6270
                        and totals["exact_embedded_joins"] == 5582 and totals["annotated_embedded_joins"] == 688
                        and not a.history_gaps and totals["physical_invocation_receipts"] == 6058
                        and len(a.receipt_joins) == 6144 and len(a.host_shared_output_joins) == 204,
                        "complete physical/embedded original accounting differs")
                report["cold"] = {"status": cold["status"], "wall_elapsed_ns": cold["wall_elapsed_ns"],
                    "checks": 11, "nested_checks": 5051, "nested_elapsed_ns": q["elapsed_ns"],
                    "nested_raw_sha256": PINS["hia-cold.cold/qualification.json"][1],
                    "reference_processes": 17, "reference_maximum_overlap": max_overlap(refs, "started_monotonic_ns", "completed_monotonic_ns"),
                    "phase_maximum_overlap": max_overlap(processes, "started_monotonic_ns", "completed_monotonic_ns"),
                    "root_invocations": 86, "original_generation_sha256": cold["generation_sha256"],
                    "modified_generation_sha256": cold["modified_generation_sha256"]}
                report["phases"] = {"totals": totals, "results": phase_results,
                    "all_original_bytes_CRC_SHA256_size_mode_read": True,
                    "all_embedded_receipts_join_actual_originals": True, "history_gaps": []}
                report["names_custody_fix"] = {"labels": 2, "compilation_receipts": 218, "runtime_receipts": 424,
                    "formerly_colliding_compilation_pairs": 46, "new_run_all_companions_physically_preserved": True,
                    "old_970_missing_bytes_not_recovered_or_reclassified": True}
                h.put(output / "names-custody-physical-pairs.json", h.wire(names_rows))
                h.put(output / "all-invocation-physical-joins.json", h.wire(a.receipt_joins))
                h.put(output / "known-producer-annotation-joins.json", h.wire(a.annotation_joins))
                h.put(output / "host-shared-output-joins.json", h.wire(a.host_shared_output_joins))
                # Re-read the complete derived compressed inventory, not the original phase binaries.
                inventory_hash = hashlib.sha256()
                inventory_lines = inventory_bytes = 0
                with gzip.open(inventory_path, "rb") as recovered:
                    for line in recovered:
                        inventory_hash.update(line)
                        inventory_bytes += len(line)
                        inventory_lines += 1
                        h.document(line)
                a.check(inventory_lines == 42899, "derived per-file audit inventory incomplete")
                report["derived_member_inventory"] = {"path": inventory_path.name,
                    "records": inventory_lines, "decoded_bytes": inventory_bytes,
                    "decoded_sha256": inventory_hash.hexdigest(),
                    "compressed_bytes": inventory_path.stat().st_size,
                    "compressed_sha256": h.digest(inventory_path.read_bytes())}
            after = h.hash_stream(stream, before.st_size)
            a.check(after == actual_before, "official input ZIP changed after all reads")
            report["original_after"] = after
        # All source comparison reads use the restored v78 copy as an additional
        # same-content witness; they are not the historical checkout's inode.
        for row in source_rows:
            with h.ordinary(Path(args.source) / row["path"], row["bytes"]) as (s, st):
                actual = h.hash_stream(s, st.st_size)
            a.check(actual == {k: row[k] for k in ("bytes", "sha256")}, "source witness changed during read")
        a.check(helper_path.read_bytes() == helper_raw and Path(__file__).read_bytes() == own_raw,
                "auditor code changed during read")
        report["status"] = "ALL_38_ORIGINAL_PHASE_BYTES_VERIFIED_NAMES_CUSTODY_FIXED"
    except BaseException as exc:
        report["errors"].append({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()})
    report["check_count"] = a.check_count
    report["reader_elapsed_ns"] = time.monotonic_ns() - started
    report["python"] = sys.version
    report["command"] = sys.argv
    receipt = h.put(output / "PHYSICAL-READBACK.json", h.wire(report))
    print(json.dumps({"status": report["status"], "checks": a.check_count, "report": receipt,
                      "errors": [{"type": x["type"], "message": x["message"]} for x in report["errors"]]}), flush=True)
    return 0 if not report["errors"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    raise SystemExit(run(parser.parse_args()))


if __name__ == "__main__":
    main()

