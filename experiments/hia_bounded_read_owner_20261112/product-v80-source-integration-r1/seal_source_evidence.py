"""Preserve existing source-only originals. Does not import or run the product."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CHECKOUT = ROOT / "checkout"


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


def create(name, data):
    with (HERE / name).open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    assert (HERE / name).read_bytes() == data


def main():
    publication = json.loads((HERE / "PRODUCT-PUBLICATION.json").read_bytes())
    delta = json.loads((ROOT / "PRODUCT-DELTA.json").read_bytes())
    source_runs = []
    for name in ("source-checks-r1", "source-checks-r2"):
        folder = ROOT / name
        report_raw = (folder / "report.json").read_bytes()
        report = json.loads(report_raw)
        owner_raw = (folder / "owner.json").read_bytes()
        owner = json.loads(owner_raw)
        assert owner["qualification_seconds"] == 180 and owner["cleanup_seconds"] == 3
        assert owner["cleanup"]["complete"] is True
        assert owner["cleanup"]["observed_echild"] is True
        assert owner["cleanup"]["leader_reaped"] is True
        assert not owner["cleanup"]["remaining_direct_children"]
        assert not owner["cleanup"]["errors"]
        assert not owner["timed_out"] and not owner["event_overflow"]
        assert [event["kind"] for event in owner["events"]] == [
            "qualification_started", "owned_child_observed", "qualification_exit_observed", "owned_child_reaped"]
        assert report["loaded_ids"] == report["executed_ids"] and report["testsRun"] == 13
        assert not report["native_executed"]
        assert len(report["steps"]) == 5 and all(row["returncode"] == 0 for row in report["steps"])
        if name.endswith("r1"):
            assert report["status"] == "HOLD" and owner["returncode"] == 1
            assert len(report["anomalies"]["failures"]) == 1
            assert report["anomalies"]["failures"][0][0].endswith("test_component_resource_and_full_source_membership_are_declared")
        else:
            assert report["status"] == "SOURCE_VERIFICATION_PASS_NOT_NATIVE_QUALIFICATION"
            assert owner["returncode"] == 0 and not any(report["anomalies"].values())
            assert not report["errors"] and not report["loader_errors"]
            for path, digest in report["source_after"].items():
                assert hashlib.sha256((CHECKOUT / path).read_bytes()).hexdigest() == digest, path
            assert len(report["source_after"]) == 816
        source_runs.append({
            "path": name, "status": report["status"], "passed_methods": 12 if name.endswith("r1") else 13,
            "loaded_ids": report["loaded_ids"], "executed_ids": report["executed_ids"],
            "anomalies": report["anomalies"], "loader_errors": report["loader_errors"],
            "report": identity(report_raw), "owner": identity(owner_raw),
            "owner_status": owner["status"], "owner_returncode": owner["returncode"],
            "owner_elapsed_ns": owner["events"][2]["monotonic_ns"] - owner["events"][0]["monotonic_ns"],
            "original_seconds": 180, "cleanup_seconds": 3, "natural_closed": True,
            "source_member_count_after": len(report["source_after"]), "native_executed": False,
        })

    old_raw = (HERE / "actual-r4b-abi-601.json").read_bytes()
    new_raw = (HERE / "source-owned-v80-abi-1153.json").read_bytes()
    old, new = json.loads(old_raw), json.loads(new_raw)
    assert len(old_raw) == 601 and len(new_raw) == 1153
    assert old["function"] == new["function"] == "f0"
    assert old["returns"] == new["returns"] == ["u32"]
    assert old["source_sha256"] == new["source_sha256"]
    assert [{"name": p["name"], "type": p["type"]} for p in new["parameters"]] == old["parameters"]
    adapter = (CHECKOUT / "hepta/hia_bounded_read_native.py").read_text()
    assert "hia_bounded_read_abi.json" not in adapter and "entry_abi" not in adapter
    abi_delta = {
        "schema": "hepta.hia.bounded-read-abi-integration-delta.v1",
        "old": {"kind": "actual development instance receipt", **identity(old_raw), "document": old},
        "new": {"kind": "source-owned descriptive entry resource", **identity(new_raw), "document": new},
        "unchanged_projections": ["function", "parameters[*].name", "parameters[*].type", "returns", "source_sha256"],
        "changed_schema": {"before": old["schema"], "after": new["schema"]},
        "added_parameter_bytes": [64, 24, 1024],
        "removed_instance_fields": {key: old[key] for key in sorted(set(old) - set(new))},
        "added_source_fields": {key: new[key] for key in sorted(set(new) - set(old))},
        "consumers": {
            "generator": "tools.generate_hia_bounded_read.entry_abi and generated_files produce and check the bytes",
            "builder": "tools.build_hia_bounded_read._build compares the complete ABI bytes with entry_abi(source) and includes its SHA/document in its build receipt",
            "source_checks": "tests.test_hia_bounded_read_source checks generation, fields, source membership and resource membership",
            "native_adapter": "does not open, parse or otherwise consume this JSON; its non-documentation AST is unchanged from actual r4b",
            "loader": "the existing v3 native manifest binds source/image; this descriptive ABI is not a substitute for that admission",
        },
        "actual_r4b_execution_proves_new_abi_consumption": False,
        "current_abi_native_execution_or_installation_claimed": False,
        "known_installation_mapping_issue": {
            "owner": "root integration",
            "test": "tests/test_hia_agent_installed_resources.py",
            "description": "Its existing NATIVE_SOURCE_FILES importer special-cases Core ABI, then derives a native module from other resource stems. Applying it to hepta/hia_bounded_read_abi.json derives nonexistent hepta.hia_hia_bounded_read_abi_native. The JSON is a descriptor; root owns resource classification and installed binding repair.",
            "fixed_here": False,
        },
    }
    create("ABI-DELTA.json", wire(abi_delta))
    create("PRODUCT-DELTA.json", (ROOT / "PRODUCT-DELTA.json").read_bytes())

    inputs = [ROOT / "BASE.json", ROOT / "PRODUCT-DELTA.json"]
    for directory in ("source-checks-r1", "source-checks-r2", "mechanical-audit-r1"):
        inputs.extend(sorted(path for path in (ROOT / directory).rglob("*") if not path.is_dir()))
    payloads, records = {}, []
    for path in sorted(inputs):
        before = path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, path
        with path.open("rb") as stream:
            content = stream.read()
        after = path.lstat()
        assert (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns), path
        name = path.relative_to(ROOT).as_posix()
        payloads[name] = content
        records.append({"path": name, "mode": stat.S_IMODE(before.st_mode), **identity(content)})
    archive = HERE / "source-originals.tar.xz"
    with archive.open("xb") as destination:
        with tarfile.open(fileobj=destination, mode="w:xz", preset=6) as tar:
            for record in records:
                member = tarfile.TarInfo(record["path"])
                member.size = record["bytes"]
                member.mode = record["mode"]
                member.mtime = member.uid = member.gid = 0
                member.uname = member.gname = ""
                tar.addfile(member, io.BytesIO(payloads[record["path"]]))
        destination.flush()
        os.fsync(destination.fileno())
    archive_raw = archive.read_bytes()
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:xz") as tar:
        members = tar.getmembers()
        assert [member.name for member in members] == [row["path"] for row in records]
        for member, row in zip(members, records):
            assert member.isfile() and member.mode == row["mode"] and member.size == row["bytes"]
            assert tar.extractfile(member).read() == payloads[member.name]
    for name, content in payloads.items():
        assert (ROOT / name).read_bytes() == content
    archive_manifest = {
        "schema": "hepta.hia.bounded-read-source-originals-archive.v1",
        "archive": {"path": archive.name, **identity(archive_raw)},
        "members": records, "member_count": len(records),
        "decoded_bytes": sum(row["bytes"] for row in records),
        "member_mode_and_bytes_roundtrip_verified": True,
        "archive_uid_gid_mtime_normalized": 0,
        "all_actual_source_runs_preserved": ["source-checks-r1", "source-checks-r2"],
        "product_executed_by_preservation": False,
    }
    create("ARCHIVE-MANIFEST.json", wire(archive_manifest))
    for directory, stem in (("source-checks-r1", "source-r1"), ("source-checks-r2", "source-r2")):
        for original, ending in (("report.json", "report.json"), ("owner.json", "owner.json"), ("worker.py", "worker.py")):
            create(stem + "-" + ending, (ROOT / directory / original).read_bytes())
    create("MECHANICAL-PROJECTION.json", (ROOT / "mechanical-audit-r1/REPORT.json").read_bytes())
    mechanical = json.loads((HERE / "MECHANICAL-PROJECTION.json").read_bytes())
    assert len(mechanical["checks"]) == 22 and all(item["passed"] for item in mechanical["checks"])
    handoff = {
        "schema": "hepta.hia.bounded-read-v80-product-handoff.v1",
        "status": "REVIEWABLE_SOURCE_VERIFIED_EXPLICIT_DEVELOPMENT_COMPONENT",
        "product": publication,
        "source_profile": "selfhost-core-linux-x86_64-v80-native-core-emitter-json-pretty-bounded-read-development",
        "declared_source_files": 815, "declared_source_plus_contract": 816,
        "product_delta": {"files": len(delta["files"]), "bytes": sum(row["bytes"] for row in delta["files"]), "manifest": "PRODUCT-DELTA.json"},
        "actual_source_only_runs": source_runs,
        "initial_failure": "r1 executed all 13 methods; one failed because tests/test_hia_program_tools.py was absent from the declared closure. The exact failed source and reports remain in source-originals.tar.xz. r2 adds that declaration and regenerates support; 13 methods pass.",
        "mechanical_projection": {"checks": 22, "report": "MECHANICAL-PROJECTION.json", "status": mechanical["status"]},
        "prior_native_evidence": {
            "commit": "a27026122c62c55994c5f836914cccf25fec3836",
            "tree": "1a2754029f64a3d7d8e9db60c744b2c2bc5efa47",
            "prefix": "experiments/hia_bounded_read_owner_20261112/actions-native-development-r2/actual-run-43175489773/",
            "run_id": 43175489773, "job_id": 131038628076, "finite_cases": 55,
            "original_methods": 8, "actual_CLI_children": 7, "outer_elapsed_ns": 34200557801,
            "original_deadline_seconds": 180, "cleanup_seconds": 3,
            "artifact_id": 13924710034, "artifact_bytes": 3493092,
            "artifact_sha256": "afb749077649195a0b62e080f33495684403cc1ae57b98ac066a920d3e2a0f29",
            "audit_checks": 260, "audit_path": "audits/native-record-audit-r1/AUDIT.json",
            "audit_bytes": 45198, "audit_sha256": "346ac6fb3bdcbcd3cbc4c90e86bc208665a1e8adf17788bf49d543a2f33a9f24",
            "audit_git_blob_sha1": "68d5300fc7deb2f7bde84a15cc053d90c3b858b5",
            "old_evidence_branch_mutation_ack": "UNKNOWN; commit object independently readable; no repeat mutation",
            "qualifies_current_v80_revision": False,
        },
        "abi_delta": "ABI-DELTA.json",
        "activation": {"default": "retained Python read_bounded", "explicit_selector": "HEPTA_HIA_BOUNDED_READ_MANIFEST", "invalid_selection_falls_back": False},
        "new_entrypoints": {
            "generator": "tools/generate_hia_bounded_read.py [--check]",
            "builder": "tools/build_hia_bounded_read.py: matching-cold entry or explicit --development",
            "validator": "tools/qualify_hia_bounded_read.py: exact 55 plus original 8 methods and 7 CLI children under original 180/3 owner",
        },
        "unchanged_limits": {"ordinary_default_input_bytes": 8388608, "compile_seconds": 20, "compile_cpu_seconds": 10, "compile_address_space_bytes": 268435456, "compile_stack_bytes": 8388608, "compile_output_bytes": 1048576, "original_CLI_child_seconds": 20, "qualification_seconds": 180, "cleanup_seconds": 3},
        "open_boundaries": [
            "The new v80 builder and validation orchestration have not executed native code, an installed package, CI, cold bootstrap, or full qualification.",
            "OS operations, Path conversion, context-manager mechanics and foreign CPython primitives remain hosted.",
            "Arbitrary foreign-object, cyclic-GC, reflection and asynchronous-interruption equivalence is not proved by the finite original controls.",
            "The current installed-resource test derives a nonexistent module for the new ABI descriptor; root owns classification and actual installed verification.",
            "A merge with v79 or another source revision must regenerate both contracts and use its own matching-source receipts.",
        ],
        "next_authorized_work": "Prepare a separately frozen native plus actual installation capsule for root review and single triggering; preserve complete populations, source identity and all original budgets. Do not trigger from this handoff.",
        "preservation": archive_manifest["archive"],
        "raw_receipt_integers_preserved": True,
    }
    create("HANDOFF.json", wire(handoff))
    print(json.dumps({"product_commit": publication["commit"], "source_runs": [(row["status"],row["passed_methods"]) for row in source_runs], "archive": archive_manifest["archive"], "members": len(records), "decoded_bytes": archive_manifest["decoded_bytes"]}))


if __name__ == "__main__":
    main()
