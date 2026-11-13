"""Resume only retained a733 evidence after reading the exact prior transport error.

This custodian imports only the frozen custodian, never the product. It performs
no compilation, native execution, tests, result-status updates, or ref changes.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import pathlib
import sys
import zipfile
import zlib

FROZEN = {
    "collect_originals.py": "a252031e27c492671cc045654ad8dd4fd25730d57ab3bd1c4c0ea9a3e6f954cb",
    "inputs/ORIGINALS.json": "22cf6e2f6d1353faee1998625aa580bcea17cfe00e196abf1c7b424018f7940d",
}
for _name, _sha in FROZEN.items():
    if hashlib.sha256(pathlib.Path(_name).read_bytes()).hexdigest() != _sha:
        raise ValueError("frozen original custodian/input bytes differ")
import collect_originals as c

CONFIG = json.loads(pathlib.Path("inputs/RESUME.json").read_bytes())
c.PREFIX = CONFIG["mount_prefix"]
ORIGINAL_DOWNLOAD = c.download
ORIGINAL_PUBLISH_RECORD = c.publish_record
CARRIER = None
CARRIER_MEMBERS = None
PRIOR_FINAL = None
PRIOR_FAILURE = None
PROVENANCE = {}
EXPECTED_ITEM = CONFIG["original"]
RECEIPT_CHUNKS = 512 * 1024


def publish_large_record(value, path):
    """Preserve exactly the original canonical JSON; never drop report fields."""
    raw = c.wire(value)
    if len(raw) <= 350000:
        return {"path": path, **c.publish_text(raw, path)}
    compressed = zlib.compress(raw, 9)
    c.require(zlib.decompress(compressed) == raw, "complete receipt zlib roundtrip differs")
    capsule = c.wire({
        "schema": "hia.lossless-zlib-text-capsule.v1",
        "original_name": path, **c.identity(raw),
        "encoding": "base64(zlib(UTF-8))",
        "data": base64.b64encode(compressed).decode("ascii"),
    })
    if len(capsule) <= 900000:
        return {"path": path + ".zlib.json", **c.publish_text(capsule, path + ".zlib.json")}
    original_meta = c.identity(raw)
    compressed_meta = c.identity(compressed)
    chunks = []
    restored = bytearray()
    for index, offset in enumerate(range(0, len(compressed), RECEIPT_CHUNKS)):
        part = compressed[offset:offset + RECEIPT_CHUNKS]
        wrapper = {
            "schema": "hia.lossless-archive-chunk.v1",
            "archive_name": path + ".zlib",
            "archive_bytes": len(compressed),
            "archive_sha256": compressed_meta["sha256"],
            "index": index, "offset": offset, "bytes": len(part),
            "sha256": hashlib.sha256(part).hexdigest(),
            "encoding": "base64", "data": base64.b64encode(part).decode("ascii"),
        }
        wrapper_path = path + ".chunks/chunk-" + str(index).zfill(4) + ".json"
        wrapper_raw = c.wire(wrapper)
        c.require(len(wrapper_raw) <= 900000, "receipt chunk exceeds fixed transport bound")
        ref = c.publish_text(wrapper_raw, wrapper_path)
        decoded = base64.b64decode(wrapper["data"], validate=True)
        c.require(decoded == part, "receipt chunk encoding differs")
        restored.extend(decoded)
        chunks.append({"index": index, "offset": offset, "bytes": len(part),
                       "sha256": wrapper["sha256"], "wrapper": {"path": wrapper_path, **ref}})
    c.require(bytes(restored) == compressed and zlib.decompress(restored) == raw,
              "complete ordered receipt reconstruction differs")
    record = {
        "schema": "hia.lossless-zlib-text-chunk-index.v1",
        "original_name": path, "original": original_meta,
        "compressed": compressed_meta,
        "encoding": "base64 chunks of zlib(UTF-8 canonical JSON)",
        "chunks": chunks, "all_published": True,
        "all_wrappers_full_readback": True,
        "ordered_offsets_complete": True,
        "whole_compressed_and_original_bytes_verified": True,
        "original_report_fields_removed": False,
        "archive_blob_is_computed_identity_only": True,
        "raw_binary_git_blob_separately_uploaded": False,
        "canonical_json_is_original_zip_member_byte_stream": False,
        "original_zip_report_bytes_preserved_separately_in_content_pool": True,
    }
    index_path = path + ".chunks/INDEX.json"
    index_raw = c.wire(record)
    c.require(len(index_raw) <= 900000, "receipt chunk index exceeds fixed transport bound")
    return {"path": index_path, "encoding": record["encoding"], "original": original_meta,
            **c.publish_text(index_raw, index_path)}


def source_snapshot():
    return {str(p): c.identity(p.read_bytes()) for p in sorted(pathlib.Path(".").rglob("*"))
            if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}


def retain_prior_error_and_carrier():
    global CARRIER, CARRIER_MEMBERS, PRIOR_FINAL, PRIOR_FAILURE, PROVENANCE
    c.STAGE = "prior-custodian:download-retained-only"
    target = c.OUT / "PRIOR-CUSTODIAN-RETAINED-ARTIFACT.zip"
    authority, run, sha = ORIGINAL_DOWNLOAD(CONFIG["carrier"], target)
    c.require(run["conclusion"] == "failure", "prior custodian terminal result differs")
    c.STAGE = "prior-custodian:complete-crc-and-original-error"
    with zipfile.ZipFile(target) as archive:
        rows = c.zip_inventory(archive)
        for name in CONFIG["required_carrier_members"]:
            c.require(name in rows and not rows[name]["directory"], "retained carrier member missing")
        failure_raw = archive.read("FAILURE.json")
        final_raw = archive.read("FINAL.json")
        expected_final = CONFIG["prior_manifest"]
        c.require(c.identity(final_raw) == expected_final, "retained prior final manifest differs")
        c.require(c.blob_bytes(expected_final["blob"]) == final_raw, "prior Git final differs from retained bytes")
        PRIOR_FINAL = json.loads(final_raw)
        PRIOR_FAILURE = json.loads(failure_raw)
        c.save(c.OUT / "PRIOR-FAILURE-ORIGINAL.json", failure_raw)
        # Preserve the actual error before deciding whether this successor applies.
        failure_ref = c.publish_text(failure_raw, "PRIOR-FAILURE-ORIGINAL.json")
        final_ref = c.publish_text(final_raw, "PRIOR-FINAL-ORIGINAL.json")
        print(json.dumps({"prior_failure": PRIOR_FAILURE,
                          "prior_failure_blob": failure_ref["blob"],
                          "prior_final_blob": final_ref["blob"]}), flush=True)
        c.require(PRIOR_FAILURE == CONFIG["expected_prior_failure"],
                  "prior failure is outside this narrow receipt-transport repair")
        c.require(PRIOR_FINAL["status"] == "CUSTODY_INCOMPLETE"
                  and PRIOR_FINAL["actual_custodian_commit"] == CONFIG["carrier"]["harness_commit"]
                  and str(PRIOR_FINAL["actual_custodian_run"]) == str(CONFIG["carrier"]["run_id"])
                  and PRIOR_FINAL["custodian_source_unchanged"] is True
                  and PRIOR_FINAL["last_stage"] == PRIOR_FAILURE["stage"]
                  and PRIOR_FINAL["unpreserved_originals"] == [EXPECTED_ITEM["key"]],
                  "prior partial boundary differs")
        intents, acks = PRIOR_FINAL["intents"], PRIOR_FINAL["acks"]
        c.require(len(intents) == len(acks) == CONFIG["prior_ack_count"],
                  "prior unknown or missing mutation ACK")
        c.require(len(PRIOR_FINAL["entries"]) == len(acks), "prior entry/ACK count differs")
        for number, (intent, ack) in enumerate(zip(intents, acks)):
            c.require(intent["ordinal"] == ack["ordinal"] == number
                      and intent["post_replayed"] is False and ack["full_readback"] is True
                      and all(intent[k] == ack[k] for k in ("path", "bytes", "sha256", "blob")),
                      "prior intent/ACK mapping differs")
        complete = PRIOR_FINAL["completed_originals"]
        c.require(len(complete) == 1 and complete[0]["key"] == "main51bc-original-core"
                  and complete[0]["index"]["blob"] == CONFIG["completed_main_index"]["blob"],
                  "already complete main custody differs")
        main_index_raw = c.blob_bytes(CONFIG["completed_main_index"]["blob"])
        c.require(c.identity(main_index_raw) == CONFIG["completed_main_index"], "main index identity differs")
        main_index = json.loads(main_index_raw)
        c.require(main_index["all_published"] is True and main_index["all_wrappers_full_readback"] is True
                  and len(main_index["chunks"]) == 89,
                  "main completed index lacks its original complete ACK boundary")
        held_original = rows[CONFIG["retained_original_member"]]
        c.require(held_original["bytes"] == EXPECTED_ITEM["artifact"]["size_in_bytes"]
                  and "sha256:" + held_original["sha256"] == EXPECTED_ITEM["artifact"]["digest"],
                  "retained a733 original ZIP differs")
    CARRIER = target
    CARRIER_MEMBERS = rows
    PROVENANCE = {
        "schema": "hia.prior-custodian-transport-recovery.v1",
        "carrier": {"artifact": authority, "run": run, "file": c.file_identity(target)},
        "carrier_members": rows,
        "carrier_all_member_crc_sha_git_verified": True,
        "prior_failure": {"original_identity": c.identity(failure_raw), "git": failure_ref},
        "prior_final": {"original_identity": c.identity(final_raw), "git": final_ref},
        "already_complete_main_index": CONFIG["completed_main_index"],
        "main_original_downloaded_again": False, "main_pool_recreated": False,
        "main_existing_chunks_republished": False,
        "a733_producer_outer_downloaded_again": False,
        "retained_original_member": CONFIG["retained_original_member"],
        "original_product_execution": False, "original_results_reclassified": False,
    }
    c.publish_record(PROVENANCE, "RETAINED-CARRIER-VERIFICATION.json")


def retained_original_download(item, target):
    """Supply the exact original from prior custody; never request its ZIP URL."""
    c.require(item == EXPECTED_ITEM and CARRIER is not None and CARRIER_MEMBERS is not None,
              "unreviewed original retrieval requested")
    artifact = c.api("/actions/artifacts/" + str(item["artifact"]["id"]))
    for key in ("id", "name", "size_in_bytes", "digest", "created_at", "expires_at"):
        c.require(artifact[key] == item["artifact"][key], "original artifact metadata changed")
    c.require(artifact["workflow_run"]["id"] == item["run_id"]
              and artifact["workflow_run"]["head_sha"] == item["harness_commit"],
              "original authority source differs")
    run = c.api("/actions/runs/" + str(item["run_id"]))
    c.require(run["status"] == "completed" and run["head_sha"] == item["harness_commit"],
              "original run/head changed")
    sha = hashlib.sha256()
    total = 0
    with zipfile.ZipFile(CARRIER) as archive:
        with archive.open(CONFIG["retained_original_member"]) as source, target.open("xb") as output:
            while part := source.read(1024 * 1024):
                total += len(part)
                c.require(total <= artifact["size_in_bytes"], "retained original exceeds authority extent")
                output.write(part)
                sha.update(part)
            output.flush()
            os.fsync(output.fileno())
    c.require(total == artifact["size_in_bytes"] and "sha256:" + sha.hexdigest() == artifact["digest"],
              "retained original complete SHA differs")
    return artifact, run, sha.hexdigest()


def run():
    before = source_snapshot()
    c.require(os.environ["GITHUB_REPOSITORY"] == c.REPOSITORY, "repository differs")
    c.require(EXPECTED_ITEM == c.INPUTS["originals"][1], "pending original input changed")
    c.require(CONFIG["carrier"]["artifact"]["id"] == 14007242551
              and EXPECTED_ITEM["artifact"]["id"] == 14006895740,
              "fixed artifact IDs differ")
    c.record("CUSTODIAN-SOURCE-BEFORE-R2.json", before)
    success = False
    failure = None
    c.publish_record = publish_large_record
    try:
        retain_prior_error_and_carrier()
        c.download = retained_original_download
        c.collect(EXPECTED_ITEM)
        c.require(len(c.RESULTS) == 1
                  and c.RESULTS[0]["receipts"]["VERIFICATION.json"]["blob"]
                      == CONFIG["already_verified_a733_summary_blob"],
                  "resumed original cold verification differs from prior complete verification")
        success = True
    except BaseException as error:
        failure = {
            "stage": c.STAGE, "error_type": type(error).__name__,
            "http_code": getattr(error, "code", None),
            "detail": str(error) if isinstance(error, (ValueError, KeyError, AssertionError))
                      else "Transport or runtime failure; no credential or signed URL is logged.",
            "original_results_reclassified": False,
        }
        c.record("FAILURE-R2.json", failure)
        try:
            c.publish_text(c.wire(failure), "FAILURE-R2.json")
        except BaseException as publish_error:
            c.record("FAILURE-R2-PUBLISH-ERROR.json", {"error_type": type(publish_error).__name__})
    finally:
        after = source_snapshot()
        c.record("CUSTODIAN-SOURCE-AFTER-R2.json", after)
        unchanged = before == after
        complete = [] if PRIOR_FINAL is None else PRIOR_FINAL["completed_originals"]
        final = {
            "schema": "hia.normal-core-evidence-custody-resume.v1",
            "status": "CUSTODY_COMPLETE" if success and unchanged else "CUSTODY_INCOMPLETE",
            "prior_collector_result": "failure",
            "prior_manifest": CONFIG["prior_manifest"],
            "prior_completed_originals_unchanged": complete,
            "resumed_originals": c.RESULTS,
            "expected_resumed_originals": 1,
            "all_two_originals_complete": bool(success and unchanged and len(complete) == 1),
            "last_stage": c.STAGE, "failure": failure,
            "intents": c.INTENTS, "acks": c.ACKS, "entries": c.ENTRIES,
            "source_before": before, "source_after": after,
            "custodian_source_unchanged": unchanged,
            "actual_custodian_commit": os.environ["GITHUB_SHA"],
            "actual_custodian_run": os.environ["GITHUB_RUN_ID"],
            "retrieval": {"carrier_artifact": CONFIG["carrier"]["artifact"]["id"],
                          "original_a733_member": CONFIG["retained_original_member"],
                          "original_producer_zip_downloads": 0},
            "unpreserved_originals": [] if success and unchanged else [EXPECTED_ITEM["key"]],
            "original_outer_zip_bytes_in_git": False,
            "all_original_nested_zip_bytes_unchanged": bool(success),
            "raw_binary_archive_blob_separately_uploaded": False,
            "product_execution": False, "compiler_execution": False, "tests_execution": False,
            "old_results_reclassified": False, "product_or_audit_refs_changed": False,
            "whole_native": False,
        }
        c.record("FINAL-R2.json", final)
        try:
            ref = c.publish_record(final, "FINAL-R2.json")
            print(json.dumps({"custody_status": final["status"], "manifest": ref}), flush=True)
        except BaseException as error:
            c.record("FINAL-R2-PUBLISH-FAILURE.json", {"stage": c.STAGE, "error_type": type(error).__name__})
            success = False
        return 0 if success and unchanged else 1


if __name__ == "__main__":
    raise SystemExit(run())
