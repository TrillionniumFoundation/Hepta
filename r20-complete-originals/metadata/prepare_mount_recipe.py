"""Describe existing R20 evidence objects; do not upload binaries or run products."""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent
OBJECTS = ROOT.parent / "v94-union-r12-r2/publication/objects"
PUBLICATION = ROOT.parent / "v120-source-parser-r20-harness/publication-r1"


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def write(name, value):
    p = OUT / name
    assert not p.exists()
    p.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def main():
    custody = json.loads((ROOT / "custody-stream-r1/REPORT.json").read_text())
    source = json.loads((ROOT / "source-manifest-readback-r1/REPORT.json").read_text())
    bounded = json.loads((ROOT / "bounded-manifest-readback-r1/REPORT.json").read_text())
    parts = json.loads((OUT / "METADATA-PARTS.json").read_text())
    chunks = json.loads((ROOT / "custody-stream-r1/INNER-CHUNKS-READBACK.json").read_text())
    assert source["source_outcome"] == "PASS" and source["source_tests_run"] == 1421
    assert len(chunks) == 237 and len(parts["parts"]) == 14
    summary = {
        "schema": "hia.r20.formal-terminal-originals-final-summary.v1",
        "formal_run": 43553551892, "formal_job": 132321186937,
        "formal_head": "28b8e6f5b44022f9d6e90d561573d41f0f7e8633",
        "status": "FORMAL_SOURCE_1421_AND_ORIGINAL_BOUNDED_62_PASS_COMPLETE_ORIGINAL_READBACK",
        "Source": {"actual_Python": source["actual_python"], "expected": 1421, "run": 1421,
                   "ordered_loaded_started_stopped_exact": True, "events": 2842,
                   "wall_seconds": source["source_wall_seconds"], "anomalies": source["anomalies"],
                   "loader_errors": source["loader_errors"], "old_ordered_projections": source["ordered_previous_projections"],
                   "generators": 139, "complete_generation_passes": 2, "syntax_files": 1574},
        "bounded62": {"Source": 10, "original_cli": 43, "Native_component": 9,
                      "all_original_ordered_ids_and_events": True,
                      "five_owners_180_plus_3_completed_rc0_cleanup_ECHILD": True,
                      "five_compile_observations_20s_1MiB_original_receipts": True,
                      "actual_packaging_test_installed_child_Python": "3.14.4",
                      "full_proof": pin((ROOT / "bounded-manifest-readback-r1/REPORT.json").read_bytes())},
        "actual_source": {"files": 3177, "bytes": 98009421,
                          "tree": "84df4b42f1e20fd7d0c7229e658cf3b458984ffb",
                          "all_bytes_mode_git_sha_individually_verified": True,
                          "complete_duplicate_physical_copy_created": False,
                          "unchanged_prepared_files": 3174, "retained_actual_generated_differences": 3},
        "outer_originals": custody["outer_artifacts"],
        "source_inner_original": custody["inner_source"],
        "metadata_capsule": {"logical_files": 152, "parts": 14, "wrapper": parts["original"],
                             "readback": pin((OUT / "METADATA-READBACK.json").read_bytes())},
        "durable_scope": {
            "source_inner_archive": "All 237 actual binary chunk objects exist from the formal producer; local independent whole-byte/CRC/member/mode verification is complete. A fresh independent connector GET of every binary chunk is not claimed.",
            "bounded_complete_raw": "Complete 48,115,943-byte ZIP retained locally and in Actions; only selected reports/proofs and metadata are in this Git handoff.",
            "whole_outer_ZIPs": "Both exact original ZIPs remain local/Actions; neither is represented as a complete Git ZIP copy.",
            "actual_product_source": "The independently verified full 3177-file tree was separately published as product commit26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d; that separate Native run is outside this formal result."},
        "new_product_executions_for_custody": 0, "current_source_cold": False, "whole_native": False,
        "original_failures_or_intermediate_recording_errors_erased": False,
    }
    write("TERMINAL-SUMMARY.json", summary)
    restore = (
        "# Exact R20 original evidence recovery\n\n"
        "This recipe preserves the completed formal Source run43553551892/job132321186937 and its separate bounded62 artifact. It does not grant current-source cold or whole-Native qualification.\n\n"
        "## Source original archive\n\n"
        "Read the237 Git binary blobs in source-archive/chunk-0000.bin through chunk-0236.bin in numeric order. These are raw decoded bytes, not Base64 text. Concatenate without separators. Require124111735 bytes, SHA256 ffc5945b5c231eb4faa09e57c7e5f8472d3dcc991338962b0a4336da881793f5 and Git blob741d9cb3e0e290aa80048bbc7e9df4d0cb63b597. The original producer performed complete GET readback for each; the independent custody verifier matched each actual downloaded archive span to those receipts. No new independent connector binary GET is claimed.\n\n"
        "The exact EVIDENCE-MANIFEST.json is inside the metadata capsule at original/custody-stream-r1/combined-source/EVIDENCE-MANIFEST.json:3387484 bytes, Git c2b851d6a1e2357a4ea7d16458e944f600f663a6. Verify its bytes before restoring. Validate every7856 regular file, every1295 directory and recorded root mode493 against that manifest; reject absolute/escaping/duplicate names, symlinks, hard links and unrecorded members. Preserve actual recorded modes. The original archive was already streamed through complete gzip CRC and member-byte/hash/Git/mode checks. Its recorded fixed Git input references remain fixed; do not replace them with HEAD.\n\n"
        "## Lossless proof metadata\n\n"
        "Concatenate the14 metadata-parts/part-####.txt Git files in exact index order as raw ASCII bytes, with no separators. Match METADATA-PARTS.json's full wrapper length/SHA/Git. Decode the wrapper JSON payload with strict Base64, verify compressed length/SHA/Git, zlib-decompress, and verify its full uncompressed length/SHA/Git. The decoded files array gives152 safe relative paths, exact bytes/hash/Git and original modes; its pool stores each distinct content as strict Base64. Check each decoded file against its record before writing into an exclusive directory. The complete logical map was already read back and compared byte-for-byte with all original metadata.\n\n"
        "## Outer ZIP and bounded-raw boundary\n\n"
        "combined-source.zip is383629576 bytes/SHA2567a6c07fb57593fd282fe4a2854bcd6ec0eb3ddca001b217c41c62f2843d570b9; parser-bounded.zip is48115943 bytes/SHA256efdca0795d327ff70cf27e2a4feddeb96cc78d14661226361b2ec6bf125c9b9e. Both original ZIPs remain in the local original directory and Actions artifacts14097884196/14098053733. Their full CRC/member/mode inventories and independent verifiers are preserved. This recipe is not a byte-exact replacement for either whole outer ZIP, and the complete bounded machine-frame/raw payload is not claimed to be in Git.\n"
    )
    p = OUT / "RESTORE.md"
    assert not p.exists()
    p.write_text(restore)
    entries, local = [], []

    def add(path, file):
        raw = file.read_bytes()
        identity = pin(raw)
        receipt = OBJECTS / (identity["git_blob"] + ".GIT-VERIFIED.json")
        present = receipt.exists()
        if present:
            stored = json.loads(receipt.read_text())
            assert stored["pin"] == identity
        row = {"path": path, "mode": "100644", "type": "blob", "sha": identity["git_blob"],
               "bytes": identity["bytes"], "sha256": identity["sha256"], "local_path": str(file),
               "independent_full_GET_receipt": str(receipt), "independent_full_GET_complete": present}
        entries.append(row)
        local.append(row)

    for i, chunk in enumerate(chunks):
        assert chunk["index"] == i and chunk["offset"] == 524288 * i and chunk["producer_full_get"] is True
        entries.append({"path": "source-archive/chunk-%04d.bin" % i, "mode": "100644", "type": "blob",
                        "sha": chunk["git_blob"], "bytes": chunk["bytes"], "sha256": chunk["sha256"],
                        "producer_full_GET": True, "producer_receipt_member": chunk["producer_receipt"],
                        "independent_verified_original_archive_span": True,
                        "independent_current_connector_binary_GET": False})
    for part in parts["parts"]:
        add(part["path"], OUT / part["path"])
    for name in (
        "METADATA-PARTS.json", "METADATA-MANIFEST.json", "METADATA-READBACK.json",
        "METADATA-ALL-PARTS-FULL-GET.json", "READER-ATTEMPT1.json", "READER-R2.json",
        "READER-ATTEMPT2-RECONCILIATION.json", "publish_metadata_session_helper.js",
        "TERMINAL-SUMMARY.json", "RESTORE.md", "prepare_mount_recipe.py",
    ):
        add("metadata/" + name, OUT / name)
    for name in (
        "FULL-JOB.log", "ARTIFACT-PINS.json", "ARTIFACTS-TERMINAL.GET.json",
        "combined-source-TRANSFER.json", "parser-bounded-TRANSFER.json",
        "custody-stream-r1/REPORT.json", "custody-stream-r1/INNER-CHUNKS-READBACK.json",
        "source-manifest-readback-r1/REPORT.json", "source-manifest-readback-r1/CANDIDATE-MANIFEST.json",
        "source-manifest-readback-r1/PREPARED-VS-ACTUAL314-DIFF.json",
        "bounded-manifest-readback-r1/REPORT.json", "verify_archive_custody.py",
        "verify_source_manifest_only.py", "verify_bounded_manifest_only.py",
        "prepare_final_metadata_capsule.py",
    ):
        add("proofs/" + name, ROOT / name)
    selected = json.loads((ROOT / "selected-originals/MANIFEST.json").read_text())["members"]
    assert len(selected) == 15
    for row in selected:
        p = ROOT / "selected-originals" / row["artifact"] / row["path"]
        assert pin(p.read_bytes()) == {k: row[k] for k in ("bytes", "sha256", "git_blob")}
        add("primary/" + row["artifact"] + "/" + row["path"], p)
    for name in ("0011-RUN.json", "0011-JOBS.json", "0011-JOBS-PAGE-SIZE-ONE.json"):
        add("terminal-api/" + name, PUBLICATION / "observations" / name)
    assert len({r["path"] for r in entries}) == len(entries)
    write("FINAL-LEAF-CANDIDATES.json", {"schema": "hia.r20.final-custody-mount-candidates.v1",
          "entries": entries, "pending_text_publications": [r for r in local if not r["independent_full_GET_complete"]],
          "source_chunk_count": 237, "whole_outer_ZIP_copies_in_Git": False,
          "whole_bounded_raw_in_Git": False, "current_source_cold": False, "whole_native": False})
    print(json.dumps({"entries": len(entries), "pending_text_publications": sum(not r["independent_full_GET_complete"] for r in local),
                      "source_chunks": 237, "metadata_parts": 14, "product_executions": 0}))


if __name__ == "__main__":
    main()
