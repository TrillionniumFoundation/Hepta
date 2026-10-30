"""Losslessly retain a completed unique-array qualification; never rerun it."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hepta.pipeline import compiler_hash


def digest(path):
    value = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            value.update(chunk)
    return value.hexdigest()


def main():
    source, output = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    start = time.perf_counter_ns()
    report_path = source / "qualification.json"
    report = json.loads(report_path.read_text())
    assert report["ok"] and report["source_bindings_unchanged"]
    assert report["compiler_sha256"] == compiler_hash()
    for relative, expected in report["source_bindings"].items():
        assert digest(ROOT / relative) == expected
    archive = output / "qualified-native-02.tar.xz"
    manifest_path, summary_path = output / "qualified-native-02.manifest.json", output / "RESULT.json"
    assert not any(path.exists() for path in (archive, manifest_path, summary_path))
    files = sorted(path for path in source.rglob("*") if path.is_file())
    assert all(not path.is_symlink() for path in source.rglob("*"))
    members = [{"path": str(path.relative_to(source)), "bytes": path.stat().st_size,
                "sha256": digest(path)} for path in files]
    with tarfile.open(archive, "w:xz", preset=6) as tar:
        for path in files:
            tar.add(path, arcname=str(path.relative_to(source)), recursive=False)
    archive_wall_ns = time.perf_counter_ns() - start
    verification_start = time.perf_counter_ns()
    with tarfile.open(archive, "r:xz") as tar:
        actual = []
        for member in tar:
            assert member.isfile()
            data = tar.extractfile(member).read()
            actual.append({"path": member.name, "bytes": len(data), "sha256": sha256(data).hexdigest()})
    assert actual == members
    for path, bound in zip(files, members):
        assert path.stat().st_size == bound["bytes"] and digest(path) == bound["sha256"]
    manifest = {"schema": "hepta.cpp-unique-native-archive.v1", "archive": archive.name,
                "bytes": archive.stat().st_size, "sha256": digest(archive), "members": members,
                "member_count": len(members), "raw_member_bytes": sum(r["bytes"] for r in members),
                "roundtrip_members_verified": True, "source_files_unchanged": True,
                "archive_creation_wall_ns": archive_wall_ns,
                "archive_verification_wall_ns": time.perf_counter_ns() - verification_start}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    summary = {"schema": "hepta.cpp-unique-qualified-result.v1", "ok": True,
               "qualified_compiler_sha256": report["compiler_sha256"],
               "compiler_source_bindings": {str(path.relative_to(ROOT)): digest(path)
                                            for path in sorted((ROOT / "hepta").glob("*.py"))},
               "source_bindings": report["source_bindings"],
               "qualification_report": {"member": "qualification.json", "bytes": report_path.stat().st_size,
                                        "sha256": digest(report_path)},
               "archive_manifest": {"path": manifest_path.name, "sha256": digest(manifest_path)},
               "archive": {key: manifest[key] for key in ("archive", "bytes", "sha256", "member_count", "raw_member_bytes")},
               "costs": report["costs"],
               "cost_boundary": "migration timer covers capture/lowering; qualification ends before report serialization; startup, serialization, archive and human engineering excluded",
               "native_original_cpp_and_generated_hia_executed": True,
               "original_cpp_objects_linked_into_generated_target": False,
               "variant_results": [{"name": row["name"], "observations": row["expected"],
                                    "project_declaration_occurrences": row["migration"]["active_declaration_count"],
                                    "standard_library_declaration_occurrences": row["migration"]["standard_library_declaration_count"],
                                    "dispositions": row["migration"]["disposition_counts"],
                                    "accounting": row["migration"]["migration_accounting"],
                                    "statistics": row["migration"]["translation_statistics"],
                                    "native_artifact": row["standalone_hia"]["artifact"],
                                    "ast_capture": row["migration"]["ast_capture"]}
                                   for row in report["variants"]],
               "missing_linear_drop_controls": report["negative_controls"],
               "qualification_source_unchanged": report["source_bindings_unchanged"],
               "standard_library_semantics_trusted": True,
               "general_cpp_source_equivalence_proved": False,
               "general_cpp_migration_supported": False,
               "performance_advantage_qualified": False,
               "general_low_cost_migration_qualified": False,
               "all_seven_user_deliverables_accepted": False}
    assert report["compiler_sha256"] == compiler_hash()
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "archive": summary["archive"], "summary_sha256": digest(summary_path),
                      "manifest_sha256": digest(manifest_path)}))


if __name__ == "__main__":
    main()
