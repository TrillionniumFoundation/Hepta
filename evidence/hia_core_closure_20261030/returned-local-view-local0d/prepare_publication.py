"""Retain exact local evidence as two ordered parts and explicit publication rows."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
SOURCE = OUT.parent / "returned-local-view-composition-20261030"
PREFIX = "evidence/hia_core_closure_20261030/returned-local-view-local0d"
ARCHIVE = OUT / "returned-local-view-local0d-complete.tar.gz"


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


archive = ARCHIVE.read_bytes()
receipt = json.loads((OUT / "returned-local-view-local0d-complete.readback.json").read_text())
assert len(archive) == receipt["bytes"] == 7001874
assert hashlib.sha256(archive).hexdigest() == receipt["sha256"]
parts = []
for index, offset in enumerate(range(0, len(archive), 4 * 1024 * 1024), start=1):
    data = archive[offset:offset + 4 * 1024 * 1024]
    path = OUT / (ARCHIVE.name + f".part{index:04d}")
    assert not path.exists()
    path.write_bytes(data)
    assert path.read_bytes() == data
    parts.append({"part": index, "offset": offset, "local_path": str(path),
                  "repository_path": PREFIX + "/raw-artifacts/" + path.name,
                  "mode": "100644", **identity(data)})
assert b"".join(Path(part["local_path"]).read_bytes() for part in parts) == archive
part_map = {"schema": "hepta.returned-local-view-evidence-parts.v1", "source_commit":
            "0d077885cc4be0b8ee96a012d7d6d2e51d1d2ace", "source_tree":
            "88478a74708cf63edf7f9304c0b4ceb820b04d01", "archive": ARCHIVE.name,
            "archive_identity": identity(archive), "part_count": len(parts), "parts": parts,
            "local_ordered_reconstruction_byte_exact": True,
            "remote_upload_or_restoration_claimed": False}
part_map_path = OUT / "raw-parts.json"
assert not part_map_path.exists()
part_map_path.write_text(json.dumps(part_map, sort_keys=True, indent=2) + "\n")
payloads = [
    (SOURCE / "README.md", "README.md"),
    (SOURCE / "PR_BODY.md", "PR_BODY.md"),
    (SOURCE / "final-local-scope.json", "final-local-scope.json"),
    (SOURCE / "final-safety-union-receipt.json", "final-safety-union-receipt.json"),
    (SOURCE / "source-export-final/manifest.json", "source-export-final/manifest.json"),
    (SOURCE / "source-export-final/source-change.patch", "source-export-final/source-change.patch"),
    (SOURCE / "recovery-final0d-readback.json", "recovery-final0d-readback.json"),
    (SOURCE / "peer/README.md", "peer/README.md"),
    (SOURCE / "peer/review.json", "peer/review.json"),
    (OUT / "returned-local-view-local0d-complete.members.json", "archive-members.json"),
    (OUT / "returned-local-view-local0d-complete.readback.json", "archive-readback.json"),
    (part_map_path, "raw-parts.json"),
    (OUT / "restore_archive.py", "restore_archive.py"),
    (Path(__file__), "prepare_publication.py"),
]
files = []
for path, relative in payloads:
    data = path.read_bytes()
    files.append({"local_path": str(path), "repository_path": PREFIX + "/" + relative,
                  "mode": "100644", **identity(data)})
files.extend(parts)
result = {"schema": "hepta.returned-local-view-publication.v1",
          "source_commit": part_map["source_commit"], "source_tree": part_map["source_tree"],
          "public_source_base": "b121c9b4a57a8a58e53360d1d67387d953348f57",
          "public_candidate_commit": None, "public_source_execution": False,
          "archive": {"local_path": str(ARCHIVE), **identity(archive), "member_count": 238},
          "files": files, "payload_files": len(files),
          "payload_bytes": sum(row["bytes"] for row in files),
          "also_publish_this_map": True, "map_repository_path": PREFIX + "/publication-files.json",
          "all_original_inputs_unchanged": True,
          "all_local_parts_reconstruct_exact_archive": True,
          "original_peer_inputs_139_verified": True,
          "original_peer_inputs_owner_122_within_main_archive": True,
          "original_peer_inputs_peer_17_within_retained_nested_peer_archive": True,
          "remote_publication_performed_by_this_agent": False,
          "new_native_or_test_executions_in_recovery": 0,
          "broad_P0_P7_closed": False}
target = OUT / "publication-files.json"
assert not target.exists()
target.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
print(json.dumps({"map": str(target), "payload_files": len(files),
                  "payload_bytes": result["payload_bytes"], "archive": identity(archive)}))
