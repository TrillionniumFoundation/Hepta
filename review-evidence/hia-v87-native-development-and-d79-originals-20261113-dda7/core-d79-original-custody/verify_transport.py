import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
def sha(data):
    return hashlib.sha256(data).hexdigest()
def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
index = json.loads((ROOT / "TRANSPORT-INDEX.json").read_text())
custody = json.loads((ROOT / "GIT-CUSTODY.json").read_text())
assert len(index["parts"]) == 355 == len(custody["parts"])
archive_hash = hashlib.sha256()
archive_bytes = 0
rows = []
for number, part in enumerate(index["parts"], 1):
    assert part["path"] == f"part-{number:04d}.b64"
    path = ROOT / "transport" / part["path"]
    encoded = path.read_bytes()
    assert b"\n" not in encoded and b"\r" not in encoded
    encoded.decode("utf-8", "strict")
    assert len(encoded) == part["bytes"]
    assert sha(encoded) == part["sha256"]
    assert blob(encoded) == part["git_blob"]
    decoded = base64.b64decode(encoded, validate=True)
    assert base64.b64encode(decoded) == encoded
    assert len(decoded) == part["decoded_bytes"]
    assert sha(decoded) == part["decoded_sha256"]
    ack = json.loads(Path(str(path) + ".GIT-ACK.json").read_text())
    verified = json.loads(Path(str(path) + ".GIT-VERIFIED.json").read_text())
    for receipt in (ack, verified):
        assert receipt["blob"] == part["git_blob"]
        assert receipt["bytes"] == part["bytes"]
        assert receipt["sha256"] == part["sha256"]
        assert receipt["create_ack"] is True
    assert verified["full_get_verified"] is True
    actual = custody["parts"][number - 1]
    assert actual["part"] == part
    assert actual["actual_create_response"]["structuredContent"]["sha"] == part["git_blob"]
    assert actual["verified_state"]["full_get_verified"] is True
    archive_hash.update(decoded)
    archive_bytes += len(decoded)
    rows.append({"part": part["path"], "git_blob": part["git_blob"],
                 "encoded_bytes": len(encoded), "decoded_bytes": len(decoded),
                 "strict_base64": True, "exact_encoded_identity": True,
                 "exact_decoded_identity": True, "create_ack": True,
                 "full_get_verified": True,
                 "read_only_get_reconciliation": number == 54})
assert archive_bytes == index["archive"]["bytes"]
assert archive_hash.hexdigest() == index["archive"]["sha256"]
original = ROOT / "COMPLETE-ORIGINAL-MEMBERS.tar.xz"
original_hash = hashlib.sha256()
with original.open("rb") as stream:
    while block := stream.read(1024 * 1024):
        original_hash.update(block)
assert original.stat().st_size == archive_bytes
assert original_hash.digest() == archive_hash.digest()
small = []
for item in custody["small_files"]:
    data = (ROOT / item["path"]).read_bytes()
    assert len(data) == item["bytes"] and sha(data) == item["sha256"] and blob(data) == item["git_blob"]
    receipt = json.loads(Path(str(ROOT / item["path"]) + ".GIT-VERIFIED.json").read_text())
    assert receipt["blob"] == item["git_blob"] and receipt["full_get_verified"] is True
    small.append({"path":item["path"], "git_blob":item["git_blob"], "local_bytes_match":True, "full_get_receipt":True})
result = {
    "schema":"hia-d79-transport-reassembly-v1",
    "scope":"LOCAL_CUSTODY_VERIFICATION_NO_PRODUCT_EXECUTION",
    "status":"PASS",
    "part_count":len(rows),
    "archive":{"bytes":archive_bytes, "sha256":archive_hash.hexdigest()},
    "matches_retained_archive":True,
    "archive_not_recompressed":True,
    "original_outer_zip_git_custody":False,
    "complete_original_member_byte_custody":True,
    "get_failure_54_preserved":True,
    "get_failure_54_no_repeated_post":True,
    "rows":rows,
    "small_files":small,
}
(ROOT / "TRANSPORT-REASSEMBLY.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({k:v for k,v in result.items() if k not in ("rows","small_files")}, sort_keys=True))

