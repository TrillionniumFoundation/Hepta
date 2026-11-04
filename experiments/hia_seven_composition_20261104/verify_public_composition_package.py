#!/usr/bin/env python3
"""Independently verify a public composition evidence package without executing evidence."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile

PRIVATE_PREFIXES = ("evidence/raw-ndu-build/hepta-contracts/", "evidence/raw-ndu-build/hepta-ndu/", "evidence/raw-ndu-build/hepta-types/")
FORBIDDEN_PARTS = {".git", ".cargo", "vendor", "third_party", "third-party", "registry", "checkouts"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def safe_relative(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and all(p not in ("", ".", "..") for p in path.parts), name
    return path

def verify(package):
    manifest_bytes=(package/"MANIFEST.json").read_bytes()
    manifest=json.loads(manifest_bytes)
    assert manifest["schema"]=="hepta.hia.composition-evidence-publication.v2"
    assert manifest["public_scope_version"]==2
    assert manifest["public_scope"]["private_upstream_content_archived"] is False
    assert manifest["public_scope"]["dependency_vendor_snapshots_archived"] is False
    producer=package.parent/"package_composition_evidence.py"
    assert sha(producer.read_bytes())==manifest["producer_sha256"]
    index=json.loads((package/"PUBLICATION_FILES.json").read_text())
    assert len({x["path"] for x in index["files"]})==len(index["files"])
    for entry in index["files"]:
        assert len(safe_relative(entry["path"]).parts)==1
        data=(package/entry["path"]).read_bytes()
        assert len(data)==entry["bytes"] and sha(data)==entry["sha256"], entry["path"]
    assert {p.name for p in package.iterdir()}=={e["path"] for e in index["files"]}|{"PUBLICATION_FILES.json"}
    inv_meta=manifest["inventory"]
    compressed=(package/inv_meta["path"]).read_bytes()
    assert len(compressed)==inv_meta["bytes"] and sha(compressed)==inv_meta["sha256"]
    inv_bytes=gzip.decompress(compressed)
    assert len(inv_bytes)==inv_meta["uncompressed_bytes"] and sha(inv_bytes)==inv_meta["uncompressed_sha256"]
    entries=[json.loads(line) for line in inv_bytes.splitlines()]
    assert len(entries)==inv_meta["entries"]==len({e["path"] for e in entries})
    expected={e["path"]:e for e in entries if e["archived"]}
    private=[e for e in entries if e["path"].startswith(PRIVATE_PREFIXES)]
    assert len(private)==115 and all(not e["archived"] for e in private)
    for name in expected:
        safe_relative(name)
        assert not name.startswith(PRIVATE_PREFIXES), name
        assert not (set(PurePosixPath(name).parts)&FORBIDDEN_PARTS), name
    observed_command_receipts=[name for name in expected if name.startswith("evidence/commands/") and name.endswith(".command.json")]
    assert len(observed_command_receipts)==31
    for name in ("RESULT.json","PLAN.json","COMBINATION.json","CORE.json","ndu-cost/REPORT.json","raw-service-cost/ORIGINAL.jsonl","raw-service-cost/ORIGINAL.jsonl.gz","raw-service-cost/RESULT.json","raw-service-cost/REGISTRATION.json","commands/ndu_model_planner.command.json"):
        assert "evidence/"+name in expected, name
    for binding in manifest["public_scope"]["verified_tracked_hepta_adapter_files"]:
        entry=expected["evidence/"+binding["input_path"]]
        assert entry["sha256"]==binding["sha256"] and entry["bytes"]==binding["bytes"]
    with tempfile.TemporaryDirectory(prefix="hia-public-package-verify-") as tmp:
        tar_path=Path(tmp)/"payload.tar"
        raw_hash=hashlib.sha256()
        compressed_hash=hashlib.sha256()
        offset=0
        with tar_path.open("xb") as f:
            for part in manifest["archive"]["parts"]:
                assert len(safe_relative(part["path"]).parts)==1
                data=(package/part["path"]).read_bytes()
                assert len(data)==part["bytes"]<=manifest["archive"]["part_limit_bytes"]
                assert sha(data)==part["sha256"]
                raw=gzip.decompress(data)
                assert offset==part["tar_offset"]
                assert len(raw)==part["uncompressed_bytes"] and sha(raw)==part["uncompressed_sha256"]
                f.write(raw)
                raw_hash.update(raw)
                compressed_hash.update(data)
                offset+=len(raw)
        assert offset==manifest["archive"]["tar_bytes"]
        assert raw_hash.hexdigest()==manifest["archive"]["tar_sha256"]
        assert compressed_hash.hexdigest()==manifest["archive"]["concatenated_gzip_sha256"]
        seen={}
        with tarfile.open(tar_path,"r") as archive:
            for member in archive:
                assert member.name in expected and member.name not in seen
                assert member.isfile() or member.islnk()
                if member.islnk():
                    assert member.linkname in seen and seen[member.linkname].isfile()
                    assert expected[member.name]["sha256"]==expected[member.linkname]["sha256"]
                h=hashlib.sha256();size=0
                stream=archive.extractfile(member)
                assert stream is not None
                for block in iter(lambda:stream.read(1024*1024),b""):
                    h.update(block);size+=len(block)
                assert h.hexdigest()==expected[member.name]["sha256"] and size==expected[member.name]["bytes"], member.name
                seen[member.name]=member
        assert set(seen)==set(expected) and len(seen)==manifest["archived_entries"]
    return {"schema":"hepta.hia.public-package-independent-verification.v1","package":str(package),"manifest_sha256":sha(manifest_bytes),"source_commit":manifest["source_commit"],"public_scope_version":2,"archive_members_verified":len(expected),"private_source_files_inventory_only":len(private),"private_source_bytes_inventory_only":sum(e["bytes"] for e in private),"command_receipts":len(observed_command_receipts),"whole_raw_measurement_stream_preserved":True,"original_qualification_commands_passed":manifest["qualification_commands_passed"],"passed":True}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("packages",nargs="+")
    args=ap.parse_args()
    for name in args.packages:
        print(json.dumps(verify(Path(name).resolve()),sort_keys=True),flush=True)

if __name__=="__main__":
    main()
