#!/usr/bin/env python3
"""Recheck retained installation readback offline."""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def read(name):
    return json.loads((ROOT / name).read_text())

def main():
    lock_bytes = (ROOT / "public-release-lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    lock_source = read("public-release-lock.source.json")
    describe = read("describe-manifest-01.response.json")["structuredContent"]
    observed = read("read-manifest-01.response.json")["structuredContent"]
    artifact = observed["result"]["content"].encode("utf-8")
    manifest = json.loads(artifact)
    failure = read("describe-manifest-02.response.json")
    assert sha256(lock_bytes).hexdigest() == lock_source["expected_sha256"]
    assert observed["status"] == describe["status"] == "completed"
    assert observed["result"]["next_cursor"] is None
    assert describe["result"]["manifest"] == observed["result"]["artifact"]
    assert sha256(artifact).hexdigest() == observed["result"]["artifact"]["sha256"]
    assert artifact == (ROOT / "retained-manifest-01.json").read_bytes()
    assert manifest["installation"] == lock["installation"]
    assert manifest["catalog_sha256"] == lock["installation"]["catalog_sha256"]
    assert failure["isError"] is True
    assert any("-32603" in item.get("text", "") for item in failure["content"])
    assert read("describe-manifest-01.request.json")["arguments"] == read("describe-manifest-02.request.json")["arguments"]
    print(json.dumps({"identity_readback": "PASS", "artifact_digest": "PASS", "release_lock_digest": "PASS", "independent_repeat": "FAILED_WITH_MINUS_32603", "overall_six_gate_acceptance": "NOT_CLOSED"}, sort_keys=True))

if __name__ == "__main__":
    main()
