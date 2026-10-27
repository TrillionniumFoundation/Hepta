"""Check retained archive bytes and its complete member inventory; never extract."""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    assert manifest["schema"] == "hepta.cpp-composed-llvm-evidence-archive.v1"
    encoded = b"".join((directory / "executions.tar.xz.base64").read_bytes().splitlines())
    raw = base64.b64decode(encoded, validate=True)
    assert len(raw) == manifest["archive_bytes"]
    assert hashlib.sha256(raw).hexdigest() == manifest["archive_sha256"]
    expected = {item["path"]: item for item in manifest["members"]}
    assert len(expected) == len(manifest["members"])
    actual = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:xz") as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            assert entry.isfile() and not name.is_absolute() and ".." not in name.parts
            assert entry.name in expected and entry.name not in actual
            wanted = expected[entry.name]
            assert entry.size == wanted["bytes"]
            stream = archive.extractfile(entry)
            assert stream is not None
            data = stream.read()
            assert len(data) == wanted["bytes"] and hashlib.sha256(data).hexdigest() == wanted["sha256"]
            actual.add(entry.name)
    assert actual == set(expected)
    frozen = (directory / "frozen-report.json").read_bytes()
    assert hashlib.sha256(frozen).hexdigest() == expected["artifacts/composed-llvm-frozen.json"]["sha256"]
    return {"ok": True, "members": len(actual), "archive_bytes": len(raw),
            "source_commit": manifest["frozen_source_commit"], "artifacts_executed": False}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
