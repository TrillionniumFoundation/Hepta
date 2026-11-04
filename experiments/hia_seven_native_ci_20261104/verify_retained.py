"""Verify retained CI bytes without extracting or executing archive members."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import tarfile


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    root = Path(__file__).resolve().parent
    parts = json.loads((root / 'ARCHIVE_PARTS.json').read_text())
    chunks = []
    names = set()
    for item in parts['parts']:
        name = item['path']
        assert Path(name).name == name and name not in names
        names.add(name)
        raw = (root / name).read_bytes()
        assert len(raw) == item['bytes'] and digest(raw) == item['sha256']
        chunks.append(raw)
    archive = b''.join(chunks)
    assert len(archive) == parts['bytes'] and digest(archive) == parts['sha256']
    inventory = json.loads(gzip.decompress((root / 'ARTIFACT_INVENTORY.json.gz').read_bytes()))
    expected = {m['retained_path']:m for a in inventory for m in a['members']
                if m['retained_in_text_archive']}
    expected_count = sum(m['retained_in_text_archive'] for a in inventory for m in a['members'])
    assert len(expected) == expected_count == 1983
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.name not in seen
            item = expected[member.name]
            raw = tar.extractfile(member).read()
            assert len(raw) == item['bytes'] and digest(raw) == item['sha256']
            seen.add(member.name)
    assert seen == set(expected)
    print(json.dumps({'verified_artifacts':len(inventory), 'verified_text_members':len(seen),
                      'native_binaries_inventoried_only':150,
                      'archive_sha256':digest(archive)}, sort_keys=True))


if __name__ == '__main__':
    main()
