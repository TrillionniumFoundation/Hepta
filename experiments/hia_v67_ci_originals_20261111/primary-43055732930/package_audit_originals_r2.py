"""Archive and independently read back every small original custody input."""
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import stat
import tarfile

ROOT = Path(__file__).resolve().parent
EXCLUDE = {'original-zip-parts', 'hia-core-608157e5-primary-43055732930-1.zip', 'audit-originals-r2.tar.xz', 'upload-receipts', 'LOCAL-GIT-BYTES.json', 'publication', 'roundtrip-r1', 'AUDIT-ORIGINALS-r2.json'}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def inventory():
    rows = []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in EXCLUDE:
            continue
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        row = {'path': relative.as_posix(), 'type': 'file' if path.is_file() else 'directory',
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'mtime_ns': info.st_mtime_ns, 'size': info.st_size if path.is_file() else 0}
        if path.is_file():
            row['sha256'] = digest(path)
        rows.append(row)
    return rows


def main():
    before = inventory()
    output = ROOT / 'audit-originals-r2.tar.xz'
    with output.open('xb') as stream, tarfile.open(fileobj=stream, mode='w:xz', format=tarfile.PAX_FORMAT) as archive:
        for row in before:
            path = ROOT / row['path']
            info = archive.gettarinfo(str(path), arcname=row['path'])
            info.pax_headers['mtime'] = str(Decimal(row['mtime_ns']) / Decimal(1_000_000_000))
            if row['type'] == 'file':
                with path.open('rb') as original:
                    archive.addfile(info, original)
            else:
                archive.addfile(info)
    observed = []
    with tarfile.open(output, 'r:xz') as archive:
        for member in archive:
            row = {'path': member.name, 'type': 'file' if member.isfile() else 'directory',
                   'mode': member.mode, 'uid': member.uid, 'gid': member.gid,
                   'mtime_ns': int(Decimal(member.pax_headers['mtime']) * 1_000_000_000),
                   'size': member.size}
            if member.isfile():
                value = hashlib.sha256()
                source = archive.extractfile(member)
                for block in iter(lambda: source.read(1 << 20), b''):
                    value.update(block)
                row['sha256'] = value.hexdigest()
            else:
                assert member.isdir()
            observed.append(row)
    assert observed == before == inventory()
    report = {'schema': 'hia.typed-originals-preservation.v1', 'status': 'EXACT_TYPED_ORIGINALS_READBACK_PASS',
              'archive': {'name': output.name, 'size': output.stat().st_size, 'sha256': digest(output)},
              'members': before, 'members_count': len(before),
              'regular_bytes': sum(row['size'] for row in before),
              'all_bytes_modes_uid_gid_mtime_ns_verified': True,
              'input_inventory_before_equals_after': True, 'qualification_executed': False}
    with (ROOT / 'AUDIT-ORIGINALS-r2.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'members'}))


if __name__ == '__main__':
    main()
