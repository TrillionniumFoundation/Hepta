"""Archive the exact additive child and compare every ZIP file to its Git blob/mode."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import stat
import subprocess
import time
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT / 'hepta-integration'
IMPLEMENTATION = '953fa62dee5aa563551d57b1374ab95b6d548b45'


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO)


def main():
    head = git('rev-parse', 'HEAD').decode().strip()
    tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    if git('status', '--porcelain') or git('rev-parse', 'HEAD^').decode().strip() != IMPLEMENTATION:
        raise ValueError('clean one-child delivery required')
    for row in git('diff', '--name-status', IMPLEMENTATION, head).decode().splitlines():
        status, name = row.split('\t')
        if status != 'A' or not (name.startswith('evidence/hia_next2_') or name == 'docs/HIA_NEXT2_STRICT_RESULTS_20261030.md'):
            raise ValueError('not an additive evidence/documentation child')
    prefix = 'Hepta-HIA-P0-P7-' + head[:7] + '/'
    target = ROOT / ('Hepta-HIA-P0-P7-20261030-' + head[:7] + '.zip')
    if target.exists():
        raise ValueError('refuse to overwrite any prior delivery')
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start = time.monotonic_ns()
    subprocess.run(['git', '--no-replace-objects', 'archive', '--format=zip', '--prefix=' + prefix,
                    '--output=' + str(target), head], cwd=REPO, check=True)
    archive_ns = time.monotonic_ns() - start
    start = time.monotonic_ns()
    expected = {}
    for row in git('ls-tree', '-r', '-z', head).split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1)
            mode, kind, oid = meta.split()
            if kind != b'blob':
                raise ValueError('non-blob Git tree member')
            expected[os.fsdecode(name)] = (mode.decode(), oid.decode())
    actual, total = set(), 0
    with zipfile.ZipFile(target) as archive:
        if archive.comment.decode() != head:
            raise ValueError('Git archive commit comment differs')
        for info in archive.infolist():
            if not info.filename.startswith(prefix):
                raise ValueError('archive prefix differs')
            name = info.filename[len(prefix):]
            if info.is_dir():
                continue
            if name in actual or name not in expected:
                raise ValueError('duplicate or unexpected ZIP member')
            actual.add(name)
            mode, oid = expected[name]
            permissions = info.external_attr >> 16
            if mode == '120000':
                if not stat.S_ISLNK(permissions):
                    raise ValueError('ZIP link mode differs')
            elif bool(permissions & stat.S_IXUSR) != (mode == '100755'):
                raise ValueError('ZIP owner execute mode differs')
            digest = hashlib.sha1(b'blob ' + str(info.file_size).encode() + b'\0')
            count = 0
            with archive.open(info) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    count += len(block)
                    digest.update(block)
            if count != info.file_size or digest.hexdigest() != oid:
                raise ValueError('ZIP member differs from Git blob: ' + name)
            total += count
    if actual != set(expected):
        raise ValueError('incomplete full-source ZIP')
    digest = hashlib.sha256()
    with target.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    manifest = REPO / 'evidence/hia_next2_integrated_20261030/DELIVERY_FILES.json'
    result = {'schema': 'hepta.hia.next2.full-source-archive.v1', 'started_utc': started_utc,
        'commit': head, 'tree': tree, 'implementation_commit': IMPLEMENTATION,
        'archive': target.name, 'archive_bytes': target.stat().st_size,
        'archive_sha256': digest.hexdigest(), 'tracked_files_verified': len(actual),
        'expanded_file_bytes': total, 'all_Git_blobs_and_owner_execute_modes_match': True,
        'archive_creation_wall_ns': archive_ns,
        'archive_readback_and_digest_wall_ns': time.monotonic_ns() - start,
        'delivery_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
        'archive_payload_executed': False, 'prior_delivery_archives_overwritten': False,
        'model_or_toolchain_binary_payloads_added': False}
    with target.with_suffix('.archive.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    target.with_suffix('.sha256').write_text(digest.hexdigest() + '  ' + target.name + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
