"""Stream retained P7 files into a portable archive without copying weights/runtime."""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import stat
import tarfile
import time

ROOT = Path('/workspace/scratch/f0c12f106c89')
STAGING = Path(__file__).resolve().parent
FRESH = ROOT / 'p7-v12-integrated-44e34b7a'
PREFIX = 'p7-v12-20261030'


def identity(path):
    value, size = hashlib.sha256(), 0
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': value.hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    started = time.monotonic_ns()
    archive = STAGING / (PREFIX + '.tar.xz')
    partial = archive.with_name(archive.name + '.partial')
    manifest = STAGING / (PREFIX + '.manifest.json')
    receipt_path = STAGING / 'PACKAGING_RECEIPT.json'
    if any(path.exists() for path in (archive, partial, manifest, receipt_path)):
        raise RuntimeError('Refuse overwrite of an existing bundle attempt')
    receipt = {'schema': 'hepta.p7.evidence-packaging.v1', 'status': 'incomplete',
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'model_weights_included': False, 'system_runtime_binary_copy_included': False,
               'raw_staging_copy_created': False, 'builder': identity(Path(__file__).resolve())}
    save(receipt_path, receipt)
    try:
        entries = []
        for category, directory in [('fresh', FRESH), ('context', STAGING / 'context'), ('historical', STAGING / 'historical')]:
            for source in sorted(directory.rglob('*')):
                info = source.lstat()
                if stat.S_ISDIR(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode) or source.name.endswith('.gguf'):
                    raise RuntimeError('Only retained regular evidence files are permitted')
                name = PREFIX + '/' + category + '/' + source.relative_to(directory).as_posix()
                entries.append({'name': name, 'source_path': str(source), **identity(source)})
        peer = STAGING / 'P7_PEER_REVIEW.json'
        if not stat.S_ISREG(peer.lstat().st_mode):
            raise RuntimeError('Independent peer review must be a regular retained file')
        entries.append({'name': PREFIX + '/review/P7_PEER_REVIEW.json',
                        'source_path': str(peer), **identity(peer)})
        if len(entries) != len({item['name'] for item in entries}):
            raise RuntimeError('Duplicate archive name')
        receipt['input_files'] = len(entries)
        receipt['input_bytes'] = sum(row['bytes'] for row in entries)
        before = time.monotonic_ns()
        with tarfile.open(partial, mode='w:xz', preset=6) as output:
            for row in entries:
                header = tarfile.TarInfo(row['name'])
                header.size = row['bytes']
                header.mode = 0o644
                header.mtime = 0
                header.uid = header.gid = 0
                with Path(row['source_path']).open('rb') as source:
                    output.addfile(header, source)
        receipt['compression_wall_ns'] = time.monotonic_ns() - before
        before = time.monotonic_ns()
        for row in entries:
            if identity(Path(row['source_path'])) != {key: row[key] for key in ('bytes', 'sha256')}:
                raise RuntimeError('Raw evidence changed during packaging')
        receipt['raw_input_recheck_wall_ns'] = time.monotonic_ns() - before
        partial.replace(archive)
        archive_id = identity(archive)
        value = {'schema': 'hepta.p7.evidence-manifest.v1',
                 'source_commit': '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304',
                 'archive': {'filename': archive.name, **archive_id},
                 'member_count': len(entries), 'uncompressed_bytes': sum(row['bytes'] for row in entries),
                 'all_raw_fresh_outputs_included': True, 'model_weights_included': False,
                 'system_runtime_binaries_included': False,
                 'historical_protocols_are_not_fresh_trial_results': True, 'entries': entries}
        save(manifest, value)
        receipt.update(status='created_pending_independent_full_readback', archive={'path': str(archive), **archive_id},
                       manifest={'path': str(manifest), **identity(manifest)}, original_raw_inputs_unchanged=True)
    except BaseException as exc:
        receipt['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        receipt['packaging_total_wall_ns'] = time.monotonic_ns() - started
        save(receipt_path, receipt)
        print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
