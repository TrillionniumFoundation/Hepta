"""Verify published evidence parts and reconstruct the exact review ZIP/bundle.

This script does not compile Lean, replay acceptance, or grant proof authority.
It reads only files beside this script and writes to one fresh output directory.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import zipfile


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_record(base, record):
    name = record['name']
    assert isinstance(name, str) and PurePosixPath(name).name == name and name not in ('.', '..')
    path = base / name
    assert path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == record['bytes'] and digest(raw) == record['sha256'], name
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='Fresh directory for the exact ZIP and git bundle')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / 'review-parts.json').read_text())
    assert manifest['schema'] == 'hepta.safe-core.review-parts.v1'
    assert manifest['measured_source_commit'] == 'ce1dd749ffaf7b0905e55473164f79741facb08c'
    parts = manifest['parts']
    assert len(parts) == 6 and all(0 < r['bytes'] <= 768 * 1024 for r in parts)
    assert [r['name'] for r in parts] == [f'safe-core-review-ce1dd749-r2.zip.part{i:03d}' for i in range(1, 7)]
    raw = b''.join(read_record(base, record) for record in parts)
    archive = manifest['archive']
    assert len(raw) == archive['bytes'] and digest(raw) == archive['sha256']
    support = {r['name']: read_record(base, r) for r in manifest['supporting_files']}
    bundle = support['safe-core-candidate.bundle']
    assert len(bundle) == 55776 and digest(bundle) == '45f6deaf94002526cb253f70c0af4e080e29c2d96ab454756db3ef66cb0de4f1'
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        assert z.testzip() is None
        for name in z.namelist():
            assert not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
        inventory_raw = z.read('review-inventory.json')
        assert inventory_raw == support['review-inventory.json']
        inventory = json.loads(inventory_raw)
        for record in inventory['files']:
            if record['archive_payload'] is not None:
                payload = z.read(record['archive_payload'])
                assert len(payload) == record['bytes'] and digest(payload) == record['sha256']
        for job in inventory['durable_source_test_jobs']:
            for record in job['files']:
                payload = z.read(record['archive_payload'])
                assert len(payload) == record['bytes'] and digest(payload) == record['sha256']
        source = json.loads(z.read('manifest.json'))
        for record in source['files']:
            payload = z.read('source/' + record['path'])
            assert len(payload) == record['bytes'] and digest(payload) == record['sha256']
        assert z.read('safe-core-candidate.bundle') == bundle
        assert z.read('acceptance-outcome.json') == support['acceptance-outcome.json']
        assert z.read('upstream-qualification-boundary.json') == support['upstream-qualification-boundary.json']
        outcome = json.loads(z.read('acceptance-outcome.json'))
        assert outcome['latest_full_acceptance']['result']['status'] == 'failed'
        assert not outcome['latest_full_acceptance']['final_independent_replay_reached']
        entries = len(z.namelist())
    destination = Path(args.output)
    destination.mkdir(parents=False, exist_ok=False)
    (destination / archive['name']).write_bytes(raw)
    (destination / 'safe-core-candidate.bundle').write_bytes(bundle)
    result = dict(schema='hepta.safe-core.restore-verification.v1', archive_sha256=digest(raw),
                  archive_bytes=len(raw), source_bundle_sha256=digest(bundle), source_bundle_bytes=len(bundle),
                  zip_entries=entries, evidence_roots=len(inventory['roots']), evidence_files=len(inventory['files']),
                  source_test_jobs=len(inventory['durable_source_test_jobs']), all_included_payload_hashes_verified=True,
                  proof_acceptance_granted=False, binary_module_payloads_included=False)
    (destination / 'restore-verification.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
