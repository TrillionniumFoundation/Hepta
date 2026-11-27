#!/usr/bin/env python3
"""Seal the completed original 136-oracle owner metadata, never its payload."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import zlib

OUT = Path('/tmp/hia-r8-original-oracle-custody-r2-dda7')
VIEW = Path('/dev/shm/hia-u32-r8-oracles-r3-dda7')
OUTER = Path('/tmp/hia-r8-original-oracle-r3-outer-dda7')
AUTHOR = Path('/tmp/hia-u32-r8-post-reset-r3-dda7')
ROOT = Path('/tmp/hia-progress-v148-20261114-dda7')
RECOVERY = Path('/tmp/hia-r8-inputs-recovery-20261114-dda7')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def dump(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def seven(s):
    return [getattr(s, field) for field in FIELDS]


def capture(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, str(path)
    raw = path.read_bytes()
    after = path.lstat()
    assert seven(before) == seven(after), str(path)
    assert len(raw) == before.st_size, str(path)
    return raw, {'path': str(path), 'identity': pin(raw),
                 'mode': stat.S_IMODE(before.st_mode), 'seven_stats': seven(before)}


def new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    os.chmod(path, 0o644)


def files_under(root):
    rows = []
    for here, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            assert stat.S_ISDIR((Path(here) / name).lstat().st_mode)
        for name in names:
            p = Path(here) / name
            assert stat.S_ISREG(p.lstat().st_mode)
            rows.append(p)
    return sorted(rows)



def main():
    started = time.time_ns()
    selected, directories = [], []
    for prefix, root in [('owner', Path(str(VIEW) + '.owner')), ('outer', OUTER),
                         ('root-readback', ROOT / 'r8-oracle-root-readback-r1')]:
        paths = files_under(root)
        directories.append({'prefix': prefix, 'path': str(root),
                            'mode': stat.S_IMODE(root.lstat().st_mode),
                            'relative_pathset': [str(p.relative_to(root)) for p in paths]})
        selected.extend((prefix + '/' + p.relative_to(root).as_posix(), p) for p in paths)
    assert len(selected) == 21
    selected.extend(('destination/' + name, VIEW / name) for name in ('RESTORE-RESULT.json', 'STORAGE-BEFORE.json'))
    selected.extend(('author/' + name, AUTHOR / name) for name in ('ORACLE-RESTORE-PLAN.json', 'ORACLE-LAUNCH.json', 'restore_oracles.py'))
    selected.extend(('root-controls/' + name, ROOT / name) for name in ('read_r8_oracle.py', 'launch_r8_oracle.py', 'R8-ORACLE-AUTHORIZATION.json'))
    assert len(selected) == len(set(x[0] for x in selected)) == 29
    selected.extend(('custody-history/r1/' + name, Path('/tmp/hia-r8-original-oracle-custody-r1-dda7') / name) for name in ('build_capsule.py', 'FAILURE.json'))
    selected.append(('custody-history/CUSTODY-AUTHOR-R2-DIFF.json', OUT / 'CUSTODY-AUTHOR-R2-DIFF.json'))
    rows, originals = [], {}
    patterns = [rb'(?i)https?://[^\s\"\x27]+[?&](?:sig|token|x-amz-signature)=',
                rb'(?i)\"(?:authorization|set-cookie)\"\s*:\s*\"[^\"]+\"',
                rb'(?im)^Authorization:\s*\S+', rb'(?im)^Set-Cookie:\s*\S+']
    for logical, path in selected:
        raw, desc = capture(path)
        assert not any(re.search(p, raw) for p in patterns), logical
        originals[logical] = raw
        rows.append({'logical_path': logical, **desc, 'content_base64': base64.b64encode(raw).decode('ascii')})
    plan = json.loads(originals['author/ORACLE-RESTORE-PLAN.json'])
    result = json.loads(originals['destination/RESTORE-RESULT.json'])
    assert result['status'] == 'PASS_EXACT_ORIGINAL_ORACLES_ONLY'
    assert len(result['restored']) == len(plan['restore_order']) == 136
    assert set(result['restored']) == set(plan['restore_order'])
    restored_raw, restored_desc = capture(RECOVERY / 'RESTORED-MANIFEST.json')
    recovered = json.loads(restored_raw)
    compact = [row for row in recovered['files'] if row['provenance'].get('family') == 'compact-R1-R5-CAS']
    old = {row['provenance']['logical']: row for row in compact}
    assert len(old) == len(compact) == 497
    catalog_rows = []
    for ordinal, logical in enumerate(plan['restore_order']):
        actual = result['restored'][logical]
        required = plan['required'][logical]
        source = old[logical]
        assert source['original_path'] == '/workspace/scratch/dda74a4fae35/u32-r8-original-oracles-20261114-r1/' + logical
        assert source['provenance']['archive'] == result['archive']
        assert actual['identity'] == required['identity'] == source['required_identity']
        assert actual['archive_member'] == required['archive_member'] == source['provenance']['member']
        assert source['provenance']['family'] == 'compact-R1-R5-CAS'
        assert required['path'] == str(VIEW / logical)
        assert actual['original_path'] == required['original_path']
        catalog_rows.append({'ordinal': ordinal, 'logical_path': logical, 'destination': required['path'],
                             'identity': actual['identity'], 'new_stat': actual['stat'],
                             'original_path': actual['original_path'],
                             'prior_recovery_expected_original_path': source['original_path'],
                             'two_distinct_historical_path_roles_preserved': True,
                             'prior_static_recovery': str(RECOVERY / source['target']),
                             'existing_payload_transport': source['provenance'],
                             'payload_bytes_in_this_capsule': 0})
    assert sum(r['identity']['bytes'] for r in catalog_rows) == 578353224
    catalog = {'schema': 'hepta.r8.original-oracle.metadata.payload-reference-catalog.v1',
               'original_ordered_136': catalog_rows, 'all_required_496': plan['required'],
               'ordered_restored_files': 136, 'restored_payload_bytes': 578353224,
               'total_required_files': 496, 'total_required_bytes': 704110777,
               'existing_static_recovery_manifest': restored_desc,
               'compact_recipe_git': 'cfa86d512908e463f093abd3653dc56846e9ab66',
               'compact_index_git': '11f0be3569dc04273f0e285fec5045e87b86fea2',
               'compact_archive': result['archive'],
               'prior_808_preparation_custody_recipe_git': '1d6b2979f1d3b1aea44886d3629986b48fbcd713',
               'source_custody_recipe_git': 'f4f8ef86024dae943b2b37ff53601cd923d5e659',
               'runtime_custody_recipe_git': '7f63bc96a951a254096e40ba06d30b5087f22ed1',
               'payload_bytes_in_this_capsule': 0,
               'historical_missing_originals_retained': result['known_original_missing_history']}
    new(OUT / 'PAYLOAD-REFERENCES.json', dump(catalog))
    raw, desc = capture(OUT / 'PAYLOAD-REFERENCES.json')
    rows.append({'logical_path': 'custody/PAYLOAD-REFERENCES.json', **desc,
                 'content_base64': base64.b64encode(raw).decode('ascii')})
    capsule = {'schema': 'hepta.lossless.metadata-files.base64.v1',
               'scope': 'Original 136-oracle restoration owner, destination metadata, outer, Root reader/readback and actual controls only; no oracle or other source/input/runtime payload.',
               'directories': directories, 'files': rows}
    raw = dump(capsule)
    packed = zlib.compress(raw, 9)
    assert zlib.decompress(packed) == raw
    decoded = json.loads(zlib.decompress(packed))
    names = []
    for row in decoded['files']:
        content = base64.b64decode(row['content_base64'], validate=True)
        assert pin(content) == row['identity']
        original, desc = capture(Path(row['path']))
        assert content == original and desc['mode'] == row['mode'] and desc['seven_stats'] == row['seven_stats']
        names.append(row['logical_path'])
    assert len(names) == len(set(names)) == 33
    for d in directories:
        assert [str(p.relative_to(d['path'])) for p in files_under(Path(d['path']))] == d['relative_pathset']
    (OUT / 'parts').mkdir()
    parts = []
    for ordinal, offset in enumerate(range(0, len(packed), 384000)):
        piece = packed[offset:offset + 384000]
        name = 'parts/%03d.json' % ordinal
        part = dump({'schema': 'hepta.zlib.metadata-capsule-part.v1', 'index': ordinal, 'offset': offset,
                     'decoded_part': pin(piece), 'complete_archive': pin(packed),
                     'base64': base64.b64encode(piece).decode('ascii')})
        new(OUT / name, part)
        parts.append({'path': name, 'mode': 0o644, 'identity': pin(part), 'decoded_part': pin(piece), 'offset': offset})
    index = {'schema': 'hepta.r8.original-oracle.metadata-custody-index.v1',
             'files': [{k: v for k, v in row.items() if k != 'content_base64'} for row in rows],
             'directories': directories, 'logical_files': 33, 'logical_bytes': sum(r['identity']['bytes'] for r in rows),
             'capsule_json': pin(raw), 'compressed_zlib': pin(packed), 'parts': parts,
             'source_input_runtime_oracle_payload_bytes_included': 0}
    new(OUT / 'INDEX.json', dump(index))
    owner = json.loads(originals['owner/OWNER-RETURNED.json'])
    outer = json.loads(originals['outer/RESULT.json'])
    proof = json.loads(originals['root-readback/RESULT.json'])
    assert outer['returncode'] == 0 and outer['ECHILD'] and outer['process_group_absent']
    assert proof['status'] == 'PASS_ORIGINAL_136_RESTORE_AND_ALL_496_CURRENT_INPUTS'
    report = {'schema': 'hepta.r8.original-oracle.complete-metadata-custody.v1',
              'status': 'PASS_ORIGINAL_136_ORACLE_METADATA_CUSTODY_ONLY',
              'created_unix_ns': time.time_ns(), 'elapsed_ns': time.time_ns() - started,
              'original_metadata_files': 29, 'custody_author_history_files': 3, 'reference_catalogs': 1, 'capsule_files': 33,
              'logical_bytes': index['logical_bytes'], 'compressed_bytes': len(packed), 'parts': len(parts),
              'original_owner': owner, 'original_outer': outer, 'root_independent_readback': proof,
              'root_full496_readback': pin(originals['root-readback/FULL-496-READBACK.json']),
              'all_original_metadata_fullbytes_modes_stats_readback': True,
              'payload_reference_catalog': pin((OUT / 'PAYLOAD-REFERENCES.json').read_bytes()),
              'index': pin((OUT / 'INDEX.json').read_bytes()),
              'historical_missing_originals_retained': result['known_original_missing_history'],
              'oracle_payloads_in_capsule': 0, 'oracle_payload_bytes_in_capsule': 0,
              'original_oracle_owner_executed_in_retained_stage': 1,
              'original_owner_budget_seconds': 180, 'original_cleanup_budget_seconds': 3,
              'outer_watchdog_seconds': 210, 'outer_watchdog_is_not_qualification_budget': True,
              'products_executed_by_custody': 0, 'new_product_observations_in_capsule': 0,
              'CI': 0, 'refs': 0, 'credentials_observed_or_included': 0,
              'limit': 'Static source and original-oracle restoration/custody only. The later eight product groups are outside this immutable stage, with no PASS or qualification inferred here.'}
    new(OUT / 'REPORT.json', dump(report))
    publication = []
    for name in ['INDEX.json', 'REPORT.json', 'build_capsule.py'] + [x['path'] for x in parts]:
        content, desc = capture(OUT / name)
        publication.append({'path': name, 'mode': 0o644, 'identity': pin(content)})
    new(OUT / 'PUBLICATION-INPUTS.json', dump({'files': publication}))
    print(json.dumps({'status': report['status'], 'files': 33, 'logical_bytes': index['logical_bytes'],
                      'compressed_bytes': len(packed), 'parts': len(parts),
                      'report': pin((OUT / 'REPORT.json').read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()
