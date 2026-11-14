#!/usr/bin/env python3
"""Seal only the completed R3 808-copy metadata, never its input payload."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import zlib

OUT = Path('/tmp/hia-r8-input-view-preparation-custody-r1-dda7')
VIEW = Path('/dev/shm/hia-u32-r8-input-view-r3-dda7')
OUTER = Path('/tmp/hia-r8-input-view-preparation-r3-outer-dda7')
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
    selected = []
    directories = []
    for prefix, root in [('records', VIEW / 'records'), ('outer', OUTER),
                         ('root-readback', ROOT / 'r8-preparation-root-readback-r1')]:
        paths = files_under(root)
        directories.append({'prefix': prefix, 'path': str(root),
                            'mode': stat.S_IMODE(root.lstat().st_mode),
                            'relative_pathset': [str(p.relative_to(root)) for p in paths]})
        selected.extend((prefix + '/' + p.relative_to(root).as_posix(), p) for p in paths)
    assert len(selected) == 13
    selected.extend((('author/' + name), AUTHOR / name) for name in
                    ('PREPARATION-PLAN.json', 'PREPARATION-LAUNCH.json', 'prepare_input_view.py'))
    selected.extend((('root-controls/' + name), ROOT / name) for name in
                    ('read_r8_preparation.py', 'launch_r8_preparation.py', 'admit_r8_preparation.py',
                     'R8-ROOT-AUTHOR-REVIEW.json', 'R8-PREPARATION-AUTHORIZATION.json'))
    assert len(selected) == 21 and len({x[0] for x in selected}) == 21
    rows = []
    originals = {}
    # These explicit inputs are metadata/code only. Check credential-bearing HTTP forms
    # without emitting any matched content. No network response is an input.
    credential_patterns = [rb'(?i)https?://[^\s\"\x27]+[?&](?:sig|token|x-amz-signature)=',
                           rb'(?i)\"(?:authorization|set-cookie)\"\s*:\s*\"[^\"]+\"',
                           rb'(?im)^Authorization:\s*\S+', rb'(?im)^Set-Cookie:\s*\S+']
    for logical, p in selected:
        raw, desc = capture(p)
        assert not any(re.search(pattern, raw) for pattern in credential_patterns), logical
        originals[logical] = raw
        rows.append({'logical_path': logical, **desc, 'content_base64': base64.b64encode(raw).decode('ascii')})

    plan = json.loads(originals['author/PREPARATION-PLAN.json'])
    view = json.loads(originals['records/CURRENT-INPUT-VIEW.json'])
    journal = [json.loads(line) for line in originals['records/COPY.jsonl'].splitlines()]
    assert len(journal) == len(view) == len(plan['copy_files']) == 808
    assert [r['destination'] for r in journal] == [str(VIEW / r['destination_relative']) for r in plan['copy_files']]
    for row in journal:
        rel = str(Path(row['destination']).relative_to(VIEW))
        assert row == view[rel]
    restored_raw, restored_desc = capture(RECOVERY / 'RESTORED-MANIFEST.json')
    restored = json.loads(restored_raw)
    source_rows = {str(RECOVERY / r['target']): r for r in restored['files']}
    references = []
    for ordinal, row in enumerate(plan['copy_files']):
        original = source_rows[row['recovered_path']]
        current = view[row['destination_relative']]
        assert original['required_identity'] == row['identity'] == current['identity']
        assert original['original_path'] == row['original_path'] == current['original_path']
        assert original['provenance'] == row['recovered_provenance']
        assert original['reference_ordinals'] == row['reference_ordinals']
        assert current['recovered_path'] == row['recovered_path']
        assert current['recovered_new_seven_stats'] == row['recovered_new_seven_stats']
        references.append({'ordinal': ordinal, 'destination': current['destination'],
                           'destination_new_seven_stats': current['destination_new_seven_stats'],
                           'original_path': row['original_path'], 'recovered_path': row['recovered_path'],
                           'identity': row['identity'], 'reference_ordinals': row['reference_ordinals'],
                           'existing_payload_transport': original['provenance'],
                           'payload_bytes_in_this_capsule': 0})
    assert sum(r['identity']['bytes'] for r in references) == 132337387
    catalog = {'schema': 'hepta.r8.preparation.metadata.payload-reference-catalog.v1',
               'source_manifest': restored_desc, 'copied_inputs': references,
               'copied_input_count': 808, 'copied_input_bytes': 132337387,
               'all_copied_payloads_refer_to_existing_transport': True,
               'copied_input_payload_bytes_in_this_capsule': 0,
               'compact_transport_recipe_git': 'cfa86d512908e463f093abd3653dc56846e9ab66',
               'compact_transport_index_git': '11f0be3569dc04273f0e285fec5045e87b86fea2',
               'source_custody_recipe_git': 'f4f8ef86024dae943b2b37ff53601cd923d5e659',
               'runtime_custody_recipe_git': '7f63bc96a951a254096e40ba06d30b5087f22ed1',
               'r3_author_recipe_git': '36766cd7f37f741280990d5b0d58b5c0176c5155',
               'source_and_runtime_payload_bytes_in_this_capsule': 0}
    catalog_raw = dump(catalog)
    new(OUT / 'PAYLOAD-REFERENCES.json', catalog_raw)
    raw, desc = capture(OUT / 'PAYLOAD-REFERENCES.json')
    rows.append({'logical_path': 'custody/PAYLOAD-REFERENCES.json', **desc,
                 'content_base64': base64.b64encode(raw).decode('ascii')})
    capsule = {'schema': 'hepta.lossless.metadata-files.base64.v1',
               'scope': 'Completed R3 808-copy metadata, original outer and Root readback. No copied input/source/runtime payload.',
               'directories': directories, 'files': rows}
    raw = dump(capsule)
    packed = zlib.compress(raw, 9)
    assert zlib.decompress(packed) == raw
    decoded = json.loads(zlib.decompress(packed))
    logical_names = []
    for row in decoded['files']:
        content = base64.b64decode(row['content_base64'], validate=True)
        assert pin(content) == row['identity']
        original_raw, current = capture(Path(row['path']))
        assert content == original_raw and current['mode'] == row['mode']
        assert current['seven_stats'] == row['seven_stats']
        logical_names.append(row['logical_path'])
    for row in directories:
        assert [str(p.relative_to(row['path'])) for p in files_under(Path(row['path']))] == row['relative_pathset']
    assert len(logical_names) == len(set(logical_names)) == 22
    parts = []
    (OUT / 'parts').mkdir()
    for number, offset in enumerate(range(0, len(packed), 384000)):
        piece = packed[offset:offset + 384000]
        name = 'parts/%03d.json' % number
        part_raw = dump({'schema': 'hepta.zlib.metadata-capsule-part.v1', 'index': number,
                         'offset': offset, 'decoded_part': pin(piece),
                         'complete_archive': pin(packed), 'base64': base64.b64encode(piece).decode('ascii')})
        new(OUT / name, part_raw)
        parts.append({'path': name, 'mode': 0o644, 'identity': pin(part_raw),
                      'decoded_part': pin(piece), 'offset': offset})
    evidence_manifest = [{k: v for k, v in row.items() if k != 'content_base64'} for row in rows]
    index = {'schema': 'hepta.r8.preparation.metadata-custody-index.v1',
             'files': evidence_manifest, 'directories': directories,
             'logical_files': 22, 'logical_bytes': sum(r['identity']['bytes'] for r in rows),
             'capsule_json': pin(raw), 'compressed_zlib': pin(packed), 'parts': parts,
             'source_input_runtime_payload_bytes_included': 0}
    new(OUT / 'INDEX.json', dump(index))
    child = json.loads(originals['records/RESULT.json'])
    owner = json.loads(originals['outer/RESULT.json'])
    proof = json.loads(originals['root-readback/RESULT.json'])
    assert child['status'] == 'PASS_808_INPUT_VIEW_ONLY'
    assert owner['returncode'] == 0 and owner['ECHILD'] and owner['process_group_absent']
    assert proof['status'] == 'PASS_808_CURRENT_INPUT_COPIES_ONLY'
    report = {'schema': 'hepta.r8.preparation.complete-metadata-custody.v1',
              'status': 'PASS_COMPLETE_PREPARATION_METADATA_ONLY', 'created_unix_ns': time.time_ns(),
              'elapsed_ns': time.time_ns() - started, 'original_files': 21,
              'custody_reference_catalogs': 1, 'capsule_files': 22,
              'logical_bytes': index['logical_bytes'], 'compressed_bytes': len(packed), 'parts': len(parts),
              'original_child': child, 'original_outer': owner, 'root_independent_readback': proof,
              'root_copy_readback_pin': pin(originals['root-readback/FULL-COPY-READBACK.json']),
              'all_original_metadata_fullbytes_and_modes_readback': True,
              'all_original_metadata_stats_unchanged': True,
              'payload_reference_catalog': pin(catalog_raw), 'index': pin((OUT / 'INDEX.json').read_bytes()),
              'input_payloads_in_capsule': 0, 'input_payload_bytes_in_capsule': 0,
              'original_136_owner_in_this_stage': 0, 'products_executed_by_this_custody': 0,
              'CI': 0, 'refs': 0, 'credentials_observed_or_included': 0,
              'qualification_limit': '808 independent input copies and metadata custody only; no oracle owner, semantic/aggregate execution, public R5, ordinary/current-cold, or whole-native qualification is transferred.'}
    new(OUT / 'REPORT.json', dump(report))
    publication = []
    for name in ['INDEX.json', 'REPORT.json', 'build_capsule.py'] + [p['path'] for p in parts]:
        content, meta = capture(OUT / name)
        publication.append({'path': name, 'mode': 0o644, 'identity': pin(content)})
    new(OUT / 'PUBLICATION-INPUTS.json', dump({'files': publication}))
    print(json.dumps({'status': report['status'], 'files': 22, 'logical_bytes': index['logical_bytes'],
                      'compressed_bytes': len(packed), 'parts': len(parts),
                      'report': pin((OUT / 'REPORT.json').read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()
