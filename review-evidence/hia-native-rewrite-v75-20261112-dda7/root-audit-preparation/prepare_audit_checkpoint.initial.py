from pathlib import Path
from hashlib import sha1, sha256
import base64, json

ROOT = Path('/workspace/scratch/dda74a4fae35')
OUT = ROOT / 'v75-audit-checkpoint'
OUT.mkdir(mode=0o700, exist_ok=False)
PREFIX = 'review-evidence/hia-native-rewrite-v75-20261112-dda7'
BASE_HEAD = 'a906df929495ec8cfd8832ffee22c1c47fa0682d'
BASE_TREE = '423945b12db7374ed69d4e5a69f626222d1a75ba'
base = json.loads((ROOT / 'v75-root-integration/AUDIT-BASE-RECURSIVE-TREE.json').read_bytes())
assert base['sha'] == BASE_TREE and base['truncated'] is False
old = {row['path']: {key: row[key] for key in ('mode', 'type', 'sha')} for row in base['tree']}
assert len([row for row in base['tree'] if row['type'] == 'blob']) == 3471
assert not any(path == PREFIX or path.startswith(PREFIX + '/') for path in old)
entries = {}
def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
def add(path, digest):
    assert path not in entries and len(digest) == 40
    entries[path] = {'path': path, 'mode': '100644', 'type': 'blob', 'sha': digest}

packets = {
    'code-r4/SOURCE.json': '93eae21429bed2d3e2f529be4de683a6153f8920',
    'code-r4/INITIAL-COMPLETE-REPORTS.json': '13dcce3608015e4b06aaf01421ec7b190823724b',
    'code-r4/FINAL-44-REPORT.json': '094955faaeae93a03aadb0f9ffbd4b5b0fd05d04',
    'code-r4/ORIGINAL-12-51-REPORT.json': 'a562d7632f34f72f2ba512de9acebab9a30d68c1',
    'code-r4/PARTIAL-45.json': 'f2ab1a312ae8f0cc8d350872e5a30f72a336d8ad',
    'code-r4/PARTIAL-74.json': 'f345bb75c5bfa3675800facf617f215cbd2429ba',
    'resources-r1/SOURCE.json': '22d51a7aaba3bd363592ab5254b8157148849ca9',
    'resources-r2/SOURCE.json': 'cf09a4438ca3897c6475325576dc94f00f02bb53',
    'source-generation-r1/PARTIAL-8.json': '074d90c7464ebbea07eaf09ba4d783798de07ba4',
    'shared-exception/ORIGINAL-COMPLETE-R3.json': '538b30f50a052130c5c84c82bb50062e83f6a030',
    'shared-exception/CI-KIT-INITIAL.json': '88bebd2af82f1a0e711963c55cbfcbb29ba3eb8b',
    'shared-exception/CI-KIT-FINAL.json': 'd858a3103ace40e349a378e8b8994469b5ac1340',
    'shared-exception/WORKFLOW-R1.yml': '1e310db58b735c28ee7c7f8935f6273a98894bd8',
    'shared-exception/WORKFLOW-R2.yml': '1029275485049c62020fe55ed9ab1af395036ca1',
    'shared-exception/PYTHON314-R2-COMPLETE-ORIGINALS.json': '0622b5bd376eeed477726525a1d65ab17b623f7b',
    'context-r4/EARLY-ORIGINALS.json': 'a9895375b69357479d244837002b0842cb345837',
    'context-r4/FROZEN-26-ORIGINALS.json': '61dbb226e2bf95dd76bc66cdc5d0ca77738fecac',
    'cli/SOURCE.json': '1cd7b1c7136e760ba1f9da7b650d0dd884f332c7',
    'reference-gcc15/CONTAINER-COMPLETE-ORIGINALS.json': '589a506c3366cdb3ae3348f37b7251b954b72e69',
    'reference-gcc15/HOST-DRIVER.py': '5a4b0251dcfa6d008fa853aa2d0eaf721d346242',
    'reference-gcc15/HOST-PREPARATION.sh': '45d5d95292349b68194cb83590b8644c1b9c5788',
    'reference-gcc15/HOST-WORKFLOW.yml': '95be9adc4bdd90b0938542aec8fa6c610fa11edc',
    'source-harness/DRIVER.py': '853c48809b250b133100f3a9b62412cd728da70c',
    'source-harness/SUPERVISOR.py': 'a07d8f176342bbcc0da592f796f2f50e742af4af',
    'source-harness/R1-WORKFLOW.yml': 'b95ccf0321900fa3f4bb80067ad47bdb94b3d3a6',
    'source-harness/R1-OVERLAY.json': '71f9b5086f925a64e404dc1dceb65bdf6b6729bc',
    'source-harness/R2-WORKFLOW.yml': 'dc2dbc8af6811f8e21f8609df7ad1a60ce78823a',
    'source-harness/R2-OVERLAY.json': '813767756a486b5f438b365d5608f47f8e0efe5d',
    'root-r2/INDEX-WITH-EXTRA-LF-TRANSPORT-ORIGINAL.json': 'b1344ac7b5a4ae6238ca4914a839cefd8fa944ba',
}
for path, digest in packets.items():
    add(path, digest)

sets = [
    ('code-r4', 'v75-code-r4-development/raw-evidence-r4/COMPLETE-MANIFEST.json',
     '8830d2dc43347613b73af727af88f627b31a8e9a', 'published_chunks'),
    ('resources-r1', 'v75-audit-checkpoint-inputs/resource-r1-index.json',
     '577c1c689a2e2215df6e4afe5afdbec095092aaa', 'chunks'),
    ('resources-r2', 'v75-audit-checkpoint-inputs/resource-r2-index.json',
     'd65d688463a0e4854a7c67a2d0e960957f6ec30a', 'chunks'),
    ('source-generation-r1', 'v75-source-generation-r1-capsule/capsule/COMPLETE-MANIFEST.json',
     '586adc66fa2d463ae0f740b67f550f0751433af2', 'published_chunks'),
    ('root-r1', 'v75-root-checkpoint-r1/PUBLICATION.json',
     'e3780d98f42b2ffdcba1afcd42b456b651c2c2fe', 'chunks'),
    ('root-r2', 'v75-root-checkpoint-r2/PUBLICATION.json',
     '144faf0eefdfc951be4c520bb8ed9157384fa0cb', 'chunks'),
]
verification = []
for name, relative, digest, key in sets:
    manifest_raw = (ROOT / relative).read_bytes()
    assert blob(manifest_raw) == digest, (name, 'manifest identity')
    value = json.loads(manifest_raw)
    rows = value[key]
    assert [row['index'] for row in rows] == list(range(len(rows)))
    joined = bytearray()
    for row in rows:
        path = Path(row['path'])
        raw = path.read_bytes()
        assert len(raw) == row['wrapper_bytes']
        assert sha256(raw).hexdigest() == row['wrapper_sha256']
        assert blob(raw) == row['blob']
        wrapper = json.loads(raw)
        binary = base64.b64decode(wrapper.get('base64', wrapper.get('data')), validate=True)
        size = row.get('raw_bytes', row.get('bytes'))
        expected_sha = row.get('raw_sha256', row.get('sha256'))
        assert row['offset'] == len(joined)
        assert len(binary) == size and sha256(binary).hexdigest() == expected_sha
        joined.extend(binary)
        add(name + '/chunks/chunk-' + str(row['index']).zfill(3) + '.json', row['blob'])
    if name == 'code-r4':
        expected_size, expected_sha = value['archive_bytes'], value['archive_sha256']
        archive_path = ROOT / 'v75-code-r4-development/raw-evidence-r4/RAW-EVIDENCE.zip'
    else:
        expected_size, expected_sha = value['archive']['bytes'], value['archive']['sha256']
        archive_path = Path(value['archive']['path'])
    assert len(joined) == expected_size and sha256(joined).hexdigest() == expected_sha
    assert archive_path.read_bytes() == joined, (name, 'complete archive bytes')
    add(name + '/COMPLETE-INDEX.json', digest)
    verification.append({
        'name': name, 'chunks': len(rows), 'archive_bytes': len(joined),
        'archive_sha256': expected_sha, 'all_wrapper_git_and_sha256_verified': True,
        'all_raw_chunk_bytes_and_sha256_verified': True,
        'whole_archive_equal_original': True,
    })

checkpoint = {
    'schema': 'hia.v75.complete-originals-audit-checkpoint.v1',
    'audit_parent': BASE_HEAD, 'audit_base_tree': BASE_TREE,
    'preserved_old_blob_paths': 3471,
    'product_head_unchanged': '7e9c5a796a29746d169f9db97392ec774f627c03',
    'product_tree_unchanged': '79843bddc6df7306299f0be6475a2fcd187b4d97',
    'source_r1': {'run': 43164226506, 'generators_passed': 77,
                  'tests': 689, 'errors': 1, 'failures': 0,
                  'result': 'FAIL', 'failure': 'two CLI assets were absent from the explicit resource-to-runtime binding map'},
    'source_r2': {'run': 43169308480, 'head': '32686bf9e7f8f3b269c7e39fba1b900e4c91a0a7',
                  'status_at_checkpoint': 'IN_PROGRESS', 'terminal_result_claimed': False,
                  'same_original_driver_supervisor_and_limits': True,
                  'all_original_test_method_ASTs_and_assertions_preserved': True},
    'shared_exception_python314': {'run': 43170086685, 'job': 131021036354,
                  'vm_native_full_frame_cases': 19, 'mechanism_controls': 18,
                  'result': 'PASS', 'scope': 'independent explicit development mechanism on complete original 7e9 source with two frozen untracked overlays'},
    'note_reference': {'host_run': 43167896880,
                  'result': 'NEW_COMPILATION_MATCH', 'bytes': 260,
                  'sha256': 'e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61',
                  'historical_file_recovered': False, 'original_35_controls_executed_by_reproduction': False},
    'context_r4': {'development_controls_passed': 26, 'complete_original_packet': packets['context-r4/FROZEN-26-ORIGINALS.json'],
                   'exact_integer_arithmetic_whole_owner_qualified': False},
    'whole_native_delivery_qualified': False,
    'default_changed': False, 'legacy_deleted': False,
    'old_code_r3_missing_archive_suffix_recovered': False,
    'complete_archive_verifications': verification,
    'immutable_blob_entries': sorted(entries.values(), key=lambda row: row['path']),
}
(OUT / 'CHECKPOINT.json').write_text(json.dumps(checkpoint, sort_keys=True, indent=2) + '\n')
(OUT / 'README.md').write_text("""# V75 original evidence checkpoint

This evidence-only checkpoint preserves all 3,471 prior audit blob paths and adds complete immutable originals. It does not advance the product branch, change defaults, delete legacy implementations, or claim whole HIA-native closure.

The first V75 source run actually passed 77 generators and executed 689 controls with one CLI resource-binding error. Its complete original report, all captured command records, and source packet remain available in the 20-part source-generation archive. The correction adds the two explicit resource bindings; the original driver, assertions, test methods, and execution limits remain unchanged. The independently launched second run is recorded as in progress at this checkpoint.

The Code R4 archive is complete at 90 of 90 chunks. The two resource audit archives, root integration archives, and source failure archive are also complete. Every indexed chunk is a real tree entry; a JSON reference alone is not treated as Git reachability. The earlier Code R3 missing archive suffix remains unrecovered.

The separate CPython 3.14.4 exception mechanism run passed all 19 full-frame VM/native comparisons and 18 mechanism controls. Context R4 has 26 actual development controls with complete raw outputs. Neither result is transferred to a different source/cold identity or called whole-runtime replacement.

A fixed real GCC 15.2 compiler reproduced the original reference requirement: exactly 260 bytes with SHA-256 e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61. These are newly compiled bytes; the original 35 runtime controls must still execute on the eventual exact product candidate.

See CHECKPOINT.json for exact run IDs, source identities, completeness checks, and claim boundaries. All previous failures and transport authoring events remain separate from later successful observations.
""")
for name in ('README.md', 'CHECKPOINT.json'):
    raw = (OUT / name).read_bytes()
    add(name, blob(raw))
event = ROOT / 'v75-root-checkpoint-r2/INDEX-TRANSPORT-EVENT.json'
add('root-r2/INDEX-TRANSPORT-EVENT.json', blob(event.read_bytes()))
plan = {
    'schema': 'hia.v75.audit-tree-additions.v1', 'base_head': BASE_HEAD,
    'base_tree': BASE_TREE, 'prefix': PREFIX,
    'entries': sorted(entries.values(), key=lambda row: row['path']),
    'new_local_blobs': [
        {'path': str(OUT / name), 'git_path': name, 'sha': blob((OUT / name).read_bytes())}
        for name in ('README.md', 'CHECKPOINT.json')
    ] + [{'path': str(event), 'git_path': 'root-r2/INDEX-TRANSPORT-EVENT.json', 'sha': blob(event.read_bytes())}],
}
(OUT / 'ADDITIONS.json').write_text(json.dumps(plan, sort_keys=True, indent=2) + '\n')
print(json.dumps({'new_blobs': len(entries), 'verified_archives': verification}, indent=2))
