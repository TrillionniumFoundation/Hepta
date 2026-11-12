"""Archive only already-copied, independently closed originals and static audit."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
PARENT = '5f1c4f6bc7f8ebdf3b3e3c9c17f543a6281346d0'
TREE = '368238ae52c42a2d61098dd5f001a43f48aaae94'
PREFIX = 'experiments/hia_cli_json_graph_20261112/c-runtime-lifetime-actual-r2b'


def wire(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def record(path, name=None):
    b = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix() if name is None else name,
            'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest()}


def create(path, b):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as f:
        f.write(b)
        f.flush()
        __import__('os').fsync(f.fileno())
    assert path.read_bytes() == b
    return record(path)


def tree_hash(leaves):
    node = {}
    for name, row in leaves.items():
        level = node
        parts = name.split('/')
        for part in parts[:-1]:
            level = level.setdefault(part, {})
        assert parts[-1] not in level
        level[parts[-1]] = (row['mode'], row['sha'])
    def visit(items):
        rows = []
        for name, value in items.items():
            if isinstance(value, dict):
                mode, digest = '40000', visit(value)
                key = name.encode() + b'/'
            else:
                mode, digest = value
                key = name.encode()
            rows.append((key, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        raw = b''.join(row[1] for row in sorted(rows))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(node)


def main():
    audit = json.loads((ROOT / 'AUDIT.json').read_bytes())
    original = json.loads((ROOT / 'ORIGINALS.json').read_bytes())
    closure = json.loads((ROOT / 'dynamic-closure-r2/REPORT.json').read_bytes())
    assert audit['qualification_status'] == 'HOLD' and audit['check_count'] == 569
    target = ROOT / 'ORIGINALS.tar.gz'
    with target.open('xb') as outer:
        with gzip.GzipFile(fileobj=outer, filename='', mode='wb', compresslevel=1, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tf:
                for row in original['rows']:
                    b = (ROOT / row['path']).read_bytes()
                    assert len(b) == row['bytes'] and hashlib.sha256(b).hexdigest() == row['sha256']
                    ti = tarfile.TarInfo(row['path'])
                    ti.size = len(b); ti.mode = 0o600; ti.mtime = 0
                    tf.addfile(ti, io.BytesIO(b))
    with tarfile.open(target, 'r:gz') as tf:
        members = tf.getmembers()
        assert [x.name for x in members] == [x['path'] for x in original['rows']]
        for member, row in zip(members, original['rows']):
            b = tf.extractfile(member).read()
            assert member.isreg() and b == (ROOT / row['path']).read_bytes()
            assert len(b) == row['bytes'] and hashlib.sha256(b).hexdigest() == row['sha256']
    archive = record(target)
    ar = create(ROOT / 'ARCHIVE-READBACK.json', wire({'schema': 'hia.cli-json.r2b-archive-readback.v1',
        'qualification_status': 'HOLD', 'archive': archive, 'regular_originals': len(original['rows']),
        'uncompressed_original_bytes': original['bytes'], 'all_original_sha256_and_bytes_equal': True,
        'archive_reconstructed_actuals': False, 'originals_modified': False}))
    transports = []
    for relative, name in [('originals/actual/work/c-build/cli-json.so', 'cli-json.so.base64'),
                           ('ORIGINALS.tar.gz', 'ORIGINALS.tar.gz.base64')]:
        b = (ROOT / relative).read_bytes()
        output = ROOT / 'binary-transport' / name
        tr = create(output, base64.b64encode(b) + b'\n')
        assert base64.b64decode(output.read_bytes(), validate=False) == b
        transports.append({'original': record(ROOT / relative), 'transport': tr})
    create(ROOT / 'binary-transport/INDEX.json', wire({'schema': 'hia.cli-json.r2b-exact-binary-transport.v1',
        'rows': transports, 'complete_companion_decode_equals_original': True,
        'raw_binary_tool_readback_not_claimed': True,
        'historical_tool_capability': 'Direct Git blob APIs refused binary UTF-8 in r1; complete base64 companions enable full-byte readback without loading the DSO.',
        'Git_ACK_and_companion_readback': 'PENDING_PUBLICATION', 'product_execution': False}))
    snapshot = Path('/tmp/hia-cli-json-body-unpack-r4f-20261112-e26e/WIP-SNAPSHOT.json')
    create(ROOT / 'R4F-PAUSED.json', wire({'schema': 'hia.cli-json.r4f-paused-for-r2b-runtime-HOLD.v1',
        'snapshot': record(snapshot, str(snapshot)), 'snapshot_files_unchanged': 14,
        'generation_compilation_native': False, 'source_writes_since_resuming': 0,
        'identified_static_followup': 'Keep the original logical stack top until UNPACK COMMIT, as ceval keeps its local stack_pointer through the iterator and sequence DECREF; evaluate in a new revision, preserving the WIP.',
        'full_CALL_SEND_UNPACK_activation_qualified': False}))
    handoff = {'schema': 'hia.cli-json.finite-r2b-actual-HOLD-handoff.v1',
        'status': 'ORIGINAL_HOLD_COMPLETE_READONLY_CUSTODY', 'parent_commit': PARENT,
        'parent_tree': TREE, 'prefix': PREFIX, 'audit': record(ROOT / 'AUDIT.json'),
        'originals': record(ROOT / 'ORIGINALS.json'), 'archive': archive, 'archive_readback': ar,
        'complete_actual_regular_files': 41, 'complete_originals_including_root_and_peer': len(original['rows']),
        'complete_original_bytes': original['bytes'], 'read_only_audit_checks': audit['check_count'],
        'C_compile': 'PASS', 'actual_C_image': audit['C_image'], 'outer': audit['outer'],
        'inner_owners': audit['inner_owners'], 'runtime_expected': 8, 'runtime_loaded': 1,
        'runtime_executed': 0, 'runtime_elapsed_ns': audit['runtime_elapsed_ns'],
        'runtime_primary_error': audit['primary_actual_error'], 'HIA_compile_executed': False,
        'lifetime_expected': 10, 'lifetime_executed': 0, 'HIA_returns': 0, 'C_pump_calls': 0,
        'original_CLI17_executed': False, 'original_traces46_executed': False,
        'four_actual_input_snapshots_byte_equal': True, 'source_files_freshly_rehashed': 182,
        'system_input_rows_bound': 4555, 'all4555_system_bytes_reread_by_failure_auditor': False,
        'dynamic_symbol_closure': record(ROOT / 'dynamic-closure-r2/REPORT.json'),
        'all_strong_undefined': closure['strong_undefined_count'],
        'compatible_exports': closure['compatible_strong_count'], 'unresolved': closure['unresolved'],
        'full_actual_runtime_and_seven_dependencies_reread': True,
        'GNU_version_visibility_and_full_original_tables_saved': True,
        'readonly_audit_first_attempt': 'Preserved: generic artifact ownership rejected a frozen uid65534 dependency. Successor audit uses the existing exact frozen system-file contract; no product admission changed.',
        'r3_status': 'SOURCE_FIX_AND_REQUEST_PENDING_REVIEW_NOT_EXECUTED',
        'runtime_symbol_admission_not_relaxed': True, 'new_product_executions': 0,
        'r4f_WIP_paused': True, 'unclosed_scopes': ['full evaluator CALL/SEND/UNPACK activation', '17 original CLI methods', '46 original traces']}
    create(ROOT / 'HANDOFF.json', wire(handoff))
    publication = ROOT / 'publication'
    publication.mkdir(mode=0o700)
    sdk = json.loads(Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e/publication/FULL-TREE.sdk.json').read_bytes())
    base = json.loads(sdk['structuredContent']['content'])
    assert base['sha'] == TREE and base['truncated'] is False
    leaves = {r['path']: {'mode': r['mode'], 'sha': r['sha']} for r in base['tree'] if r['type'] == 'blob'}
    assert len(leaves) == 6082 and tree_hash(leaves) == TREE
    old_blobs = {row['sha'] for row in leaves.values()}
    additions = []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or publication in path.parents:
            continue
        r = record(path)
        b = path.read_bytes()
        try:
            b.decode('utf-8', 'strict'); encoding = 'utf-8'
        except UnicodeDecodeError:
            encoding = 'base64'
        r.update(absolute=str(path), repository_path=PREFIX + '/' + r['path'], git_mode='100644', encoding=encoding)
        assert r['repository_path'] not in leaves
        leaves[r['repository_path']] = {'mode': '100644', 'sha': r['git_blob']}
        additions.append(r)
    unique = {}
    for row in additions:
        if row['git_blob'] not in old_blobs:
            unique.setdefault(row['git_blob'], row)
    result = {'schema': 'hia.cli-json.r2b-failure-publication-plan.v1', 'parent_commit': PARENT,
              'parent_tree': TREE, 'prefix': PREFIX, 'parent_leaves': 6082,
              'new_leaves': len(additions), 'full_leaves': len(leaves), 'expected_tree': tree_hash(leaves),
              'all_additions': additions, 'new_blobs': list(unique.values()),
              'tree_elements': [{'path': r['repository_path'], 'mode': '100644', 'type': 'blob', 'sha': r['git_blob']} for r in additions]}
    create(publication / 'PLAN.json', wire(result))
    print(json.dumps({k: result[k] for k in ('parent_commit', 'new_leaves', 'full_leaves', 'expected_tree')}))
    print(json.dumps({'archive': archive, 'new_unique_blobs': len(unique), 'total_new_blob_bytes': sum(r['bytes'] for r in unique.values())}))


if __name__ == '__main__':
    main()
