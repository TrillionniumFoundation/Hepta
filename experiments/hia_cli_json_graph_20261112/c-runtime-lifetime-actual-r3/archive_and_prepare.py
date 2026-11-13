"""Freeze complete r3 failure custody, without rebuilding or loading products."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
PARENT = '7e2d37f425987c827a09f5cd0207595fd86e2e56'
TREE = 'b927868c54bb3e45a174cf68d1a4cd8c667e401d'
PREFIX = 'experiments/hia_cli_json_graph_20261112/c-runtime-lifetime-actual-r3'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def record(path, name=None):
    raw = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix() if name is None else name,
        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    assert path.read_bytes() == raw
    return record(path)


def tree_hash(leaves):
    root = {}
    for name, row in leaves.items():
        cursor = root
        parts = name.split('/')
        for part in parts[:-1]: cursor = cursor.setdefault(part, {})
        assert parts[-1] not in cursor
        cursor[parts[-1]] = (row['mode'], row['sha'])
    def visit(node):
        rows = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, digest, key = '40000', visit(value), name.encode() + b'/'
            else:
                mode, digest = value; key = name.encode()
            rows.append((key, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        raw = b''.join(row[1] for row in sorted(rows))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(root)


def main():
    audit = json.loads((ROOT / 'AUDIT.json').read_bytes())
    originals = json.loads((ROOT / 'ORIGINALS.json').read_bytes())
    assert audit['qualification_status'] == 'HOLD' and audit['check_count'] == 571
    assert originals['count'] == 60 and originals['bytes'] == 10554895
    source = Path('/tmp/hia-cli-json-runtime-layout-static-r4-20261112-e26e')
    for path in sorted(source.iterdir()):
        assert path.is_file() and not path.is_symlink()
        create(ROOT / 'runtime-ELF-static' / path.name, path.read_bytes())
    static = json.loads((ROOT / 'runtime-ELF-static/STATIC-ELF-REPORT.r2.json').read_bytes())
    assert static['PT_LOAD_count'] == 6 and static['executable_PT_LOAD_count'] == 2
    assert len(static['base11']) == 11 and len(static['control5']) == 5
    assert static['unique_required_functions'] == 15
    old_root = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-actual-r2b-git-review/ROOT-READBACK.json')
    assert hashlib.sha256(old_root.read_bytes()).hexdigest() == '4ccacda2667321683ec95cc0cfec004a0a9705a05b8471a331838c42f1d99c40'
    create(ROOT / 'reference/ROOT-R2B-GIT-READBACK.original.json', old_root.read_bytes())
    target = ROOT / 'ORIGINALS.tar.gz'
    with target.open('xb') as outer:
        with gzip.GzipFile(fileobj=outer, filename='', mode='wb', compresslevel=1, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tf:
                for row in originals['rows']:
                    raw = (ROOT / row['path']).read_bytes()
                    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
                    info = tarfile.TarInfo(row['path']); info.size = len(raw); info.mode = 0o600; info.mtime = 0
                    tf.addfile(info, io.BytesIO(raw))
    with tarfile.open(target, 'r:gz') as tf:
        members = tf.getmembers()
        assert [x.name for x in members] == [r['path'] for r in originals['rows']]
        for member, row in zip(members, originals['rows']):
            raw = tf.extractfile(member).read()
            assert member.isreg() and raw == (ROOT / row['path']).read_bytes()
            assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    archive = record(target)
    ar = create(ROOT / 'ARCHIVE-READBACK.json', wire({
        'schema': 'hia.cli-json.r3-failure-archive-readback.v1', 'qualification_status': 'HOLD',
        'archive': archive, 'regular_originals': 60, 'uncompressed_original_bytes': originals['bytes'],
        'all_original_bytes_and_SHA_equal_after_full_tar_decode': True,
        'originals_modified': False, 'reconstructed_product_outputs': False}))
    transports = []
    for relative, name in [('originals/actual/work/c-build/cli-json.so', 'cli-json.so.base64'),
                           ('ORIGINALS.tar.gz', 'ORIGINALS.tar.gz.base64')]:
        raw = (ROOT / relative).read_bytes()
        pin = create(ROOT / 'binary-transport' / name, base64.b64encode(raw) + b'\n')
        assert base64.b64decode((ROOT / 'binary-transport' / name).read_bytes()) == raw
        transports.append({'original': record(ROOT / relative), 'transport': pin})
    create(ROOT / 'binary-transport/INDEX.json', wire({
        'schema': 'hia.cli-json.r3-exact-binary-transport.v1', 'rows': transports,
        'complete_companion_decode_equals_original': True, 'raw_binary_tool_readback_not_claimed': True,
        'full_UTF8_companions_support_actual_byte_readback': True,
        'Git_ACK_and_companion_readback': 'PENDING_PUBLICATION', 'product_execution': False}))
    snapshot = Path('/tmp/hia-cli-json-body-unpack-r4f-20261112-e26e/WIP-SNAPSHOT.json')
    snap = json.loads(snapshot.read_bytes())
    for row in snap['files']:
        raw = (snapshot.parent / row['path']).read_bytes()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    create(ROOT / 'R4F-PAUSED.json', wire({
        'schema': 'hia.cli-json.r4f-paused-for-r3-runtime-HOLD.v1',
        'snapshot': record(snapshot, str(snapshot)), 'all_snapshot_files_unchanged': 14,
        'new_r4f_source_writes_generation_compilation_native': False,
        'readonly_finding': 'BEGIN reduces private active.top before iterator/sequence DECREF; official generic and three specialized UNPACK cases update the local stack pointer only afterwards. An isolated successor must retain the old logical top until COMMIT while retaining the explicit lease owners on quarantine.',
        'observational_equivalence_not_proved': True, 'full_CALL_SEND_UNPACK_activation_closed': False}))
    handoff = {
        'schema': 'hia.cli-json.r3-runtime-ELF-HOLD-handoff.v1',
        'status': 'ORIGINAL_HOLD_COMPLETE_READONLY_CUSTODY',
        'parent_commit': PARENT, 'parent_tree': TREE, 'prefix': PREFIX,
        'audit': record(ROOT / 'AUDIT.json'), 'originals': record(ROOT / 'ORIGINALS.json'),
        'archive': archive, 'archive_readback': ar,
        'actual_regular_files': 42, 'full_originals_count': 60, 'full_original_bytes': originals['bytes'],
        'readonly_joins': 571, 'C_compile': 'PASS', 'actual_C_image': audit['C_image'],
        'outer': audit['outer'], 'inner_owners': audit['inner_owners'],
        'runtime_expected': 8, 'runtime_loaded': 2, 'runtime_executed': 1,
        'runtime_elapsed_ns': audit['runtime_elapsed_ns'],
        'runtime_completed_id': audit['runtime_executed_ids'][0],
        'runtime_failed_id': audit['runtime_loaded_ids'][1],
        'primary_error': 'runtime ELF profile differs',
        'actual_runtime_ELF_type': 2, 'actual_PT_LOAD_count': 6,
        'actual_executable_PT_LOAD_count': 2, 'lowest_PT_LOAD_virtual_address': 4190208,
        'actual_previous_missing_TLS_and_raised_setter_imports_absent': True,
        'static_all16_entries_report': record(ROOT / 'runtime-ELF-static/STATIC-ELF-REPORT.r2.json'),
        'all16_entries_have_unique_complete_function_and_executable_segment': True,
        'runtime_process_mapping_not_recorded_before_original_failure': True,
        'read_only_reader_first_identity_schema_error_preserved': True,
        'new_mapped_runtime_probe_executed': False,
        'HIA_compile_executed': False, 'lifetime_expected': 10, 'lifetime_executed': 0,
        'HIA_returns': 0, 'C_pump_calls': 0,
        'four_actual_input_snapshots_byte_equal': True, 'source_files_freshly_reread': 182,
        'system4555_bound_in_actual_snapshots': True, 'all4555_system_reread_by_this_failure_auditor': False,
        'original17_CLI_executed': False, 'original46_traces_executed': False,
        'new_product_executions': 0, 'original_result_not_reclassified': True,
        'next_fix_not_yet_implemented': 'Both mapped-runtime entrances must distinguish ET_EXEC absolute symbol values from ET_DYN load bias, proving the file, anchor, whole symbol span and mapping ownership; merely accepting kind 2 is insufficient.',
        'next_request_requires_root_review': True, 'r4f_WIP_unchanged_and_paused': True}
    create(ROOT / 'HANDOFF.json', wire(handoff))
    publication = ROOT / 'publication'; publication.mkdir(mode=0o700)
    sdk = json.loads(Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e/publication/FULL-TREE.sdk.json').read_bytes())
    base = json.loads(sdk['structuredContent']['content'])
    assert base['sha'] == TREE and not base['truncated']
    leaves = {r['path']: {'mode': r['mode'], 'sha': r['sha']} for r in base['tree'] if r['type'] == 'blob'}
    assert len(leaves) == 6393 and tree_hash(leaves) == TREE
    old_blobs = {r['sha'] for r in leaves.values()}
    additions = []
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or publication in path.parents: continue
        row = record(path)
        try: path.read_bytes().decode('utf-8'); encoding = 'utf-8'
        except UnicodeDecodeError: encoding = 'base64'
        row.update(absolute=str(path), repository_path=PREFIX + '/' + row['path'], git_mode='100644', encoding=encoding)
        assert row['repository_path'] not in leaves
        leaves[row['repository_path']] = {'mode': row['git_mode'], 'sha': row['git_blob']}
        additions.append(row)
    unique = {}
    for row in additions:
        if row['git_blob'] not in old_blobs: unique.setdefault(row['git_blob'], row)
    plan = {'schema': 'hia.cli-json.r3-failure-publication-plan.v1',
        'parent_commit': PARENT, 'parent_tree': TREE, 'prefix': PREFIX,
        'parent_leaves': 6393, 'new_leaves': len(additions), 'full_leaves': len(leaves),
        'expected_tree': tree_hash(leaves), 'all_additions': additions,
        'new_blobs': list(unique.values()),
        'tree_elements': [{'path': r['repository_path'], 'mode': r['git_mode'], 'type': 'blob', 'sha': r['git_blob']}
                          for r in additions]}
    create(publication / 'PLAN.json', wire(plan))
    print(json.dumps({k: plan[k] for k in ('new_leaves','full_leaves','expected_tree')}))
    print(json.dumps({'archive': archive, 'new_unique_blobs': len(unique),
        'new_unique_bytes': sum(r['bytes'] for r in unique.values()), 'handoff': record(ROOT / 'HANDOFF.json')}))


if __name__ == '__main__':
    main()
