"""Static identity/AST readback and lossless handoff; never import product code."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
from pathlib import Path
import stat
import zlib

ROOT = Path('/workspace/scratch/dda74a4fae35')
SCOPE = Path(__file__).resolve().parent
OUT = SCOPE / 'prepared-r2'
H = OUT / 'harness'
OLD = ROOT / 'v94-native-namespace-budget-r1/ci-phase-r1'
PRODUCT = ROOT / 'v120-union-r20/source'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def write(name, raw):
    path = OUT / name
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o644)
    assert path.read_bytes() == raw
    return identity(raw)


def functions(raw):
    return {n.name: n for n in ast.walk(ast.parse(raw)) if isinstance(n, ast.FunctionDef)}


def dump(node):
    return ast.dump(node, include_attributes=False)


def main():
    plan = json.loads((OUT / 'PLAN.json').read_bytes())
    manifest = json.loads((OUT / 'HARNESS-MANIFEST.json').read_bytes())
    actual = {p.relative_to(H).as_posix(): p for p in H.rglob('*') if p.is_file()}
    assert len(actual) == len(manifest) == 16
    assert set(actual) == {r['path'] for r in manifest}
    for row in manifest:
        path = actual[row['path']]
        assert stat.S_ISREG(path.lstat().st_mode) and stat.S_IMODE(path.stat().st_mode) == 0o644
        assert identity(path.read_bytes()) == {'bytes': row['bytes'], 'sha256': row['sha256'], 'git_blob': row['sha']}
    inputs = json.loads(actual['inputs/INPUTS.json'].read_bytes())
    source = json.loads(actual['inputs/SOURCE-MANIFEST.json'].read_bytes())
    assert len(source) == inputs['source_files'] == 3177
    assert identity(actual['inputs/SOURCE-MANIFEST.json'].read_bytes()) == inputs['source_manifest']
    old_module = json.loads((OLD / 'actual/raw/evidence/REPORT.json').read_bytes())['original_test_file']
    assert old_module == inputs['original_test_file'] == identity((PRODUCT / 'tests/test_hia_agent_native_tools.py').read_bytes())
    parts = json.loads(actual['inputs/RETAINED-PARTS.json'].read_bytes())
    chunks = []
    for part in parts['parts']:
        raw = actual['inputs/' + part['path']].read_bytes()
        assert part['offset'] == sum(map(len, chunks))
        assert identity(raw) == {key: part[key] for key in ('bytes', 'sha256', 'git_blob')}
        chunks.append(raw)
    raw = b''.join(chunks)
    assert identity(raw) == inputs['retained_packet'] == parts['complete']
    wrapper = json.loads(raw)
    decoded = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert identity(decoded) == wrapper['decoded']
    packet = json.loads(decoded)
    assert len(packet['files']) == wrapper['members'] == 16
    assert packet['source_commit'] == inputs['source_commit'] == plan['source_commit']
    assert packet['source_tree'] == inputs['source_tree'] == plan['source_tree']
    for row in packet['files'].values():
        data = base64.b64decode(row['base64'], validate=True)
        assert identity(data) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
        assert zlib.crc32(data) & 0xffffffff == row['crc32']
        assert row['mode'] in (0o644, 0o700)
    joint = packet['files']['original-nested-evidence/ArtifactNamespaceNativeTests/joint-build.json']
    current = json.loads(base64.b64decode(joint['base64'], validate=True))['source_manifest']
    assert len(current) == 1552 and all(source[name]['sha256'] == value for name, value in current.items())

    old_f = functions((OLD / 'harness/tools/observe_case.py').read_bytes())
    new_f = functions(actual['tools/observe_case.py'].read_bytes())
    unchanged = sorted(set(old_f) - {'main', 'json_init'})
    assert all(dump(old_f[name]) == dump(new_f[name]) for name in unchanged)
    assert isinstance(new_f['json_init'].body[0], ast.If)
    assert ast.unparse(new_f['json_init'].body[0].test) == 'type(image) is NativeStoreLifecycleImage'
    generic = ast.FunctionDef(**{key: getattr(new_f['json_init'], key) for key in new_f['json_init']._fields})
    generic.body = generic.body[1:]
    assert dump(generic) == dump(old_f['json_init'])
    original_try = [n for n in old_f['main'].body if isinstance(n, ast.Try)]
    actual_try = [n for n in new_f['main'].body if isinstance(n, ast.Try)]
    assert len(original_try) == len(actual_try) == 1 and dump(original_try[0]) == dump(actual_try[0])
    # The complete try contains all observer installations, all poisons, the
    # original loader, result assertions and receipt/report finalization.
    old_run = functions((OLD / 'harness/tools/run_phase.py').read_bytes())
    new_run = functions(actual['tools/run_phase.py'].read_bytes())
    assert all(dump(old_run[name]) == dump(new_run[name]) for name in ('unpack', 'retained_map', 'run_case'))
    for name in ('tools/budget_profile.py', 'tools/diagnose_source_scan.py'):
        assert actual[name].read_bytes() == (OLD / 'harness' / name).read_bytes()
    assert actual['inputs/STORE-OBSERVER-ADDENDUM.md'].read_bytes() == (OLD / 'STORE-OBSERVER-ADDENDUM.md').read_bytes()
    workflow = actual['.github/workflows/diagnostic.yml'].read_text()
    product_workflow = (PRODUCT / '.github/workflows/hia-core.yml').read_text()
    start = product_workflow.index('      - name: Install qualified Clang 20 native execution prerequisites\n')
    end = product_workflow.index('      - name: Prepare original locked Rust caller dependencies\n', start)
    exact = product_workflow[start:end]
    assert workflow.count(exact) == 1 and identity(exact.encode()) == plan['production_prerequisite_block']
    assert workflow.count('ref: ' + plan['source_commit']) == 1
    assert workflow.count(plan['branch_intent']) == 1
    assert 'timeout-minutes: 40' in workflow and 'contents: read' in workflow
    assert 'python-version: \'3.14.4\'' in workflow
    assert inputs['group_limit_seconds'] == 1800 and inputs['cleanup_seconds'] == 3
    prereq = functions((PRODUCT / 'tools/qualify_hia_store_lifecycle.py').read_bytes())['_prerequisites']
    assert 'z3.get_version() == (4, 15, 4, 0)' in ast.unparse(prereq)
    guard_candidate = functions((ROOT / 'v94-native-namespace-budget-r1/guard-r2/source/tools/hia_selfhost_contract.py').read_bytes())
    guard_actual = functions((PRODUCT / 'tools/hia_selfhost_contract.py').read_bytes())
    guard_comparison = {name: dump(guard_candidate[name]) == dump(guard_actual[name]) for name in
        ('_source_capture_protocol', '_source_protocol_current', '_source_lexical_read', '_source_relative_name', 'file_digests')}
    assert guard_comparison == {'_source_capture_protocol': False, '_source_protocol_current': False,
                               '_source_lexical_read': True, '_source_relative_name': True, 'file_digests': True}
    result = {
        'schema': 'hepta.namespace-r20-phase-static-readback.v1', 'status': 'PASS_STATIC_ONLY',
        'parser_python': __import__('sys').version, 'harness_files': 16,
        'harness_manifest': identity((OUT / 'HARNESS-MANIFEST.json').read_bytes()),
        'harness_tree_from_preparation': plan['harness_tree'],
        'original_test_module_full_bytes_same_old_phase': True,
        'full_observation_try_block_ast_unchanged': True, 'unchanged_observer_functions': unchanged,
        'exact_store_generic_bypass_then_original_generic_ast': True,
        'original_store_receipt_observer_ast_unchanged': True,
        'original_timer_snapshot_helpers_byte_unchanged': True,
        'retained_packet_members': 16, 'retained_packet_parts': len(parts['parts']),
        'retained_crc_sha_git_bytes_modes_reconstructed': True,
        'joint_source_manifest_paths': len(current), 'actual_source_manifest_files': len(source),
        'production_toolchain_workflow_block_byte_exact': True,
        'prerequisite_extra_processes_planned_before_group': 2,
        'prerequisite_process_seconds_each': 30,
        'original_budgets': {'context_ms': 3000, 'native_ms': 1000, 'group_seconds': 1800, 'cleanup_seconds': 3, 'job_minutes': 40},
        'guard_candidate_vs_r20_ast_equal': guard_comparison,
        'product_imports': 0, 'product_executions': 0, 'new_benchmark_measurements': 0,
        'github_mutations': 0, 'qualification': False,
    }
    result_id = write('STATIC-READBACK.json', encoded(result))
    old_rows = json.loads((OLD / 'publication/HARNESS-MANIFEST.json').read_bytes())
    old_names = {row['path'] for row in old_rows}
    files = []
    for name in sorted(old_names | set(actual)):
        before = (OLD / 'harness' / name).read_bytes() if name in old_names else None
        after = actual[name].read_bytes() if name in actual else None
        files.append({'path': name,
            'before': None if before is None else {'mode': '100644', **identity(before), 'text': before.decode()},
            'after': None if after is None else {'mode': '100644', **identity(after), 'text': after.decode()}})
    body = encoded({'schema': 'hepta.namespace-r20-harness-full-before-after.v1',
                    'status': 'AUTHORED_NOT_PUBLISHED_NOT_EXECUTED', 'parent_intent': plan['sole_parent_intent'],
                    'tree': plan['harness_tree'], 'files': files, 'plan': plan, 'static_readback': result})
    wrapped = encoded({'schema': 'hepta.lossless-zlib-base64-capsule.v1', 'decoded': identity(body),
                       'payload': base64.b64encode(zlib.compress(body, 6)).decode('ascii')})
    assert zlib.decompress(base64.b64decode(json.loads(wrapped)['payload'], validate=True)) == body
    capsule_id = write('HANDOFF-CAPSULE.zlib.json', wrapped)
    print(json.dumps({'static_readback': result_id, 'capsule': capsule_id,
                      'harness_tree': plan['harness_tree'], 'product_executions': 0, 'git_publications': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
