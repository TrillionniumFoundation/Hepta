"""Freeze source bytes and a request; never import or execute product code."""
from __future__ import annotations
import ast
import difflib
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'source'
REPOSITORY = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
CLASSES = (
    'tests.test_hia_core_compare_source.ExactNumericComparisonSourceTests',
    'tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests',
    'tests.test_hia_core_compare_lifecycle.NumericComparisonLifecycleSourceTests',
    'tests.test_hia_compiler_owner_gates.CompilerOwnerGateTests',
    'tests.test_hia_core_unpack_gates.CoreUnpackGateSourceTests',
    'tests.test_hia_store_page_gates.StorePageCIGateTests',
    'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests',
    'tests.test_hia_selfhost_contract.SelfhostContractTests',
    'tests.test_hia_core_lowering_native.CoreLoweringSourceTests',
    'tests.test_hia_core_unpack_native.UnpackCompositionSourceTests',
)


def save(name, value):
    with (HERE / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def digest(raw):
    return {'size': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tree_hash(leaves):
    root = {}
    for row in leaves:
        current = root
        parts = row['path'].split('/')
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        if parts[-1] in current:
            raise ValueError('duplicate tree entry')
        current[parts[-1]] = row
    def walk(node):
        rows = []
        for name, value in node.items():
            directory = 'sha' not in value
            mode = '40000' if directory else value['mode']
            sha = walk(value) if directory else value['sha']
            rows.append((name + ('/' if directory else ''),
                mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        raw = b''.join(value for _, value in sorted(rows))
        return sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return walk(root)


def methods(path):
    return {cls.name + '.' + method.name: ast.dump(method)
            for cls in ast.parse(path.read_bytes()).body if isinstance(cls, ast.ClassDef)
            for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')}


def main():
    # Import only the non-product fixed-file metadata helper.
    spec = importlib.util.spec_from_file_location('numeric_source_freeze_metadata', HERE / 'control/common.py')
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    base = json.loads((HERE / 'BASE-GIT-TREE.json').read_bytes())
    assert base['commit'] == '1fd7a1366a2f1fe3f8a6207e400464beb3686a58'
    assert base['tree'] == 'c7aa2396bb242efb89cd4135557d51e1d2ccfda1'
    assert len(base['leaves']) == 4075 and tree_hash(base['leaves']) == base['tree']
    original = {row['path']: row for row in base['leaves']}
    snapshots = common.snapshot(SOURCE)
    source_files = common.content(snapshots)
    delta = []
    virtual = dict(original)
    for row in source_files:
        name, old = row['relative_path'], original.get(row['relative_path'])
        mode = '100755' if row['mode'] & 0o111 else '100644'
        if old is None or (old['sha'], old['size'], old['mode']) != (row['git_blob_sha1'], row['size'], mode):
            delta.append({'path': name, 'before': old,
                'after': dict(path=name, type='blob', mode=mode, sha=row['git_blob_sha1'],
                              size=row['size'], sha256=row['sha256'])})
        virtual[name] = dict(path=name, type='blob', mode=mode, sha=row['git_blob_sha1'], size=row['size'])
    all_ids, counts = [], []
    for name in CLASSES:
        module, cls = name.rsplit('.', 1)
        path = SOURCE / Path(*module.split('.')).with_suffix('.py')
        node = next(node for node in ast.parse(path.read_bytes()).body
                    if isinstance(node, ast.ClassDef) and node.name == cls)
        names = sorted(node.name for node in node.body
                       if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        assert len(names) == len(set(names))
        all_ids.extend(name + '.' + method for method in names)
        counts.append({'class': name, 'count': len(names)})
    assert [row['count'] for row in counts] == [11, 9, 6, 20, 14, 6, 4, 7, 4, 2]
    assert len(all_ids) == len(set(all_ids)) == 83
    parsed = []
    for name in [row['path'] for row in delta if row['path'].endswith('.py')]:
        ast.parse((SOURCE / name).read_bytes(), filename=name)
        parsed.append(name)
    for path in sorted((HERE / 'control').glob('*.py')):
        ast.parse(path.read_bytes(), filename=str(path))
        parsed.append(str(path.relative_to(HERE)))
    child_assignment = next(node for node in ast.parse((SOURCE / 'tests/test_hia_core_lowering_native.py').read_bytes()).body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'INSTALLED_CHILD' for target in node.targets))
    child = ast.literal_eval(child_assignment.value)
    ast.parse(child, filename='INSTALLED_CHILD')
    old11 = SOURCE / 'tests/fixtures/hia_core_compare_source_before_portability.py.txt'
    now11 = SOURCE / 'tests/test_hia_core_compare_source.py'
    assert methods(old11) == methods(now11) and len(methods(now11)) == 11
    old15 = methods(SOURCE / 'tests/fixtures/hia_core_lowering_before_dual_companions.py.txt')
    now15 = methods(SOURCE / 'tests/test_hia_core_lowering_native.py')
    changed = 'CoreLoweringNativeTests.test_actual_installed_wheel_uses_complete_bundle_without_authoring'
    assert len(old15) == len(now15) == 15 and old15.keys() == now15.keys()
    assert all(old15[name] == now15[name] for name in old15 if name != changed)
    old_author = ast.parse((SOURCE / 'tests/fixtures/hia_core_compare_generator_before_standard_entry.py.txt').read_bytes())
    new_author = ast.parse((SOURCE / 'tools/generate_hia_core_compare.py').read_bytes())
    remove_main = lambda value: ast.dump(ast.Module(body=[node for node in value.body
        if not (isinstance(node, ast.FunctionDef) and node.name == 'main')], type_ignores=[]))
    assert remove_main(old_author) == remove_main(new_author)
    baseline = json.loads((SOURCE / 'tests/fixtures/hia_core_compare_integration_baseline.json').read_bytes())
    workflow = (SOURCE / '.github/workflows/hia-core.yml').read_text()
    generators = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
    assert generators == baseline['generator_prefix'] + ['core_compare'] and len(generators) == 62
    assert workflow.count("python-version: '3.14.4'") == 2
    frozen_core = json.loads((SOURCE / 'tests/fixtures/hia_core_compare_core39.json').read_bytes())['files']
    assert len(frozen_core) == 40
    assert len({row['path'] for row in frozen_core}) == 40
    for expected in frozen_core:
        name = expected['path']
        actual = digest((SOURCE / name).read_bytes())
        assert actual == {key: expected[key] for key in ('size', 'sha256', 'git_blob_sha1')}
    runtime = common.pin(Path(sys.executable).resolve(strict=True))
    assert runtime['nlink'] == 1 and runtime['mode'] & 0o022 == 0
    owner = common.pin(SOURCE / 'tools/hia_selfhost_process_owner.py')
    assert owner['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
    controls = [common.pin(path) for path in sorted((HERE / 'control').glob('*.py'))]
    request = {'schema': 'hepta.hia.core-compare-integration-source-request.v1',
        'revision': 'r1-with-independent-terminal-epoch-correction', 'status': 'FROZEN_UNEXECUTED',
        'base_commit': base['commit'], 'base_tree': base['tree'],
        'base_full_leaf_count': len(base['leaves']),
        'source_root': str(SOURCE), 'physical_source_count': len(source_files),
        'physical_source_bytes': sum(row['size'] for row in source_files),
        'virtual_source_tree_before_derivation': tree_hash(list(virtual.values())),
        'actual_git_HEAD_claimed': False, 'full_checkout_created': False,
        'evidence_root': '/tmp/hia-core-compare-integration-source-r1',
        'runtime': runtime, 'process_owner': owner, 'control_inputs': controls,
        'source_files': source_files, 'generator_names': generators,
        'derivations': [['tools/generate_hia_selfhost_contract.py', []],
            ['tests/test_hia_selfhost_language_coverage.py', ['--generate-inventory']],
            ['tools/generate_hia_selfhost_contract.py', []],
            ['tools/generate_hia_selfhost_contract.py', ['--check']]],
        'allowed_derived_changes': ['docs/HIA_SELFHOST_CORE_SUPPORT.json', 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'],
        'both_derived_files_required_to_change': False,
        'source_after_generation_and_after_derivation_must_be_stable': True,
        'test_classes': list(CLASSES), 'class_denominators': counts, 'expected_ids': all_ids,
        'expected_methods': 83, 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'minimum_available_bytes': 536870912, 'minimum_available_inodes': 4096,
        'anticipated_new_evidence_bytes_upper_estimate': 41943040,
        'estimate_is_not_a_product_or_output_cap': True,
        'native_and_compiler_and_subprocess_entry_poison_required_in_each_source_child': True,
        'source_Core_VM_allowed': True,
        'native_executed': False, 'complete18_executed': False, 'complete116_executed': False,
        'cold_executed': False, 'installed_executed': False, 'remote_triggered': False}
    save('REQUEST.json', request)
    save('EXPECTED-SOURCE-IDS.json', {'classes': counts, 'expected_ids': all_ids,
        'method_count': 83, 'original_numeric_methods': 11, 'new_integration_methods': 9,
        'new_lifecycle_methods': 6, 'existing_other_source_methods': 57})
    save('SOURCE-DELTA.json', {'base_commit': base['commit'], 'base_tree': base['tree'],
        'virtual_tree': request['virtual_source_tree_before_derivation'], 'full_virtual_leaf_count': len(virtual),
        'derived_documents_still_base_bytes_until_the_single_source_run': True,
        'delta_count': len(delta), 'delta': delta})
    save('SOURCE-PHYSICAL-PINS.json', snapshots)
    save('STATIC-CHECKS.json', {'status': 'STATIC_SOURCE_AND_AST_ONLY',
        'parsed_paths': parsed, 'installed_child_literal_parsed': True,
        'original11_method_AST_equal': True, 'fourteen_other_Core_method_AST_equal': True,
        'original15_ids_equal': True, 'numeric_generator_except_main_AST_equal': True,
        'all_Core39_plus_ABI_bytes_equal': True, 'original61_prefix_equal': True,
        'current_candidate_test_methods_executed': 0, 'current_candidate_native_executed': False,
        'prior_native_r3_scope_not_inherited_by_new_bridge': True,
        'new_source_denominator': 83, 'new_lifecycle_fixture_is_synthetic_not_native': True})
    process = subprocess.Popen(['git', 'cat-file', '--batch'], cwd=REPOSITORY,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    differences = []
    try:
        for row in delta:
            old = row['before']
            old_raw = b''
            if old is not None:
                process.stdin.write((old['sha'] + '\n').encode()); process.stdin.flush()
                assert process.stdout.readline().decode().split() == [old['sha'], 'blob', str(old['size'])]
                old_raw = process.stdout.read(old['size']); assert process.stdout.read(1) == b'\n'
                assert digest(old_raw)['git_blob_sha1'] == old['sha']
            new_raw = (SOURCE / row['path']).read_bytes()
            differences.extend(difflib.unified_diff(old_raw.decode().splitlines(keepends=True),
                new_raw.decode().splitlines(keepends=True), fromfile='base/' + row['path'], tofile='candidate/' + row['path']))
        process.stdin.close()
        assert process.wait(timeout=20) == 0 and process.stderr.read() == b''
    finally:
        if process.poll() is None:
            if not process.stdin.closed: process.stdin.close()
            process.wait(timeout=20)
    with (HERE / 'SOURCE-DELTA.diff').open('x') as stream:
        stream.writelines(differences)
    old_bridge = SOURCE / 'tests/fixtures/hia_core_compare_before_terminal_epoch.py.txt'
    with (HERE / 'BRIDGE-TERMINAL-EPOCH.diff').open('x') as stream:
        stream.writelines(difflib.unified_diff(old_bridge.read_text().splitlines(keepends=True),
            (SOURCE / 'hepta/hia_core_compare_native.py').read_text().splitlines(keepends=True),
            fromfile='finite-r3/hepta/hia_core_compare_native.py', tofile='integration/hepta/hia_core_compare_native.py'))
    save('LAUNCH.json', {'schema': 'hepta.hia.core-compare-integration-source-launch.v1',
        'operation': 'SOURCE_ONLY_RUN_EXACTLY_ONCE_AFTER_CANONICAL_REVIEW',
        'request': common.pin(HERE / 'REQUEST.json'),
        'command': [runtime['path'], '-I', '-S', '-B', str(HERE / 'control/launch.py')],
        'cwd': str(HERE), 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'shell': 'bash', 'login': False, 'no_native_or_remote_execution_authorized': True})
    print(json.dumps({'status': 'FROZEN_UNEXECUTED', 'delta_count': len(delta),
        'physical_files': len(source_files), 'physical_bytes': request['physical_source_bytes'],
        'virtual_tree': request['virtual_source_tree_before_derivation'], 'virtual_leaves': len(virtual),
        'source_methods': len(all_ids), 'generators': len(generators),
        'request': common.pin(HERE / 'REQUEST.json'), 'launch': common.pin(HERE / 'LAUNCH.json')}))


if __name__ == '__main__':
    main()
