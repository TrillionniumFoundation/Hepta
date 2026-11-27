"""Compose the frozen optional CLI bundle over exact R10-R2.

This authoring operation parses source, copies bytes, and checks projections.
It does not import product modules, run generators/tests, or publish any ref.
"""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
WORK = HERE.parent
BASE = WORK / 'v92-union-r10-r2/source'
R10 = WORK / 'v92-union-r10'
OUT = HERE / 'source'
INPUT = WORK / 'v89-cli-discovery-routing-r1/portable-r1/handoff-final-r2'
PACKET_BLOB = '7a09f77bfaec5c21f60cd5a4b3c89daabafb131f'
SPEC_BLOB = 'dfed52b46f5cfc5fde5f0c49de55fb2ce3f414bd'
BASE_WORKFLOW_BLOB = '184a5b214b279b75025c30a73676ddd119f9af40'
BASE_WORKFLOW_SHA256 = '4fbfe863311fac2d453d902c6205766ebfa482c8a9e5f296f55a4c328b6084ab'
BASE_PLAN_BLOB = '035d0681a26bb6398d1def298ee9f990b7b4d7ff'
WORKFLOW = '.github/workflows/hia-core.yml'
PROCESS_ARCHIVE_LINE = '            ${{ runner.temp }}/hia-linux-process-matching-cold/\n'
BUNDLE_ARCHIVE_LINE = '            ${{ runner.temp }}/hia-cli-discovery-bundle-matching-cold/\n'
NEW_NATIVE_STEP = (
    '      - name: Native CLI discovery bundle with matching cold and all original 43 plus nine controls\n'
    '        run: python -B -m tools.qualify_hia_cli_discovery_bundle --cold-report "$RUNNER_TEMP/hia-cold.json" --evidence "$RUNNER_TEMP/hia-cli-discovery-bundle-matching-cold"\n'
)
SHARED_PROJECTIONS = {'MANIFEST.in', 'hepta/hia_agent_contract.py', 'tools/hia_selfhost_contract.py'}
APPLICATION_MODULES = (
    'hepta/hia_cli_discovery_facts.py',
    'hepta/hia_cli_discovery_routing_native.py',
    'hepta/hia_cli_parser_context_native.py',
    'hepta/hia_cli_parser_context_foreign.py',
    'hepta/hia_cli_parser_context_data.py',
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def object_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': object_hash('blob', raw), 'mode': '100644'}


def snapshot(root):
    files, caches = {}, {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), path
        if not path.is_file():
            assert path.is_dir(), path
            continue
        name = path.relative_to(root).as_posix()
        assert stat.S_IMODE(path.stat().st_mode) == 0o644, path
        pin = identity(path.read_bytes())
        if '__pycache__' in Path(name).parts:
            assert path.parent.name == '__pycache__' and path.suffix == '.pyc', path
            caches[name] = pin
        else:
            assert path.suffix != '.pyc', path
            files[name] = pin
    return files, caches


def tree_hash(manifest):
    tree = {}
    for name, row in manifest.items():
        node = tree
        parts = name.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = row['mode'], row['git_blob']

    def emit(node):
        raw = b''
        for name, value in sorted(node.items(), key=lambda item: (item[0] + ('/' if isinstance(item[1], dict) else '')).encode()):
            mode, oid = ('40000', emit(value)) if isinstance(value, dict) else value
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
        return object_hash('tree', raw)
    return emit(tree)


def declarations(text):
    result = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result


def append_tuple(text, symbol, additions):
    nodes = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == symbol]
    assert len(nodes) == 1 and isinstance(nodes[0].value, ast.Tuple), symbol
    node = nodes[0].value
    before = ast.literal_eval(node)
    assert type(before) is tuple and len(additions) == len(set(additions))
    assert not set(before) & set(additions), symbol
    lines = text.splitlines(True)
    assert lines[node.end_lineno - 1].strip() == ')'
    at = sum(map(len, lines[:node.end_lineno - 1]))
    after = text[:at] + ''.join('    ' + repr(name) + ',\n' for name in additions) + text[at:]
    assert declarations(after)[symbol] == before + tuple(additions)
    return after


def assert_pin(raw, pin):
    assert raw is not None and pin is not None
    actual = identity(raw)
    assert pin['mode'] == '100644'
    assert all(actual[key] == pin[key] for key in actual), (actual, pin)


def relative_imports(raw):
    values = set()
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            values.update([node.module + '.py'] if node.module else [name.name + '.py' for name in node.names])
    return sorted(values)


def test_methods(text, module):
    result = {}
    for cls in ast.parse(text).body:
        if isinstance(cls, ast.ClassDef):
            for method in cls.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith('test_'):
                    key = module + '.' + cls.name + '.' + method.name
                    assert key not in result
                    result[key] = method
    return result


def assertion_calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
            and n.func.value.id == 'self' and n.func.attr.startswith('assert')]


def main():
    assert not OUT.exists(), 'never overwrite an earlier integration attempt'
    packet_raw = (INPUT / 'SOURCE-PACKET.zlib.json').read_bytes()
    spec_raw = (INPUT / 'REGISTRATION-SPEC.json').read_bytes()
    assert identity(packet_raw)['git_blob'] == PACKET_BLOB
    assert identity(spec_raw)['git_blob'] == SPEC_BLOB
    wrapper = json.loads(packet_raw)
    data = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert len(data) == wrapper['raw_bytes'] and hashlib.sha256(data).hexdigest() == wrapper['raw_sha256']
    assert object_hash('blob', data) == wrapper['raw_git_blob']
    packet, spec = json.loads(data), json.loads(spec_raw)
    rows = {row['path']: row for row in packet['files']}
    assert len(rows) == len(packet['files']) == 24
    new_paths = {name for name, row in rows.items() if row['before'] is None}
    assert new_paths == set(spec['SOURCE_FILES_additions']) and len(new_paths) == 17
    for row in rows.values():
        for side in ('before', 'after'):
            if row[side] is not None:
                assert_pin(row[side]['text'].encode(), row[side])

    base, caches = snapshot(BASE)
    old_r10 = json.loads((R10 / 'SOURCE-MANIFEST.json').read_bytes())
    assert len(base) == len(old_r10) == 3083 and base.keys() == old_r10.keys()
    differing = [name for name in base if base[name] != old_r10[name]]
    assert differing == [WORKFLOW], differing
    baseline_workflow = (BASE / WORKFLOW).read_bytes()
    assert identity(baseline_workflow)['git_blob'] == BASE_WORKFLOW_BLOB
    assert len(baseline_workflow) == 113094 and hashlib.sha256(baseline_workflow).hexdigest() == BASE_WORKFLOW_SHA256
    original_r10_workflow = (R10 / 'source' / WORKFLOW).read_text()
    r10_r2_projection = original_r10_workflow.replace(
        '            ${{ runner.temp }}/hia-linux-stdio-matching-cold/\n',
        '            ${{ runner.temp }}/hia-linux-stdio-matching-cold/\n' + PROCESS_ARCHIVE_LINE, 1)
    assert r10_r2_projection.encode() == baseline_workflow
    (HERE / 'BASELINE-MANIFEST.json').write_bytes(encoded(base))
    (HERE / 'BASE-R10-R2-READBACK.json').write_bytes(encoded({
        'schema': 'hia.r11.exact-r10-r2-preimage-readback.v1',
        'r10_source_manifest': identity((R10 / 'SOURCE-MANIFEST.json').read_bytes()),
        'base_directory': str(BASE), 'base_plan_blob': BASE_PLAN_BLOB,
        'paths': len(base), 'calculated_git_tree': tree_hash(base),
        'changed_vs_original_r10': differing,
        'all_other_3082_source_bytes_modes_equal': True,
        'workflow': identity(baseline_workflow),
        'workflow_delta': {'only': PROCESS_ARCHIVE_LINE.rstrip('\n'),
                           'position': 'immediately after main archive stdio matching-cold path'},
        'excluded_interpreter_caches': caches,
        'source_path_set_exact_to_original_r10': True,
    }))

    preimages, projections = {}, {}
    for name, row in rows.items():
        current = (BASE / name).read_bytes() if name in base else None
        if name in SHARED_PROJECTIONS:
            assert current is not None and current != row['before']['text'].encode()
            preimages[name] = {'mode': 'explicit-additive-projection', 'actual_base': identity(current),
                              'component_before': {k: v for k, v in row['before'].items() if k != 'text'}}
        elif row['before'] is None:
            assert current is None, name
            preimages[name] = {'mode': 'exact-new-file', 'actual_base': None}
        else:
            assert current == row['before']['text'].encode(), name
            preimages[name] = {'mode': 'exact-full-bytes', 'actual_base': identity(current)}
    assert sum(row['mode'] == 'exact-full-bytes' for row in preimages.values()) == 4

    # Copy only the previously enumerated exact source paths; no wildcard filter.
    for name in base:
        destination = OUT / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BASE / name, destination)
        destination.chmod(0o644)
    history = []

    def put(name, raw, reason):
        path = OUT / name
        before = path.read_bytes() if path.exists() else None
        assert before != raw, name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
        history.append({'path': name, 'before': identity(before) if before is not None else None,
                        'after': identity(raw), 'reason': reason})

    for name, row in rows.items():
        if name not in SHARED_PROJECTIONS:
            put(name, row['after']['text'].encode(), 'Exact frozen cumulative CLI bundle after full before/new-file validation.')
            continue
        actual = (OUT / name).read_text()
        if name == 'MANIFEST.in':
            before, after = row['before']['text'], row['after']['text']
            assert after.startswith(before)
            addition = after[len(before):]
            assert addition == ''.join(line + '\n' for line in spec['MANIFEST_in_additions'])
            assert all(line not in actual.splitlines() for line in spec['MANIFEST_in_additions'])
            merged = actual + addition
            assert merged[:-len(addition)] == actual
            projections[name] = {'kind': 'exact-append', 'added_text': addition,
                                  'component_before_after_verified': True, 'all_existing_bytes_retained': True}
        else:
            symbol = 'NATIVE_SOURCE_FILES' if name.startswith('hepta/') else 'SOURCE_FILES'
            additions = spec[symbol + '_additions']
            assert append_tuple(row['before']['text'], symbol, additions) == row['after']['text']
            merged = append_tuple(actual, symbol, additions)
            old_values, new_values = declarations(actual), declarations(merged)
            assert new_values[symbol] == old_values[symbol] + tuple(additions)
            assert {key: value for key, value in old_values.items() if key != symbol} == {
                key: value for key, value in new_values.items() if key != symbol}
            projections[name] = {'kind': 'exact-tuple-append', 'symbol': symbol,
                                  'additions': additions, 'before_count': len(old_values[symbol]),
                                  'after_count': len(new_values[symbol]),
                                  'component_before_after_verified': True,
                                  'all_existing_members_order_and_other_declarations_retained': True}
        put(name, merged.encode(), 'Apply only the frozen additive hunk to the actual R10-R2 shared file; preserve all intervening integration content.')

    fixture_name = 'tests/test_hia_installed_fixture_resources.py'
    before_fixture = (OUT / fixture_name).read_text()
    fixture_projections = [
        ("self.assertEqual(len(values['NATIVE_SOURCE_FILES']),90)", "self.assertEqual(len(values['NATIVE_SOURCE_FILES']),92)"),
        ('self.assertEqual(len(assets),200)', 'self.assertEqual(len(assets),202)'),
    ]
    after_fixture = before_fixture
    for left, right in fixture_projections:
        assert after_fixture.count(left) == 1
        after_fixture = after_fixture.replace(left, right)
    reversed_fixture = after_fixture
    for left, right in reversed(fixture_projections):
        assert reversed_fixture.count(right) == 1
        reversed_fixture = reversed_fixture.replace(right, left)
    assert reversed_fixture == before_fixture
    put(fixture_name, after_fixture.encode(), 'Two exact count literals reflect two real native-bridge resources; all twelve groups and original negative/boundary assertions remain.')
    projections[fixture_name] = {'kind': 'two-resource-count-literals-only', 'changes': fixture_projections,
                                'reverse_projection_full_bytes_equal': True}

    before_workflow = baseline_workflow.decode()
    after_workflow = before_workflow
    generator_names = [Path(name).stem.removeprefix('generate_hia_') for name in spec['generators']]
    assert generator_names == ['cli_discovery_routing', 'cli_parser_context']
    generator_anchor = ' native_cli_process; do'
    assert after_workflow.count(generator_anchor) == 1
    after_workflow = after_workflow.replace(generator_anchor, ' native_cli_process ' + ' '.join(generator_names) + '; do')
    source_anchor = "              'tests.test_hia_linux_cli_process.LinuxCliProcessSourceTests',\n"
    selector_line = '              ' + repr(spec['Source_selector']) + ',\n'
    assert after_workflow.count(source_anchor) == 1 and selector_line not in after_workflow
    after_workflow = after_workflow.replace(source_anchor, source_anchor + selector_line)
    native_anchor = '      - name: Native linked loader and compiler receipt bindings\n'
    assert after_workflow.count(native_anchor) == 1 and NEW_NATIVE_STEP not in after_workflow
    after_workflow = after_workflow.replace(native_anchor, NEW_NATIVE_STEP + native_anchor)
    archive_anchor = '            ${{ runner.temp }}/hia-cli-discovery-json-matching-cold/\n'
    assert after_workflow.count(archive_anchor) == 1 and BUNDLE_ARCHIVE_LINE not in after_workflow
    after_workflow = after_workflow.replace(archive_anchor, archive_anchor + BUNDLE_ARCHIVE_LINE)
    before_native = before_workflow.split('\n  native:\n', 1)[1]
    after_native = after_workflow.split('\n  native:\n', 1)[1]
    assert after_native.replace(NEW_NATIVE_STEP, '').replace(BUNDLE_ARCHIVE_LINE, '') == before_native
    put(WORKFLOW, after_workflow.encode(), 'Append two generators/one Source selector and one strict cold Native qualifier; add its path to the original main always archive and retain the R10-R2 process fix.')

    import yaml
    old_yaml, new_yaml = yaml.safe_load(before_workflow), yaml.safe_load(after_workflow)
    old_jobs, new_jobs = old_yaml['jobs'], new_yaml['jobs']
    assert {key: value for key, value in old_yaml.items() if key != 'jobs'} == {
        key: value for key, value in new_yaml.items() if key != 'jobs'}
    assert old_jobs.keys() == new_jobs.keys()
    for name in old_jobs:
        if name not in ('source', 'native'):
            assert old_jobs[name] == new_jobs[name]
    assert {key: value for key, value in old_jobs['native'].items() if key != 'steps'} == {
        key: value for key, value in new_jobs['native'].items() if key != 'steps'}
    old_steps, new_steps = old_jobs['native']['steps'], new_jobs['native']['steps']
    assert len(old_steps) == 120 and len(new_steps) == 121
    new_step = yaml.safe_load(NEW_NATIVE_STEP)[0]
    assert new_steps.count(new_step) == 1
    projected_steps = [deepcopy(step) for step in new_steps if step != new_step]
    archive = next(step for step in projected_steps if step.get('name') == 'Preserve actual cold failure and stage evidence')
    assert archive['if'] == 'always()'
    archive['with']['path'] = archive['with']['path'].replace(BUNDLE_ARCHIVE_LINE.strip() + '\n', '')
    assert projected_steps == old_steps
    actual_archive = next(step for step in new_steps if step.get('name') == 'Preserve actual cold failure and stage evidence')
    archived = actual_archive['with']['path'].splitlines()
    assert archived.count(PROCESS_ARCHIVE_LINE.strip()) == archived.count(BUNDLE_ARCHIVE_LINE.strip()) == 1
    assert new_step['run'] == spec['production_qualifier']

    def source_selectors(jobs):
        step = next(step for step in jobs['source']['steps'] if step.get('name') == 'Core source and independent reference controls')
        script = step['run'].split("python -B - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        return declarations(script)['names']
    old_selectors, new_selectors = source_selectors(old_jobs), source_selectors(new_jobs)
    assert len(old_selectors) == 228 and new_selectors == old_selectors + (spec['Source_selector'],)
    old_generators = re.search(r'for component in (.*?); do', before_workflow).group(1).split()
    new_generators = re.search(r'for component in (.*?); do', after_workflow).group(1).split()
    assert len(old_generators) == 121 and new_generators == old_generators + generator_names
    workflow_projection = {
        'schema': 'hia.r11.workflow-exact-projection.v1',
        'before': identity(baseline_workflow), 'after': identity(after_workflow.encode()),
        'original_native_fragment_sha256': hashlib.sha256(before_native.encode()).hexdigest(),
        'original_native_steps': 120, 'new_native_steps': 121,
        'new_native_step_exact_text': NEW_NATIVE_STEP,
        'new_main_archive_path_exact_text': BUNDLE_ARCHIVE_LINE,
        'process_main_archive_repair_inherited_exact_text': PROCESS_ARCHIVE_LINE,
        'removing_only_new_step_and_new_archive_path_recovers_original_native_bytes': True,
        'original_120_step_commands_conditions_budgets_and_order_unchanged': True,
        'all_workflow_triggers_permissions_and_other_jobs_unchanged': True,
        'main_archive_always_and_exact_path_checks': True,
        'new_generators': generator_names, 'generator_count_before_after': [121, 123],
        'new_source_selector': spec['Source_selector'], 'selector_count_before_after': [228, 229],
        'source_count_expected_before_after': [1319, 1329],
        'source_count_is_static_registration_not_executed_loader': True,
        'generation_executed': False, 'tests_executed': False,
    }
    (HERE / 'WORKFLOW-PROJECTION.json').write_bytes(encoded(workflow_projection))

    contract = declarations((OUT / 'hepta/hia_agent_contract.py').read_text())
    original_contract = declarations((BASE / 'hepta/hia_agent_contract.py').read_text())
    role_names = [key for key in contract if key.endswith('_BUILD_FILES') or key in ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES')]
    groups = {key: contract[key] for key in role_names}
    assert len(groups) == 12 and len(contract['NATIVE_SOURCE_FILES']) == 92 and len(contract['ENTRY_BUILD_FILES']) == 11
    assert sum(map(len, groups.values())) == 202
    for role in role_names:
        if role != 'NATIVE_SOURCE_FILES':
            assert contract[role] == original_contract[role]
    all_assets = [name for role, values in groups.items() for name in values if role != 'DISCOVERY_FILES']
    assert len(all_assets) == len(set(all_assets))
    for name in spec['NATIVE_SOURCE_FILES_additions']:
        assert all_assets.count(name) == 1
        assert (OUT / 'MANIFEST.in').read_text().splitlines().count('include ' + name) == 1
        stem = Path(name).stem
        bridge = OUT / 'hepta' / ('hia_' + stem + '_native.py')
        assert bridge.is_file() and declarations(bridge.read_text())['SOURCE_NAME'] == name

    source_names = declarations((OUT / 'tools/hia_selfhost_contract.py').read_text())['SOURCE_FILES']
    old_source_names = declarations((BASE / 'tools/hia_selfhost_contract.py').read_text())['SOURCE_FILES']
    assert len(old_source_names) == 1307
    assert source_names == old_source_names + tuple(spec['SOURCE_FILES_additions'])
    assert len(source_names) == len(set(source_names)) == 1324
    assert all((OUT / name).is_file() for name in source_names)

    checker_name = 'hepta/hia_checker_identity.py'
    assert (OUT / checker_name).read_bytes() == (BASE / checker_name).read_bytes()
    checker = declarations((OUT / checker_name).read_text())
    semantic = set(checker['SEMANTIC_CORE_SOURCE_FILES'])
    mechanisms = set(checker['MECHANISM_SOURCE_FILES'])
    assert len(semantic) == 54 and len(mechanisms) == 52 and semantic.isdisjoint(mechanisms)
    app_basenames = {Path(name).name for name in APPLICATION_MODULES}
    assert app_basenames.isdisjoint(semantic | mechanisms)
    assert {'cli.py', 'hia_cli_native.py', 'hia_cli_discovery_json_native.py'}.isdisjoint(semantic | mechanisms)
    protected_incoming = {}
    for name in sorted(semantic | mechanisms):
        dependencies = set(relative_imports((OUT / 'hepta' / name).read_bytes()))
        incoming = sorted(dependencies & app_basenames)
        if incoming:
            protected_incoming[name] = incoming
    assert not protected_incoming
    application_edges = {name: relative_imports((OUT / name).read_bytes()) for name in APPLICATION_MODULES}
    owner_text = (OUT / 'tools/hia_cli_discovery_bundle_custody.py').read_text()
    owner_constants = {node.value for node in ast.walk(ast.parse(owner_text)) if isinstance(node, ast.Constant) and type(node.value) is str}
    assert set(APPLICATION_MODULES) <= owner_constants
    assert set(APPLICATION_MODULES) <= set(source_names)
    closure = {
        'schema': 'hia.r11.application-cli-closure-review.v1',
        'checker_source_unchanged': identity((OUT / checker_name).read_bytes()),
        'semantic_core': 54, 'mechanisms': 52,
        'new_application_modules': list(APPLICATION_MODULES),
        'actual_application_relative_imports': application_edges,
        'incoming_relative_imports_from_declared_core_or_mechanism_to_new_cli': protected_incoming,
        'all_five_explicitly_bound_by_SOURCE_FILES_and_bundle_OWNER_FILES': True,
        'installed_hepta_source_identity_is_existing_complete_package_custody': True,
        'reason_no_checker_role_added': 'These optional application CLI objects have no incoming Core/mechanism import. Existing CLI/control/JSON objects are outside both checker role lists. Their owner cold closure and complete installed package source identity remain explicit.',
        'execution': 'SOURCE_REVIEW_ONLY',
    }
    (HERE / 'STATIC-CLOSURE.json').write_bytes(encoded(closure))

    # Source-test retention is checked structurally without loading or executing tests.
    preservation = {}
    for name in ('tests/test_hia_cli_discovery_json.py', fixture_name):
        module = name[:-3].replace('/', '.')
        before_text, after_text = (BASE / name).read_text(), (OUT / name).read_text()
        before_methods, after_methods = test_methods(before_text, module), test_methods(after_text, module)
        assert before_methods.keys() == after_methods.keys()
        changed_methods = []
        for key in before_methods:
            old, new = before_methods[key], after_methods[key]
            assert len(assertion_calls(old)) == len(assertion_calls(new)), key
            if ast.dump(old, include_attributes=False) != ast.dump(new, include_attributes=False):
                changed_methods.append(key)
        assert len(changed_methods) == (1 if 'discovery_json' in name else 2)
        preservation[name] = {'before': identity(before_text.encode()), 'after': identity(after_text.encode()),
                              'ordered_declared_ids': list(before_methods), 'method_count_unchanged': len(before_methods),
                              'all_assertion_call_counts_preserved': True, 'exact_changed_methods': changed_methods}
    for name, pin in spec['original43_modules'].items():
        raw = (OUT / name).read_bytes()
        assert_pin(raw, pin)
        assert raw == (BASE / name).read_bytes()
    retained = json.loads((OUT / 'tests/fixtures/hia_cli_routing_retained.json').read_bytes())
    for name, projection in retained['integration_projections'].items():
        assert (BASE / name).read_bytes() == projection['before']['text'].encode()
        assert (OUT / name).read_bytes() == projection['after']['text'].encode()
    new_module = 'tests.test_hia_cli_discovery_routing_native'
    new_methods = test_methods((OUT / (new_module.replace('.', '/') + '.py')).read_text(), new_module)
    declared_source = sorted(key for key in new_methods if '.CliDiscoveryRoutingSourceTests.' in key)
    declared_native = sorted(key for key in new_methods if '.CliDiscoveryRoutingNativeTests.' in key)
    assert declared_source == spec['Source_exact_ids'] and len(declared_source) == 10
    assert declared_native == spec['Native_exact_ids'] and len(declared_native) == 9
    (HERE / 'SOURCE-METHOD-PRESERVATION.json').write_bytes(encoded({
        'schema': 'hia.r11.source-method-preservation.v1', 'changed_existing_test_files': preservation,
        'original43_module_bytes_unchanged': spec['original43_modules'],
        'original43_ordered_ids': spec['original43_ordered_ids'],
        'new_source_declared_ids': declared_source, 'new_native_declared_ids': declared_native,
        'all_other_existing_test_files_will_be_full_manifest_equal': True,
        'no_product_test_or_loader_execution': True,
    }))

    final, output_caches = snapshot(OUT)
    assert not output_caches and len(final) == 3100
    assert set(final) - set(base) == new_paths and not set(base) - set(final)
    changes = {name: {'before': base.get(name), 'after': pin} for name, pin in final.items() if base.get(name) != pin}
    assert set(changes) == set(rows) | {WORKFLOW, fixture_name} and len(changes) == 26
    assert {row['path'] for row in history} == set(changes)
    for name in base:
        if name.startswith('tests/') and name not in preservation:
            assert name not in changes, name
    for name in changes:
        if name.endswith('.py'):
            ast.parse((OUT / name).read_bytes(), filename=name)
    after_base, after_caches = snapshot(BASE)
    assert after_base == base and after_caches == caches
    (HERE / 'SOURCE-MANIFEST.json').write_bytes(encoded(final))
    (HERE / 'COMPONENT-PROJECTIONS.json').write_bytes(encoded({
        'schema': 'hia.r11.frozen-component-projections.v1', 'component_packet': identity(packet_raw),
        'component_registration': identity(spec_raw), 'preimage_classification': preimages,
        'explicit_projections': projections, 'all_other_component_after_bytes_exact': True,
    }))
    registration = {
        'schema': 'hia.r11.optional-cli-bundle-union-registration.v1',
        'status': 'AUTHORED_NOT_GENERATED_NOT_QUALIFIED',
        'base_directory': str(BASE), 'base_calculated_git_tree': tree_hash(base),
        'source_directory': str(OUT), 'source_calculated_git_tree': tree_hash(final),
        'base_source_files': 3083, 'source_files': 3100,
        'SOURCE_FILES_before_after': [1307, 1324], 'SOURCE_FILES_additions': spec['SOURCE_FILES_additions'],
        'NATIVE_SOURCE_FILES_before_after': [90, 92], 'NATIVE_SOURCE_FILES_additions': spec['NATIVE_SOURCE_FILES_additions'],
        'ENTRY_BUILD_FILES_before_after': [11, 11], 'resource_group_count': 12, 'resources_before_after': [200, 202],
        'MANIFEST_in_additions': spec['MANIFEST_in_additions'],
        'checker_Core_MECH_before_after': [[54, 52], [54, 52]],
        'generators_before_after': [121, 123], 'generators_additions': spec['generators'],
        'source_selectors_before_after': [228, 229], 'Source_selector_addition': spec['Source_selector'],
        'Source_exact_ids_additions': declared_source,
        'expected_source_count_before_after': [1319, 1329], 'not_an_executed_loader_result': True,
        'Native_steps_before_after': [120, 121], 'Native_step_addition': new_step,
        'Native_qualifier_exact_groups': spec['production_qualifier_groups'],
        'Native_exact_ids': declared_native, 'original43_ordered_ids': spec['original43_ordered_ids'],
        'main_archive_additions_vs_R10_R2': [BUNDLE_ARCHIVE_LINE.strip()],
        'main_archive_additions_vs_R10': [PROCESS_ARCHIVE_LINE.strip(), BUNDLE_ARCHIVE_LINE.strip()],
        'limits': spec['limits'], 'production_positive_executed': False,
        'generation_pending': ['both new owners on final interpreter', 'checker inventory', 'language coverage', 'source support', 'rewrite inventory with actual Git state'],
        'parser_metadata_is_runtime_specific': True, 'no_support_or_checker_generated_bytes_imported_from_component': True,
        'default_changed': False, 'whole_cli_native': False,
        'qualification_not_inherited': True, 'all_component_history_failures_retained': True,
    }
    (HERE / 'REGISTRATION-SPEC.json').write_bytes(encoded(registration))
    report = {
        'schema': 'hia.r11.frozen-cli-discovery-bundle-integration.v1',
        'status': 'AUTHORED_STATIC_PROJECTIONS_VERIFIED_GENERATION_AND_TESTS_PENDING',
        'base_directory': str(BASE), 'base_plan_blob': BASE_PLAN_BLOB,
        'base_source_files': len(base), 'base_calculated_git_tree': tree_hash(base),
        'source_files': len(final), 'calculated_git_tree': tree_hash(final),
        'component_packet': identity(packet_raw), 'component_registration': identity(spec_raw),
        'exact_component_files': 24, 'component_new_paths': 17, 'changed_paths': len(changes),
        'base_full_bytes_modes_unchanged': True, 'no_paths_deleted': True,
        'excluded_interpreter_caches': caches, 'no_unknown_files_excluded': True,
        'registration': registration, 'workflow_projection': workflow_projection,
        'application_checker_boundary': closure, 'existing_test_preservation': preservation,
        'default_changed': False, 'whole_cli_native': False,
        'generation_executed': False, 'tests_executed': False, 'loader_executed': False,
        'matching_current_source_cold_executed': False, 'formal_cpython314_executed': False,
        'changes': changes, 'history': history,
        'prior_component_result_is_only_local_development_on_its_own_exact_source': packet['actual_result'],
        'prior_component_raw_custody': packet['raw_custody'],
    }
    (HERE / 'INTEGRATION.json').write_bytes(encoded(report))
    file_rows = []
    for name in sorted(changes):
        before = None if name not in base else dict(base[name], text=(BASE / name).read_text())
        after = dict(final[name], text=(OUT / name).read_text())
        file_rows.append({'path': name, 'before': before, 'after': after})
    payload = encoded({'schema': 'hia.r11.complete-exact-before-after-source-packet.v1',
                       'status': report['status'], 'base_directory': str(BASE),
                       'base_plan_blob': BASE_PLAN_BLOB, 'base_tree': tree_hash(base),
                       'source_tree': tree_hash(final), 'base_manifest': base, 'source_manifest': final,
                       'files': file_rows, 'registration': registration, 'history': history,
                       'component_packet': identity(packet_raw), 'workflow_projection': workflow_projection,
                       'generation_executed': False, 'tests_executed': False,
                       'matching_current_source_cold_executed': False})
    compressed = zlib.compress(payload, 9)
    wrapper = {'schema': 'hia.zlib-source-capsule.v1', 'encoding': 'base64+zlib',
               'raw_bytes': len(payload), 'raw_sha256': hashlib.sha256(payload).hexdigest(),
               'raw_git_blob': object_hash('blob', payload), 'payload': base64.b64encode(compressed).decode()}
    transport = encoded(wrapper)
    (HERE / 'SOURCE-PACKET.zlib.json').write_bytes(transport)
    assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'], validate=True)) == payload
    print(json.dumps({key: report[key] for key in (
        'status', 'base_source_files', 'base_calculated_git_tree', 'source_files', 'calculated_git_tree',
        'exact_component_files', 'component_new_paths', 'changed_paths', 'base_full_bytes_modes_unchanged',
        'no_paths_deleted', 'generation_executed', 'tests_executed', 'matching_current_source_cold_executed')}, indent=2))
    print(json.dumps({'source_packet': identity(transport), 'integration': identity((HERE / 'INTEGRATION.json').read_bytes()),
                      'registration': identity((HERE / 'REGISTRATION-SPEC.json').read_bytes())}, indent=2))


if __name__ == '__main__':
    main()
