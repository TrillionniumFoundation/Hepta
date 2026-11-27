"""Freeze an exact R11 + Linux-file registration successor.

This is a source composition operation. It imports no product modules and does
not execute generators, unittest loaders, tests, native images, or Git writes.
The complete R11 source and component preimages are verified before publishing
the new local source directory. Every generated metadata seed is retained for
the parent's subsequent real regeneration on the final tree.
"""
from __future__ import annotations

import ast
import base64
import difflib
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
BASE = WORK / 'v93-union-r11/source'
OUT = HERE / 'source'
COMPONENT = WORK / 'v93-linux-file-entry-r1/handoff'
BASE_TREE = '4561802d6b5548e8933913716eedf01f4189d7e3'
PACKET_BLOB = '0c113e1f12829d383652cb2dc33c57ba937a6e1a'
SPEC_BLOB = 'e75c5a9bcb2a731a535ecc6e1b754eaf10637459'
WORKFLOW = '.github/workflows/hia-core.yml'
ASSETS = (
    'examples/hia_bootstrap/selfhost_linux_file.hepta',
    'examples/hia_bootstrap/linux_file_entry_packer.hepta',
    'examples/hia_bootstrap/native_file_read.hepta',
)
GENERATORS = ('selfhost_linux_file', 'linux_file_entry', 'native_file_read')
SOURCE_SELECTOR = 'tests.test_hia_linux_file.LinuxFileSourceTests'
SHARED = ('hepta/hia_agent_assembly.py', 'hepta/hia_program.py',
          'hepta/hia_program_runtime.py')
ROLE_NAMES = ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES',
              'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES',
              'EMITTER_BUILD_FILES', 'BYTE_WRAPPER_BUILD_FILES', 'MACHINE_OBJECT_BUILD_FILES',
              'EXECUTION_OBSERVATION_BUILD_FILES', 'CONTINUATION_BUILD_FILES', 'ENTRY_BUILD_FILES')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def object_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': object_hash('blob', raw), 'mode': '100644'}


def validate_pin(raw, pin):
    actual = identity(raw)
    assert pin['mode'] in ('0644', '100644'), pin
    assert all(actual[key] == pin[key] for key in ('bytes', 'sha256', 'git_blob')), (actual, pin)


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
    root = {}
    for name, row in manifest.items():
        node = root
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
    return emit(root)


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
    assert lines[node.end_lineno - 1].strip() == ')', symbol
    at = sum(map(len, lines[:node.end_lineno - 1]))
    added = ''.join('    ' + repr(name) + ',\n' for name in additions)
    after = text[:at] + added + text[at:]
    assert after[:at] + after[at + len(added):] == text
    assert declarations(after)[symbol] == before + tuple(additions)
    return after


def replace_once(text, before, after):
    assert before != after and text.count(before) == 1, before
    result = text.replace(before, after, 1)
    assert result.count(after) == 1, after
    assert result.replace(after, before, 1) == text
    return result


def methods(text, module):
    result = {}
    for cls in ast.parse(text).body:
        if isinstance(cls, ast.ClassDef):
            for node in cls.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
                    key = module + '.' + cls.name + '.' + node.name
                    assert key not in result
                    result[key] = node
    return result


def method_bytes(text, node):
    start = min([node.lineno] + [deco.lineno for deco in node.decorator_list])
    return ''.join(text.splitlines(True)[start - 1:node.end_lineno])


def relative_imports(raw):
    values = set()
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            values.update([node.module + '.py'] if node.module else [name.name + '.py' for name in node.names])
    return sorted(values)


def main():
    assert not OUT.exists(), 'exclusive new source directory required'
    assert not (HERE / 'SOURCE-PACKET.zlib.json').exists(), 'never overwrite a frozen integration'
    packet_raw = (COMPONENT / 'SOURCE-PACKET.zlib.json').read_bytes()
    spec_raw = (COMPONENT / 'REGISTRATION-SPEC.json').read_bytes()
    assert identity(packet_raw)['git_blob'] == PACKET_BLOB
    assert identity(spec_raw)['git_blob'] == SPEC_BLOB
    wrapper = json.loads(packet_raw)
    payload = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert len(payload) == wrapper['raw_bytes']
    assert hashlib.sha256(payload).hexdigest() == wrapper['raw_sha256']
    assert object_hash('blob', payload) == wrapper['raw_git_blob']
    packet, component_spec = json.loads(payload), json.loads(spec_raw)
    assert packet['schema'] == 'hia.linux-file-development-overlay.v1'
    rows = packet['files']
    assert len(rows) == 11 and set(rows) == set(component_spec['owned_paths'])
    assert set(ASSETS) == set(component_spec['ENTRY_BUILD_FILES_additions'])
    new_paths = sorted(name for name, row in rows.items() if row['before'] is None)
    assert len(new_paths) == 8
    assert new_paths == sorted(component_spec['SOURCE_FILES_additions_or_dynamic_members'])

    base, caches = snapshot(BASE)
    recorded_base = json.loads((BASE.parent / 'SOURCE-MANIFEST.json').read_bytes())
    assert base == recorded_base and len(base) == 3100
    assert tree_hash(base) == BASE_TREE
    contents, history, projections = {}, [], {}

    def read(name):
        return contents[name] if name in contents else (BASE / name).read_bytes()

    def put(name, raw, reason):
        assert name not in contents, ('one final author per path', name)
        before = (BASE / name).read_bytes() if name in base else None
        assert before != raw, name
        contents[name] = raw
        history.append({'path': name, 'before': None if before is None else identity(before),
                        'after': identity(raw), 'reason': reason})

    # All three public shared files are exact physical preimages, not projections.
    component_preimages = {}
    for name, row in rows.items():
        raw = row['text'].encode()
        validate_pin(raw, row)
        if row['before'] is None:
            assert name not in base and not (BASE / name).exists(), name
            component_preimages[name] = {'kind': 'exact-new-file', 'before': None}
        else:
            validate_pin(row['before_text'].encode(), row['before'])
            assert name in SHARED and (BASE / name).read_bytes() == row['before_text'].encode(), name
            component_preimages[name] = {'kind': 'exact-full-preimage', 'before': base[name]}
        put(name, raw, 'Exact frozen Linux-file component bytes after full preimage/new-path validation; no component result is inherited.')
    assert sorted(name for name, row in rows.items() if row['before'] is not None) == sorted(SHARED)

    name = 'hepta/hia_agent_contract.py'
    before = read(name).decode()
    after = append_tuple(before, 'ENTRY_BUILD_FILES', ASSETS)
    put(name, after.encode(), 'Append only three standalone assets to the existing twelfth resource role; preserve all eleven predecessor ENTRY members and NATIVE92.')
    projections[name] = {'kind': 'tuple-append', 'symbol': 'ENTRY_BUILD_FILES', 'additions': ASSETS}

    name = 'tools/hia_selfhost_contract.py'
    before = read(name).decode()
    put(name, append_tuple(before, 'SOURCE_FILES', new_paths).encode(), 'Append all eight new full source paths; preserve the exact original 1324-member prefix.')
    projections[name] = {'kind': 'tuple-append', 'symbol': 'SOURCE_FILES', 'additions': new_paths}

    name = 'MANIFEST.in'
    before = read(name).decode()
    added = ''.join('include ' + asset + '\n' for asset in ASSETS)
    assert before.endswith('\n') and all('include ' + asset not in before.splitlines() for asset in ASSETS)
    put(name, (before + added).encode(), 'Append the same three ENTRY resources to sdist; all previous includes and frozen caller fixtures remain.')
    projections[name] = {'kind': 'exact-append', 'text': added}

    name = 'tools/hia_candidate_preflight.py'
    before = read(name).decode()
    anchor = "        'examples/hia_bootstrap/native_cli_process.hepta',\n    })\n    combined = files + entry"
    replacement = "        'examples/hia_bootstrap/native_cli_process.hepta',\n" + ''.join('        ' + repr(asset) + ',\n' for asset in ASSETS) + '    })\n    combined = files + entry'
    after = replace_once(before, anchor, replacement)
    put(name, after.encode(), 'Extend only the finite ENTRY allowlist; preserve sequential twelve-role reads, uniqueness, and the original 256-entry bound.')
    projections[name] = {'kind': 'exact-replacement', 'before': anchor, 'after': replacement}

    name = 'hepta/hia_checker_identity.py'
    before = read(name).decode()
    after = append_tuple(before, 'MECHANISM_SOURCE_FILES', ('hia_linux_file.py',))
    anchor = "CHECKER_MECHANISM_EXTERNAL_PROVIDERS = {\n"
    replacement = anchor + " 'hia_linux_file.py': ('hia_program_runtime.py',),\n"
    after = replace_once(after, anchor, replacement)
    generated_end = '# END GENERATED CHECKER CUSTODY\n'
    assert before.count(generated_end) == after.count(generated_end) == 1
    assert before.split(generated_end, 1)[0] == after.split(generated_end, 1)[0]
    put(name, after.encode(), 'Add the explicit Linux-file mechanism and exact runtime provider edge. Keep physical generated closure as an unqualified seed for actual final-tree regeneration.')
    projections[name] = {'kind': 'mechanism-tuple-append-and-exact-provider-entry',
                         'mechanism': 'hia_linux_file.py', 'providers': ('hia_program_runtime.py',),
                         'generated_block_unchanged_pending_real_regeneration': True}

    name = 'tools/check_hia_core_only.py'
    before = read(name).decode()
    anchor = "    'examples/hia_bootstrap/native_cli_process.hepta': 'hepta.hia.linux-cli-process.v1',\n"
    added_role = "    'examples/hia_bootstrap/native_file_read.hepta': 'hepta.hia.linux-file.v1',\n"
    after = replace_once(before, anchor, anchor + added_role)
    put(name, after.encode(), 'Declare one exact physical source/profile role; all default/unknown-path refusal logic and five old stdio roles remain unchanged.')
    projections[name] = {'kind': 'exact-replacement', 'before': anchor, 'after': anchor + added_role}

    name = 'tests/test_hia_source_suffix.py'
    before = read(name).decode()
    anchor = "        expected_profiles['examples/hia_bootstrap/native_cli_process.hepta'] = 'hepta.hia.linux-cli-process.v1'\n"
    added_expected = "        expected_profiles['examples/hia_bootstrap/native_file_read.hepta'] = 'hepta.hia.linux-file.v1'\n"
    after = replace_once(before, anchor, anchor + added_expected)
    original_methods = methods(before, name[:-3].replace('/', '.'))
    template_id, template = next((key, node) for key, node in original_methods.items()
                                if node.name == 'test_native_cli_process_source_role_is_explicit_and_fully_verified')
    template_text = method_bytes(before, template)
    new_method = template_text
    for old, new, count in (
        ('test_native_cli_process_source_role_is_explicit_and_fully_verified', 'test_native_file_source_role_is_explicit_and_fully_verified', 1),
        ('from hepta.hia_linux_cli_process import PROFILE', 'from hepta.hia_linux_file import PROFILE', 1),
        ('examples/hia_bootstrap/native_cli_process.hepta', 'examples/hia_bootstrap/native_file_read.hepta', 1),
        ('unregistered_cli_process', 'unregistered_file', 2),
    ):
        assert new_method.count(old) == count, old
        new_method = new_method.replace(old, new)
    assert template_text in after
    after = replace_once(after, template_text, template_text + '\n' + new_method)
    put(name, after.encode(), 'Preserve the original five stdio controls and complete CLI source-role method. Add an independent file-role method covering both source forms, default/unknown-path/SSA/symlink refusal, and exact profile calls.')
    projections[name] = {'kind': 'one-expectation-entry-plus-new-independent-method',
                         'expected_mapping_added_line': added_expected,
                         'template_original_method': template_id,
                         'template_original_bytes_unchanged': True,
                         'new_method_text': new_method}

    name = 'tests/test_hia_installed_fixture_resources.py'
    before = read(name).decode()
    anchor = "               'examples/hia_bootstrap/native_cli_process.hepta')"
    replacement = "               'examples/hia_bootstrap/native_cli_process.hepta',\n" + ',\n'.join('               ' + repr(asset) for asset in ASSETS) + ')'
    after = replace_once(before, anchor, replacement)
    after = replace_once(after, 'self.assertEqual(len(assets),202)', 'self.assertEqual(len(assets),205)')
    put(name, after.encode(), 'Extend the exact ENTRY fixture tuple and total resource count. Retain NATIVE92, disjointness, every original negative input, 256 bound, and fresh installed-byte checks for each ENTRY asset.')
    projections[name] = {'kind': 'exact-entry-tuple-plus-total-count', 'entry_additions': ASSETS,
                         'resource_count_before_after': [202, 205], 'NATIVE_count_unchanged': 92}

    name = 'tests/test_hia_linux_stdio_cold.py'
    before = read(name).decode()
    anchor = "        self.assertEqual(ENTRY_BUILD_FILES, original + PROFILE_SOURCE_FILES + process + cli_process)"
    replacement = '        file_process = (' + repr(ASSETS[0]) + ',\n' + ''.join('                        ' + repr(asset) + (',\n' if i < 2 else ')\n') for i, asset in enumerate(ASSETS[1:], 1))
    replacement += '        self.assertEqual(ENTRY_BUILD_FILES, original + PROFILE_SOURCE_FILES + process + cli_process + file_process)'
    after = replace_once(before, anchor, replacement)
    after = replace_once(after, 'for name in PROFILE_SOURCE_FILES + process + cli_process:',
                          'for name in PROFILE_SOURCE_FILES + process + cli_process + file_process:')
    put(name, after.encode(), 'Extend only the Source resource-inventory method with all three real new ENTRY assets; retain every Native method and original strict-cold behavior.')
    projections[name] = {'kind': 'exact-source-resource-method-extension', 'new_entry_tuple': ASSETS}
    old_test_sha, new_test_sha = hashlib.sha256(before.encode()).hexdigest(), hashlib.sha256(after.encode()).hexdigest()

    name = 'tools/qualify_hia_linux_stdio.py'
    before = read(name).decode()
    anchor = " 'tests/test_hia_linux_stdio_cold.py': '" + old_test_sha + "',"
    replacement = " 'tests/test_hia_linux_stdio_cold.py': '" + new_test_sha + "',"
    after = replace_once(before, anchor, replacement)
    assert declarations(after)['TEST_SOURCE_PINS'] == dict(declarations(before)['TEST_SOURCE_PINS'], **{'tests/test_hia_linux_stdio_cold.py': new_test_sha})
    put(name, after.encode(), 'Update only the actual complete cold-test source SHA after the resource Source-method extension. No caller ID, cold/receipt guard, native behavior or budget changes.')
    projections[name] = {'kind': 'one-exact-source-pin', 'source': 'tests/test_hia_linux_stdio_cold.py',
                         'sha256_before_after': [old_test_sha, new_test_sha]}

    name = 'tests/test_hia_proof_contract_native.py'
    before = read(name).decode()
    anchor = 'self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 52, 106))'
    replacement = 'self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 53, 107))'
    after = replace_once(before, anchor, replacement)
    put(name, after.encode(), 'Update only the exact role counts for the one new explicit mechanism. Preserve the original exhaustive AST provider-edge comparison, disjointness and all-nine-checker fresh custody assertions.')
    projections[name] = {'kind': 'exact-role-count-tuple', 'before': [54, 52, 106], 'after': [54, 53, 107]}

    before_workflow = read(WORKFLOW).decode()
    generator_anchor = ' cli_parser_context; do'
    after_workflow = replace_once(before_workflow, generator_anchor,
                                  ' cli_parser_context ' + ' '.join(GENERATORS) + '; do')
    selector_anchor = "              'tests.test_hia_cli_discovery_routing_native.CliDiscoveryRoutingSourceTests',\n"
    selector_line = '              ' + repr(SOURCE_SELECTOR) + ',\n'
    after_workflow = replace_once(after_workflow, selector_anchor, selector_anchor + selector_line)
    assert before_workflow.split('\n  native:\n', 1)[1] == after_workflow.split('\n  native:\n', 1)[1]
    put(WORKFLOW, after_workflow.encode(), 'Append three owner generators and one Source class only. The entire original 121-step Native job, all evidence paths, conditions and limits remain byte-identical; no fake file cold qualifier is added.')

    import yaml
    old_yaml, new_yaml = yaml.safe_load(before_workflow), yaml.safe_load(after_workflow)
    old_jobs, new_jobs = old_yaml['jobs'], new_yaml['jobs']
    assert {k: v for k, v in old_yaml.items() if k != 'jobs'} == {k: v for k, v in new_yaml.items() if k != 'jobs'}
    assert old_jobs.keys() == new_jobs.keys()
    assert {k: v for k, v in old_jobs.items() if k != 'source'} == {k: v for k, v in new_jobs.items() if k != 'source'}
    assert len(old_jobs['native']['steps']) == len(new_jobs['native']['steps']) == 121

    def source_selectors(jobs):
        step = next(step for step in jobs['source']['steps'] if step.get('name') == 'Core source and independent reference controls')
        script = step['run'].split("python -B - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        return declarations(script)['names']
    old_selectors, new_selectors = source_selectors(old_jobs), source_selectors(new_jobs)
    assert len(old_selectors) == 229 and new_selectors == old_selectors + (SOURCE_SELECTOR,)
    old_generators = re.search(r'for component in (.*?); do', before_workflow).group(1).split()
    new_generators = re.search(r'for component in (.*?); do', after_workflow).group(1).split()
    assert len(old_generators) == 123 and new_generators == old_generators + list(GENERATORS)
    workflow_projection = {
        'before': identity(before_workflow.encode()), 'after': identity(after_workflow.encode()),
        'original_121_native_steps_fragment_sha256': hashlib.sha256(before_workflow.split('\n  native:\n', 1)[1].encode()).hexdigest(),
        'entire_native_fragment_identical': True, 'Native_steps_before_after': [121, 121],
        'generator_names_before': old_generators, 'generator_names_after': new_generators,
        'source_selectors_before': old_selectors, 'source_selectors_after': new_selectors,
        'all_original_selectors_exact_ordered_prefix': True,
        'source_count_expected_before_after': [1329, 1342],
        'not_an_executed_loader_result': True,
    }

    old_contract = declarations((BASE / 'hepta/hia_agent_contract.py').read_text())
    contract = declarations(read('hepta/hia_agent_contract.py'))
    assert {name for name in contract if name.endswith('_BUILD_FILES') or name in ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES')} == set(ROLE_NAMES)
    groups = {name: contract[name] for name in ROLE_NAMES}
    assert len(groups['NATIVE_SOURCE_FILES']) == 92 and len(groups['ENTRY_BUILD_FILES']) == 14
    assert groups['ENTRY_BUILD_FILES'] == old_contract['ENTRY_BUILD_FILES'] + ASSETS
    assert all(groups[name] == old_contract[name] for name in ROLE_NAMES if name != 'ENTRY_BUILD_FILES')
    assert sum(map(len, groups.values())) == 205
    all_assets = tuple('docs/' + name for name in groups['DISCOVERY_FILES']) + tuple(path for role in ROLE_NAMES[1:] for path in groups[role])
    assert len(all_assets) == len(set(all_assets)) == 205
    for asset in ASSETS:
        assert all_assets.count(asset) == 1
        assert read('MANIFEST.in').decode().splitlines().count('include ' + asset) == 1
        assert asset in contents
    sources_before = declarations((BASE / 'tools/hia_selfhost_contract.py').read_text())['SOURCE_FILES']
    sources_after = declarations(read('tools/hia_selfhost_contract.py'))['SOURCE_FILES']
    assert len(sources_before) == 1324
    assert sources_after == sources_before + tuple(new_paths)
    assert len(sources_after) == len(set(sources_after)) == 1332
    assert all(name in base or name in contents for name in sources_after)

    before_checker = declarations((BASE / 'hepta/hia_checker_identity.py').read_text())
    checker = declarations(read('hepta/hia_checker_identity.py'))
    assert checker['SEMANTIC_CORE_SOURCE_FILES'] == before_checker['SEMANTIC_CORE_SOURCE_FILES']
    core, mechanism = set(checker['SEMANTIC_CORE_SOURCE_FILES']), set(checker['MECHANISM_SOURCE_FILES'])
    assert len(core) == 54 and len(mechanism) == 53 and core.isdisjoint(mechanism)
    providers = checker['CHECKER_MECHANISM_EXTERNAL_PROVIDERS']
    assert providers == dict(before_checker['CHECKER_MECHANISM_EXTERNAL_PROVIDERS'], **{'hia_linux_file.py': ('hia_program_runtime.py',)})
    actual_edges = {}
    for name in sorted(mechanism):
        dependencies = set(relative_imports(read('hepta/' + name)))
        external = dependencies - core - mechanism
        assert external == set(providers.get(name, ())), (name, external, providers.get(name))
        actual_edges[name] = {'actual_relative_imports': sorted(dependencies), 'external_providers': sorted(external)}
    closure = {'semantic_core_before_after': [54, 54], 'mechanisms_before_after': [52, 53],
               'one_new_mechanism': 'hia_linux_file.py', 'actual_edges_all_53': actual_edges,
               'public_shared_new_edges': {name: sorted(set(relative_imports(read(name))) - set(relative_imports((BASE / name).read_bytes()))) for name in SHARED},
               'generated_physical_closure_not_recomputed': True,
               'physical_closure_support_language_and_inventory_require_real_final_generation': True,
               'all_Native_HELD_CAPTURED_selector_tables_unchanged': True}
    for symbol in ('NATIVE_OWNERS', 'HELD_NATIVE_OWNERS', 'CAPTURED_NATIVE_OWNERS'):
        assert checker[symbol] == before_checker[symbol]
    expected_profiles = declarations((BASE / 'tools/check_hia_core_only.py').read_text())['EXPLICIT_SOURCE_PROFILES']
    assert declarations(read('tools/check_hia_core_only.py'))['EXPLICIT_SOURCE_PROFILES'] == dict(expected_profiles, **{ASSETS[2]: 'hepta.hia.linux-file.v1'})

    # Full original test functions are retained, except five documented Source
    # inventory/role expectations. Native method bodies remain exact bytes.
    allowed_changed = {
        'tests/test_hia_source_suffix.py': {'test_linux_stdio_source_roles_are_explicit_and_fully_verified'},
        'tests/test_hia_installed_fixture_resources.py': {'test_standalone_entry_role_is_exact_disjoint_and_preflight_bounded', 'test_entry_assets_are_fresh_identity_inputs_and_missing_fails_before_backend'},
        'tests/test_hia_linux_stdio_cold.py': {'test_entry_resources_keep_all_four_predecessors_and_are_not_runtime_bridges'},
        'tests/test_hia_proof_contract_native.py': {'test_core_and_mechanism_roles_have_exact_provider_edges'},
    }
    preservation = {}
    for name, allowed in allowed_changed.items():
        before, after = (BASE / name).read_text(), read(name).decode()
        old_methods, new_methods = methods(before, name[:-3].replace('/', '.')), methods(after, name[:-3].replace('/', '.'))
        assert set(old_methods) <= set(new_methods)
        assert [key for key in new_methods if key in old_methods] == list(old_methods)
        changed = []
        for key, node in old_methods.items():
            old_text = method_bytes(before, node)
            new_text = method_bytes(after, new_methods[key])
            if old_text != new_text:
                changed.append(node.name)
                old_assertions = [n for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith('assert')]
                new_assertions = [n for n in ast.walk(new_methods[key]) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith('assert')]
                assert len(old_assertions) == len(new_assertions), key
        assert set(changed) == allowed, (name, changed, allowed)
        additions = sorted(set(new_methods) - set(old_methods))
        assert len(additions) == (1 if name.endswith('test_hia_source_suffix.py') else 0)
        preservation[name] = {'before': identity(before.encode()), 'after': identity(after.encode()),
                              'original_declared_ids_in_definition_order': list(old_methods),
                              'all_original_ids_and_order_preserved': True,
                              'exact_changed_Source_methods': changed,
                              'all_other_original_method_bytes_identical': True,
                              'all_original_assertion_counts_preserved': True,
                              'new_declared_ids': additions}
    new_test_methods = methods(read('tests/test_hia_linux_file.py'), 'tests.test_hia_linux_file')
    declared_file_ids = sorted(new_test_methods)
    assert declared_file_ids == component_spec['Source_exact_IDs'] and len(declared_file_ids) == 12
    added_ids = preservation['tests/test_hia_source_suffix.py']['new_declared_ids'] + declared_file_ids
    assert len(added_ids) == 13
    assert read('tools/hia_retained_agent_callers.py') == (BASE / 'tools/hia_retained_agent_callers.py').read_bytes()
    assert read('setup.py') == (BASE / 'setup.py').read_bytes()
    assert read('hepta/hia_native_helpers.py') == (BASE / 'hepta/hia_native_helpers.py').read_bytes()
    # Resource identities are dynamically assembled from all twelve existing
    # tuples in these files. No old frozen caller source is rewritten.
    assert 'ENTRY_BUILD_FILES' in read('tools/hia_retained_agent_callers.py').decode()
    assert 'ENTRY_BUILD_FILES' in read('setup.py').decode()
    for name in base:
        if name.startswith('tests/') and name not in allowed_changed:
            assert name not in contents, name

    direct_generator_dependencies = (
        'tools/generate_hia_selfhost.py', 'tools/generate_hia_selfhost_linux_stdio.py',
        'tools/generate_hia_selfhost_linux_process.py', 'tools/generate_hia_linux_process_entry.py',
        'tools/generate_hia_native_cli_process.py', 'tools/generate_hia_elf_linker.py',
    )
    dependency_pins = {}
    for name in direct_generator_dependencies:
        row = packet['source_manifest'][name]
        validate_pin(read(name), row)
        dependency_pins[name] = identity(read(name))
    for name, raw in contents.items():
        if name.endswith('.py'):
            ast.parse(raw, filename=name)
    predicted = dict(base)
    predicted.update({name: identity(raw) for name, raw in contents.items()})
    assert len(predicted) == 3108 and len(contents) == 23
    assert sorted(set(predicted) - set(base)) == new_paths

    # No source is written until every strict preimage and static projection has
    # completed. The output directory is exclusive and never reused on failure.
    OUT.mkdir()
    for name in base:
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name in contents:
            path.write_bytes(contents[name])
        else:
            shutil.copyfile(BASE / name, path)
        path.chmod(0o644)
    for name in new_paths:
        path = OUT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents[name]); path.chmod(0o644)
    final, final_caches = snapshot(OUT)
    assert final == predicted and not final_caches
    after_base, after_caches = snapshot(BASE)
    assert after_base == base and after_caches == caches
    changes = {name: {'before': base.get(name), 'after': final[name]} for name in sorted(contents)}
    registration = {
        'schema': 'hia.r12.linux-file-union-registration.v1',
        'status': 'AUTHORED_NOT_GENERATED_NOT_EXECUTED_NOT_QUALIFIED',
        'base_directory': str(BASE), 'base_source_files': 3100, 'base_tree': BASE_TREE,
        'source_directory': str(OUT), 'source_files': 3108, 'source_tree': tree_hash(final),
        'component_packet': PACKET_BLOB, 'component_spec': SPEC_BLOB,
        'SOURCE_FILES_before_after': [1324, 1332], 'SOURCE_FILES_additions': new_paths,
        'ENTRY_BUILD_FILES_before_after': [11, 14], 'ENTRY_BUILD_FILES_additions': ASSETS,
        'NATIVE_SOURCE_FILES_before_after': [92, 92],
        'resource_group_count': 12, 'resources_before_after': [202, 205],
        'exact_resource_groups_after': groups,
        'MANIFEST_in_additions': ['include ' + name for name in ASSETS],
        'preflight_allowlist_actual_path': 'tools/hia_candidate_preflight.py:native_source_files.entry_paths',
        'preflight_original_256_unique_bound_unchanged': True,
        'component_spec_helper_whitelist_wording_corrected': 'The actual finite entry_paths declaration is in tools/hia_candidate_preflight.py, not hia_native_helpers.py. Helpers and setup already consume all twelve resource roles dynamically and are byte-identical to R11.',
        'checker_Core_MECH_before_after': [[54, 52], [54, 53]],
        'checker_mechanism_added': 'hia_linux_file.py',
        'checker_external_provider_added': {'hia_linux_file.py': ['hia_program_runtime.py']},
        'core_only_exact_source_profile': {ASSETS[2]: 'hepta.hia.linux-file.v1'},
        'generators_before_after': [123, 126],
        'generators_additions': ['tools/generate_hia_' + name + '.py' for name in GENERATORS],
        'generator_check_arguments': ['--check'],
        'Source_selectors_before_after': [229, 230], 'Source_selector_added': SOURCE_SELECTOR,
        'Source_declared_added_ids': added_ids, 'Source_static_expected_before_after': [1329, 1342],
        'Source_count_is_not_actual_loader_result': True,
        'Native_steps_before_after': [121, 121], 'entire_Native_fragment_byte_identical': True,
        'new_production_Native_selector': None, 'matching_current_cold_qualifier': 'NOT_IMPLEMENTED',
        'matching_current_cold_positive': False, 'installed_positive_for_new_assets': False,
        'old_stdio_qualifier_only_pin_update': projections['tools/qualify_hia_linux_stdio.py'],
        'all_existing_resource_fixture_and_retained_caller_roles_preserved': True,
        'frozen_caller_txt_bytes_unchanged': True,
        'limits': component_spec['limits'],
        'generation_pending': ['checker full physical import closure', 'all 126 owner generators twice and original --check',
                               'language coverage', 'selfhost support', 'native rewrite inventory with actual Git state'],
        'generation_executed': False, 'tests_executed': False, 'loader_executed': False,
        'current_cold_or_native_or_full_qualification_inherited': False,
        'old_CPython_read_bounded_complete_equivalence': False,
        'old_13_CLI_file_actions_implemented': False,
        'file_profile_contract': '99942a5ffef6f6df80d90bd1e9d3e2d67450cc22',
        'component_result': '30f2af9590cf86753686e62b7ccbb8680945de4f',
        'component_metadata_gap_addendum': 'eafefdd1dd8ca4cf89b7c62c36eb3334fb9533a1',
    }
    report = {
        'schema': 'hia.r12.linux-file-source-integration.v1',
        'status': 'AUTHORED_STATIC_PREIMAGES_AND_PROJECTIONS_VERIFIED_EXECUTION_PENDING',
        'base_directory': str(BASE), 'base_files': len(base), 'base_tree': tree_hash(base),
        'source_directory': str(OUT), 'source_files': len(final), 'source_tree': tree_hash(final),
        'component_paths': 11, 'new_paths': 8, 'changed_paths': len(changes),
        'shared_three_full_preimages_exact': True,
        'base_all_bytes_modes_and_caches_unchanged': True, 'no_paths_deleted': True,
        'source_before_and_after_copy_full_hash_mode_readback': True,
        'excluded_base_caches': caches, 'unrecognized_omissions': [],
        'registration': registration, 'workflow_projection': workflow_projection,
        'component_preimage_classification': component_preimages,
        'direct_generator_dependency_bytes_match_frozen_component': dependency_pins,
        'exact_mechanism_provider_edges': closure,
        'Source_method_preservation': preservation,
        'history': history, 'changes': changes,
        'generation_executed': False, 'tests_executed': False, 'loader_executed': False,
        'native_or_cold_or_formal314_executed': False,
    }
    reports = {'BASELINE-MANIFEST.json': base, 'SOURCE-MANIFEST.json': final,
               'INTEGRATION.json': report, 'REGISTRATION-SPEC.json': registration,
               'WORKFLOW-PROJECTION.json': workflow_projection,
               'STATIC-MECHANISM-EDGES.json': closure,
               'SOURCE-METHOD-PRESERVATION.json': preservation,
               'COMPONENT-PROJECTIONS.json': {'component_packet': identity(packet_raw),
                                             'component_registration': identity(spec_raw),
                                             'preimages': component_preimages, 'projections': projections}}
    for name, value in reports.items():
        target = HERE / name
        with target.open('xb') as handle:
            handle.write(encoded(value))
    file_rows = []
    for name in sorted(contents):
        before = None if name not in base else dict(base[name], text=(BASE / name).read_text())
        after = dict(final[name], text=contents[name].decode())
        diff = ''.join(difflib.unified_diff([] if before is None else before['text'].splitlines(True),
                                           after['text'].splitlines(True),
                                           fromfile='/dev/null' if before is None else 'before/' + name,
                                           tofile='after/' + name))
        file_rows.append({'path': name, 'before': before, 'after': after, 'unified_diff': diff})
    source_payload = encoded({'schema': 'hia.r12.complete-before-after-source-packet.v1',
                              'status': report['status'], 'base_tree': BASE_TREE,
                              'source_tree': tree_hash(final), 'base_manifest': base, 'source_manifest': final,
                              'files': file_rows, 'registration': registration, 'history': history,
                              'component_packet': PACKET_BLOB, 'workflow_projection': workflow_projection,
                              'source_method_preservation': preservation, 'mechanism_edges': closure,
                              'generation_executed': False, 'tests_executed': False, 'loader_executed': False})
    transport = encoded({'schema': 'hia.zlib-source-capsule.v1', 'encoding': 'zlib+base64',
                         'raw_bytes': len(source_payload), 'raw_sha256': hashlib.sha256(source_payload).hexdigest(),
                         'raw_git_blob': object_hash('blob', source_payload),
                         'payload': base64.b64encode(zlib.compress(source_payload, 9)).decode()})
    assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'], validate=True)) == source_payload
    with (HERE / 'SOURCE-PACKET.zlib.json').open('xb') as handle:
        handle.write(transport)
    print(json.dumps({key: report[key] for key in ('status', 'base_files', 'base_tree', 'source_files', 'source_tree',
                                                    'component_paths', 'new_paths', 'changed_paths',
                                                    'generation_executed', 'tests_executed', 'loader_executed')}, indent=2))
    print(json.dumps({'source_packet': identity(transport),
                      'registration': identity((HERE / 'REGISTRATION-SPEC.json').read_bytes()),
                      'integration': identity((HERE / 'INTEGRATION.json').read_bytes())}, indent=2))


if __name__ == '__main__':
    main()
