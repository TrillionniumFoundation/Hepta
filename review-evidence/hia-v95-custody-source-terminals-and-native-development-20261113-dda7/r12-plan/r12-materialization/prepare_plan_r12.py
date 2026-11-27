"""Normalize frozen R12 sources without executing generation or product tests."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import zlib

import yaml

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v93-union-r11'
WORKFLOW = '.github/workflows/hia-core.yml'
OLD_PLAN_BLOB = 'c19cd878115b1e9d3d4b81024838b36575a6bf30'
CAPSULE_BLOB = 'f5b87f67060e01f332bf607d878d6dc0e0ab53f6'
INTEGRATION_BLOB = '1bb2f49bec5e75f613a64659904dcad8e6b668a3'
REGISTRATION_BLOB = 'ce3050c7a3f5b829409f7e1ba2fd9e24542c9636'
DRIVER_BLOB = 'cfe319279641b124bcd724437857686f36d1aa07'


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def object_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'git_blob': object_hash('blob', raw), 'mode': '100644',
            'sha256': hashlib.sha256(raw).hexdigest()}


def tree_hash(manifest):
    root = {}
    for name, pin in manifest.items():
        pieces = name.split('/')
        assert all(part not in ('', '.', '..') for part in pieces)
        node = root
        for part in pieces[:-1]:
            node = node.setdefault(part, {})
        assert pieces[-1] not in node
        node[pieces[-1]] = (pin['mode'], pin['git_blob'])

    def descend(node):
        rows = []
        for name, value in node.items():
            if isinstance(value, dict):
                rows.append((name.encode() + b'/', b'40000 ' + name.encode() + b'\0' + bytes.fromhex(descend(value))))
            else:
                mode, oid = value
                rows.append((name.encode(), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)))
        return object_hash('tree', b''.join(raw for _, raw in sorted(rows)))
    return descend(root)


def read_exact(root, manifest):
    files, values = set(), {}
    for path in root.rglob('*'):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode), path
        if stat.S_ISDIR(info.st_mode):
            continue
        assert stat.S_ISREG(info.st_mode), path
        name = path.relative_to(root).as_posix()
        files.add(name)
        assert name in manifest, ('unexpected source path', name)
        assert stat.S_IMODE(info.st_mode) == 0o644, name
        raw = path.read_bytes()
        assert identity(raw) == manifest[name], name
        values[name] = raw
    assert files == set(manifest), (root, sorted(set(manifest) - files))
    return values


def file_inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), path
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o644, path
            result[path.relative_to(root).as_posix()] = identity(path.read_bytes())
        else:
            assert path.is_dir(), path
    return result


def literal_assignment(raw, name):
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(('missing literal declaration', name))


def methods(raw, path):
    text = raw.decode()
    lines = text.splitlines(keepends=True)
    module = path.removesuffix('.py').replace('/', '.')
    result = {}
    for node in ast.parse(text).body:
        if not isinstance(node, ast.ClassDef):
            continue
        for method in node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) or not method.name.startswith('test_'):
                continue
            start = min([method.lineno] + [item.lineno for item in method.decorator_list])
            body = ''.join(lines[start - 1:method.end_lineno]).encode()
            assertions = sum(isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
                             and item.func.attr.startswith('assert') for item in ast.walk(method))
            result[module + '.' + node.name + '.' + method.name] = (body, assertions)
    return result


def main():
    assert not (ROOT / 'harness').exists() and not (ROOT / 'input-blobs').exists()
    capsule_raw = (ROOT / 'SOURCE-PACKET.zlib.json').read_bytes()
    integration_raw = (ROOT / 'INTEGRATION.json').read_bytes()
    spec_raw = (ROOT / 'REGISTRATION-SPEC.json').read_bytes()
    assert identity(capsule_raw)['git_blob'] == CAPSULE_BLOB
    assert identity(integration_raw)['git_blob'] == INTEGRATION_BLOB
    assert identity(spec_raw)['git_blob'] == REGISTRATION_BLOB
    wrapper = json.loads(capsule_raw)
    raw = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert len(raw) == wrapper['raw_bytes'] and identity(raw)['git_blob'] == wrapper['raw_git_blob']
    assert identity(raw)['sha256'] == wrapper['raw_sha256']
    packet, integration, spec = json.loads(raw), json.loads(integration_raw), json.loads(spec_raw)
    baseline = json.loads((ROOT / 'BASELINE-MANIFEST.json').read_bytes())
    final = json.loads((ROOT / 'SOURCE-MANIFEST.json').read_bytes())
    assert len(baseline) == 3100 and len(final) == 3108
    assert baseline == packet['base_manifest'] and final == packet['source_manifest']
    before, after = read_exact(BASE / 'source', baseline), read_exact(ROOT / 'source', final)
    assert tree_hash(baseline) == '4561802d6b5548e8933913716eedf01f4189d7e3'
    assert tree_hash(final) == '06524acb76047fc271ab6b6597362fd5f3499d00'
    changed = sorted(name for name in after if before.get(name) != after[name])
    new_source = sorted(set(after) - set(before))
    assert not set(before) - set(after)
    assert len(changed) == 23 and len(new_source) == 8
    assert set(changed) == set(integration['changes']) == {row['path'] for row in packet['files']}
    assert packet['registration'] == spec and packet['workflow_projection'] == integration['workflow_projection']
    for row in packet['files']:
        name = row['path']
        if row['before'] is None:
            assert name not in before
        else:
            assert row['before']['text'].encode() == before[name]
            assert {key: value for key, value in row['before'].items() if key != 'text'} == identity(before[name])
        assert row['after']['text'].encode() == after[name]
        assert {key: value for key, value in row['after'].items() if key != 'text'} == identity(after[name])
        assert integration['changes'][name] == {'before': identity(before[name]) if name in before else None,
                                               'after': identity(after[name])}

    old_plan_raw = (BASE / 'harness/inputs/MATERIALIZATION-R11.json').read_bytes()
    assert identity(old_plan_raw)['git_blob'] == OLD_PLAN_BLOB
    old_plan = json.loads(old_plan_raw)
    plan = deepcopy(old_plan)
    authors_raw = (BASE / 'harness/inputs/AUTHORING-R11.json').read_bytes()
    authors = {row['path']: row for row in json.loads(authors_raw)}
    original_authors = deepcopy(authors)
    assert len(authors) == plan['expected_authored_files'] == 448
    assert len(plan['packets']) == 64 and len(plan['allowed_overrides']) == 174
    assert not set(changed) & {row['path'] for row in plan['exact_retained'] + plan['regeneration_seeds']}
    existing_authors = sorted(set(changed) & set(authors))
    first_authored = sorted(set(changed) - set(authors))
    assert len(existing_authors) == 15 and len(first_authored) == 8
    assert first_authored == new_source
    for name in existing_authors:
        assert authors[name]['sha'] == identity(before[name])['git_blob'], name
        assert authors[name]['text'].encode() == before[name], name
        assert authors[name]['mode'] == final[name]['mode'], name

    workflow = after[WORKFLOW].decode()
    old_workflow = before[WORKFLOW].decode()
    source, native = workflow.split('  native:\n', 1)
    old_source, old_native = old_workflow.split('  native:\n', 1)
    assert native == old_native
    assert workflow.split('  source:\n', 1)[0] == old_workflow.split('  source:\n', 1)[0]
    jobs = yaml.safe_load(workflow)['jobs']
    assert len(jobs['native']['steps']) == 121
    generators = re.search(r'for component in (.*?); do', source).group(1).split()
    additions = [Path(name).stem.removeprefix('generate_hia_') for name in spec['generators_additions']]
    assert additions == ['selfhost_linux_file', 'linux_file_entry', 'native_file_read']
    assert generators == plan['generators'] + additions
    assert generators == plan['source_registration']['generators'] + additions
    assert len(generators) == 126
    test_run = next(row['run'] for row in jobs['source']['steps'] if row.get('name') == 'Core source and independent reference controls')
    body = ast.parse('\n'.join(test_run.splitlines()[1:-1]) + '\n')
    assignment = next(node for node in body.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'names' for target in node.targets))
    selectors = list(ast.literal_eval(assignment.value))
    assert selectors == plan['source_registration']['selectors'] + [spec['Source_selector_added']]
    assert len(selectors) == 230
    projected_source = source.replace(' ' + ' '.join(additions) + '; do', '; do', 1)
    selected_line = next(line for line in projected_source.splitlines(keepends=True) if spec['Source_selector_added'] in line)
    assert projected_source.count(selected_line) == 1
    projected_source = projected_source.replace(selected_line, '', 1)
    assert projected_source == old_source
    fragment = '  source:\n' + workflow.split('  source:\n', 1)[1].split('  native:\n', 1)[0]
    old_fragment = (BASE / 'harness/inputs/SOURCE-R11-FRAGMENT.yml').read_bytes()
    assert identity(old_fragment)['git_blob'] == plan['source_registration']['after_fragment']['blob']
    assert old_fragment == ('  source:\n' + old_workflow.split('  source:\n', 1)[1].split('  native:\n', 1)[0]).encode()

    old_contract = literal_assignment(before['tools/hia_selfhost_contract.py'], 'SOURCE_FILES')
    new_contract = literal_assignment(after['tools/hia_selfhost_contract.py'], 'SOURCE_FILES')
    assert len(old_contract) == 1324 and len(new_contract) == 1332
    assert len(set(new_contract)) == len(new_contract)
    assert set(new_contract) - set(old_contract) == set(spec['SOURCE_FILES_additions']) == set(new_source)
    assert [name for name in new_contract if name in old_contract] == list(old_contract)
    assert not set(new_contract) - set(after)
    groups = spec['exact_resource_groups_after']
    assert len(groups) == 12 and sum(map(len, groups.values())) == 205
    for name, values in groups.items():
        assert list(literal_assignment(after['hepta/hia_agent_contract.py'], name)) == values, name
    assert len(groups['ENTRY_BUILD_FILES']) == 14 and len(groups['NATIVE_SOURCE_FILES']) == 92
    assert literal_assignment(after['hepta/hia_checker_identity.py'], 'SEMANTIC_CORE_SOURCE_FILES') == literal_assignment(before['hepta/hia_checker_identity.py'], 'SEMANTIC_CORE_SOURCE_FILES')
    assert len(literal_assignment(after['hepta/hia_checker_identity.py'], 'SEMANTIC_CORE_SOURCE_FILES')) == 54
    old_mech = literal_assignment(before['hepta/hia_checker_identity.py'], 'MECHANISM_SOURCE_FILES')
    new_mech = literal_assignment(after['hepta/hia_checker_identity.py'], 'MECHANISM_SOURCE_FILES')
    assert len(old_mech) == 52 and len(new_mech) == 53
    assert set(new_mech) - set(old_mech) == {'hia_linux_file.py'}

    method_checks = {}
    for name, recorded in integration['Source_method_preservation'].items():
        old_methods, new_methods = methods(before[name], name), methods(after[name], name)
        assert [key for key in new_methods if key in old_methods] == list(old_methods), name
        actual_changed = [key for key in old_methods if old_methods[key][0] != new_methods[key][0]]
        actual_new = [key for key in new_methods if key not in old_methods]
        assert {key.rsplit('.', 1)[1] for key in actual_changed} == set(recorded['exact_changed_Source_methods']), name
        assert actual_new == recorded['new_declared_ids'], name
        for key in old_methods:
            assert new_methods[key][1] >= old_methods[key][1], key
        method_checks[name] = {'old_ids_in_definition_order': list(old_methods), 'changed_ids': actual_changed,
                               'new_ids': actual_new, 'old_assertion_call_counts_preserved': True,
                               'all_other_old_method_bytes_exact': True}
    all_new = set(methods(after['tests/test_hia_linux_file.py'], 'tests/test_hia_linux_file.py'))
    for value in method_checks.values():
        all_new.update(value['new_ids'])
    assert all_new == set(spec['Source_declared_added_ids']) and len(all_new) == 13
    assert all(before[name] == after[name] for name in before if name.endswith('.py.txt'))

    # Copy immutable preparation inputs only; no source module is imported or executed.
    inherited_inputs = file_inventory(BASE / 'input-blobs')
    inherited_harness = file_inventory(BASE / 'harness')
    shutil.copytree(BASE / 'input-blobs', ROOT / 'input-blobs', copy_function=os.link)
    shutil.copytree(BASE / 'harness', ROOT / 'harness', copy_function=os.link)
    assert file_inventory(ROOT / 'input-blobs') == inherited_inputs
    assert file_inventory(ROOT / 'harness') == inherited_harness

    chunks, current = [], []
    for name in changed:
        row = {'path': name, 'before': identity(before[name]) if name in before else None,
               'after': dict(identity(after[name]), text=after[name].decode())}
        if current and len(encode({'files': current + [row]})) > 635000:
            chunks.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        chunks.append(current)
    new_packets = []
    for index, chunk in enumerate(chunks):
        label = 'linux-file-integration-r12-' + str(index).zfill(2)
        normalized = {'schema': 'hia.reviewed-joint-source-overlay.v1', 'label': label,
            'scope': 'EXACT_OPTIONAL_LINUX_FILE_PROFILE_AUTHORED_NOT_GENERATED_NOT_COLD_QUALIFIED',
            'component_integration_packet': identity(capsule_raw),
            'component_integration_report': identity(integration_raw),
            'component_registration': identity(spec_raw), 'base_plan': identity(old_plan_raw),
            'full_before_bytes_preserved_in_integration_capsule': True,
            'all121_native_step_bytes_preserved': True,
            'source_methods_and_prior_ordered_selectors_preserved': True,
            'component_limitations': [
                'The thirteen original CLI file actions remain unconnected.',
                'The file profile does not claim complete CPython read_bounded equivalence.',
                'No matching-current-source cold qualifier exists for this new file component.',
                'Original budgets and all old profile rejections remain unchanged.',
                'The inherited parser generator has a separately preserved CPython 3.14 _colorize.Argparse failure; this plan does not fix or conceal it.',
            ], 'whole_native': False, 'default_changed': False, 'files': chunk}
        payload = encode(normalized)
        assert len(payload) <= 650000, (label, len(payload))
        pin = {'label': label, 'blob': identity(payload)['git_blob'], 'bytes': len(payload),
               'sha256': identity(payload)['sha256'], 'layout': 'array-after', 'files': len(chunk)}
        (ROOT / 'input-blobs' / (pin['blob'] + '.blob')).write_bytes(payload)
        plan['packets'].append(pin)
        new_packets.append(pin)
        for row in chunk:
            name, value = row['path'], row['after']
            if name in authors:
                previous = authors[name]
                assert previous['sha'] == row['before']['git_blob']
                plan['allowed_overrides'].append({'path': name, 'from_packet': previous['packet'],
                    'to_packet': label, 'from': previous['sha'], 'to': value['git_blob']})
            authors[name] = {'path': name, 'text': value['text'], 'sha': value['git_blob'],
                            'bytes': value['bytes'], 'mode': value['mode'], 'packet': label,
                            'packet_blob': pin['blob']}
    assert len(authors) == 456 and len(plan['allowed_overrides']) == 189
    assert plan['packets'][:64] == old_plan['packets']
    assert plan['allowed_overrides'][:174] == old_plan['allowed_overrides']
    assert {row['path'] for row in plan['allowed_overrides'][174:]} == set(existing_authors)
    for name, row in authors.items():
        if name in changed:
            assert row['text'].encode() == after[name] and row['sha'] == final[name]['git_blob']
        else:
            assert row == original_authors[name]

    plan['expected_authored_files'] = len(authors)
    plan['generators'] = generators
    registration = plan['source_registration']
    registration['prior_after_fragment_r11'] = deepcopy(registration['after_fragment'])
    registration['after_fragment'] = dict(identity(fragment.encode()), blob=identity(fragment.encode())['git_blob'])
    registration['generators'] = generators
    registration['selectors'] = selectors
    registration['extra_selectors'].append(spec['Source_selector_added'])
    registration['authored_counts'] = {'generators': 126, 'owner_loop_generators': 126, 'selectors': 230,
                                     'actual_loaded_test_ids': None, 'actual_executed_tests': None}
    registration['prior_required_support_actions_r11'] = deepcopy(registration['required_support_actions'])
    registration['required_support_actions'] = [value.replace('all123 owner', 'all126 owner').replace(
        'actual229 selectors', 'actual230 selectors') for value in registration['required_support_actions']]
    registration['notes'].append(
        'R12 preserves all prior Source methods and ordered selectors. It adds twelve LinuxFileSourceTests '
        'and one SourceSuffix method, three generators, eight SOURCE_FILES, three ENTRY assets, and one '
        'explicit mechanism provider. All 121 Native step bytes remain exact. There is no new Native '
        'selector or matching-current-source cold qualification. The inherited R11 parser generator '
        'failed on actual CPython 3.14.4 before any product tests; that failure remains unchanged and '
        'requires a separate successor revision.')
    plan['source_contract']['declared_paths'] = 1332
    classification = {'changed_existing_source_paths': len(set(changed) & set(before)),
        'new_source_paths': len(new_source), 'existing_packet_owned_overrides': len(existing_authors),
        'first_time_authored_paths': len(first_authored), 'first_time_authored_existing_paths': [],
        'packet_owned_paths': existing_authors, 'first_time_authored_path_list': first_authored,
        'explanation': 'All fifteen changed existing paths match their R11 packet-owned complete text and Git identity. All eight new paths enter the author table for the first time. Actual counts are 448+8=456 authors and 174+15=189 explicit overrides.'}
    plan['r12_integration'] = {'integration_packet': identity(capsule_raw),
        'integration_report': identity(integration_raw), 'registration_spec': identity(spec_raw),
        'base_plan': identity(old_plan_raw), 'source_tree': tree_hash(final), 'source_paths_changed': 23,
        'new_source_paths': 8, 'source_files': 3108, 'source_tests_expected': 1342,
        'prior_source_ids_expected': 1329, 'prior_source_ids_required_as_ordered_projection': True,
        'new_component_source_ids': spec['Source_declared_added_ids'], 'source_contract_paths': 1332,
        'entry_resources': 14, 'native_resources': 92, 'all_resource_total': 205,
        'semantic_core_roles': 54, 'mechanism_roles': 53, 'native_steps': 121,
        'entire_native_fragment_byte_identical': True, 'new_production_native_selector': None,
        'matching_current_source_cold_qualifier': 'NOT_IMPLEMENTED',
        'workflow_projection': integration['workflow_projection'],
        'author_origin_classification': classification,
        'old_13_cli_file_actions_implemented': False, 'old_cpython_read_bounded_complete_equivalence': False,
        'default_changed': False, 'matching_current_source_cold': False,
        'generation_executed': False, 'tests_executed': False, 'whole_native': False}
    failure_dir = ROOT.parent / 'v93-source-r11-original'
    failure_receipt_raw = (failure_dir / 'failed-command-original/0161-generate-122-cli_parser_context.json').read_bytes()
    failure_stderr_raw = (failure_dir / 'failed-command-original/0161-generate-122-cli_parser_context.stderr').read_bytes()
    failure_result_raw = (failure_dir / 'ORIGINAL-RESULT.json').read_bytes()
    assert identity(failure_receipt_raw)['git_blob'] == 'fb4b1f6d9472e868194ad25ed003f811a451a594'
    assert identity(failure_stderr_raw)['git_blob'] == '6ad34acdfc4b75ef5402167c977e0dc91c05770a'
    assert identity(failure_result_raw)['git_blob'] == '50a08f9830010079fa9ae7a29bf73fe3eb0f6185'
    failure_receipt, failure_result = json.loads(failure_receipt_raw), json.loads(failure_result_raw)
    assert failure_receipt['returncode'] == 1 and failure_receipt['timed_out'] is False
    assert failure_result['product_tests_executed'] == 0 and failure_result['status'] == 'FAIL'
    assert b'unsupported authoring graph value: _colorize.Argparse' in failure_stderr_raw
    plan['prior_formal_source_failure_r11'] = {'run': 43468679071, 'job': 132034512598,
        'status': 'GENERATION_FAIL_BEFORE_PRODUCT_TESTS', 'python': failure_result['python'],
        'product_tests_executed': 0, 'syntax': failure_result['syntax'],
        'command': failure_receipt, 'command_receipt': identity(failure_receipt_raw),
        'stderr': identity(failure_stderr_raw), 'result': identity(failure_result_raw),
        'known_failure': 'unsupported authoring graph value: _colorize.Argparse',
        'terminal_partial_source_files': failure_result['terminal_source_snapshot']['files'],
        'source_corrected_in_this_plan': False}

    changed_keys = {'allowed_overrides', 'expected_authored_files', 'generators', 'packets',
                    'source_contract', 'source_registration'}
    for key in old_plan:
        if key not in changed_keys:
            assert plan[key] == old_plan[key], key
    assert plan['source_test_environment'] == {
        'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE': '@EVIDENCE@/checks/hia-candidate-build-source',
        'HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE': '@EVIDENCE@/checks/hia-linux-process-source',
        'HEPTA_HIA_LINUX_STDIO_SOURCE_EVIDENCE': '@EVIDENCE@/checks/hia-linux-stdio-source'}
    inputs = ROOT / 'harness/inputs'
    author_output = encode([authors[name] for name in sorted(authors)])
    (inputs / 'AUTHORING-R12.json').write_bytes(author_output)
    (inputs / 'SOURCE-R12-FRAGMENT.yml').write_bytes(fragment.encode())
    plan_raw = encode(plan)
    (inputs / 'MATERIALIZATION-R12.json').write_bytes(plan_raw)
    driver = (ROOT / 'harness/tools/materialize_candidate_r14.py').read_bytes()
    assert identity(driver)['git_blob'] == DRIVER_BLOB
    for pin in plan['harness_files']:
        body = (ROOT / 'harness' / pin['path']).read_bytes()
        assert len(body) == pin['bytes'] and identity(body)['git_blob'] == pin['blob']
    for name, pin in inherited_harness.items():
        assert identity((ROOT / 'harness' / name).read_bytes()) == pin, name
    for name, pin in inherited_inputs.items():
        assert identity((ROOT / 'input-blobs' / name).read_bytes()) == pin, name

    old_local = (BASE / 'run_local_generation_r11.py').read_text()
    local = old_local
    replacements = [('v93-union-r11', 'v94-union-r12'),
        (OLD_PLAN_BLOB, identity(plan_raw)['git_blob']),
        ('MATERIALIZATION-R11.json', 'MATERIALIZATION-R12.json'),
        ('AUTHORING-R11.json', 'AUTHORING-R12.json'),
        ('all_64_source_packets_checked', 'all_' + str(len(plan['packets'])) + '_source_packets_checked'),
        ('len(authored) == 448', 'len(authored) == 456')]
    for left, right in replacements:
        assert local.count(left) == 1, (left, local.count(left))
        local = local.replace(left, right)
    projected = local
    for left, right in reversed(replacements):
        assert projected.count(right) == 1
        projected = projected.replace(right, left)
    assert projected == old_local
    ast.parse(local)
    (ROOT / 'run_local_generation_r12.py').write_text(local)
    report = {'schema': 'hia.r12.plan-preparation.v1',
        'status': 'PREPARED_NOT_GENERATED_WITH_INHERITED_ACTUAL_PARSER_FAILURE',
        'base_plan': identity(old_plan_raw), 'plan': identity(plan_raw), 'driver': identity(driver),
        'new_packets': new_packets, 'total_packets': len(plan['packets']), 'authored_files': len(authors),
        'explicit_overrides': len(plan['allowed_overrides']), 'author_origin_classification': classification,
        'source_files': 3108, 'source_tree': tree_hash(final), 'source_contract': 1332,
        'generators': 126, 'selectors': 230, 'tests_expected_not_executed': 1342,
        'new_component_source_declared_ids': spec['Source_declared_added_ids'],
        'changed_paths': changed, 'new_files': 8,
        'all_old_source_ids_required_as_ordered_projection': True,
        'source_fragment': identity(fragment.encode()), 'workflow': identity(after[WORKFLOW]),
        'Source_method_byte_and_assertion_review': method_checks,
        'source_fragment_only_three_generators_and_one_selector_added': True,
        'all121_native_steps_fragment_identical': identity(native.encode()), 'native_steps': 121,
        'three_source_evidence_environments_preserved': plan['source_test_environment'],
        'all_inherited_harness_guard_file_bytes_unchanged': inherited_harness,
        'all_inherited_input_blob_file_bytes_unchanged': inherited_inputs,
        'original_failure_histories_unchanged': sorted(key for key in old_plan if key.startswith('prior_')),
        'prior_formal_source_failure_r11': plan['prior_formal_source_failure_r11'],
        'exact_retained_and_regeneration_seed_ownership_collisions': [],
        'local_generation_script': identity(local.encode()),
        'local_generation_script_projection': replacements, 'local_generation_script_executed': False,
        'source_bytes_or_modes_changed_by_plan_preparation': False,
        'generation_executed': False, 'product_tests_executed': 0,
        'matching_current_source_cold': False, 'whole_native': False, 'default_changed': False,
        'old_13_cli_file_actions_implemented': False}
    (ROOT / 'PREPARATION.json').write_bytes(encode(report))
    compressed = zlib.compress(author_output, 9)
    transport = encode({'schema': 'hia.zlib-complete-author-table.v1', 'encoding': 'base64+zlib',
        'raw_bytes': len(author_output), 'raw_sha256': identity(author_output)['sha256'],
        'raw_git_blob': identity(author_output)['git_blob'], 'rows': len(authors),
        'payload': base64.b64encode(compressed).decode()})
    (ROOT / 'AUTHORING-R12.zlib.json').write_bytes(transport)
    assert zlib.decompress(base64.b64decode(json.loads(transport)['payload'], validate=True)) == author_output
    index = {'schema': 'hia.complete-author-table-index.v1', 'rows': len(authors),
        'full_author_table': identity(author_output), 'transport': identity(transport),
        'files': [{key: value for key, value in authors[name].items() if key != 'text'} for name in sorted(authors)]}
    (ROOT / 'AUTHORING-R12-INDEX.json').write_bytes(encode(index))
    assert read_exact(ROOT / 'source', final) == after
    assert read_exact(BASE / 'source', baseline) == before
    print(json.dumps({key: report[key] for key in ('status', 'plan', 'driver', 'new_packets',
        'total_packets', 'authored_files', 'explicit_overrides', 'source_files', 'source_tree', 'source_contract',
        'generators', 'selectors', 'tests_expected_not_executed', 'native_steps',
        'generation_executed', 'product_tests_executed')}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
