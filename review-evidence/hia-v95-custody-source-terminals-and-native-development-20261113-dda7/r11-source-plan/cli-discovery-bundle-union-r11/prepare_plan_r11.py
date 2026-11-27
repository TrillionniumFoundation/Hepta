"""Normalize the reviewed R11 overlay and prepare, but never execute, its plan."""
from __future__ import annotations

import ast
import base64
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import zlib

import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v92-union-r10-r2'
WORKFLOW = '.github/workflows/hia-core.yml'
OLD_PLAN_BLOB = '035d0681a26bb6398d1def298ee9f990b7b4d7ff'
CAPSULE_BLOB = 'cbe5f8c8e0c6c17afdf9f676cf362ea8550d003a'
INTEGRATION_BLOB = '866753c9587d1674505b235fb867d5509e9281a4'
REGISTRATION_BLOB = '9f6774355803d27b5d02840ec635283cbbc7609d'
DRIVER_BLOB = 'cfe319279641b124bcd724437857686f36d1aa07'
FIRST_AUTHORED_PATH = 'hepta/hia_opcodes.py'
FIRST_AUTHORED_BEFORE = 'eb2d086258503e6e4e9b5aa16ccb059eebe1d4b3'

helper_spec = importlib.util.spec_from_file_location('r11_pure_author_helpers', ROOT / 'integrate_cli_discovery_bundle.py')
helper = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(helper)
encode, identity, tree_hash = helper.encoded, helper.identity, helper.tree_hash


def read_exact(root, manifest):
    result = {}
    for name, pin in manifest.items():
        path = root / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644, name
        raw = path.read_bytes()
        assert identity(raw) == pin, name
        result[name] = raw
    return result


def files_below(root):
    result = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), path
        if path.is_file():
            assert path.parent.name != '__pycache__' and path.suffix != '.pyc', path
            result[path.relative_to(root).as_posix()] = identity(path.read_bytes())
        else:
            assert path.is_dir()
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
    assert len(baseline) == 3083 and len(final) == 3100
    assert baseline == packet['base_manifest'] and final == packet['source_manifest']
    before, after = read_exact(BASE / 'source', baseline), read_exact(ROOT / 'source', final)
    assert files_below(ROOT / 'source') == final
    assert tree_hash(baseline) == 'e21ae3f2e4e4131db928beb7cf7780f0c79b1e44'
    assert tree_hash(final) == '4561802d6b5548e8933913716eedf01f4189d7e3'
    changed = sorted(name for name in after if before.get(name) != after[name])
    new_source = sorted(set(after) - set(before))
    assert not set(before) - set(after)
    assert len(changed) == 26 and len(new_source) == 17
    assert set(changed) == set(integration['changes']) == {row['path'] for row in packet['files']}
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

    old_plan_raw = (BASE / 'harness/inputs/MATERIALIZATION-R10-R2.json').read_bytes()
    assert identity(old_plan_raw)['git_blob'] == OLD_PLAN_BLOB
    old_plan = json.loads(old_plan_raw)
    plan = deepcopy(old_plan)
    authors_raw = (BASE / 'harness/inputs/AUTHORING-R10-R2.json').read_bytes()
    authors = {row['path']: row for row in json.loads(authors_raw)}
    original_authors = deepcopy(authors)
    assert len(authors) == plan['expected_authored_files'] == 430
    assert len(plan['packets']) == 61 and len(plan['allowed_overrides']) == 166
    assert not set(changed) & {row['path'] for row in plan['exact_retained'] + plan['regeneration_seeds']}
    existing_authors = sorted(set(changed) & set(authors))
    first_authored = sorted(set(changed) - set(authors))
    first_authored_existing_sources = sorted(set(first_authored) & set(before))
    assert len(existing_authors) == 8 and len(first_authored) == 18
    assert first_authored_existing_sources == [FIRST_AUTHORED_PATH]
    assert identity(before[FIRST_AUTHORED_PATH])['git_blob'] == FIRST_AUTHORED_BEFORE
    for name in existing_authors:
        assert authors[name]['sha'] == identity(before[name])['git_blob'], name
        assert authors[name]['text'].encode() == before[name], name
    assert set(first_authored) - {FIRST_AUTHORED_PATH} == set(new_source)

    workflow = after[WORKFLOW].decode()
    source, native = workflow.split('  native:\n', 1)
    old_native = before[WORKFLOW].decode().split('  native:\n', 1)[1]
    assert native.replace(helper.NEW_NATIVE_STEP, '').replace(helper.BUNDLE_ARCHIVE_LINE, '') == old_native
    jobs = yaml.safe_load(workflow)['jobs']
    assert len(jobs['native']['steps']) == 121
    generators = re.search(r'for component in (.*?); do', source).group(1).split()
    additions = ['cli_discovery_routing', 'cli_parser_context']
    assert generators == plan['generators'] + additions
    assert generators == plan['source_registration']['generators'] + additions
    assert len(generators) == 123
    test_run = next(row['run'] for row in jobs['source']['steps'] if row.get('name') == 'Core source and independent reference controls')
    body = ast.parse('\n'.join(test_run.splitlines()[1:-1]) + '\n')
    assignment = next(node for node in body.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == 'names' for target in node.targets))
    selectors = list(ast.literal_eval(assignment.value))
    assert selectors == plan['source_registration']['selectors'] + [spec['Source_selector_addition']]
    assert len(selectors) == 229
    fragment = '  source:\n' + workflow.split('  source:\n', 1)[1].split('  native:\n', 1)[0]
    old_fragment = (BASE / 'harness/inputs/SOURCE-R10-R2-FRAGMENT.yml').read_bytes()
    assert identity(old_fragment)['git_blob'] == plan['source_registration']['after_fragment']['blob']
    assert old_fragment == ('  source:\n' + before[WORKFLOW].decode().split('  source:\n', 1)[1].split('  native:\n', 1)[0]).encode()
    assert spec['SOURCE_FILES_before_after'] == [1307, 1324]

    # Inputs and every existing guard are copied byte-for-byte, never executed.
    inherited_input_files = files_below(BASE / 'input-blobs')
    inherited_harness_files = files_below(BASE / 'harness')
    shutil.copytree(BASE / 'input-blobs', ROOT / 'input-blobs')
    shutil.copytree(BASE / 'harness', ROOT / 'harness')
    assert files_below(ROOT / 'input-blobs') == inherited_input_files
    assert files_below(ROOT / 'harness') == inherited_harness_files

    chunks, current = [], []
    for name in changed:
        row = {'path': name, 'before': identity(before[name]) if name in before else None,
               'after': dict(identity(after[name]), text=after[name].decode())}
        if current and len(encode({'files': current + [row]})) > 640000:
            chunks.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        chunks.append(current)
    new_packets = []
    for index, chunk in enumerate(chunks):
        label = 'cli-discovery-bundle-integration-r11-' + str(index).zfill(2)
        normalized = {
            'schema': 'hia.reviewed-joint-source-overlay.v1', 'label': label,
            'scope': 'EXACT_OPTIONAL_CLI_PARSER_DISCOVERY_BUNDLE_PENDING_GENERATION_AND_CURRENT_SOURCE_COLD',
            'component_integration_packet': identity(capsule_raw),
            'component_integration_report': identity(integration_raw),
            'component_registration': identity(spec_raw), 'base_plan': identity(old_plan_raw),
            'original_native_steps_preserved': 120,
            'native_projection': 'Remove only the one added qualifier and bundle main-archive path to recover all R10-R2 Native bytes.',
            'source_methods_and_all_prior_selectors_preserved': True,
            'component_limitations': [
                'Optional Python-facing CLI bundle; it does not replace the direct ELF CLI profile.',
                'Original forty-three CLI test source bytes remain exact; actual combined execution is pending.',
                'Parser metadata must be generated on the final interpreter.',
                'No component development result supplies matching-current-source cold or formal CPython 3.14 qualification.',
                'Mechanical Python ports, admission facts and unmigrated actual foreign providers remain explicit.',
            ],
            'whole_native': False, 'default_changed': False, 'files': chunk,
        }
        raw = encode(normalized)
        assert len(raw) <= 650000, (label, len(raw))
        pin = {'label': label, 'blob': identity(raw)['git_blob'], 'bytes': len(raw),
               'sha256': identity(raw)['sha256'], 'layout': 'array-after', 'files': len(chunk)}
        (ROOT / 'input-blobs' / (pin['blob'] + '.blob')).write_bytes(raw)
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
    assert len(authors) == 448 and len(plan['allowed_overrides']) == 174
    assert plan['packets'][:61] == old_plan['packets']
    assert plan['allowed_overrides'][:166] == old_plan['allowed_overrides']
    assert {row['path'] for row in plan['allowed_overrides'][166:]} == set(existing_authors)
    for name, row in authors.items():
        if name in changed:
            assert row['text'].encode() == after[name] and row['sha'] == final[name]['git_blob']
        else:
            assert row == original_authors[name]

    plan['expected_authored_files'] = 448
    plan['generators'] = generators
    registration = plan['source_registration']
    registration['prior_after_fragment_r10_r2'] = deepcopy(registration['after_fragment'])
    registration['after_fragment'] = dict(identity(fragment.encode()), blob=identity(fragment.encode())['git_blob'])
    registration['generators'] = generators
    registration['selectors'] = selectors
    registration['extra_selectors'].append(spec['Source_selector_addition'])
    registration['authored_counts'] = {'generators': 123, 'owner_loop_generators': 123, 'selectors': 229,
                                       'actual_loaded_test_ids': None, 'actual_executed_tests': None}
    registration['prior_required_support_actions_r10_r2'] = deepcopy(registration['required_support_actions'])
    registration['required_support_actions'] = [value.replace('all121 owner', 'all123 owner').replace(
        'actual228 selectors', 'actual229 selectors') for value in registration['required_support_actions']]
    registration['notes'].append(
        'R11 preserves all R10-R2 Source methods and ordered selectors, adds ten optional CLI bundle Source methods, '
        'two generators, seventeen SOURCE_FILES and two native-bridge resources. All 120 prior Native execution '
        'commands/conditions/budgets remain byte-exact under the explicit projection of one added qualifier and '
        'one new main-archive directory. The actual R9 archive-coverage failure and its R10-R2 process repair are '
        'retained. New bundle original43 plus nine controls require actual matching-current-source cold; no local '
        'development observation supplies that qualification.')
    plan['source_contract']['declared_paths'] = 1324
    classification = {
        'changed_existing_source_paths': len(set(changed) & set(before)),
        'new_source_paths': len(new_source), 'existing_packet_owned_overrides': len(existing_authors),
        'first_time_authored_paths': len(first_authored),
        'first_time_authored_existing_main_path': FIRST_AUTHORED_PATH,
        'first_time_authored_existing_main_preimage': identity(before[FIRST_AUTHORED_PATH]),
        'explanation': 'Nine existing source files change, but only eight were packet-owned. hia_opcodes.py is inherited from the original main tree and enters the explicit author table for the first time. Its full real preimage is retained in the exact integration capsule. Thus 430+18=448 authors and 166+8=174 overrides; it is not an override of a nonexistent packet.',
    }
    plan['r11_integration'] = {
        'integration_packet': identity(capsule_raw), 'integration_report': identity(integration_raw),
        'registration_spec': identity(spec_raw), 'base_plan': identity(old_plan_raw),
        'source_paths_changed': 26, 'new_source_paths': 17, 'source_files': 3100,
        'source_tests_expected': 1329, 'prior_source_ids_expected': 1319,
        'prior_source_ids_required_as_ordered_projection': True,
        'new_component_source_ids': spec['Source_exact_ids_additions'],
        'source_contract_paths': 1324, 'entry_resources': 11, 'native_resources': 92,
        'all_resource_total': 202, 'semantic_core_roles': 54, 'mechanism_roles': 52,
        'native_steps': 121, 'old_native_execution_steps_preserved': 120,
        'native_projection': integration['workflow_projection'],
        'new_native_qualifier': spec['Native_step_addition'],
        'qualifier_groups': spec['Native_qualifier_exact_groups'],
        'author_origin_classification': classification,
        'default_changed': False, 'matching_current_source_cold': False,
        'generation_executed': False, 'tests_executed': False, 'whole_native': False,
    }
    # All pre-existing failure histories, guards, references and source environments stay exact.
    changed_keys = {'allowed_overrides', 'expected_authored_files', 'generators', 'packets',
                    'source_contract', 'source_registration'}
    for key in old_plan:
        if key not in changed_keys:
            assert plan[key] == old_plan[key], key
    assert len(plan['source_test_environment']) == 3
    assert plan['source_test_environment'] == {
        'HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE': '@EVIDENCE@/checks/hia-candidate-build-source',
        'HEPTA_HIA_LINUX_PROCESS_SOURCE_EVIDENCE': '@EVIDENCE@/checks/hia-linux-process-source',
        'HEPTA_HIA_LINUX_STDIO_SOURCE_EVIDENCE': '@EVIDENCE@/checks/hia-linux-stdio-source',
    }
    inherited_fail = plan['prior_formal_source_failure_r9']
    assert (inherited_fail['actual_tests'], inherited_fail['actual_passes'], inherited_fail['actual_failures']) == (1306, 1305, 1)
    assert inherited_fail['result_blob'] == '8634a2afa3aac1b9856d3cb7560c1d7af8f79090'

    inputs = ROOT / 'harness/inputs'
    author_output = encode([authors[name] for name in sorted(authors)])
    (inputs / 'AUTHORING-R11.json').write_bytes(author_output)
    (inputs / 'SOURCE-R11-FRAGMENT.yml').write_text(fragment)
    plan_raw = encode(plan)
    (inputs / 'MATERIALIZATION-R11.json').write_bytes(plan_raw)
    driver = (ROOT / 'harness/tools/materialize_candidate_r14.py').read_bytes()
    assert identity(driver)['git_blob'] == DRIVER_BLOB
    for pin in plan['harness_files']:
        body = (ROOT / 'harness' / pin['path']).read_bytes()
        assert len(body) == pin['bytes'] and identity(body)['git_blob'] == pin['blob']
    for name, pin in inherited_harness_files.items():
        assert identity((ROOT / 'harness' / name).read_bytes()) == pin, name
    for name, pin in inherited_input_files.items():
        assert identity((ROOT / 'input-blobs' / name).read_bytes()) == pin, name

    old_local = (BASE / 'run_local_generation_r10_r2.py').read_text()
    local = old_local
    replacements = [
        ('v92-union-r10-r2', 'v93-union-r11'),
        (OLD_PLAN_BLOB, identity(plan_raw)['git_blob']),
        ('MATERIALIZATION-R10-R2.json', 'MATERIALIZATION-R11.json'),
        ('AUTHORING-R10-R2.json', 'AUTHORING-R11.json'),
        ('all_61_source_packets_checked', 'all_' + str(len(plan['packets'])) + '_source_packets_checked'),
        ('len(authored) == 430', 'len(authored) == 448'),
    ]
    for left, right in replacements:
        assert local.count(left) == 1, (left, local.count(left))
        local = local.replace(left, right)
    projected_local = local
    for left, right in reversed(replacements):
        assert projected_local.count(right) == 1
        projected_local = projected_local.replace(right, left)
    assert projected_local == old_local
    ast.parse(local)
    (ROOT / 'run_local_generation_r11.py').write_text(local)
    report = {
        'schema': 'hia.r11.plan-preparation.v1', 'status': 'PREPARED_NOT_GENERATED_NOT_QUALIFIED',
        'base_plan': identity(old_plan_raw), 'plan': identity(plan_raw), 'driver': identity(driver),
        'new_packets': new_packets, 'total_packets': len(plan['packets']), 'authored_files': 448,
        'explicit_overrides': 174, 'author_origin_classification': classification,
        'source_files': 3100, 'source_contract': 1324, 'generators': 123, 'selectors': 229,
        'tests_expected': 1329, 'new_component_source_declared_ids': spec['Source_exact_ids_additions'],
        'changed_paths': changed, 'new_files': 17,
        'all_old_source_ids_required_as_ordered_projection': True,
        'source_fragment': identity(fragment.encode()), 'workflow': identity(after[WORKFLOW]),
        'old120_native_commands_conditions_budgets_preserved': True,
        'native_projection': integration['workflow_projection'], 'native_steps': 121,
        'three_source_evidence_environments_preserved': plan['source_test_environment'],
        'all_inherited_harness_guard_file_bytes_unchanged': inherited_harness_files,
        'original_failure_histories_unchanged': sorted(key for key in old_plan if key.startswith('prior_')),
        'prior_formal_source_failure_r9': inherited_fail,
        'exact_retained_and_regeneration_seed_ownership_collisions': [],
        'local_generation_script': identity(local.encode()),
        'local_generation_script_projection': replacements,
        'local_generation_script_executed': False,
        'source_bytes_changed_by_plan_preparation': False,
        'generation_executed': False, 'product_tests_executed': 0,
        'matching_current_source_cold': False, 'whole_native': False, 'default_changed': False,
    }
    (ROOT / 'PREPARATION.json').write_bytes(encode(report))
    # The large author list is additionally provided losslessly as one small transport.
    compressed_authors = zlib.compress(author_output, 9)
    authors_transport = encode({'schema': 'hia.zlib-complete-author-table.v1', 'encoding': 'base64+zlib',
        'raw_bytes': len(author_output), 'raw_sha256': identity(author_output)['sha256'],
        'raw_git_blob': identity(author_output)['git_blob'], 'rows': 448,
        'payload': base64.b64encode(compressed_authors).decode()})
    (ROOT / 'AUTHORING-R11.zlib.json').write_bytes(authors_transport)
    assert zlib.decompress(base64.b64decode(json.loads(authors_transport)['payload'], validate=True)) == author_output
    assert read_exact(ROOT / 'source', final) == after
    assert read_exact(BASE / 'source', baseline) == before
    print(json.dumps({key: report[key] for key in ('status', 'plan', 'driver', 'new_packets', 'total_packets',
        'authored_files', 'explicit_overrides', 'source_files', 'source_contract', 'generators', 'selectors',
        'tests_expected', 'native_steps', 'generation_executed', 'product_tests_executed')}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
