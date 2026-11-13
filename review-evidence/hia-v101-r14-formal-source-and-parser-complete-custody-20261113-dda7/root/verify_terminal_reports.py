"""Verify original R14 terminal reports against the frozen complete ordered IDs."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
INPUT = ROOT.parent / 'v95-audit-mount-r1/v101-r14-formal'
PINS = {
    'combined-result': 'eb19a2e329de55b180cdd883b7803fd810dec138',
    'source': 'ac78efb70e84b6db441c6e64527e199b89f5eec1',
    'bounded': '9f86bca7ba0ee0a948568c45833f20698792c6ff',
    'source10': 'eed71e5729a3de5d68bb6e0a16079bd5e38f800b',
    'original43': '49a71597b37affe3c6b37643b2e55d7968641611',
    'native9': '0509a15c4e90a71faecbe3aa82b8ad4123609df4'}
EXPECTED_PIN = '8e2560232f5c0b47eedaa417968866bdcfeb2893'
TREE = '94ea52604a5e61806d9da98a20326111d3081a83'
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    raws = {name: (INPUT / (name + '.json')).read_bytes() for name in PINS}
    for name, raw in raws.items():
        assert identity(raw)['git_blob'] == PINS[name], name
    values = {name: json.loads(raw) for name, raw in raws.items()}
    expected_raw = (ROOT.parent / 'v97-union-r14/FORMAL-EXPECTED-IDS.json').read_bytes()
    assert identity(expected_raw)['git_blob'] == EXPECTED_PIN
    expected = json.loads(expected_raw)
    source, bounded, combined = values['source'], values['bounded'], values['combined-result']
    assert source['status'] == 'PASS' and source['complete'] is True
    assert source['ordered_ids'] == source['actual_started_ids'] == source['actual_stopped_ids'] == expected['r14_expected_ordered_ids']
    assert source['tests_run'] == source['expected'] == len(set(source['ordered_ids'])) == 1353
    assert source['selectors'] == expected['selectors'] and len(source['selectors']) == 231
    for key in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes',
                'duplicate_ids', 'missing_a733_ids', 'missing_frozen_a733_ids',
                'missing_frozen_main_ids', 'missing_main_ids'):
        assert not source[key], key
    assert all(not value for value in source['loader_errors'].values())
    projections = {}
    for key in ('r13_expected_ordered_ids', 'r12_expected_ordered_ids',
                'required_r11_ordered_projection', 'original_r10_r2_ordered_ids'):
        ids = expected[key]
        assert [value for value in source['ordered_ids'] if value in set(ids)] == ids
        projections[key] = len(ids)
    assert set(projections.values()) == {1352, 1342, 1329, 1319}
    assert source['whole_native'] is False and source['native_qualification'] is False
    assert 0 < source['wall_seconds'] < 1800
    assert combined['status'] == 'SOURCE_PASS' and combined['source_tests'] == source
    assert combined['source_test_stage_started'] is True and not combined['failures']
    assert combined['product_tests_executed'] == 1353
    assert combined['native_qualification_jobs_executed'] == combined['cold_qualifications'] == 0
    assert combined['generation'] == {'generator_count': 131,
        'physical_paths_retired_in_development_tree': 55, 'real_generation_passes': 2, 'tree': TREE}
    assert combined['syntax'] == {'checked': 1531, 'failures': 0}
    assert combined['candidate']['tree'] == TREE and combined['candidate']['files'] == 3121
    assert combined['candidate']['local_tree_independently_verified'] is True
    assert combined['candidate']['source_gate_pass'] is True
    assert combined['terminal_source_snapshot']['files'] == 3121
    assert combined['terminal_source_snapshot']['all_partial_generated_bytes_captured'] is True
    assert combined['terminal_source_snapshot']['fixed_original_git_dependencies_retained'] is True
    for key in ('product_ref_changed', 'default_changed', 'legacy_host_implementation_deleted', 'whole_native'):
        assert combined[key] is False, key
    assert bounded['status'] == 'PASS' and not bounded['failures']
    assert bounded['tests_run'] == bounded['required_tests'] == expected['bounded_total'] == 62
    assert bounded['source_unchanged'] is True and bounded['python'].startswith('3.14.4 ')
    assert bounded['executable'] == '/opt/hostedtoolcache/Python/3.14.4/x64/bin/python3.14'
    authority = bounded['source_authority']
    assert authority['source_tree'] == TREE and authority['source_files'] == 3121
    assert authority['tests_run'] == 1353 and authority['result'] == identity(raws['combined-result'])
    assert authority['source_tests'] == identity(raws['source'])
    for key in ('whole_native', 'product_refs_changed', 'current_source_cold_qualification', 'full_Source_pass_inherited'):
        assert bounded[key] is False, key
    groups = []
    assert set(bounded['groups']) == {'source', 'original43', 'native', 'build', 'fresh5'}
    for name, value in bounded['groups'].items():
        assert value['status'] == value['report']['status'] == 'PASS', name
        assert value['command']['returncode'] == 0
        assert value['command']['owner_limits'] == {'cleanup_seconds': 3, 'qualification_seconds': 180}
        assert value['report']['source_unchanged'] is True
        assert value['report']['python'] == bounded['python']
    for group, name, number in [('source', 'source10', 10), ('original43', 'original43', 43), ('native', 'native9', 9)]:
        value, owner = values[name], bounded['groups'][group]
        assert value == owner['report'] and identity(raws[name]) == owner['report_pin']
        assert value['loaded'] == value['tests_run'] == number
        assert value['loaded_ids'] == value['started_ids'] == value['stopped_ids'] == expected['bounded_groups'][group]
        assert len(set(value['loaded_ids'])) == number
        for key in ('errors', 'failures', 'loader_errors', 'skipped', 'expected_failures', 'unexpected_successes'):
            assert not value[key], (group, key)
        groups.append({'group': group, 'tests': number, 'exact_ordered_original_ids': True,
                       'original_owner_limits': owner['command']['owner_limits'],
                       'wall_ns': owner['command']['wall_ns'], 'report': identity(raws[name])})
    assert values['original43']['declared_packaging_interpreter'] == bounded['executable']
    components = bounded['groups']['build']['report']['build']['components']
    assert set(components) == {'control', 'discovery', 'format', 'parser_context', 'routing'}
    assert all(value['compiler_sha256'] == COMPILER for value in components.values())
    assert len(bounded['groups']['fresh5']['report']['records']) == 5
    report = {'schema': 'hia.root.formal-r14-exact-id-readback.v1', 'status': 'PASS',
              'run': 43501909045, 'job': 132149597308, 'source_tests': 1353, 'source_selectors': 231,
              'source_started_stopped_and_expected_ids_exact': True, 'ordered_old_projections': projections,
              'source_wall_seconds': source['wall_seconds'], 'source_original_limit_seconds': 1800,
              'generators': 131, 'generation_passes': 2, 'syntax_files': 1531,
              'bounded_original_tests': 62, 'groups': groups, 'python': bounded['python'],
              'executable': bounded['executable'], 'packaging_versions': bounded['packaging_versions'],
              'packaging_interpreter_equals_test_interpreter': True, 'source_tree': TREE,
              'source_files': 3121, 'reports': {name: identity(raw) for name, raw in raws.items()},
              'expected_ids': identity(expected_raw),
              'raw_events_full_buffers_source_archives_and_compile_receipts': 'SEPARATE_OWNER_FULL_CUSTODY_REVIEW',
              'full_original_Native121_gate_qualified': False, 'current_source_cold_qualified': False,
              'product_ref_changed': False, 'whole_native': False}
    with (ROOT / 'FORMAL-TERMINAL-REPORT-READBACK.json').open('x') as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    assert all((INPUT / (name + '.json')).read_bytes() == raw for name, raw in raws.items())
    print(json.dumps({'status': 'PASS', 'Source': 1353, 'bounded': 62, 'tree': TREE,
                      'python': bounded['python'], 'whole_native': False}, sort_keys=True))


if __name__ == '__main__':
    main()
