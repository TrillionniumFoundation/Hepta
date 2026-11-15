"""Two Store codecs, six explicit generation owners; no products at import."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import traceback
from retained_guards import *
import retained_observer as observer
from retained_fence import protected_source_fence

SCHEMA = 'hepta.hia.store-codecs-generation.v1'
SOURCE_TREE = '7f694b80c7ab76eb9d62402aeea4c331503ddc16'
STAGES = ('head-generate-1', 'head-generate-2', 'head-check',
          'catalog-generate-1', 'catalog-generate-2', 'catalog-check')
COMPONENTS = ('head', 'catalog')
PHASES = ('generate-1', 'generate-2', 'check')


def shape(plan):
    require(plan['schema'] == SCHEMA + '.plan'
            and plan['state'] == 'AUTHOR_ONLY_ROOT_EXECUTION_REQUIRED'
            and plan['limits'] == LIMITS and plan['storage_floor'] == MINIMUM_FREE
            and plan['stages'] == list(STAGES) and plan['source_count'] == 3210
            and plan['runtime_count'] == 2496 and plan['source_tree'] == SOURCE_TREE,
            'fixed source/runtime/counts/original budgets/stage order required')
    require(set(plan['components']) == set(COMPONENTS)
            and plan['future_output_pins'] is None
            and plan['install_generated_assets'] is False
            and plan['automatic_retry'] is False,
            'generation-only independent output contract changed')
    scope = Path(plan['scope'])
    require(scope.is_absolute() and '..' not in scope.parts
            and Path(plan['attempt']) == scope / 'generation-attempt-r1'
            and Path(plan['source']).is_absolute(), 'fixed independent scope required')
    protected = [Path(value) for value in plan['protected_roots']]
    require(Path(plan['source']) in protected
            and Path(plan['runtime']['base_prefix']) in protected
            and all(not scope.is_relative_to(p) and not p.is_relative_to(scope) for p in protected),
            'generated output must be outside every fixed authority root')
    require(set(plan['controls']) == {
        'generation_support.py', 'run_generation.py', 'run_generation_child.py',
        'retained_guards.py', 'retained_observer.py', 'retained_fence.py'},
        'complete six-control pathset required')
    require({x.name for x in (Path(plan['author']) / 'controls').iterdir()} == set(plan['controls']),
            'unexpected active control file')
    for component in COMPONENTS:
        spec = plan['components'][component]
        require(Path(spec['root']) in protected
                and Path(spec['generator']['path']).parent == Path(spec['root'])
                and Path(spec['policy']['path']).parent == Path(spec['root'])
                and Path(spec['authority']['path']).parent == Path(spec['root'])
                and type(spec['expected_functions']) is int and spec['expected_functions'] > 5,
                'complete original codec author binding required')


def author_guard(plan):
    shape(plan)
    for row in plan['controls'].values():
        checked(row)
    for row in plan['inputs'].values():
        checked(row)
    for rows in plan['directory_bindings'].values():
        guard_directories(rows)
    for component in COMPONENTS:
        spec = plan['components'][component]
        for row in spec['author_files'].values():
            checked(row)
        for key in ('generator', 'policy', 'authority'):
            checked(spec[key])
    return {'controls': len(plan['controls']), 'fixed_inputs': len(plan['inputs']),
            'codec_author_files': {key: len(plan['components'][key]['author_files']) for key in COMPONENTS},
            'all_bytes_read': True}


def source_authorities(plan):
    expected = decode(checked(plan['source_map']))
    state = decode(checked(plan['source_state']))
    identity_fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    require(len(expected) == 3210 and observer.tree_digest(expected) == SOURCE_TREE,
            'complete actual source manifest differs')
    result = {}
    for name in COMPONENTS:
        spec = plan['components'][name]
        authority = decode(checked(spec['authority']))
        require(authority['source'] == plan['source'] and authority['source_count'] == 3210
                and authority['source_tree'] == SOURCE_TREE
                and len(authority['read_sources']) == 16,
                'original generator authority domain differs')
        for relative, row in authority['read_sources'].items():
            require(relative in expected and relative in state
                    and set(row) == {'pin', 'posix_mode', 'seven_stats'}
                    and {key: expected[relative][key] for key in ('bytes', 'sha256', 'git_blob')}
                        == row['pin']
                    and row['posix_mode'] == stat.S_IMODE(state[relative]['st_mode'])
                    and row['seven_stats'] == [state[relative][key] for key in identity_fields],
                    'selected authority does not equal complete source manifest/state')
        snapshot = authority['source_snapshot']
        require(snapshot['path'] == plan['source_map']['path']
                and snapshot['pin'] == {key: plan['source_map']['pin'][key]
                                        for key in ('bytes', 'sha256', 'git_blob')}
                and snapshot['seven_stats'] == [plan['source_map']['stat'][key] for key in identity_fields]
                and snapshot['posix_mode'] == stat.S_IMODE(plan['source_map']['stat']['st_mode']),
                'original complete source snapshot identity differs')
        require(authority['runtime_map']['path'] == plan['runtime_map']['path']
                and authority['runtime_map']['pin'] ==
                    {key: plan['runtime_map']['pin'][key] for key in ('bytes', 'sha256', 'git_blob')},
                'generator and full runtime map differ')
        result[name] = {'authority': spec['authority']['pin'], 'selected_sources': 16}
    return result


def full_guard(plan, runtime_guard=None):
    started = time.monotonic_ns()
    authors = author_guard(plan)
    current = source_guard(plan, observer)
    runtime = runtime_files_guard(plan)
    authorities = source_authorities(plan)
    if runtime_guard is not None:
        runtime_guard(plan['runtime'])
    return {'source': current, 'runtime': runtime, 'authors': authors,
            'authorities': authorities, 'source_tree': SOURCE_TREE,
            'all_source_bytes_read': True, 'all_runtime_bytes_read': True,
            'source_files': 3210, 'runtime_files': 2496,
            'started_ns': started, 'finished_ns': time.monotonic_ns()}


def equal_guard(before, after):
    keys = ('source', 'runtime', 'authors', 'authorities', 'source_tree',
            'all_source_bytes_read', 'all_runtime_bytes_read', 'source_files', 'runtime_files')
    require({key: before[key] for key in keys} == {key: after[key] for key in keys},
            'complete immutable guard result changed')


def phase(plan, label):
    require(label in STAGES, 'unknown original generation stage')
    component, action = label.split('-', 1)
    require(component in COMPONENTS and action in PHASES, 'invalid component phase')
    return component, action, plan['components'][component]


def stage_paths(plan, label):
    component, action, spec = phase(plan, label)
    directory = Path(plan['attempt']) / ('%02d-' % (STAGES.index(label) + 1) + label)
    first = Path(plan['attempt']) / ('%02d-' % (STAGES.index(component + '-generate-1') + 1)
                                    + component + '-generate-1')
    asset = (first if action == 'check' else directory) / 'outputs' / spec['asset_name']
    return directory, {'asset': str(asset), 'report': str(directory / 'outputs' / 'GENERATION.json')}


def command_for(plan, label):
    _, action, spec = phase(plan, label)
    _, paths = stage_paths(plan, label)
    command = [spec['generator']['path'], '--output', paths['asset'], '--report', paths['report']]
    if action == 'check':
        command.append('--check')
    return command


def output_capture(paths):
    return {key: capture(Path(value)) for key, value in paths.items()}


def same_outputs(first, second):
    require(set(first) == set(second) == {'asset', 'report'}, 'complete generated pair required')
    for key in ('asset', 'report'):
        require(first[key]['pin'] == second[key]['pin'] and checked(first[key]) == checked(second[key]),
                'complete independent generated bytes differ: ' + key)


def read_projection(value):
    require(set(value) == {'before', 'after', 'edits', 'whole_inverse_equal', 'ordinary_SHA_algebra_retained'}
            and value['whole_inverse_equal'] is True and value['ordinary_SHA_algebra_retained'] is True,
            'actual whole SHA projection proof required')
    edits = value['edits']
    require(type(edits) is list and len(edits) == 12
            and set(edits[0]) == {'before', 'after'}
            and 'before_whole_base64' in edits[1], 'complete SHA edit sequence differs')
    previous = base64.b64decode(edits[1]['before_whole_base64'], validate=True).decode()
    require(previous.count(edits[0]['after']) == 1, 'first SHA inverse fragment differs')
    original = previous.replace(edits[0]['after'], edits[0]['before'], 1)
    without_mode = lambda raw: {key: val for key, val in pin(raw).items() if key != 'mode'}
    require(without_mode(original.encode()) == value['before'], 'complete SHA original text pin differs')
    current = original
    for edit in edits:
        if 'identifier_before' in edit:
            require(set(edit) == {'identifier_before', 'identifier_after', 'count'}, 'identifier proof keys differ')
            pattern = r'\b' + re.escape(edit['identifier_before']) + r'\b'
            require(len(re.findall(pattern, current)) == edit['count'], 'SHA identifier count differs')
            current = re.sub(pattern, edit['identifier_after'], current)
        elif 'replace_all_count' in edit:
            before = base64.b64decode(edit['before_whole_base64'], validate=True).decode()
            after = base64.b64decode(edit['after_whole_base64'], validate=True).decode()
            require(current == before and before.count(edit['literal_before']) == edit['replace_all_count']
                    and before.replace(edit['literal_before'], edit['literal_after']) == after,
                    'full SHA replace-all projection differs')
            current = after
        else:
            require(set(edit) == {'before', 'after'} and current.count(edit['before']) == 1,
                    'single SHA projection fragment differs')
            current = current.replace(edit['before'], edit['after'], 1)
    require(without_mode(current.encode()) == value['after'], 'complete projected SHA source pin differs')
    inverse = current
    for edit in reversed(edits):
        if 'identifier_before' in edit:
            pattern = r'\b' + re.escape(edit['identifier_after']) + r'\b'
            require(len(re.findall(pattern, inverse)) == edit['count'], 'inverse identifier count differs')
            inverse = re.sub(pattern, edit['identifier_before'], inverse)
        elif 'replace_all_count' in edit:
            require(inverse == base64.b64decode(edit['after_whole_base64'], validate=True).decode(),
                    'inverse complete projection differs')
            inverse = base64.b64decode(edit['before_whole_base64'], validate=True).decode()
        else:
            require(inverse.count(edit['after']) == 1, 'inverse single fragment differs')
            inverse = inverse.replace(edit['after'], edit['before'], 1)
    require(inverse == original, 'complete SHA forward/inverse text differs')
    return {'before': value['before'], 'after': value['after'], 'edits': len(edits),
            'complete_forward_and_inverse': True,
            'original_text_origin': 'actual frozen generator calls retained source_program under its owner'}


def admit_outputs(plan, component, outputs):
    spec = plan['components'][component]
    asset = checked(outputs['asset'])
    raw = checked(outputs['report'])
    report = decode(raw)
    keys = {'schema', 'status', 'asset', 'functions', 'blocks', 'ops', 'SHA_projection',
            'native_compile', 'kernel_execution', 'sqlite_backend_replaced', 'default_activated'}
    if component == 'catalog':
        keys |= {'catalogue_graph_verified', 'transaction_row_semantics_verified'}
    require(set(report) == keys and report['schema'] == spec['report_schema']
            and report['status'] == 'GENERATED_AND_CORE_VERIFIED_ONLY'
            and report['asset'] == {key: outputs['asset']['pin'][key] for key in ('bytes', 'sha256', 'git_blob')}
            and stat.S_IMODE(outputs['asset']['stat']['st_mode']) == 0o644
            and report['functions'] == spec['expected_functions']
            and type(report['blocks']) is int and report['blocks'] > 0
            and type(report['ops']) is int and report['ops'] > 0,
            'actual complete generated asset/report/counts differ')
    require(all(report[key] is False for key in keys & {
        'native_compile', 'kernel_execution', 'sqlite_backend_replaced', 'default_activated',
        'catalogue_graph_verified', 'transaction_row_semantics_verified'}),
        'generation-only result expanded its qualification')
    proof = read_projection(report['SHA_projection'])
    require(raw == encoded(report) and len(asset) == report['asset']['bytes'],
            'actual complete report encoding differs')
    return {'asset': outputs['asset']['pin'], 'report': outputs['report']['pin'],
            'functions': report['functions'], 'blocks': report['blocks'], 'ops': report['ops'],
            'SHA_projection': proof, 'generation_only': True}


def artifact_guard(rows):
    for row in rows:
        checked(row)


def stage_artifacts(directory):
    state = metadata(directory)
    return [capture(directory / name) for name, info in sorted(state.items())
            if stat.S_ISREG(info['st_mode'])]


def fence(plan, prior):
    source = decode(checked(plan['source_state']))
    runtime = decode(checked(plan['runtime_map']))
    inodes = {(row['st_dev'], row['st_ino']) for row in source.values()}
    inodes.update((row['new_file_seven_stat'][0], row['new_file_seven_stat'][1]) for row in runtime['files'])
    all_rows = list(plan['controls'].values()) + list(plan['inputs'].values()) + list(prior)
    for name in COMPONENTS:
        all_rows += list(plan['components'][name]['author_files'].values())
    inodes.update((row['stat']['st_dev'], row['stat']['st_ino']) for row in all_rows)
    bound = dict(plan)
    bound['extra_protected_inputs'] = [row['path'] for row in all_rows]
    protected_source_fence(inodes, bound)


def output_pathset(plan, label):
    directory, paths = stage_paths(plan, label)
    _, action, _ = phase(plan, label)
    expected = {'.', 'GENERATION.json'}
    if action != 'check':
        expected.add(Path(paths['asset']).name)
    state = metadata(directory / 'outputs')
    require(set(state) == expected and stat.S_ISDIR(state['.']['st_mode'])
            and all(stat.S_ISREG(row['st_mode']) for name, row in state.items() if name != '.'),
            'complete independent generated output pathset differs')
    return state
