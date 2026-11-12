"""Read one fixed complete diagnostic stream into a smaller custody channel.

This is not a product runner or a qualification validator. Whole originals that
do not fit remain in the always-uploaded artifact, with explicit omission pins.
The optional JSON projection is derived evidence, never an original report.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import PREFIX, REPO, blob, create, read, require, wire

TRIGGER = 'codex/hia-core-emitter-native-development-run-r3-20261112-e26e'
ROOT_NAME = 'hia-core-emitter-native-development-r3'
FULL_NAME = 'hia-core-emitter-native-full-diagnostics'
SMALL_NAME = 'hia-core-emitter-native-small-diagnostics'
MAX_FULL = 12 << 20
MAX_FULL_RAW = 8 << 20
MAX_RAW = 512 << 10
MAX_STDOUT = 1 << 20
MAX_DERIVED = 128 << 10
FRAME_BYTES = 8192
FULL_FRAME_BYTES = 24576
STAGES = ('prepare', 'run-preparation', 'admit-preparation', 'run-tests', 'finalize')
FULL_PREFIX = 'HIA_CORE_EMITTER_NATIVE_'
PREFIX_SMALL = 'HIA_CORE_EMITTER_SMALL_'
stdout_bytes_reserved = 0
EXCERPT = 'derived/development-summary.json'
FULL_STDERR = 'diagnostic-control/full-diagnostics.stderr.log'

def pins(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'git_blob_sha1': blob(raw)}

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON object key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))

def fixed_names():
    names = ['stage/' + stage + '.' + stream + '.log'
             for stage in STAGES for stream in ('stdout', 'stderr')]
    names += ['context.json', 'PREPARED.json', 'preparation-setup.json', 'tests-setup.json',
              'PREPARATION-ACCEPTANCE.json', 'FINAL.json']
    names += [phase + '-guard/' + name for phase in ('preparation', 'tests')
              for name in ('request.json', 'guardian.json', 'child.stdout.log', 'child.stderr.log')]
    names += ['preparation/report.json', 'preparation/final-HIA_SELFHOST_LANGUAGE_COVERAGE.json',
              'preparation/final-HIA_SELFHOST_CORE_SUPPORT.json']
    names += ['callers/report.json', 'callers/component.unittest.log',
              'callers/original-machine.unittest.log', 'callers/original-core.unittest.log',
              'callers/component-fixture/installed-control/report.json',
              'callers/component-fixture/installed-control/processes.json',
              'callers/component-fixture/installed-control/installed-execution.stdout',
              'callers/component-fixture/installed-control/installed-execution.stderr']
    require(len(names) == len(set(names)) == 35, 'fixed diagnostic denominator differs')
    return names

def gated_phase(name):
    if name.startswith('preparation/'):
        return 'preparation'
    if name.startswith('callers/'):
        return 'tests'
    for phase in ('preparation', 'tests'):
        if name.startswith(phase + '-guard/') and not name.endswith('/request.json'):
            return phase
    return None

def current(args):
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    control = workspace / 'control' / PREFIX
    require(Path(__file__).resolve().parent == control
            and re.fullmatch('[0-9a-f]{40}', args.control_commit) is not None
            and read(workspace / 'control/.git/HEAD', 256)[0].decode().strip() == args.control_commit
            and os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER
            and os.environ.get('HIA_CORE_EMITTER_NATIVE_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
            and not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN')
            and not any(value for name, value in os.environ.items()
                        if name.startswith(('GIT_', 'LD_'))),
            'small diagnostic execution context differs')
    raw, policy_pin = read(control / 'policy.json', 1 << 20)
    policy = strict_json(raw)
    require(policy_pin['sha256'] == args.policy_sha256
            and policy['schema'] == 'hia.core-emitter-native-actions-policy.v1'
            and policy['trigger_branch'] == TRIGGER
            and policy['phase_controller_seconds'] == 180 and policy['cleanup_seconds'] == 3
            and policy['small_diagnostics'] == {
                'full_fixed_file_count': 35, 'maximum_frame_raw_bytes': MAX_RAW,
                'maximum_stdout_bytes': MAX_STDOUT, 'maximum_derived_projection_bytes': MAX_DERIVED,
                'frame_bytes': FRAME_BYTES, 'whole_file_omission_only': True,
                'full_originals_and_full_stream_always_artifact': True,
                'all_35_originals_claimed_in_small_channel': False},
            'small diagnostic frozen policy differs')
    for name in ('common.py', 'diagnostics.py', 'small_diagnostics.py'):
        own, pin = read(control / name, 1 << 20)
        wanted = policy['controls'][name]
        require(pins(own) == wanted and pin['sha256'] == wanted['sha256'],
                'small diagnostic source differs')
    expected = {'control_commit': args.control_commit,
                'workflow_commit': os.environ['GITHUB_SHA'],
                'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
                'policy_sha256': args.policy_sha256, 'candidate': policy['candidate']}
    return temp, policy, expected

def decode_full(raw, expected):
    require(len(raw) <= MAX_FULL and raw.endswith(b'\n'), 'full diagnostic stream incomplete')
    lines = raw.decode('utf-8', errors='strict').splitlines(keepends=True)
    cursor = 0
    def take(kind):
        nonlocal cursor
        require(cursor < len(lines), 'truncated full diagnostic record sequence')
        line = lines[cursor]
        cursor += 1
        prefix = FULL_PREFIX + kind + ' '
        require(line.startswith(prefix) and line.endswith('\n') and not line.endswith('\r\n'),
                'unexpected full diagnostic marker')
        value = strict_json(line[len(prefix):])
        require(type(value) is dict, 'full diagnostic object required')
        return value
    begin = take('DIAGNOSTIC_BEGIN')
    require(begin == {'schema': 'hia.core-emitter-native-diagnostic.v1', **expected,
                      'maximum_original_raw_bytes': MAX_FULL_RAW, 'maximum_stdout_bytes': MAX_FULL,
                      'frame_bytes': FULL_FRAME_BYTES, 'fixed_file_count': 35, 'directory_scans': 0,
                      'product_execution': False, 'original_exit_status_modified': False,
                      'frames_are_original_bytes': True}, 'full stream is not bound to this operation')
    boundary = take('DIAGNOSTIC_BOUNDARY')
    require(set(boundary) == {'closed_current_phase_ECHILD', 'error_type_by_phase',
                              'natural_success_inferred'}
            and boundary['natural_success_inferred'] is False
            and set(boundary['closed_current_phase_ECHILD']) == {'preparation', 'tests'}
            and all(type(value) is bool for value in boundary['closed_current_phase_ECHILD'].values())
            and type(boundary['error_type_by_phase']) is dict
            and set(boundary['error_type_by_phase']) <= {'preparation', 'tests'}
            and all(type(value) is str for value in boundary['error_type_by_phase'].values()),
            'full diagnostic closed-phase boundary differs')
    originals, ledger = {}, {}
    for name in fixed_names():
        require(cursor < len(lines), 'missing full diagnostic file')
        phase = gated_phase(name)
        if lines[cursor].startswith(FULL_PREFIX + 'ORIGINAL_UNAVAILABLE '):
            value = take('ORIGINAL_UNAVAILABLE')
            require(value['name'] == name and value['status'] in {
                'MISSING', 'READ_REFUSED', 'OMITTED_RAW_BUDGET', 'CLOSED_CURRENT_PHASE_NOT_PROVEN'},
                'unexpected full unavailable record')
            if phase and not boundary['closed_current_phase_ECHILD'][phase]:
                require(value['status'] == 'CLOSED_CURRENT_PHASE_NOT_PROVEN'
                        and value['phase'] == phase and value['original_bytes_printed'] == 0,
                        'unclosed phase file was not refused')
            else:
                require(value['status'] != 'CLOSED_CURRENT_PHASE_NOT_PROVEN',
                        'incorrect phase refusal')
            ledger[name] = {'full_channel_status': value['status'], 'full_observation': value}
            continue
        require(not phase or boundary['closed_current_phase_ECHILD'][phase],
                'full stream exposed an unclosed phase original')
        value = take('ORIGINAL_BEGIN')
        require(set(value) == {'name', 'bytes', 'sha256', 'git_blob_sha1', 'frame_bytes', 'frame_count'}
                and value['name'] == name and type(value['bytes']) is int
                and 0 <= value['bytes'] <= MAX_FULL_RAW
                and value['frame_bytes'] == FULL_FRAME_BYTES
                and value['frame_count'] == (value['bytes'] + FULL_FRAME_BYTES - 1) // FULL_FRAME_BYTES,
                'full original header differs')
        blocks, offset = [], 0
        for index in range(value['frame_count']):
            frame = take('ORIGINAL_FRAME')
            require(set(frame) == {'name', 'index', 'offset', 'bytes', 'sha256', 'base64'}
                    and frame['name'] == name and frame['index'] == index
                    and frame['offset'] == offset
                    and frame['bytes'] == min(FULL_FRAME_BYTES, value['bytes'] - offset)
                    and type(frame['base64']) is str,
                    'full original frame identity differs')
            block = base64.b64decode(frame['base64'], validate=True)
            require(base64.b64encode(block).decode('ascii') == frame['base64']
                    and len(block) == frame['bytes'] and sha256(block).hexdigest() == frame['sha256'],
                    'full original frame bytes differ')
            blocks.append(block)
            offset += len(block)
        body = b''.join(blocks)
        end = take('ORIGINAL_END')
        require(end == {key: value[key] for key in ('name', 'bytes', 'sha256', 'frame_count')}
                and pins(body) == {key: value[key] for key in ('bytes', 'sha256', 'git_blob_sha1')},
                'full original end or whole bytes differ')
        originals[name] = body
        ledger[name] = {'full_channel_status': 'COMPLETE_ORIGINAL_READ', **pins(body)}
    end = take('DIAGNOSTIC_END')
    require(cursor == len(lines) and end['maximum_raw_bytes'] == MAX_FULL_RAW
            and end['maximum_stdout_bytes'] == MAX_FULL
            and end['closed_current_phase_ECHILD'] == boundary['closed_current_phase_ECHILD']
            and end['original_exit_status_modified'] is False
            and end['native_or_cold_qualification_claimed'] is False
            and type(end['original_raw_byte_budget_reserved']) is int
            and type(end['verified_original_bytes_read']) is int
            and sum(len(body) for body in originals.values()) == end['original_raw_bytes_printed']
            and 0 <= end['original_raw_bytes_printed'] <= end['verified_original_bytes_read']
                <= end['original_raw_byte_budget_reserved'] <= MAX_FULL_RAW
            and type(end['fixed_file_observations']) is dict
            and set(end['fixed_file_observations']) <= set(fixed_names()),
            'full diagnostic terminal accounting differs')
    for name, body in originals.items():
        require(end['fixed_file_observations'].get(name) ==
                {'status': 'COMPLETE_ORIGINAL_READ', **pins(body)},
                'full terminal original pin differs')
    return originals, ledger, boundary, end

def bounded(value, maximum=16384):
    raw = wire(value)
    if len(raw) <= maximum:
        return value
    return {'derived_value_omitted_whole': True, 'encoding': 'common.wire(value)',
            **pins(raw), 'maximum_bytes': maximum}

def fields(value, names, maximum=16384):
    require(type(value) is dict, 'projection object required')
    return {name: bounded(value[name], maximum) for name in names if name in value}

def projection(originals, expected):
    summary = {'schema': 'hia.core-emitter-native-small-derived-projection.v1',
               'kind': 'DERIVED_PROJECTION_NOT_AN_ORIGINAL',
               'original_JSON_whitespace_or_full_object_not_preserved': True,
               'qualification_validator_executed': False,
               'native_or_cold_qualification_claimed': False,
               'current_operation': expected, 'records': {}}
    targets = ('FINAL.json', 'preparation/report.json', 'callers/report.json',
               'preparation-guard/guardian.json', 'tests-guard/guardian.json')
    for name in targets:
        if name not in originals:
            summary['records'][name] = {'status': 'NO_VERIFIED_FULL_ORIGINAL_IN_STREAM'}
            continue
        row = {'original_pin': pins(originals[name]), 'status': 'DERIVED_FIELDS_FROM_VERIFIED_ORIGINAL'}
        try:
            value = strict_json(originals[name])
            if name == 'FINAL.json':
                row['fields'] = fields(value, ('schema', 'status', 'scope', 'error',
                    'cold_qualified', 'whole_native_claimed', 'original_limits_changed',
                    'all_owned_processes_closed_before_read', 'phase_owners',
                    'source_preserved_after_only_two_declared_derivations', 'complete_source_after',
                    'preparation_acceptance_original'))
                if type(value.get('complete_native_callers')) is dict:
                    row['complete_native_callers'] = fields(value['complete_native_callers'],
                        ('report_original', 'complete_method_count', 'unique_test_ids',
                         'actual_step_totals', 'group_actual_step_totals', 'public_actual_modes',
                         'private_actual_modes', 'component_private_actual_modes',
                         'component_actual_yield_modes', 'one_original_180_second_owner_required'))
            elif name == 'preparation/report.json':
                row['fields'] = fields(value, ('schema', 'status', 'scope', 'candidate',
                    'error', 'preservation_error', 'seconds', 'profile', 'derived_worktree_tree',
                    'actual_HEAD_remains_initial_candidate', 'derived_tree_has_published_commit',
                    'controller_seconds', 'cleanup_seconds', 'compile_child_wall_seconds',
                    'compile_child_CPU_seconds', 'original_compile_capacity_bytes',
                    'generated_HIA_sources_recreated', 'cold_qualified', 'B1_equals_B2',
                    'source_preserved_except_declared_derivations', 'source_stable_after_derivation',
                    'original_generated_asset_identity_verified', 'abi_original', 'compiler_original',
                    'derived_source_delta', 'final_inventory_originals', 'source_before', 'source_after'))
                for key in ('B0', 'B1', 'B2'):
                    if key in value:
                        row[key] = fields(value[key], ('status', 'abi_status', 'artifact_sha256',
                            'input_sha256', 'produced_sha256', 'produced_bytes', 'format',
                            'source_unchanged', 'forbidden_compiler_modules_loaded', 'returncode'))
                units = value.get('unit_receipts', [])
                require(type(units) is list and len(units) <= 39, 'projection unit denominator differs')
                row['units'] = []
                for unit in units:
                    item = fields(unit, ('name', 'source', 'manifest'), 2048)
                    for key in ('manifest_original', 'image_original'):
                        if type(unit.get(key)) is dict:
                            item[key] = fields(unit[key], ('path', 'bytes', 'sha256', 'git_blob_sha1'))
                    if type(unit.get('native_compile_receipt')) is dict:
                        item['receipt_fields'] = fields(unit['native_compile_receipt'],
                            ('status', 'abi_status', 'input_sha256', 'artifact_sha256',
                             'produced_sha256', 'produced_bytes', 'format', 'source_unchanged',
                             'forbidden_compiler_modules_loaded'))
                    row['units'].append(item)
                for key in ('compile_originals', 'build_files', 'development_source_manifest'):
                    if key in value:
                        row[key + '_wire_pin'] = {'encoding': 'common.wire(value)', **pins(wire(value[key]))}
                        row[key + '_item_count'] = len(value[key])
            elif name == 'callers/report.json':
                row['fields'] = fields(value, ('schema', 'status', 'scope', 'exception',
                    'final_identity_error', 'seconds', 'development_group',
                    'complete_three_groups_required_for_qualification', 'complete_three_groups_executed',
                    'expected_groups', 'expected_bundle_roles', 'component_denominator',
                    'original_machine_denominator', 'original_core_denominator', 'public_control_mode_count',
                    'abi_control_mode_count', 'private_fixture_modes', 'private_generator_modes',
                    'native_step_ledger_schema', 'group_bundle_roles', 'native_mode_entries_are_attempts',
                    'retained_owner_entries', 'hosted_primitive_kinds', 'default_activated',
                    'whole_native_claimed', 'source_stable', 'manifest_images_bundle_stable',
                    'caller_bundle_stable', 'component_bundle_stable', 'all_required_modes_attempted',
                    'all_required_modes_have_actual_step_returns', 'private_fixture_mode_has_actual_step_returns',
                    'all_generator_modes_have_actual_step_returns', 'all_generator_modes_have_actual_yield_returns',
                    'all_native_step_statuses_observed', 'actual_native_step_statuses',
                    'manifest', 'manifest_sha256', 'abi_sha256', 'complete_image_sha256'))
                groups = value.get('groups', [])
                require(type(groups) is list and len(groups) <= 3, 'projection group denominator differs')
                row['groups'] = [fields(group, ('label', 'modules', 'expected_methods', 'tests_run',
                    'strict_pass', 'loaded_ids', 'executed_ids', 'loader_errors', 'errors', 'failures',
                    'skipped', 'expectedFailures', 'unexpectedSuccesses')) for group in groups]
                for key in ('source_before', 'source_after', 'native_step_returns', 'input_bindings',
                            'bundle_observations'):
                    if key in value:
                        row[key + '_wire_pin'] = {'encoding': 'common.wire(value)', **pins(wire(value[key]))}
                        row[key + '_item_count'] = len(value[key])
            else:
                row['fields'] = fields(value, ('schema', 'status', 'input_identity_preserved',
                    'error', 'preservation_error', 'owner_error'))
                life = value.get('lifecycle', {})
                row['lifecycle_fields'] = fields(life, ('status', 'returncode', 'controller_seconds',
                    'cleanup_seconds', 'exit_before_deadline', 'timed_out', 'interrupted_signals',
                    'owner_error', 'event_overflow', 'cleanup', 'events'))
        except BaseException as error:
            row['status'] = 'PROJECTION_REFUSED'
            row['error_type'] = type(error).__name__
        summary['records'][name] = row
    return wire(summary)

def priority():
    wanted = ['stage/finalize.stderr.log', 'stage/run-tests.stderr.log',
              'stage/run-preparation.stderr.log', 'stage/admit-preparation.stderr.log',
              'stage/prepare.stderr.log', 'tests-guard/child.stderr.log',
              'preparation-guard/child.stderr.log', 'stage/finalize.stdout.log',
              'stage/run-tests.stdout.log', 'stage/run-preparation.stdout.log',
              'stage/admit-preparation.stdout.log', 'stage/prepare.stdout.log',
              'tests-guard/guardian.json', 'preparation-guard/guardian.json',
              'FINAL.json', 'callers/report.json', 'preparation/report.json',
              'callers/component-fixture/installed-control/report.json',
              'callers/component-fixture/installed-control/installed-execution.stderr']
    return wanted + [name for name in fixed_names() if name not in wanted]

def encode(kind, value):
    return (PREFIX_SMALL + kind + ' ' +
            json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def write_stdout(raw):
    global stdout_bytes_reserved
    require(stdout_bytes_reserved + len(raw) <= MAX_STDOUT, 'small stdout bound exhausted')
    # Charge before the write: an interrupted or partially successful write
    # cannot permit a second emission beyond the total fixed stdout bound.
    stdout_bytes_reserved += len(raw)
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()

def frame_file(name, raw, kind):
    count = (len(raw) + FRAME_BYTES - 1) // FRAME_BYTES
    output = [encode('FILE_BEGIN', {'name': name, 'kind': kind, **pins(raw),
                                    'frame_bytes': FRAME_BYTES, 'frame_count': count})]
    for index, offset in enumerate(range(0, len(raw), FRAME_BYTES)):
        block = raw[offset:offset + FRAME_BYTES]
        output.append(encode('FILE_FRAME', {'name': name, 'index': index, 'offset': offset,
            'bytes': len(block), 'sha256': sha256(block).hexdigest(),
            'base64': base64.b64encode(block).decode('ascii')}))
    output.append(encode('FILE_END', {'name': name, **pins(raw), 'frame_count': count}))
    return b''.join(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    temp, policy, expected = current(args)
    sources, ledger, full, boundary = {}, {}, {}, {}
    complete, refusal = False, None
    try:
        raw, pin = read(temp / (FULL_NAME + '.stdout.log'), MAX_FULL)
        full['stream_original'] = pin
        sources, ledger, boundary, terminal = decode_full(raw, expected)
        full['terminal_accounting'] = terminal
        complete = True
    except BaseException as error:
        refusal = type(error).__name__
        sources = {}
        ledger = {name: {'full_channel_status': 'FULL_STREAM_UNAVAILABLE_OR_REFUSED',
                         'sha256': None} for name in fixed_names()}
    try:
        stderr_raw, stderr_pin = read(temp / (FULL_NAME + '.stderr.log'), MAX_RAW)
        full['stderr_original'] = stderr_pin
        sources[FULL_STDERR] = stderr_raw
    except BaseException as error:
        full['stderr_refused'] = {'error_type': type(error).__name__, 'sha256': None}
    excerpt_raw = projection(sources, expected)
    excerpt_observation = pins(excerpt_raw)
    selected = []
    used = 0
    if len(excerpt_raw) <= MAX_DERIVED:
        create(temp / (SMALL_NAME + '.derived.json'), excerpt_raw)
        selected.append((EXCERPT, excerpt_raw, 'DERIVED_PROJECTION_NOT_AN_ORIGINAL'))
        used += len(excerpt_raw)
        excerpt_observation['status'] = 'DERIVED_PROJECTION_INCLUDED'
    else:
        excerpt_observation['status'] = 'DERIVED_PROJECTION_OMITTED_WHOLE_BUDGET'
    for name in priority() + [FULL_STDERR]:
        if name not in sources:
            if name in ledger:
                ledger[name]['small_channel_status'] = 'NO_VERIFIED_ORIGINAL_AVAILABLE'
            continue
        body = sources[name]
        observation = ledger.setdefault(name, {'full_channel_status': 'DIAGNOSTIC_STDERR_READ', **pins(body)})
        if used + len(body) > MAX_RAW:
            observation['small_channel_status'] = 'WHOLE_ORIGINAL_OMITTED_SMALL_RAW_BUDGET'
            continue
        selected.append((name, body, 'COMPLETE_ORIGINAL'))
        used += len(body)
        observation['small_channel_status'] = 'WHOLE_ORIGINAL_SELECTED'
    # Build the complete output before any stdout. Whole lower-priority files are
    # removed if framing overhead, rather than payload size, hits the stdout cap.
    while True:
        manifest = {'schema': 'hia.core-emitter-native-small-diagnostic.v1', **expected,
            'status': 'BOUNDED_DIAGNOSTIC_CAPTURED' if complete else 'SMALL_DIAGNOSTIC_HOLD',
            'fixed_original_file_count': 35, 'maximum_frame_raw_bytes': MAX_RAW,
            'maximum_stdout_bytes': MAX_STDOUT, 'frame_bytes': FRAME_BYTES,
            'selected_files': [{'name': name, 'kind': kind, **pins(body)}
                               for name, body, kind in selected],
            'selected_original_raw_bytes': sum(len(body) for name, body, kind in selected
                                               if kind == 'COMPLETE_ORIGINAL'),
            'derived_projection': excerpt_observation, 'full_diagnostic': full,
            'full_stream_complete_and_bound': complete, 'full_stream_refusal_type': refusal,
            'closed_current_phase_ECHILD': boundary.get('closed_current_phase_ECHILD'),
            'whole_file_ledger': ledger,
            'full_originals_and_full_stream_always_artifact': True,
            'all_35_originals_claimed_in_small_channel': False,
            'native_or_cold_qualification_claimed': False,
            'qualification_validator_executed': False,
            'product_execution': False, 'original_exit_status_modified': False}
        prefix = encode('BEGIN', manifest) + b''.join(frame_file(*item) for item in selected)
        result = {'schema': 'hia.core-emitter-native-small-diagnostic-result.v1',
                  'status': manifest['status'], 'current_operation': expected,
                  'manifest_wire_pin': pins(wire(manifest)),
                  'selected_file_count': len(selected),
                  'selected_frame_raw_bytes': sum(len(body) for _, body, _ in selected),
                  'prefix_stdout_bytes': len(prefix), 'prefix_stdout_sha256': sha256(prefix).hexdigest(),
                  'all_35_originals_claimed_in_small_channel': False,
                  'native_or_cold_qualification_claimed': False,
                  'original_exit_status_modified': False}
        result_raw = wire(result)
        ending = encode('END', {'result_original': pins(result_raw), **result})
        output = prefix + ending
        if len(output) <= MAX_STDOUT:
            break
        removable = [index for index, (_, _, kind) in enumerate(selected) if kind == 'COMPLETE_ORIGINAL']
        require(removable, 'small diagnostic metadata alone exceeds fixed stdout bound')
        index = removable[-1]
        name, _, _ = selected.pop(index)
        ledger[name]['small_channel_status'] = 'WHOLE_ORIGINAL_OMITTED_SMALL_STDOUT_BUDGET'
    require(sum(len(body) for _, body, _ in selected) <= MAX_RAW, 'small frame payload bound differs')
    result_pin = create(temp / (SMALL_NAME + '.RESULT.json'), result_raw)
    require({key: result_pin[key] for key in ('bytes', 'sha256', 'git_blob_sha1')} == pins(result_raw),
            'small result original readback differs')
    create(temp / (SMALL_NAME + '.manifest.json'), wire(manifest))
    create(temp / (SMALL_NAME + '.stdout.log'), output)
    # The late END is emitted only after complete fixed files have been created
    # and read back. No product or prior phase exit status is rewritten.
    write_stdout(output)
    return 0 if complete else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        refusal = encode('CONTROL_REFUSED', {'error_type': type(error).__name__,
            'native_or_cold_qualification_claimed': False, 'original_exit_status_modified': False})
        if stdout_bytes_reserved + len(refusal) <= MAX_STDOUT:
            write_stdout(refusal)
        raise SystemExit(1)
