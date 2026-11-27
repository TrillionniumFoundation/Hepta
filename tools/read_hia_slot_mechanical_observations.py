"""Independent pure-data readback of complete Slot original/VM/Native gates.

This reader imports no product, executes no input code and never derives an
expectation from a candidate. All structured observation leaves are compared
with type-sensitive canonical bytes, including exception metadata and GC counts
that belong to the original inputs. Full tracebacks and post-seal GC remain raw
diagnostics; their extra implementation frames are not normalized into a PASS.
"""
from __future__ import annotations
import argparse
from itertools import zip_longest
import hashlib
import json
import os
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hia_slot_operations_qualification_support import (
    ORIGINAL_SECONDS, CANDIDATE_SECONDS, CLEANUP_SECONDS,
    admit_originals, admit_cases, admit_product, canonical, checked_int, pin,
    read_json, regular_bytes, sha, successful_exit, unique_pairs, write_json,
)

RAW_FILES = ('observations.jsonl', 'raw-exceptions.jsonl', 'progress.jsonl',
             'post-seal-gc.json', 'source-before.json', 'source-after.json',
             'product-before.json', 'product-after.json', 'planned.json',
             'runtime.json', 'report.json')


def require(value, message):
    if not value:
        raise ValueError(message)


def typed_equal(left, right):
    return canonical(left) == canonical(right)


def read_bytes_at_pin(path, expected_pin):
    """Hash the same bytes supplied to the consumer; never refresh authority."""
    raw = regular_bytes(path)
    require(typed_equal({'bytes': len(raw), 'sha256': sha(raw)}, expected_pin),
            'consumed raw bytes differ from prior pin: ' + str(path))
    return raw


def read_json_at_pin(path, expected_pin):
    return json.loads(read_bytes_at_pin(path, expected_pin), object_pairs_hook=unique_pairs,
        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))


def read_lines(path, *, expected_pin=None):
    # Explicit prior authority is never refreshed. Other original callers bind
    # their own pin before opening the stream and keep their original interface.
    expected_pin = pin(path) if expected_pin is None else expected_pin
    digest, size = hashlib.sha256(), 0
    with Path(path).open('rb') as stream:
        for number, raw in enumerate(stream, 1):
            digest.update(raw)
            size += len(raw)
            require(raw.endswith(b'\n'), 'unterminated JSONL record')
            value = json.loads(raw, object_pairs_hook=unique_pairs,
                parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
            require(raw == canonical(value) + b'\n', 'noncanonical JSONL record ' + str(number))
            yield value
    require(typed_equal({'bytes': size, 'sha256': digest.hexdigest()}, expected_pin),
            'consumed JSONL stream differs from prior pin: ' + str(path))
    require(typed_equal(pin(path), expected_pin),
            'JSONL path changed after consumption: ' + str(path))


def leaves(left, right, path=''):
    if type(left) is not type(right):
        yield {'path': path, 'expected': left, 'actual': right, 'reason': 'type'}
    elif type(left) is dict:
        if set(left) != set(right):
            yield {'path': path, 'expected_keys': sorted(left), 'actual_keys': sorted(right),
                   'reason': 'keys'}
        for key in left.keys() & right.keys():
            yield from leaves(left[key], right[key], path + '/' + key.replace('~', '~0').replace('/', '~1'))
    elif type(left) is list:
        if len(left) != len(right):
            yield {'path': path, 'expected_length': len(left), 'actual_length': len(right),
                   'reason': 'length'}
        for index, (a, b) in enumerate(zip(left, right)):
            yield from leaves(a, b, path + '/' + str(index))
    elif left != right:
        yield {'path': path, 'expected': left, 'actual': right, 'reason': 'value'}




def mechanical_counters(value, pid):
    """Validate actual C counters; no product imports or derived expectations."""
    keys = ("public_calls", "raw_frame_calls", "initialized", "final_receipts")
    require(type(value) is dict and set(value) == {"schema", "pid", "overflow", *keys},
            "mechanical counter schema differs")
    require(value["schema"] == "hepta.slot.mechanical.execution-counters.v1"
            and type(value["pid"]) is int and value["pid"] == pid
            and value["overflow"] is False, "mechanical counter PID/overflow differs")
    for name in keys:
        row = value[name]
        require(type(row) is list and len(row) == 16 and row[0] == 0
                and all(type(x) is int and 0 <= x <= (1 << 64) - 1 for x in row),
                "mechanical per-mode counter differs")
    for mode in range(1, 16):
        require(value["final_receipts"][mode] <= value["initialized"][mode]
                <= value["public_calls"][mode] + value["raw_frame_calls"][mode],
                "mechanical receipt counter precedes actual entry")
    return value


def mechanical_counter_delta(before, after, pid, *, require_public):
    mechanical_counters(before, pid)
    mechanical_counters(after, pid)
    delta = {}
    for name in ("public_calls", "raw_frame_calls", "initialized", "final_receipts"):
        require(all(a <= b for a, b in zip(before[name], after[name])),
                "mechanical counter went backwards")
        delta[name] = [b - a for a, b in zip(before[name], after[name])]
    if require_public:
        require(sum(delta["public_calls"]) > 0 and sum(delta["initialized"]) > 0
                and sum(delta["raw_frame_calls"]) == 0,
                "complete v5 public domain did not actually enter C/HIA")
    return delta

def mechanical_launch(directory, command, runtime, expected_bundle, source_root, source_pins, observer_kind='finite'):
    path = Path(directory) / 'observation/mechanical-launch.json'
    raw = regular_bytes(path)
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(raw == canonical(value) + b'\n', 'noncanonical mechanical launch evidence')
    require(value['schema'] == 'hepta.slot.mechanical.observer-launch.v1',
            'wrong mechanical launcher schema')
    require(value['outer_argv'] == command['argv'][3:]
            and value['inner_argv'] == runtime['argv'], 'mechanical actual outer/inner argv differs')
    for name in ('pid', 'ppid', 'pgid'):
        checked_int(value[name], runtime[name])
    require(value['exception'] is None and type(value['returned_code']) is int
            and value['returned_code'] == 0 and value['expected_observations_supplied'] is False,
            'mechanical observer did not naturally complete')
    require(typed_equal(value['bundle'], expected_bundle), 'mechanical administrator pin differs')
    outer, inner = value['outer_argv'], value['inner_argv']
    require(len(outer) > 8 and outer[1:8] == [
        '--bundle', expected_bundle['path'], '--expected-bundle-sha256',
        expected_bundle['sha256'], '--observer', observer_kind, '--']
        and outer[8:] == inner, 'mechanical candidate argv is not the fixed transparent launcher')
    source_root = Path(source_root).resolve(strict=True)
    require(observer_kind in ('finite', 'public'), 'undeclared mechanical observer')
    original_name = ('tests/hia_slot_operations_observer.py' if observer_kind == 'finite'
                     else 'tests/hia_slot_operations_public_observer.py')
    launcher_name = 'tests/hia_slot_mechanical_capsule_observer.py'
    require(Path(outer[0]).resolve(strict=True) == source_root / launcher_name
            and Path(inner[0]).resolve(strict=True) == source_root / original_name,
            'mechanical launcher/observer absolute path differs')
    require(value['observer'] == {'path': original_name, **source_pins[original_name]}
            and pin(source_root / original_name) == source_pins[original_name]
            and pin(source_root / launcher_name) == source_pins[launcher_name],
            'mechanical observer/launcher source pin differs')
    require(value['terminal_identity'] == {'native_helpers_sha256': expected_bundle['sha256']},
            'mechanical terminal identity differs')
    bundle_raw = regular_bytes(expected_bundle['path'])
    require({'path': expected_bundle['path'], 'bytes': len(bundle_raw), 'sha256': sha(bundle_raw)}
            == expected_bundle, 'mechanical administrator bytes changed')
    bundle = json.loads(bundle_raw, object_pairs_hook=unique_pairs)
    require(bundle['schema'] == 'hepta.hia.native-helpers.v5'
            and bundle['abi'] == 'hia-worker-mechanical-bridges-v1'
            and len(bundle['bridges']) == 1
            and typed_equal(bundle['bridges'][0], value['bridge']), 'mechanical bridge record differs')
    sealed = value['sealed_executable']
    require(type(sealed['bytes']) is int and sealed['bytes'] == value['bridge']['binary']['bytes']
            and sealed['sha256'] == value['bridge']['binary']['sha256']
            and sealed['abi'] == value['bridge']['abi']
            and type(sealed['modes']) is int and sealed['modes'] == 15
            and type(sealed['ports']) is int and sealed['ports'] == 136,
            'actual mechanical image/ABI differs')
    require(type(sealed['seals']) is int and sealed['seals'] == sealed['required_seals'] == 15
            and type(sealed['actual_module_file']) is str
            and sealed['actual_module_file'].startswith('/proc/self/fd/')
            and sealed['actual_module_file'].removeprefix('/proc/self/fd/').isdecimal(),
            'mechanical executable was not the sealed descriptor')
    mechanical_counter_delta(value["counters_before"], value["counters_after"],
                             runtime["pid"], require_public=True)
    require(regular_bytes(path) == raw and regular_bytes(expected_bundle['path']) == bundle_raw,
            'mechanical launch inputs changed during readback')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}

def admit_capture_revision(report, runtime, product_pins, capture_version):
    """Bind the declared snapshot protocol and implementation to source custody."""
    require(capture_version in ('original-v1', 'deferred-json-snapshots-v3'),
            'unknown supervising snapshot revision')
    count = runtime['argv'].count('--capture-version')
    if capture_version == 'original-v1':
        require(report['original_observer_definitions_or_cases_modified'] is False
                and report.get('observer_capture') == {
                    'version': 'original-v1', 'changed_snapshot_expressions': 0,
                    'changed_seal_statements': 0, 'changed_product_expressions': 0,
                    'changed_case_inputs': 0},
                'original observer revision differs')
        require(count == 0 or (count == 1
                and runtime['argv'][runtime['argv'].index('--capture-version') + 1:]
                and runtime['argv'][runtime['argv'].index('--capture-version') + 1]
                    == capture_version), 'actual original snapshot revision differs')
    else:
        name = 'tests/hia_slot_observer_capture.py'
        require(name in product_pins,
                'snapshot implementation is outside the frozen source closure')
        require(report['original_observer_definitions_or_cases_modified'] is True
                and report.get('observer_capture') == {
                    'version': 'deferred-json-snapshots-v3', 'changed_snapshot_expressions': 2,
                    'changed_seal_statements': 2, 'changed_product_expressions': 0,
                    'changed_case_inputs': 0,
                    'consumer_representation': 'canonical-json-bytes',
                    'implementation': {'path': name, **product_pins[name]}},
                'deferred snapshot revision or implementation pin differs')
        require(count == 1
                and runtime['argv'][runtime['argv'].index('--capture-version') + 1:]
                and runtime['argv'][runtime['argv'].index('--capture-version') + 1]
                    == capture_version, 'actual child snapshot revision differs')


def child(directory, *, expected, input_pin, source_pins, product_pins, backend, group, parent_pid, mechanical_bundle=None, mechanical_root=None, capture_version='original-v1'):
    directory = Path(directory)
    observed = directory / 'observation'
    command, result = read_json(directory / 'command.json'), read_json(directory / 'result.json')
    require(typed_equal(result['command'], command), 'parent command/result differs')
    require(successful_exit(result), 'child did not naturally succeed with its owned group gone')
    for name in ('pid', 'pgid', 'parent_pid', 'timeout_seconds', 'cleanup_seconds'):
        checked_int(command[name])
    checked_int(command['parent_pid'], parent_pid)
    checked_int(command['pid'], command['pgid'])
    checked_int(command['timeout_seconds'], ORIGINAL_SECONDS if backend == 'original' else CANDIDATE_SECONDS)
    checked_int(command['cleanup_seconds'], CLEANUP_SECONDS)
    require(command['new_session'] is True, 'child was not created in an owned session')
    effective = command.get('effective_timeout_seconds')
    require(type(effective) in (int, float) and 0 < effective <= command['timeout_seconds'],
            'actual enforced child timeout differs')
    require(result['stdout'] == pin(directory / 'stdout.log')
            and result['stderr'] == pin(directory / 'stderr.log'), 'raw child logs changed')
    raw_pins = {name: pin(observed / name) for name in RAW_FILES}
    report, runtime, plan = (read_json_at_pin(observed / name, raw_pins[name])
                            for name in ('report.json', 'runtime.json', 'planned.json'))
    require(report['schema'] == 'hepta.slot-operations.complete-observations.v1'
            and report['status'] == 'RECORDED', 'child full observations were not recorded')
    require(report['backend'] == backend and report['group'] == group, 'wrong child backend/input group')
    require(typed_equal(report['runtime'], runtime), 'runtime report differs')
    for key in ('pid', 'ppid', 'pgid'):
        checked_int(runtime[key], command['pid'] if key != 'ppid' else parent_pid)
    require(runtime['backend'] == backend, 'actual child backend differs')
    if backend == 'original':
        require(runtime['argv'] == command['argv'][3:], 'actual original command/runtime binding differs')
        launch_pin = None
    else:
        require(backend == 'native' and mechanical_bundle is not None,
                'v5 accepts only its explicit actual native lane')
        launch_pin = mechanical_launch(directory, command, runtime, mechanical_bundle,
                                       mechanical_root, product_pins)
    # python -I -B script ... : sys.argv begins with script at argv[3].
    require(typed_equal(plan['input'], input_pin) and typed_equal(report['input'], input_pin),
            'raw independent input identity differs')
    require(plan['ordered_ids'] == expected, 'child plan input order differs')
    checked_int(plan['count'], len(expected))
    checked_int(report['planned'], len(expected))
    require(report['started'] == report['stopped'] == expected and report['failures'] == [],
            'not every complete input reached a terminal observation')
    for before, after, pins in (
            ('source-before.json', 'source-after.json', source_pins),
            ('product-before.json', 'product-after.json', product_pins)):
        require(typed_equal(read_json_at_pin(observed / before, raw_pins[before]), pins)
                and typed_equal(read_json_at_pin(observed / after, raw_pins[after]), pins), 'source custody differs')
    require(report['source_stable'] is True and report['product_stable'] is True,
            'child did not retain source custody')
    admit_capture_revision(report, runtime, product_pins, capture_version)
    require(report['candidate_read_any_expected_observations'] is False,
            'candidate read independent expectations')
    checked_int(report['actual_SQL'], 0)
    require(report['all_SQL_and_decision_providers_explicitly_fake'] is True,
            'finite provider scope differs')
    require(report['native_controller'] is (backend == 'native')
            and report['independent_VM_controller'] is (backend == 'vm'), 'actual backend declaration differs')
    progress = list(read_lines(observed / 'progress.jsonl', expected_pin=raw_pins['progress.jsonl']))
    require(progress == [event for name in expected for event in (
        {'event': 'started', 'id': name}, {'event': 'stopped', 'id': name})],
        'started/stopped progress is not complete ordered input pairs')
    rows = 0
    for name, row in zip_longest(expected, read_lines(observed / 'observations.jsonl', expected_pin=raw_pins['observations.jsonl'])):
        require(name is not None and row is not None and row['id'] == name,
                'raw observation IDs differ')
        checked_int(row['fault_hits'])
        # Actual expected fault cardinality is checked below against the source
        # cases, not inferred from an identifier spelling.
        require(row['unraisable'] == [], 'unraisable callback in original/candidate')
        checked_int(row['sql_prefix_length'])
        rows += 1
    require([row['id'] for row in read_lines(observed / 'raw-exceptions.jsonl', expected_pin=raw_pins['raw-exceptions.jsonl'])] == expected,
            'full raw traceback inventory differs')
    require(report['observations_sha256'] == raw_pins['observations.jsonl']['sha256'],
            'raw observation hash differs')
    late = read_json_at_pin(observed / 'post-seal-gc.json', raw_pins['post-seal-gc.json'])
    checked_int(late['collected'])
    require(late['not_part_of_handler_result'] is True and late['no_prior_record_rewritten'] is True,
            'post-seal GC diagnostics were not kept separate')
    require([row['id'] for row in late['cases']] == expected
            and all(row['unraisable'] == [] for row in late['cases']), 'post-seal diagnostic inventory differs')
    counts = report['controller']
    if backend == 'original':
        require(counts is None and not (observed / 'controller.json').exists(),
                'original expectation ran a candidate controller')
    else:
        controller = read_json(observed / 'controller.json')
        require(typed_equal(controller['counts'], counts), 'controller counters disagree')
        checked_int(counts['returned_entries'])
        require(counts['returned_entries'] > 0 and counts['retained_calls'] == [],
                'candidate did not execute the selected controller or used retained bodies')
        for table in ('events', 'modes'):
            require(type(counts[table]) is dict and bool(counts[table]), 'missing actual entry counts')
            for value in counts[table].values():
                checked_int(value)
                require(value > 0, 'nonpositive actual event count')
            require(sum(counts[table].values()) == counts['returned_entries'], 'entry conservation differs')
        require(int(counts['events'].get('0', 0)) > 0 and int(counts['events'].get('4', 0)) > 0,
                'no initialized/finalized controller frames')
        if backend == 'native':
            checked_int(counts['attempted_entries'], counts['returned_entries'])
            admission = controller['admission']
            require(admission['native_mapping'] is True, 'native child used no actual mapped image')
            require(pin(admission['manifest_path']) == admission['manifest']
                    and pin(admission['image_path']) == admission['image'],
                    'actual manifest/image custody differs')
        else:
            require(controller['admission']['kind'] == 'INDEPENDENT_VM_COMPONENT_INJECTION'
                    and controller['admission']['native_mapping'] is False,
                    'VM was misrepresented as native admission')
    if launch_pin is not None:
        require(pin(launch_pin['path']) == {key: launch_pin[key] for key in ('bytes', 'sha256')},
                'mechanical launch evidence changed after observation comparison')
    require(all(typed_equal(pin(observed / name), saved)
                for name, saved in raw_pins.items()), 'child raw files changed before return')
    return {'mechanical_launch': launch_pin,
            'raw': raw_pins,
            'records': rows, 'runtime': runtime, 'counts': counts,
            'command': pin(directory / 'command.json'), 'result': pin(directory / 'result.json')}


def compare(expected, actual, output, *, expected_pin, actual_pin):
    """All mismatches retained; no field is normalized or omitted."""
    count = differing = leaf_count = 0
    with Path(output).open('xb') as stream:
        for original, candidate in zip_longest(
                read_lines(expected, expected_pin=expected_pin),
                read_lines(actual, expected_pin=actual_pin)):
            if original is None or candidate is None:
                value = {'id': None, 'reason': 'record-count', 'expected': original, 'actual': candidate}
                stream.write(canonical(value) + b'\n')
                differing += 1
                continue
            count += 1
            if canonical(original) != canonical(candidate):
                changes = list(leaves(original, candidate))
                stream.write(canonical({'id': original['id'], 'actual_id': candidate['id'],
                                        'differences': changes}) + b'\n')
                differing += 1
                leaf_count += len(changes)
    require(typed_equal(pin(expected), expected_pin) and typed_equal(pin(actual), actual_pin),
            'comparison operands changed before terminal readback')
    return {'records_compared': count, 'different_cases': differing,
            'different_leaves': leaf_count, 'raw_diff': pin(output)}


def read_evidence(root, oracle_root, derived, product_freeze, freeze_sha, evidence, output,
                  *, bridge_bundle, expected_bridge_sha256):
    bridge_raw = regular_bytes(bridge_bundle)
    require(sha(bridge_raw) == expected_bridge_sha256, 'external mechanical bundle pin differs')
    bridge_pin = {'path': str(Path(bridge_bundle).resolve(strict=True)),
                  'bytes': len(bridge_raw), 'sha256': expected_bridge_sha256}
    source = admit_originals(oracle_root)
    product = admit_product(root, product_freeze, freeze_sha)
    evidence, output = Path(evidence), Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan_pin, frozen_pin = pin(evidence / 'plan.json'), pin(evidence / 'expectations-frozen.json')
    plan = read_json_at_pin(evidence / 'plan.json', plan_pin)
    frozen = read_json_at_pin(evidence / 'expectations-frozen.json', frozen_pin)
    checked_int(plan['parent_pid'])
    require(plan['backends'] == ['native'], 'v5 requires its complete actual native lane')
    require(typed_equal(plan['mechanical_bundle'], bridge_pin), 'producer mechanical pin differs')
    require(plan['groups'] == ['original248', 'derived7574'], 'complete group inventory differs')
    capture_version = plan.get('observer_capture_version', 'original-v1')
    require(capture_version in ('original-v1', 'deferred-json-snapshots-v3'),
            'unknown complete observation snapshot revision')
    require(frozen['schema'] == 'hepta.slot-mechanical.independent-expectations.v1',
            'missing independent expectation freeze')
    require(frozen['candidate_started'] is False, 'expectations were not frozen before candidate children')
    result, comparisons, problems = {}, [], []
    for group in plan['groups']:
        cases, case_pin = admit_cases(oracle_root, derived, group)
        expected = [case['id'] for case in cases]
        originals = []
        for repetition in (1, 2):
            name = group + '-original-' + str(repetition)
            originals.append(name)
            result[name] = child(evidence / name, expected=expected, input_pin=case_pin, source_pins=source,
                product_pins=product, backend='original', group=group, parent_pid=plan['parent_pid'],
                capture_version=capture_version)
            require(result[name]['raw'] == frozen['groups'][group]['originals'][str(repetition)],
                    'frozen original raw files changed before/after candidates')
        first = evidence / originals[0] / 'observation'
        second = evidence / originals[1] / 'observation'
        require(read_bytes_at_pin(first / 'observations.jsonl', result[originals[0]]['raw']['observations.jsonl'])
                == read_bytes_at_pin(second / 'observations.jsonl', result[originals[1]]['raw']['observations.jsonl']),
                'fresh same-runtime original observations are unstable')
        require(read_bytes_at_pin(first / 'raw-exceptions.jsonl', result[originals[0]]['raw']['raw-exceptions.jsonl'])
                == read_bytes_at_pin(second / 'raw-exceptions.jsonl', result[originals[1]]['raw']['raw-exceptions.jsonl']),
                'fresh original raw exception observations are unstable')
        for row, case in zip(read_lines(first / 'observations.jsonl', expected_pin=result[originals[0]]['raw']['observations.jsonl']), cases):
            checked_int(row['fault_hits'], 0 if case['fault'] is None else 1)
        for backend in plan['backends']:
            name = group + '-' + backend
            result[name] = child(evidence / name, expected=expected, input_pin=case_pin, source_pins=source,
                product_pins=product, backend=backend, group=group, parent_pid=plan['parent_pid'],
                mechanical_bundle=bridge_pin, mechanical_root=root,
                capture_version=capture_version)
            require(result[name]['runtime']['version'] == result[originals[0]]['runtime']['version']
                    and result[name]['runtime']['implementation'] == result[originals[0]]['runtime']['implementation'],
                    'candidate did not use its original expectations runtime')
            for row, case in zip(read_lines(evidence / name / 'observation/observations.jsonl', expected_pin=result[name]['raw']['observations.jsonl']), cases):
                checked_int(row['fault_hits'], 0 if case['fault'] is None else 1)
            observation = compare(first / 'observations.jsonl',
                evidence / name / 'observation/observations.jsonl', output / (name + '-all-diffs.jsonl'),
                expected_pin=result[originals[0]]['raw']['observations.jsonl'],
                actual_pin=result[name]['raw']['observations.jsonl'])
            observation.update({'group': group, 'backend': backend,
                'original_raw': result[originals[0]]['raw']['observations.jsonl'],
                'actual_raw': result[name]['raw']['observations.jsonl']})
            comparisons.append(observation)
            if observation['different_cases']:
                problems.append(name)
    require(typed_equal(admit_product(root, product_freeze, freeze_sha), product)
            and typed_equal(admit_originals(oracle_root), source), 'readback sources changed')
    require(regular_bytes(bridge_bundle) == bridge_raw, 'mechanical external authority changed')
    require(typed_equal(pin(evidence / 'plan.json'), plan_pin)
            and typed_equal(pin(evidence / 'expectations-frozen.json'), frozen_pin),
            'plan or expectation authority changed before terminal readback')
    for name, record in result.items():
        require(all(typed_equal(pin(evidence / name / 'observation' / filename), saved)
                    for filename, saved in record['raw'].items()),
                'child raw evidence changed before terminal readback')
        saved = record['mechanical_launch']
        if saved is not None:
            require(pin(saved['path']) == {key: saved[key] for key in ('bytes', 'sha256')},
                    'mechanical launcher changed before final readback')
    complete = all(value['different_cases'] == 0 for value in comparisons)
    report = {'schema': 'hepta.slot-mechanical.observations-independent-readback.v1',
        'status': 'PASS' if complete else 'HOLD', 'children': result,
        'mechanical_bundle': bridge_pin, 'v5_control_scope': True,
        'comparisons': comparisons, 'mismatched_complete_groups': problems,
        'original_count': 248, 'derived_count': 7574, 'total_cases_per_backend': 7822,
        'same_runtime_originals_generated_twice_before_candidates': True,
        'post_seal_gc_scope': 'raw retained diagnostics; not compared as handler observations',
        'all_original_per_case_fields_compared': True,
        'observer_capture_version': capture_version,
        'raw_tracebacks_scope': 'complete files/IDs retained; candidate implementation stack frames may differ',
        'product_freeze': pin(product_freeze), 'expectations_freeze': frozen_pin,
        'no_product_code_imported_or_executed_by_reader': True}
    write_json(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'oracle-root', 'derived-inputs', 'product-freeze', 'evidence', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    parser.add_argument('--bridge-bundle', type=Path, required=True)
    parser.add_argument('--expected-bridge-sha256', required=True)
    options = parser.parse_args()
    try:
        report = read_evidence(options.root, options.oracle_root, options.derived_inputs,
            options.product_freeze, options.product_freeze_sha256, options.evidence, options.output,
            bridge_bundle=options.bridge_bundle, expected_bridge_sha256=options.expected_bridge_sha256)
    except BaseException as error:
        options.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json(options.output / 'HOLD.json', {'status': 'HOLD',
            'type': type(error).__module__ + '.' + type(error).__qualname__, 'message': str(error)})
        raise
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
