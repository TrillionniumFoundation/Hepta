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


def read_lines(path):
    with Path(path).open('rb') as stream:
        for number, raw in enumerate(stream, 1):
            require(raw.endswith(b'\n'), 'unterminated JSONL record')
            value = json.loads(raw, object_pairs_hook=unique_pairs,
                parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
            require(raw == canonical(value) + b'\n', 'noncanonical JSONL record ' + str(number))
            yield value


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


def child(directory, *, expected, input_pin, source_pins, product_pins, backend, group, parent_pid):
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
    for name in RAW_FILES:
        regular_bytes(observed / name)
    report, runtime, plan = (read_json(observed / name)
                            for name in ('report.json', 'runtime.json', 'planned.json'))
    require(report['schema'] == 'hepta.slot-operations.complete-observations.v1'
            and report['status'] == 'RECORDED', 'child full observations were not recorded')
    require(report['backend'] == backend and report['group'] == group, 'wrong child backend/input group')
    require(typed_equal(report['runtime'], runtime), 'runtime report differs')
    for key in ('pid', 'ppid', 'pgid'):
        checked_int(runtime[key], command['pid'] if key != 'ppid' else parent_pid)
    require(runtime['backend'] == backend and runtime['argv'] == command['argv'][3:],
            'actual child command/runtime binding differs')
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
        require(typed_equal(read_json(observed / before), pins)
                and typed_equal(read_json(observed / after), pins), 'source custody differs')
    require(report['source_stable'] is True and report['product_stable'] is True,
            'child did not retain source custody')
    require(report['candidate_read_any_expected_observations'] is False
            and report['original_observer_definitions_or_cases_modified'] is False,
            'independent expectation boundary differs')
    checked_int(report['actual_SQL'], 0)
    require(report['all_SQL_and_decision_providers_explicitly_fake'] is True,
            'finite provider scope differs')
    require(report['native_controller'] is (backend == 'native')
            and report['independent_VM_controller'] is (backend == 'vm'), 'actual backend declaration differs')
    progress = list(read_lines(observed / 'progress.jsonl'))
    require(progress == [event for name in expected for event in (
        {'event': 'started', 'id': name}, {'event': 'stopped', 'id': name})],
        'started/stopped progress is not complete ordered input pairs')
    rows = 0
    for name, row in zip_longest(expected, read_lines(observed / 'observations.jsonl')):
        require(name is not None and row is not None and row['id'] == name,
                'raw observation IDs differ')
        checked_int(row['fault_hits'])
        # Actual expected fault cardinality is checked below against the source
        # cases, not inferred from an identifier spelling.
        require(row['unraisable'] == [], 'unraisable callback in original/candidate')
        checked_int(row['sql_prefix_length'])
        rows += 1
    require([row['id'] for row in read_lines(observed / 'raw-exceptions.jsonl')] == expected,
            'full raw traceback inventory differs')
    require(report['observations_sha256'] == pin(observed / 'observations.jsonl')['sha256'],
            'raw observation hash differs')
    late = read_json(observed / 'post-seal-gc.json')
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
    return {'raw': {name: pin(observed / name) for name in RAW_FILES},
            'records': rows, 'runtime': runtime, 'counts': counts,
            'command': pin(directory / 'command.json'), 'result': pin(directory / 'result.json')}


def compare(expected, actual, output):
    """All mismatches retained; no field is normalized or omitted."""
    count = differing = leaf_count = 0
    with Path(output).open('xb') as stream:
        for original, candidate in zip_longest(read_lines(expected), read_lines(actual)):
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
    return {'records_compared': count, 'different_cases': differing,
            'different_leaves': leaf_count, 'raw_diff': pin(output)}


def read_evidence(root, oracle_root, derived, product_freeze, freeze_sha, evidence, output):
    source = admit_originals(oracle_root)
    product = admit_product(root, product_freeze, freeze_sha)
    evidence, output = Path(evidence), Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan, frozen = read_json(evidence / 'plan.json'), read_json(evidence / 'expectations-frozen.json')
    checked_int(plan['parent_pid'])
    require(plan['backends'] in (['vm'], ['native'], ['vm', 'native']), 'undeclared backend order')
    require(plan['groups'] == ['original248', 'derived7574'], 'complete group inventory differs')
    require(frozen['schema'] == 'hepta.slot-operations.independent-expectations.v1',
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
                product_pins=product, backend='original', group=group, parent_pid=plan['parent_pid'])
            require(result[name]['raw'] == frozen['groups'][group]['originals'][str(repetition)],
                    'frozen original raw files changed before/after candidates')
        first = evidence / originals[0] / 'observation'
        second = evidence / originals[1] / 'observation'
        require(regular_bytes(first / 'observations.jsonl') == regular_bytes(second / 'observations.jsonl'),
                'fresh same-runtime original observations are unstable')
        require(regular_bytes(first / 'raw-exceptions.jsonl') == regular_bytes(second / 'raw-exceptions.jsonl'),
                'fresh original raw exception observations are unstable')
        for row, case in zip(read_lines(first / 'observations.jsonl'), cases):
            checked_int(row['fault_hits'], 0 if case['fault'] is None else 1)
        for backend in plan['backends']:
            name = group + '-' + backend
            result[name] = child(evidence / name, expected=expected, input_pin=case_pin, source_pins=source,
                product_pins=product, backend=backend, group=group, parent_pid=plan['parent_pid'])
            require(result[name]['runtime']['version'] == result[originals[0]]['runtime']['version']
                    and result[name]['runtime']['implementation'] == result[originals[0]]['runtime']['implementation'],
                    'candidate did not use its original expectations runtime')
            for row, case in zip(read_lines(evidence / name / 'observation/observations.jsonl'), cases):
                checked_int(row['fault_hits'], 0 if case['fault'] is None else 1)
            observation = compare(first / 'observations.jsonl',
                evidence / name / 'observation/observations.jsonl', output / (name + '-all-diffs.jsonl'))
            observation.update({'group': group, 'backend': backend,
                'original_raw': pin(first / 'observations.jsonl'),
                'actual_raw': pin(evidence / name / 'observation/observations.jsonl')})
            comparisons.append(observation)
            if observation['different_cases']:
                problems.append(name)
    require(typed_equal(admit_product(root, product_freeze, freeze_sha), product)
            and typed_equal(admit_originals(oracle_root), source), 'readback sources changed')
    complete = all(value['different_cases'] == 0 for value in comparisons)
    report = {'schema': 'hepta.slot-operations.observations-independent-readback.v1',
        'status': 'PASS' if complete else 'HOLD', 'children': result,
        'comparisons': comparisons, 'mismatched_complete_groups': problems,
        'original_count': 248, 'derived_count': 7574, 'total_cases_per_backend': 7822,
        'same_runtime_originals_generated_twice_before_candidates': True,
        'post_seal_gc_scope': 'raw retained diagnostics; not compared as handler observations',
        'all_original_per_case_fields_compared': True,
        'raw_tracebacks_scope': 'complete files/IDs retained; candidate implementation stack frames may differ',
        'product_freeze': pin(product_freeze), 'expectations_freeze': pin(evidence / 'expectations-frozen.json'),
        'no_product_code_imported_or_executed_by_reader': True}
    write_json(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'oracle-root', 'derived-inputs', 'product-freeze', 'evidence', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    options = parser.parse_args()
    try:
        report = read_evidence(options.root, options.oracle_root, options.derived_inputs,
            options.product_freeze, options.product_freeze_sha256, options.evidence, options.output)
    except BaseException as error:
        options.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json(options.output / 'HOLD.json', {'status': 'HOLD',
            'type': type(error).__module__ + '.' + type(error).__qualname__, 'message': str(error)})
        raise
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
