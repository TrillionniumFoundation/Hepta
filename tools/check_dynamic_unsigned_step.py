"""Isolated finite true-edge/phi/usize-step checks, never Core/Lean proof.

Uses the existing ordinary VM without changing instructions or admission gates.
The temporary operation patch is single-process/nonconcurrent research only.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from hepta.hia_program import verify_program
from hepta.hia_opcodes import SCALARS, scalar_value_valid
from hepta import hia_program_runtime as vm
from hepta.hia_initialization import _PURE, _RESOURCE
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS, source_identity as ledger_identity, encoded

MAXIMUM = 2**64 - 1


def source_identity():
    result = ledger_identity()
    root = Path(__file__).resolve().parents[1]
    for path in (Path(__file__), root / 'tools/extract_initialization_obligations.py',
                 root / 'experiments/hia_initialization_frontiers_20261103/UNSIGNED_STEP_CONNECTION.md'):
        result[str(path.relative_to(root))] = sha256(path.read_bytes()).hexdigest()
    return result


def denied():
    return {**DENY, 'actual_core_bridge_proved': False, 'whole_loop_proved': False,
            'all_entries_step_safe': False,
            'obligations': [{'id': name, 'status': 'unproved'} for name, _ in OBLIGATIONS]}


def extract_step_slices(program):
    report = {'schema': 'hepta.hia.unsigned-step-slices.v1', 'status': 'unknown', 'slices': [], **denied()}
    try:
        identity = source_identity()
        if not hasattr(program, 'as_dict'):
            encoded(program)
        checked = verify_program(program)
        document = checked.as_dict()
        encoded(document)
        if (sum(len(f['blocks']) for f in document['functions']) > 128 or
                sum(len(b['ops']) for f in document['functions'] for b in f['blocks']) > 2048 or
                sum(len(b['params']) + sum(len(op['out']) for op in b['ops'])
                    for f in document['functions'] for b in f['blocks']) > 4096):
            report.update(status='rejected', reason='slice_size_bound')
            return report
        for function in document['functions']:
            blocks = {b['id']: b for b in function['blocks']}
            types = {p['name']: p['type'] for b in blocks.values() for p in b['params']}
            types.update({o['name']: o['type'] for b in blocks.values() for op in b['ops'] for o in op['out']})
            for header in blocks.values():
                term = header['term']
                if term['op'] != 'branch' or len(header['ops']) != 1:
                    continue
                compare = header['ops'][0]
                if (compare['op'] != 'compare.lt' or compare['out'][0]['name'] != term['cond']
                        or any(types[a] != 'usize' for a in compare['args'])):
                    continue
                index, extent = compare['args']
                edge = term['then']
                body = blocks[edge['target']]
                if body is header or edge['args'].count(index) != 1 or edge['args'].count(extent) != 1:
                    continue
                ipos, npos = edge['args'].index(index), edge['args'].index(extent)
                body_index, body_extent = body['params'][ipos]['name'], body['params'][npos]['name']
                constants = {}
                for ordinal, op in enumerate(body['ops']):
                    # A nested invoke could replace pending edge state. Initial
                    # fragment has no calls/unknown operations before the add.
                    if op['op'] not in _PURE | _RESOURCE:
                        break
                    if op['op'] == 'const':
                        for out in op['out']:
                            constants[out['name']] = (out['type'], op['attrs']['value'])
                    if (op['op'] in {'int.add.checked', 'int.add.wrap'} and len(op['out']) == 1
                            and op['out'][0]['type'] == 'usize' and op['args'][0] == body_index
                            and constants.get(op['args'][1]) == ('usize', 1)):
                        report['slices'].append({'function': function['name'], 'header': header['id'],
                            'compare_ordinal': 0, 'compare': deepcopy(compare), 'condition': term['cond'],
                            'arm': 'then', 'target': body['id'], 'index': index, 'extent': extent,
                            'bindings': [{'parameter': deepcopy(p), 'operand': a} for p, a in zip(body['params'],edge['args'])],
                            'body_index': body_index, 'body_extent': body_extent,
                            'step_ordinal': ordinal, 'step': deepcopy(op),
                            'model_theorem': 'HiaInitializationPrefix.increment_within_limit',
                            'scope': 'only this dynamic true-edge reaching this add normally'})
                        break  # one first eligible step per edge, not all add sites
        report.update(core_sha256=checked.sha256, source_sha256=identity)
        if identity != source_identity():
            report.update(status='unknown', reason='source_changed', slices=[])
        elif report['slices']:
            report.update(status='extracted', reason='conditional_slice_not_semantic_proof')
        else:
            report.update(status='rejected', reason='no_supported_true_edge_unit_step')
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        report.update(status='rejected', reason='malformed_or_unsupported', slices=[])
    except Exception:
        report.update(status='unknown', reason='incomplete_extraction', slices=[])
    return report


def observe_unsigned_steps(program, arguments, *, function='calculate', max_events=1024, **limits):
    if type(max_events) is not int or not 0 <= max_events <= 4096:
        raise ValueError('invalid observation event limit')
    extracted = extract_step_slices(program)
    report = {'schema': 'hepta.hia.dynamic-unsigned-step.v1', 'status': extracted['status'],
              'extraction': extracted, 'function': function, 'arguments': deepcopy(arguments),
              'limits': deepcopy(limits), 'event_limit': max_events, 'events': [], 'vm_outcome': None,
              'finite_step_matches': False, 'observation_complete': False,
              'finite_observation_only': True, 'ordinary_zero_initialization_retained': True, **denied()}
    if extracted['status'] != 'extracted':
        return report
    checked = verify_program(program)
    operation = vm._Machine.operation
    events, pending, complete, maps = [], None, True, None

    def watched(machine, ins, env, depth):
        nonlocal pending, complete, maps
        if maps is None:
            locations = {id(op): (f['name'], b['id'], n)
                         for f in machine.functions.values() for b in f['blocks']
                         for n, op in enumerate(b['ops'])}
            maps = (locations, {(s['function'], s['header'], 0): (number, s)
                               for number, s in enumerate(extracted['slices'])})
        location = maps[0].get(id(ins))
        selected = maps[1].get(location)
        event = None
        if pending is not None:
            s = pending['slice']
            if location is None or location[:2] != (s['function'], s['target']):
                pending = None
            else:
                # The first actual target operation must see a new environment
                # with ALL phi operands snapshotted from the selected source.
                if pending['target_env'] is None:
                    okay = env is not pending['source_env']
                    for p, value in pending['values']:
                        actual = env.get(p['name'])
                        if p['type'] in SCALARS:
                            okay = okay and scalar_value_valid(actual, p['type']) and type(actual) is type(value) and actual == value
                        else:
                            okay = okay and actual is value
                    if not okay:
                        complete, pending = False, None
                    else:
                        pending['target_env'] = env
                if pending is not None and location[2] == s['step_ordinal']:
                    i, n = pending['index'], pending['extent']
                    valid = (env is pending['target_env']
                             and all(scalar_value_valid(env[name], 'usize')
                                     for name in (s['body_index'], s['body_extent'], ins['args'][1]))
                             and env[s['body_index']] == i
                             and env[s['body_extent']] == n and env[ins['args'][1]] == 1)
                    event = {'slice_index': pending['slice_index'], 'index': i, 'extent': n, 'arm': 'then',
                             'phi_bindings_checked': len(pending['values']),
                             'simultaneous_phi_matches': valid, 'vm_step': machine.steps}
                    pending = None
        try:
            result = operation(machine, ins, env, depth)
        except Exception:
            if event is not None:
                event.update(outcome='failure', finite_step_matches=False)
                events.append(event)
            raise
        if event is not None:
            value = env[ins['out'][0]['name']]
            event.update(outcome='success', result=value,
                finite_step_matches=(event['simultaneous_phi_matches'] and type(value) is int
                    and value == event['index'] + 1 and value <= event['extent'] <= MAXIMUM))
            events.append(event)
        if selected is not None:
            slice_index, selected = selected
            pending = None
            if env[selected['condition']] is True and len(events) >= max_events:
                complete = False
            if complete and env[selected['condition']] is True:
                i, n = env[selected['index']], env[selected['extent']]
                if not (scalar_value_valid(i, 'usize') and scalar_value_valid(n, 'usize') and i < n):
                    complete = False
                else:
                    pending = {'slice': selected, 'slice_index': slice_index, 'index': i, 'extent': n, 'source_env': env,
                        'target_env': None, 'values': [(row['parameter'], env[row['operand']]) for row in selected['bindings']]}
        return result

    with patch.object(vm._Machine, 'operation', watched):
        try:
            outcome = vm.execute_program(checked, function, arguments, **limits)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            outcome = error.report
    unchanged = extracted['source_sha256'] == source_identity()
    complete = complete and unchanged
    report.update(status='observed' if complete else 'incomplete', events=events, vm_outcome=outcome,
                  observation_complete=complete, sources_unchanged=unchanged,
                  finite_step_matches=complete and bool(events) and all(e['finite_step_matches'] for e in events),
                  event_limit=max_events, actual_core_bridge_proved=False)
    return report
