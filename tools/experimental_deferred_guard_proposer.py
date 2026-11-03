"""Untrusted experimental CFG factoring proposal; never production admission.

The independent checker must validate every mapping, operand, effect and proof.
The structural model is used for construction only, never as authority.
"""
from copy import deepcopy

from hepta.hia_program import SCALARS, verify_program
from hepta.hia_reduction import _freeze_pipeline
from tools.research_deferred_guard_model import edges, frontier

SCHEMA = 'hepta.hia.experimental-deferred-guard.v1'


def propose_deferred_guard(base, reduction):
    original, narrowed, fast, frozen = _freeze_pipeline(base, reduction)
    if len(frozen['guarded']['guards']) != 1:
        raise ValueError('first experiment requires exactly one guarded function')
    guard = frozen['guarded']['guards'][0]
    document = narrowed.as_dict()
    function = next(f for f in document['functions'] if f['name'] == guard['function'])
    fast_function = next(f for f in fast.as_dict()['functions'] if f['name'] == function['name'])
    if any(p['type'] not in SCALARS for p in function['params']) or any(t not in SCALARS for t in function['returns']):
        raise ValueError('first experiment requires scalar public interface')
    plan = frontier(function, fast_function, guard)
    if plan['entry_dispatch'] or not plan['different']:
        raise ValueError('first experiment requires common entry and at least one divergence')
    if any(e['target'] == function['entry'] for b in function['blocks'] for _, e in edges(b)):
        raise ValueError('incoming edges to the function ABI entry are outside first profile')
    old_blocks = {b['id']: b for b in function['blocks']}
    fast_blocks = {b['id']: b for b in fast_function['blocks']}
    used_values = {p['name'] for f in document['functions'] for b in f['blocks'] for p in b['params']}
    used_values.update(o['name'] for f in document['functions'] for b in f['blocks'] for op in b['ops'] for o in op['out'])
    used_blocks = {b['id'] for f in document['functions'] for b in f['blocks']}

    def fresh(stem, used):
        index = 0
        while stem + str(index) in used:
            index += 1
        name = stem + str(index)
        used.add(name)
        return name

    def value():
        return fresh('dg_v_', used_values)

    names, maps, snapshots = {}, {}, {}
    for role, selected in [('shared', plan['shared']), ('fast', plan['suffix']), ('slow', plan['suffix'])]:
        names[role] = {name: fresh('dg_' + role + '_', used_blocks) for name in selected}
        maps[role] = {}
        source = fast_blocks if role == 'fast' else old_blocks
        for name in selected:
            block = source[name]
            for parameter in block['params']:
                maps[role][parameter['name']] = parameter['name'] if role == 'shared' and name == function['entry'] else value()
            for operation in block['ops']:
                for output in operation['out']:
                    maps[role][output['name']] = value()
            if role == 'shared':
                snapshots[name] = guard['argument'] if name == function['entry'] else value()

    guard_names = {tuple(edge): fresh('dg_guard_', used_blocks) for edge in plan['cuts']}
    output_blocks = []
    for role in ('shared', 'fast', 'slow'):
        source = fast_blocks if role == 'fast' else old_blocks
        selected = list(names[role])
        if role == 'shared':
            selected.remove(function['entry'])
            selected.insert(0, function['entry'])
        rename = maps[role]
        for name in selected:
            block = deepcopy(source[name])
            block['id'] = names[role][name]
            for parameter in block['params']:
                parameter['name'] = rename[parameter['name']]
            if role == 'shared' and name != function['entry']:
                block['params'].append({'name': snapshots[name], 'type': 'usize'})
            for operation in block['ops']:
                operation['args'] = [rename[a] for a in operation['args']]
                for output in operation['out']:
                    output['name'] = rename[output['name']]
            term = block['term']
            if term['op'] == 'ret':
                term['values'] = [rename[a] for a in term['values']]
            else:
                if term['op'] == 'branch':
                    term['cond'] = rename[term['cond']]
                for side, edge in edges(block):
                    target = edge['target']
                    edge['args'] = [rename[a] for a in edge['args']]
                    if role == 'shared':
                        edge['target'] = names[role].get(target) or guard_names[(name, side, target)]
                        edge['args'].append(snapshots[name])
                    else:
                        edge['target'] = names[role][target]
            output_blocks.append(block)

    for source, side, target in plan['cuts']:
        params = [{'name': value(), 'type': p['type']} for p in old_blocks[target]['params']]
        snapshot, limit, condition = value(), value(), value()
        ordinary = [p['name'] for p in params]
        params.append({'name': snapshot, 'type': 'usize'})
        output_blocks.append({'id': guard_names[(source, side, target)], 'params': params,
            'ops': [{'op': 'const', 'args': [], 'out': [{'name': limit, 'type': 'usize'}], 'attrs': {'value': guard['maximum']}},
                    {'op': 'compare.le', 'args': [snapshot, limit], 'out': [{'name': condition, 'type': 'bool'}], 'attrs': {}}],
            'term': {'op': 'branch', 'cond': condition,
                     'then': {'target': names['fast'][target], 'args': ordinary},
                     'else': {'target': names['slow'][target], 'args': ordinary}}})
    function['entry'] = names['shared'][function['entry']]
    function['blocks'] = output_blocks
    candidate = verify_program(document)
    layout = {'function': function['name'],
        **{role: [{'source_block': name, 'candidate_block': new} for name, new in names[role].items()]
           for role in ('shared', 'fast', 'slow')},
        'guards': [{'source_block': source, 'edge': side, 'target_block': target,
                    'candidate_block': new} for (source, side, target), new in guard_names.items()]}
    return {'schema': SCHEMA, 'base_sha256': original.sha256, 'reduction': frozen,
            'candidate_core': candidate.as_dict(), 'layout': layout}
