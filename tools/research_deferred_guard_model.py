#!/usr/bin/env python3
"""Design-time frontier/SSA model only. Never emits or admits transformed Core."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def edges(block):
    term = block['term']
    if term['op'] == 'jump':
        return [('jump', term)]
    if term['op'] == 'branch':
        return [(side, term[side]) for side in ('then', 'else')]
    if term['op'] == 'ret':
        return []
    raise ValueError('model supports only jump, branch and return terminators')


def inventory(slow, fast, guard):
    if (slow['name'] != fast['name'] or slow['entry'] != fast['entry']
            or slow['params'] != fast['params'] or slow['returns'] != fast['returns']):
        raise ValueError('identical function interface required')
    if set(guard) != {'function', 'argument', 'maximum'} or guard['function'] != slow['name']:
        raise ValueError('one original input-bound compare.le guard required')
    parameter = next((p for p in slow['params'] if p['name'] == guard['argument']), None)
    if (not parameter or parameter['type'] != 'usize' or type(guard['maximum']) is not int
            or not 0 <= guard['maximum'] < 2**64):
        raise ValueError('guard must be total unsigned comparison on original immutable usize input')
    if not 1 <= len(slow['blocks']) <= 128 or len(fast['blocks']) > 128:
        raise ValueError('bounded 128-block first profile required')
    if any(op['op'] == 'call' for fn in (slow, fast) for block in fn['blocks'] for op in block['ops']):
        raise ValueError('calls/recursion require a separate whole-call-graph proof')
    a = {b['id']: b for b in slow['blocks']}
    b = {b['id']: b for b in fast['blocks']}
    if len(a) != len(slow['blocks']) or len(b) != len(fast['blocks']) or set(a) != set(b):
        raise ValueError('complete duplicate-free matched block inventory required')
    for name in a:
        if a[name]['params'] != b[name]['params'] or a[name]['term'] != b[name]['term']:
            raise ValueError('this first model requires unchanged block interfaces and terminators')
        if any(e['target'] not in a for _, e in edges(a[name])):
            raise ValueError('closed successor inventory required')
    return a, b


def frontier(slow, fast, guard):
    a, b = inventory(slow, fast, guard)
    changed = {name for name in a if a[name] != b[name]}
    shared, cuts = set(), set()
    todo = [slow['entry']]
    while todo:
        name = todo.pop()
        if name in changed or name in shared:
            continue
        shared.add(name)
        for side, edge in edges(a[name]):
            if edge['target'] in changed:
                cuts.add((name, side, edge['target']))
            else:
                todo.append(edge['target'])
    starts = {target for _, _, target in cuts}
    if slow['entry'] in changed:
        starts.add(slow['entry'])
    suffix = set()
    todo = list(starts)
    while todo:
        name = todo.pop()
        if name in suffix:
            continue
        suffix.add(name)
        todo.extend(e['target'] for _, e in edges(a[name]))
    return {'shared': sorted(shared), 'different': sorted(changed),
            'cuts': [list(c) for c in sorted(cuts)], 'suffix': sorted(suffix),
            'entry_dispatch': slow['entry'] in changed,
            'guard_snapshot': {'argument': guard['argument'], 'type': 'usize',
                               'origin': 'original_function_input', 'carry': 'unchanged_on_every_shared_edge'},
            'suffix_namespace': 'selected_version_only',
            'guard_evaluation': 'at_first_divergence_only',
            'performance_qualified': False, 'production_admission': False}


def check_plan(slow, fast, guard, plan):
    # A design envelope, not a checker for generated Core. The later checker
    # must bind actual definitions, edge operands and alpha-renamed clones.
    expected = frontier(slow, fast, guard)
    if type(plan) is not dict or json.dumps(plan, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError('incomplete frontier, mutable snapshot, or non-closed selected suffix')
    return True


def symbolic_obligations():
    import z3 as z
    if z.get_version_string() != '4.15.4':
        raise ValueError('pinned Z3 4.15.4 required')
    n, snapshot, current, limit = z.BitVecs('original_input snapshot current limit', 64)
    results = {}
    def query(name, constraints, wanted):
        solver = z.Solver(); solver.set(timeout=5000)
        solver.add(*constraints)
        outcome = solver.check()
        if str(outcome) != wanted:
            raise ValueError('unexpected model proof outcome: ' + name + ': ' + str(outcome))
        row = {'result': str(outcome), 'smt2': solver.to_smt2()}
        if outcome == z.sat:
            row['counterexample'] = {str(d): str(solver.model()[d]) for d in solver.model().decls()}
        results[name] = row
    query('immutable_snapshot_preserves_selection',
          [snapshot == n, z.ULE(snapshot, limit) != z.ULE(n, limit)], 'unsat')
    query('arbitrary_later_state_cannot_change_captured_selection',
          [snapshot == n, current != n, z.ULE(snapshot, limit) != z.ULE(n, limit)], 'unsat')
    query('mutated_phi_argument_breaks_selection',
          [limit == 7, current == n + 1, z.ULE(current, limit) != z.ULE(n, limit)], 'sat')
    query('wrong_phi_operand_breaks_selection',
          [n == 3, current == 9, limit == 7, z.ULE(current, limit) != z.ULE(n, limit)], 'sat')
    query('signed_guard_breaks_selection',
          [limit == 7, (n <= limit) != z.ULE(n, limit)], 'sat')
    # Abstract one-step stuttering-simulation obligation: identical common
    # transition, equal state, same nondeterministic input and original guard.
    # Structural equality and correct alpha-renaming remain prerequisites.
    state_a, state_b, oracle = z.Ints('state_a state_b oracle')
    transition = z.Function('common_transition', z.IntSort(), z.IntSort(), z.IntSort())
    event = z.Function('ordered_resource_event', z.IntSort(), z.IntSort(), z.IntSort())
    query('common_step_under_explicit_equal_transition_assumption',
          [state_a == state_b, z.Or(transition(state_a, oracle) != transition(state_b, oracle),
                                    event(state_a, oracle) != event(state_b, oracle))], 'unsat')
    return {'solver': z.get_version_string(), 'obligations': results,
            'scope': 'conditional abstract state/guard model; not generated-Core, whole-language or machine-code proof',
            'production_admission': False, 'performance_qualified': False}


def toy_run(n, *, deferred, mutated_snapshot=False, omit_fill_cut=False,
            reselect_on_backedge=False, fail_allocation=False, prefix_increment=False,
            prefix_cycles=0, prefix_trap=False, steps=40):
    """Finite differential model with loop-carried state and ordered events.

    Fast/slow deliberately return different tags. This checks preservation of
    the existing selected-version semantics, not their equivalence to a base.
    Events are modeled strings, not real HIA owner/loan execution.
    """
    current, pc, mode = n, 'allocate', None if deferred else n <= 7
    events, guards = [], 0 if deferred else 1
    remaining_prefix = prefix_cycles
    value = None
    for step in range(steps):
        if deferred and mode is None and pc in {'fill', 'reduce'}:
            if not (omit_fill_cut and pc == 'fill'):
                mode = (current if mutated_snapshot else n) <= 7
                guards += 1
        selected = False if mode is None else mode
        if pc == 'allocate':
            events.append(('allocation_attempt', fail_allocation))
            if prefix_increment:
                current = (current + 1) & 255
            pc = 'refuse' if fail_allocation else 'trap' if prefix_trap else 'prefix_loop' if remaining_prefix else 'header'
        elif pc == 'refuse':
            return {'status': 'returned', 'value': 1001, 'events': events, 'guards': guards}
        elif pc == 'trap':
            events.append(('trap',))
            return {'status': 'trapped', 'value': None, 'events': events, 'guards': guards}
        elif pc == 'prefix_loop':
            events.append(('prefix_tick', remaining_prefix))
            current = (current + 1) & 255
            remaining_prefix -= 1
            if not remaining_prefix:
                pc = 'header'
        elif pc == 'header':
            pc = 'empty_return' if current == 0 else 'fill'
        elif pc == 'empty_return':
            events.append(('drop_empty',))
            return {'status': 'returned', 'value': 0, 'events': events, 'guards': guards}
        elif pc == 'fill':
            events.extend([('borrow_mut',), ('write', 'fast' if selected else 'slow'), ('loan_end',)])
            current = (current - 1) & 255
            if current:
                if reselect_on_backedge:
                    mode = None
                pc = 'fill'
            else:
                pc = 'reduce'
        elif pc == 'reduce':
            events.extend([('borrow_read',), ('read',), ('loan_end',), ('drop',)])
            value = 10 if selected else 20
            return {'status': 'returned', 'value': value, 'events': events, 'guards': guards}
    return {'status': 'prefix_only', 'value': value, 'events': events, 'guards': guards}


def observation(run):
    # Step/guard counts deliberately excluded from the equivalence claim.
    return {k: run[k] for k in ('status', 'value', 'events')}


if __name__ == '__main__':
    from hepta.hia_program_source import lower_source
    from hepta.hia_reduction import propose_reduction_pipeline
    result = {'model': symbolic_obligations(), 'frontiers': {}}
    for workload in ('linear', 'affine'):
        core = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
        proposal = propose_reduction_pipeline(core, include_induction=True)
        slow = proposal['narrowed_core']['functions'][0]
        fast = proposal['guarded']['fast_core']['functions'][0]
        guard = proposal['guarded']['guards'][0]
        result['frontiers'][workload] = frontier(slow, fast, guard)
    print(json.dumps(result, indent=2, sort_keys=True))
