"""Experimental initialization frontier structure checker; never zero-elision authority.

Reuses the production closed-profile origin domain, but derives ingress and
completion-edge coverage separately from actual reverified Core. Conditional
prefix reasoning is not a whole-language, backend or machine-checked proof.
"""
from collections import deque
from hashlib import sha256
from pathlib import Path
from hepta.hia_program import verify_program
from hepta.hia_initialization import (_PURE, _RESOURCE, _TOP, _edges, _one, _union)
from hepta.hia_opcodes import SCALARS

MAX_BLOCKS = 128
MAX_OPERATIONS = 2048
MAX_VALUES = 4096
MAX_FLOW_STEPS = 4096
MAX_FLOW_WORK = 262144
DENY = {'authority': 'DENY_ALL', 'initialization_elision_authorized': False,
        'production_admission': False, 'native_admission': False,
        'performance_qualified': False, 'quota_equivalence': False}

def _analyze(function):
    blocks = {block["id"]: block for block in function["blocks"]}
    if (not blocks or len(blocks) > MAX_BLOCKS
            or sum(len(b["ops"]) for b in blocks.values()) > MAX_OPERATIONS
            or sum(len(b["params"]) + sum(len(op["out"]) for op in b["ops"]) for b in blocks.values()) > MAX_VALUES
            or any(p["type"] not in SCALARS for p in function["params"])
            or any(t not in SCALARS for t in function["returns"])
            or any(b["term"]["op"] not in {"ret", "jump", "branch", "trap"}
                   or any(op["op"] not in _PURE | _RESOURCE for op in b["ops"])
                   for b in blocks.values())):
        return False, [], "outside_closed_local_buffer_profile"
    predecessors = {name: set() for name in blocks}
    for name, block in blocks.items():
        for edge in _edges(block):
            predecessors[edge["target"]].add(name)
    allocations = {op["out"][0]["name"]: (name, op)
                   for name, block in blocks.items() for op in block["ops"]
                   if op["op"] in {"buffer.new", "buffer.try_new"}}
    if not allocations:
        return False, [], "no_local_allocation"
    # One static root must mean at most one dynamic allocation per invocation.
    # Allocation sites inside a cycle cannot inherit an earlier instance's fill.
    for block_name, _ in allocations.values():
        pending = [edge["target"] for edge in _edges(blocks[block_name])]
        seen = set()
        while pending:
            name = pending.pop()
            if name == block_name:
                return False, [], "allocation_site_can_repeat"
            if name not in seen:
                seen.add(name)
                pending.extend(edge["target"] for edge in _edges(blocks[name]))
    origins, types, definitions = {}, {}, {}
    for block in blocks.values():
        for p in block["params"]:
            types[p["name"]], origins[p["name"]] = p["type"], frozenset()
        for op in block["ops"]:
            for out in op["out"]:
                types[out["name"]] = out["type"]
                definitions[out["name"]] = op
    for p in function["params"]:
        origins[p["name"]] = frozenset({("argument", p["name"])})
    pending, queued, steps, work = deque([function["entry"]]), {function["entry"]}, 0, 0
    while pending:
        name = pending.popleft()
        queued.remove(name)
        steps += 1
        block = blocks[name]
        work += 1 + len(block["ops"]) + sum(len(edge["args"]) for edge in _edges(block))
        if steps > MAX_FLOW_STEPS or work > MAX_FLOW_WORK:
            return False, [], "origin_flow_budget_exhausted"
        for op in block["ops"]:
            for out in op["out"]:
                value = out["name"]
                if op["op"] == "const":
                    new = frozenset({("constant", out["type"], op["attrs"]["value"])})
                elif op["op"] in {"borrow.read", "borrow.mut", "owner.move"}:
                    new = origins.get(op["args"][0], frozenset())
                elif op["op"] in {"buffer.new", "buffer.try_new"} and out["type"] == "buffer":
                    new = frozenset({("allocation", value)})
                elif op["op"] == "int.cast" and types[op["args"][0]] == out["type"]:
                    new = origins.get(op["args"][0], frozenset())
                else:
                    new = frozenset({("value", value)})
                origins[value] = _union(origins.get(value, frozenset()), new)
        for edge in _edges(block):
            changed = False
            for p, arg in zip(blocks[edge["target"]]["params"], edge["args"]):
                before = origins[p["name"]]
                after = _union(before, origins.get(arg, frozenset()))
                if after != before:
                    origins[p["name"]] = after
                    changed = True
            if changed and edge["target"] not in queued:
                pending.append(edge["target"])
                queued.add(edge["target"])
    if any(not origins[p["name"]] for b in blocks.values() for p in b["params"]):
        return False, [], "incomplete_origin_flow"
    reachable, pending = set(), [function['entry']]
    while pending:
        name = pending.pop()
        if name not in reachable:
            reachable.add(name)
            pending.extend(edge['target'] for edge in _edges(blocks[name]))
    if reachable != set(blocks):
        return False, [], 'unreachable_block'

    # Preserve edge identities, including two branch arms with the same target.
    def labelled(block):
        term = block['term']
        if term['op'] == 'jump':
            return [('jump', term)]
        if term['op'] == 'branch':
            return [('then', term['then']), ('else', term['else'])]
        return []
    incoming = {name: [] for name in blocks}
    for name, block in blocks.items():
        for side, edge in labelled(block):
            incoming[edge['target']].append((name, side, edge))

    certificates = []
    for header in blocks.values():
        term = header['term']
        if term['op'] != 'branch' or len(header['ops']) != 1:
            continue
        compare = header['ops'][0]
        if compare['op'] != 'compare.lt' or compare['out'][0]['name'] != term['cond']:
            continue
        index, limit = compare['args']
        params = [p['name'] for p in header['params']]
        if index not in params or limit not in params or types[index] != 'usize' or types[limit] != 'usize':
            continue
        body, exit_block = blocks[term['then']['target']], blocks[term['else']['target']]
        if (body['id'] == header['id'] or exit_block['id'] in {body['id'], header['id']}
                or body['term']['op'] != 'jump' or body['term']['target'] != header['id']):
            continue
        stores = [op for op in body['ops'] if op['op'] == 'buffer.store']
        if len(stores) != 1 or any(op['op'] not in _PURE | {'borrow.mut', 'loan.end', 'buffer.store'} for op in body['ops']):
            continue
        if term['then']['args'].count(index) != 1 or term['then']['args'].count(limit) != 1:
            continue
        index_position, limit_position = params.index(index), params.index(limit)
        body_index_position = term['then']['args'].index(index)
        body_limit_position = term['then']['args'].index(limit)
        body_index = body['params'][body_index_position]['name']
        body_limit = body['params'][body_limit_position]['name']
        store = stores[0]
        if store['args'][1] != body_index:
            continue
        root = _one(origins.get(store['args'][0], frozenset()))
        if root is None or root[0] != 'allocation' or root[1] not in allocations:
            continue
        requested = _one(origins.get(allocations[root[1]][1]['args'][0], frozenset()))
        if requested is None or _one(origins[limit]) != requested or _one(origins[body_limit]) != requested:
            continue
        step_name = body['term']['args'][index_position]
        step = definitions.get(step_name)
        if (step is None or step not in body['ops'] or step['op'] not in {'int.add.checked', 'int.add.wrap'}
                or len(step['out']) != 1 or step['out'][0]['type'] != 'usize'
                or step['args'][0] != body_index
                or _one(origins.get(step['args'][1], frozenset())) != ('constant', 'usize', 1)
                or body['ops'].index(step) <= body['ops'].index(store)
                or _one(origins.get(body['term']['args'][limit_position], frozenset())) != requested):
            continue
        # Do not collapse incoming edges by predecessor name: every phi operand
        # on every arm must bind the seed index and exact allocation extent.
        seed_edges = []
        safe = True
        for destination, i_position, n_position in ((header['id'], index_position, limit_position),
                                                    (body['id'], body_index_position, body_limit_position)):
            for source, side, edge in incoming[destination]:
                if destination == header['id'] and source == body['id'] and side == 'jump':
                    continue
                if destination == body['id'] and source == header['id'] and side == 'then':
                    continue
                if (_one(origins.get(edge['args'][i_position], frozenset())) != ('constant', 'usize', 0)
                        or _one(origins.get(edge['args'][n_position], frozenset())) != requested):
                    safe = False
                    break
                seed_edges.append({'source': source, 'side': side, 'target': destination,
                                   'index_operand': edge['args'][i_position],
                                   'extent_operand': edge['args'][n_position]})
        if not safe or not seed_edges:
            continue
        certificates.append({'kind': 'counted_fill', 'allocation': root[1], 'header': header['id'],
            'body': body['id'], 'completion_edge': [header['id'], 'else', exit_block['id']],
            'seed_edges': seed_edges, 'index': index, 'extent': limit, 'store_index': body_index,
            'step': step_name, 'invariant': 'same dynamic root: [0,i) explicitly stored, 0<=i<=N',
            'direct_body_condition': 'i=0; successful checked store implies 0<N; trapping paths do not complete'})

    # An empty extent is fully initialized without requiring any store. This
    # certificate is tied to the SAME immutable origin as allocation length.
    for name, block in blocks.items():
        term = block['term']
        if term['op'] != 'branch':
            continue
        compare = definitions.get(term['cond'])
        if compare is None or compare not in block['ops'] or compare['op'] != 'compare.lt':
            continue
        zero, limit = compare['args']
        if types[zero] != 'usize' or types[limit] != 'usize' or _one(origins.get(zero, frozenset())) != ('constant', 'usize', 0):
            continue
        extent = _one(origins.get(limit, frozenset()))
        if extent is None:
            continue
        for allocation, (_, operation) in allocations.items():
            if _one(origins.get(operation['args'][0], frozenset())) == extent:
                certificates.append({'kind': 'empty_extent', 'allocation': allocation,
                    'completion_edge': [name, 'else', term['else']['target']],
                    'zero_operand': zero, 'extent_operand': limit,
                    'invariant': 'not (0<N) for usize N implies N=0; empty written interval is complete'})

    reads = [(name, op) for name, block in blocks.items() for op in block['ops'] if op['op'] == 'buffer.load']
    if not reads:
        return False, certificates, 'outside_read_coverage_research_profile'
    if not certificates:
        return False, [], 'no_checked_completion_certificates'
    for name, op in reads:
        root = _one(origins.get(op['args'][0], frozenset()))
        if root is None or root[0] != 'allocation':
            return False, certificates, 'ambiguous_or_nonlocal_read_root'
        cuts = {tuple(c['completion_edge']) for c in certificates if c['allocation'] == root[1]}
        seen, pending = set(), [function['entry']]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            for side, edge in labelled(blocks[current]):
                if (current, side, edge['target']) not in cuts:
                    pending.append(edge['target'])
        if name in seen:
            return False, certificates, 'read_path_without_same_root_completion'
    return True, certificates, 'all_read_paths_cross_checked_same_root_completion_edges'


def checker_identity():
    root = Path(__file__).resolve().parents[1]
    paths = [Path(__file__), *sorted((root / 'hepta').glob('*.py'))]
    value = sha256()
    for path in paths:
        value.update(str(path.relative_to(root)).encode() + b'\0' + path.read_bytes() + b'\0')
    return value.hexdigest()


def check_initialization_frontiers(program):
    report = {'schema': 'hepta.hia.experimental-initialization-frontiers.v1', 'status': 'unknown',
              'functions': [], 'whole_language_proof': False, 'backend_refinement_proof': False,
              'conditional_prefix_argument_only': True, **DENY}
    try:
        identity = checker_identity()
        checked = verify_program(program)
        report.update(core_sha256=checked.sha256, checker_sha256=identity)
        for function in checked.as_dict()['functions']:
            eligible, certificates, reason = _analyze(function)
            report['functions'].append({'function': function['name'], 'checked': eligible,
                                        'certificates': certificates, 'reason': reason})
        if checker_identity() != identity:
            report.update(status='unknown', reason='checker_changed_during_verification')
        elif report['functions'] and all(row['checked'] for row in report['functions']):
            report.update(status='checked', reason='experimental_structure_only_not_zero_elision_authority')
        else:
            report.update(status='rejected', reason='unsupported_or_uncovered_actual_core')
    except (ValueError, KeyError, IndexError, TypeError, RecursionError) as error:
        report.update(status='rejected', reason=type(error).__name__ + ': unsupported_or_malformed_core')
    except Exception as error:
        report.update(status='unknown', reason=type(error).__name__ + ': check_incomplete')
    return report
