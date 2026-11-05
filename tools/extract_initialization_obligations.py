"""Read-only Core/model obligation transport. No proof, emitter, or authority.

Reconstruction authenticates a ledger against this checkout, not a theorem.
All semantic connection obligations remain unresolved even on an exact match.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_program import verify_program
from tools.check_initialization_frontiers import check_initialization_frontiers, DENY

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_BYTES = 4 * 1024 * 1024
OBLIGATIONS = (
    ('environment_phi', 'Simultaneous ordered incoming operands refine the model environment.'),
    ('dynamic_owner', 'Static root denotes the same live dynamic allocation instance.'),
    ('allocation_extent', 'Normal allocation success binds requested N to actual owner length; failure does not.'),
    ('finite_integer', 'Unsigned Core values and unit steps refine bounded Nat without wrap.'),
    ('direct_body_seed', 'Successful checked seed store establishes 0<N; traps do not complete.'),
    ('store_write_frame', 'Successful store refines write at the same root/index/byte and frames other bytes.'),
    ('value_schedule', 'Stored value schedule and dependencies are independent of initial bytes where needed.'),
    ('normal_completion', 'Reached completion edge entails normal completed fill, not a trapped prefix.'),
    ('empty_extent', 'Empty completion uses the same allocation extent, including every phi edge.'),
    ('trace_edge_cut', 'Actual traces refine labelled CFG edges and per-load same-root cuts.'),
    ('post_completion_frame', 'Coverage persists through later effects without inheriting a dropped/reallocated root.'),
    ('observational_boundary', 'Output/resource/backend/quota equivalence requires separate proofs.'),
)


# Names identify existing model statements to connect to, not discharged proofs.
MODEL_SYMBOLS = {
    'environment_phi': ('Memory',),
    'dynamic_owner': ('Memory',),
    'allocation_extent': ('FullyInitialized',),
    'finite_integer': ('increment_within_limit',),
    'direct_body_seed': ('zero_prefix', 'write_extends_prefix'),
    'store_write_frame': ('write_at_index', 'write_at_other', 'write_extends_prefix'),
    'value_schedule': ('PrefixValues', 'completed_fill_independent_of_initial'),
    'normal_completion': ('completed_exit_is_exact_bound', 'completed_exit_establishes_initialized'),
    'empty_extent': ('zero_prefix', 'FullyInitialized'),
    'trace_edge_cut': ('completed_fill_initialized',),
    'post_completion_frame': ('write_at_other', 'FullyInitialized'),
    'observational_boundary': ('completed_fill_matches_zeroed',),
}


def encoded(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(data) > MAX_JSON_BYTES:
        raise ValueError('transport_size_limit')
    return data


def source_identity():
    paths = [Path(__file__), ROOT / 'tools/check_initialization_frontiers.py',
             ROOT / 'experiments/hia_initialization_frontiers_20261103/CORE_MODEL_CONNECTION.md',
             ROOT / 'formal/HiaInitializationPrefix.lean', ROOT / 'formal/toolchain-lock.json',
             ROOT / 'formal/proof-dependencies.txt', ROOT / 'tools/qualify_hia_initialization_prefix.py',
             ROOT / 'tools/qualify_hia_selected_formal.py', *sorted((ROOT / 'hepta').glob('*.py'))]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in paths}


def labelled(block):
    term = block['term']
    return ([('jump', term)] if term['op'] == 'jump' else
            [('then', term['then']), ('else', term['else'])] if term['op'] == 'branch' else [])


def function_ledger(function, structure):
    blocks = {b['id']: b for b in function['blocks']}
    edges, operations, definitions = [], [], []
    for block in function['blocks']:
        for slot, param in enumerate(block['params']):
            definitions.append({'value': param['name'], 'type': param['type'],
                                'block': block['id'], 'parameter_slot': slot})
        for ordinal, op in enumerate(block['ops']):
            locator = {'block': block['id'], 'ordinal': ordinal}
            operations.append({**locator, 'operation': deepcopy(op)})
            for slot, output in enumerate(op['out']):
                definitions.append({'value': output['name'], 'type': output['type'],
                                    **locator, 'output_slot': slot,
                                    'direct_dependencies': list(op['args'])})
        for arm, edge in labelled(block):
            edges.append({'source': block['id'], 'arm': arm, 'target': edge['target'],
                          'bindings': [{'slot': slot, 'parameter': deepcopy(param), 'operand': operand}
                                       for slot, (param, operand) in enumerate(zip(
                                           blocks[edge['target']]['params'], edge['args']))]})
    roots = sorted({c['allocation'] for c in structure['certificates']})
    reads = []
    for row in operations:
        if row['operation']['op'] != 'buffer.load':
            continue
        cuts_by_candidate_root = []
        for root in roots:
            cuts = sorted({tuple(c['completion_edge']) for c in structure['certificates']
                           if c['allocation'] == root})
            reached, pending = set(), [function['entry']]
            while pending:
                current = pending.pop()
                if current in reached:
                    continue
                reached.add(current)
                pending.extend(e['target'] for e in edges if e['source'] == current and
                               (current, e['arm'], e['target']) not in cuts)
            cuts_by_candidate_root.append({'candidate_allocation': root,
                'removed_edges': [list(c) for c in cuts],
                'reachable_blocks_without_edges': sorted(reached),
                'load_block_reachable': row['block'] in reached,
                'load_root_connection': 'unproved'})
        reads.append({**deepcopy(row), 'candidate_cuts': cuts_by_candidate_root})
    return {'function': function['name'], 'exact_function': deepcopy(function),
            'definitions': definitions, 'operations': operations, 'edges': edges,
            'allocations': [deepcopy(r) for r in operations if r['operation']['op'] in {'buffer.new', 'buffer.try_new'}],
            'loads': reads, 'structure_certificates': deepcopy(structure['certificates']),
            'obligations': [{'id': name, 'status': 'unproved', 'claim_required': claim,
                             'candidate_model_symbols': ['HiaInitializationPrefix.' + symbol
                                                         for symbol in MODEL_SYMBOLS[name]]}
                            for name, claim in OBLIGATIONS]}


def extract_obligations(program):
    report = {'schema': 'hepta.hia.initialization-obligation-ledger.v1', 'status': 'unknown',
              'actual_core_bridge_proved': False, 'model_replayed': False,
              'output_equivalence_proved': False, 'functions': [], **DENY}
    try:
        encoded(program)
        identity = source_identity()
        checked = verify_program(program)
        structure = check_initialization_frontiers(checked.as_dict())
        if structure['status'] != 'checked':
            report.update(status='rejected', reason='unsupported_or_uncovered_structure')
            return report
        report.update(core_sha256=checked.sha256, source_sha256=identity,
                      functions=[function_ledger(f, s) for f, s in zip(
                          checked.as_dict()['functions'], structure['functions'])])
        if source_identity() != identity:
            report.update(status='unknown', reason='sources_changed_during_extraction', functions=[])
        else:
            report.update(status='extracted', reason='transport_only_all_semantic_obligations_unproved')
        encoded(report)
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        report.update(status='rejected', reason='malformed_unsupported_or_oversized', functions=[])
    except Exception:
        report.update(status='unknown', reason='incomplete_extraction', functions=[])
    return report


def check_obligation_transport(program, proposed):
    """Reject stale/mutated data by full reconstruction, not producer hashes.

    This is NOT an independent Core checker or proof verifier: it deliberately
    reruns the extractor and research structure checker with the same sources.
    """
    result = {'status': 'rejected', 'reason': 'transport_mismatch',
              'actual_core_bridge_proved': False, **DENY}
    try:
        expected = extract_obligations(program)
        if expected['status'] == 'extracted' and encoded(proposed) == encoded(expected):
            result.update(status='matched', reason='exact_transport_only_semantic_obligations_unproved')
    except (ValueError, TypeError, RecursionError):
        pass
    return result
