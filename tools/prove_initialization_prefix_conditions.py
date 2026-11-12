"""Conditional scalar lemmas only; not a proof of the Core-to-invariant bridge."""
from hashlib import sha256
from pathlib import Path

DENY = {'authority': 'DENY_ALL', 'initialization_elision_authorized': False,
        'production_admission': False, 'native_admission': False,
        'performance_qualified': False, 'quota_equivalence': False,
        'actual_core_bridge_proved': False, 'backend_refinement_proved': False}


def prove_prefix_conditions():
    report = {'schema': 'hepta.hia.initialization-prefix-conditions.v1', 'status': 'unknown',
              'obligations': [], 'scope': 'manual abstract premises, not extracted actual Core facts', **DENY}
    try:
        import z3
        report['solver_version'] = z3.get_version_string()
        if report['solver_version'] != '4.15.4':
            report['reason'] = 'pinned_solver_unavailable'
            return report
        source = Path(__file__).read_bytes()
        report['source_sha256'] = sha256(source).hexdigest()
        n, i, j = z3.Ints('n i j')
        written = z3.Array('written', z3.IntSort(), z3.BoolSort())
        def prefix(array, extent):
            return z3.ForAll([j], z3.Implies(z3.And(0 <= j, j < extent), z3.Select(array, j)))
        after = z3.Store(written, i, True)
        maximum = 2**64 - 1
        bi, bn = z3.BitVecs('i64 n64', 64)
        cases = [
            ('empty_prefix', 'unsat', [z3.Not(prefix(written, 0))]),
            ('successful_store_extends_prefix', 'unsat',
             [0 <= i, i < n, n <= maximum, prefix(written, i), z3.Not(prefix(after, i + 1))]),
            ('unit_step_does_not_wrap_under_unsigned_bound', 'unsat',
             [z3.ULT(bi, bn), z3.Not(z3.UGT(bi + 1, bi))]),
            ('direct_zero_body_normal_store', 'unsat',
             [i == 0, 0 < n, n <= maximum,
              z3.Or(i + 1 > n, z3.Not(prefix(after, i + 1)))]),
            ('normal_completion_covers_extent', 'unsat',
             [0 <= i, i <= n, z3.Not(i < n), prefix(written, i), z3.Not(prefix(written, n))]),
            ('unsigned_zero_false_edge_means_empty', 'unsat',
             [z3.Not(z3.ULT(z3.BitVecVal(0, 64), bn)), bn != 0]),
            ('stride_two_leaves_a_hole', 'sat',
             [i == 0, n == 2, written == z3.K(z3.IntSort(), False),
              z3.Not(z3.Select(after, 1))]),
            ('nonzero_seed_leaves_index_zero', 'sat',
             [i == 1, n == 2, written == z3.K(z3.IntSort(), False),
              z3.Not(z3.Select(after, 0))]),
            ('short_extent_does_not_cover_requested_extent', 'sat',
             [n == 4, prefix(written, 3), z3.Not(z3.Select(written, 3))]),
            ('another_root_does_not_inherit_stores', 'sat',
             [prefix(written, 4), z3.Not(z3.Select(z3.Array('other_root', z3.IntSort(), z3.BoolSort()), 0))]),
        ]
        for name, expected, assumptions in cases:
            solver = z3.Solver()
            solver.set(timeout=1000)
            solver.add(*assumptions)
            status = str(solver.check())
            row = {'name': name, 'expected': expected, 'status': status,
                   'timeout_ms': 1000, 'smt2': solver.to_smt2()}
            if status == 'sat':
                row['model'] = str(solver.model())
            elif status == 'unknown':
                row['reason_unknown'] = solver.reason_unknown()
            report['obligations'].append(row)
        if sha256(Path(__file__).read_bytes()).hexdigest() != report['source_sha256']:
            report['reason'] = 'source_changed'
        elif all(row['status'] == row['expected'] for row in report['obligations']):
            report.update(status='checked', reason='conditional_scalar_obligations_only')
        else:
            report['reason'] = 'an_obligation_did_not_match'
    except Exception as error:
        report.update(reason='solver_or_source_unavailable', error_type=type(error).__name__)
    return report
