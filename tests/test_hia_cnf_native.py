"""Check the HIA Boolean solver before and after cold native compilation."""

import random
import struct
import unittest
from unittest.mock import patch

from hepta.hia_cnf_native import (REPLY, REQUEST, SAT, SOURCE, SPARSE_REPLY, SPARSE_REQUEST,
                                  SPARSE_WORKSPACE, UNKNOWN, UNSAT, WORKSPACE,
                                  bitblast_clauses, selected_cnf)
from tests.test_hia_core_workspace_facts_native import vm_run
from tools.generate_hia_cnf import source_program


def packet(variables, clauses, steps):
    return (struct.pack('<4Q', REQUEST, variables, len(clauses), steps)
            + b''.join(struct.pack('<2Q', *clause) for clause in clauses))


def satisfied(model, clauses):
    return all(positive & model or negative & ~model for positive, negative in clauses)


class CnfSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_vm_observations(self):
        self.assertEqual(SOURCE.read_text(), source_program())
        top = 1 << 63
        for variables, clauses, steps, verdict, model, cost in (
            (0, [], 0, UNKNOWN, 0, 0), (0, [], 1, SAT, 0, 1),
            (0, [(0, 0)], 1, UNKNOWN, 0, 1), (0, [(0, 0)], 2, UNSAT, 0, 2),
            (64, [(top, 0)], 10, SAT, top, 4),
            (64, [(top, 0), (0, top)], 10, UNSAT, 0, 5),
        ):
            encoded = packet(variables, clauses, steps)
            self.assertEqual(vm_run(SOURCE, encoded, 32, WORKSPACE),
                             (32, struct.pack('<4Q', REPLY, verdict, model, cost)))
        malformed = (packet(65, [], 1), packet(63, [(top, 0)], 1), packet(0, [], 1) + b'x')
        for encoded in malformed:
            self.assertEqual(vm_run(SOURCE, encoded, 32, WORKSPACE), (0xfffffffd, b'\xa5' * 32))

    def test_sparse_vm_frame_preflights_all_literals(self):
        def sparse(variables, clauses, steps, entries):
            return (struct.pack('<5Q', SPARSE_REQUEST, variables, clauses, steps, len(entries))
                    + struct.pack(f'<{len(entries)}H', *entries))

        # The last variable is true, the first false. Both are included in
        # the witness; unset intervening variables are left false.
        encoded = sparse(65, 2, 30, (130, 0, 3, 0))
        size, result = vm_run(SOURCE, encoded, 41, SPARSE_WORKSPACE)
        self.assertEqual(size, 41)
        self.assertEqual(struct.unpack_from('<3Q', result), (SPARSE_REPLY, SAT, 65))
        self.assertEqual(result[32:], b'\0' * 8 + b'\x01')
        for bad in (encoded[:-1], sparse(65, 2, 20, (132, 0, 3, 0)),
                    sparse(65, 2, 20, (0,)), sparse(65, 2, 20, (130, 0, 0, 3)),
                    sparse(65, 2, 20, (1, 0, 3, 0))):
            self.assertEqual(vm_run(SOURCE, bad, 41, SPARSE_WORKSPACE), (0xfffffffd, b'\xa5' * 41))


class CnfInstalledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = selected_cnf()
        if cls.native is None:
            raise unittest.SkipTest('a source-bound HIA Boolean image is required')

    def test_differential_boolean_formulas_and_bounded_work(self):
        rng = random.Random(125113)
        counts = {SAT: 0, UNSAT: 0}
        for variables in range(8):
            for _ in range(120):
                clauses = []
                for _ in range(rng.randrange(16)):
                    members = rng.sample(range(variables), rng.randrange(min(variables, 3) + 1))
                    positive = sum(1 << item for item in members if rng.getrandbits(1))
                    negative = sum(1 << item for item in members) ^ positive
                    clauses.append((positive, negative))
                oracle = any(satisfied(model, clauses) for model in range(1 << variables))
                verdict, model, _ = self.native.solve(variables, clauses, steps=10000)
                self.assertEqual(verdict, SAT if oracle else UNSAT)
                sparse = [[2 * (index + 1) + sign
                           for sign, mask in enumerate((positive, negative))
                           for index in range(variables) if mask & (1 << index)]
                          for positive, negative in clauses]
                sparse_verdict, sparse_model, _ = self.native.solve_sparse(variables, sparse, steps=10000)
                self.assertEqual(sparse_verdict, verdict)
                counts[verdict] += 1
                if verdict == SAT:
                    self.assertTrue(satisfied(model, clauses))
                    self.assertTrue(satisfied(sparse_model, clauses))
        self.assertGreater(counts[SAT], 0)
        self.assertGreater(counts[UNSAT], 0)
        impossible = [(0, 0)]
        self.assertEqual(self.native.solve(0, impossible, steps=1), (UNKNOWN, 0, 1))
        self.assertEqual(self.native.solve(0, impossible, steps=2), (UNSAT, 0, 2))
        # Four occupants cannot fit in three slots; unit propagation alone
        # cannot decide this formula before choosing at least one branch.
        placements = [(7 << (3 * occupant), 0) for occupant in range(4)]
        for slot in range(3):
            placements.extend((0, (1 << (3 * first + slot)) | (1 << (3 * second + slot)))
                              for first in range(4) for second in range(first + 1, 4))
        self.assertEqual(self.native.solve(12, placements, steps=24)[0], UNKNOWN)
        self.assertEqual(self.native.solve(12, placements, steps=10000)[0], UNSAT)

    def test_sparse_decisions_past_64_variables_and_high_bit_witness(self):
        long_chain = [(2,)]
        long_chain.extend((2 * item + 1, 2 * (item + 1)) for item in range(1, 132))
        long_chain.append((8192,))
        verdict, model, cost = self.native.solve_sparse(4096, long_chain, steps=100000)
        self.assertEqual(verdict, SAT)
        self.assertEqual(model, (1 << 4095) | ((1 << 132) - 1))
        self.assertGreater(cost, 132)
        long_chain.append((265,))
        self.assertEqual(self.native.solve_sparse(4096, long_chain, steps=100000)[0], UNSAT)
        self.assertEqual(self.native.solve_sparse(4096, long_chain, steps=32), (UNKNOWN, 0, 32))

    def test_actual_optimizer_discharge_and_legacy_counterexample(self):
        try:
            import z3
        except ImportError:
            self.skipTest('the transitional bit-blast front end requires the pinned Z3 binding')
        from hepta.hia_optimization import fold_constants, verify_optimization
        from tests.test_hia_optimization import arithmetic, constant_program
        from tests.test_hia_program import b, c, f, i, m, ret

        flag_a, flag_b, flag_c, flag_d = z3.Bools('a b c d')
        formula = z3.And(flag_a, z3.Implies(flag_a, flag_b), z3.Implies(flag_b, flag_c),
                         z3.Implies(flag_c, flag_d), z3.Not(flag_d))
        variables, clauses = bitblast_clauses(z3, formula, timeout_ms=100)
        self.assertEqual((variables, len(clauses)), (4, 5))
        self.assertEqual(self.native.solve_sparse(variables, clauses, steps=100)[0], UNSAT)

        before = constant_program()
        after, _ = fold_constants(before)
        with patch.object(z3.Solver, 'check', side_effect=AssertionError('legacy solve invoked')):
            report = verify_optimization(before, after)
        self.assertEqual(report['status'], 'verified', report)
        discharge = report['obligations'][0]['discharge']
        self.assertEqual(discharge['image_sha256'], self.native.image_sha256)
        self.assertEqual(discharge['method'], 'native_hia_cnf')

        # Both U64 operands range over their complete declared domains.
        params = [('left', 'u64'), ('right', 'u64')]
        wide = m(f('check', params, ['bool'], [], [b('entry', params, [
            c('zero', 'u64', 0),
            i('compare.ne', ['left', 'right'], [('different', 'bool')]),
            i('bit.xor', ['left', 'right'], [('delta', 'u64')]),
            i('compare.eq', ['delta', 'zero'], [('equal', 'bool')]),
            i('bool.and', ['different', 'equal'], [('out', 'bool')]),
        ], ret('out'))]))
        constant = m(f('check', params, ['bool'], [], [b('entry', params, [
            c('out', 'bool', False),
        ], ret('out'))]))
        with patch.object(z3.Solver, 'check', side_effect=AssertionError('legacy solve invoked')):
            report = verify_optimization(wide, constant)
        self.assertEqual(report['status'], 'verified', report)
        self.assertGreater(report['obligations'][0]['discharge']['variables'], 128)

        old = verify_optimization(arithmetic(typ='u32'), arithmetic('int.add.wrap', 'u32'))
        self.assertEqual(old['status'], 'rejected', old)
        self.assertIn('counterexample', old['obligations'][-1])
