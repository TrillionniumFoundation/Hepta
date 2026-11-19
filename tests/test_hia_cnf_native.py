"""Check the HIA Boolean solver before and after cold native compilation."""

import random
import struct
import unittest
from unittest.mock import patch

from hepta.hia_cnf_native import (REPLY, REQUEST, SAT, SOURCE, UNKNOWN, UNSAT,
                                  WORKSPACE, bitblast_clauses, selected_cnf)
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
                counts[verdict] += 1
                if verdict == SAT:
                    self.assertTrue(satisfied(model, clauses))
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

    def test_actual_optimizer_discharge_and_legacy_counterexample(self):
        try:
            import z3
        except ImportError:
            self.skipTest('the transitional bit-blast front end requires the pinned Z3 binding')
        from hepta.hia_optimization import fold_constants, verify_optimization
        from tests.test_hia_optimization import arithmetic, constant_program

        a, b, c, d = z3.Bools('a b c d')
        formula = z3.And(a, z3.Implies(a, b), z3.Implies(b, c), z3.Implies(c, d), z3.Not(d))
        variables, clauses = bitblast_clauses(z3, formula, timeout_ms=100)
        self.assertEqual((variables, len(clauses)), (4, 5))
        self.assertEqual(self.native.solve(variables, clauses, steps=100)[0], UNSAT)

        before = constant_program()
        after, _ = fold_constants(before)
        with patch.object(z3.Solver, 'check', side_effect=AssertionError('legacy solve invoked')):
            report = verify_optimization(before, after)
        self.assertEqual(report['status'], 'verified', report)
        discharge = report['obligations'][0]['discharge']
        self.assertEqual(discharge['image_sha256'], self.native.image_sha256)
        self.assertEqual(discharge['method'], 'native_hia_cnf')
        old = verify_optimization(arithmetic(typ='u32'), arithmetic('int.add.wrap', 'u32'))
        self.assertEqual(old['status'], 'rejected', old)
        self.assertIn('counterexample', old['obligations'][-1])
