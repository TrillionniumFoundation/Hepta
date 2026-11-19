"""Check the HIA Boolean solver before and after cold native compilation."""

import builtins
from hashlib import sha256
from operator import ge, gt, le, lt
import random
import struct
import unittest
from unittest.mock import patch

from hepta.hia_cnf_native import (REPLY, REQUEST, SAT, SOURCE, SPARSE_REPLY, SPARSE_REQUEST,
                                  SPARSE_WORKSPACE, UNKNOWN, UNSAT, WORKSPACE,
                                  bitblast_clauses, bitvector_circuit, selected_cnf)
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
                batched_verdict, batched_model, _ = self.native.solve_sparse(variables, sparse, steps=10000,
                                                                             batch=True)
                self.assertEqual(batched_verdict, verdict)
                counts[verdict] += 1
                if verdict == SAT:
                    self.assertTrue(satisfied(model, clauses))
                    self.assertTrue(satisfied(sparse_model, clauses))
                    self.assertTrue(satisfied(batched_model, clauses))
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

    def test_native_projection_handles_unaligned_bits_and_projects_witness(self):
        import z3

        ctx = z3.Context()
        first = z3.BitVec('native_five_bits', 5, ctx=ctx)
        second = z3.BitVec('native_three_bits', 3, ctx=ctx)
        joined = z3.Concat(z3.Extract(4, 2, first), second)
        expressions = (
            (z3.LShR(joined << 2, 1), lambda a, b: (((a >> 2) * 8 + b) << 2 & 63) >> 1),
            (z3.SignExt(3, second), lambda a, b: b | 56 if b & 4 else b),
            (z3.ZeroExt(3, second), lambda a, b: b),
            (z3.LShR(joined, 63), lambda a, b: 0),
            (joined << 63, lambda a, b: 0),
            (joined * 63, lambda a, b: (-((a >> 2) * 8 + b)) & 63),
        )
        for a, b in ((0, 0), (7, 3), (8, 4), (21, 5), (31, 7)):
            for expr, independent in expressions:
                result = independent(a, b)
                premise = z3.And(first == a, second == b)
                for formula, expected in ((z3.And(premise, expr == result), SAT),
                                          (z3.And(premise, expr != result), UNSAT)):
                    circuit = bitvector_circuit(z3, formula)
                    self.assertIsNotNone(circuit)
                    verdict, assignment, *_ = self.native.solve_circuit(circuit.nodes, circuit.returns, steps=200000)
                    self.assertEqual(verdict, expected, (a, b, expr))
                    if verdict == SAT:
                        witness = circuit.witness(z3, assignment, formula)
                        self.assertIsNotNone(witness)
                        self.assertEqual((witness.eval(first).as_long(), witness.eval(second).as_long()), (a, b))

    def test_batch_propagates_long_units_without_weakening_the_work_budget(self):
        variables = 1024
        chain = [(2,)]
        chain.extend((2 * index + 1, 2 * (index + 1)) for index in range(1, variables))
        self.assertEqual(self.native.solve_sparse(variables, chain, steps=10_000)[0], UNKNOWN)
        verdict, model, cost = self.native.solve_sparse(variables, chain, steps=10_000, batch=True)
        self.assertEqual((verdict, model), (SAT, (1 << variables) - 1))
        self.assertLess(cost, 10_000)
        self.assertEqual(self.native.solve_sparse(variables, chain, steps=32, batch=True), (UNKNOWN, 0, 32))
        chain.append((2 * variables + 1,))
        verdict, model, cost = self.native.solve_sparse(variables, chain, steps=10_000, batch=True)
        self.assertEqual((verdict, model), (UNSAT, 0))
        self.assertLess(cost, 10_000)

    def test_watched_solver_handles_repeated_literals_and_undoes_only_the_dead_branch(self):
        rng = random.Random(3017)
        for variables in range(1, 7):
            literals = range(2, 2 * variables + 2)
            for index in range(240):
                clauses = [[rng.choice(literals) for _ in range(rng.randrange(1, 6))]
                           for _ in range(rng.randrange(1, 15))]
                if index % 11 == 0:
                    clauses.append([])
                if index % 13 == 0:
                    clauses.extend(([2, 3, 2, 2, 2], [3, 3, 2, 3, 3, 2, 2]))

                def satisfies(bits):
                    return all(any(bool(bits & 1 << ((token >> 1) - 1)) != bool(token & 1)
                                   for token in clause) for clause in clauses)

                verdict, model, _ = self.native.solve_sparse(variables, clauses, steps=100_000, watched=True)
                expected = SAT if any(satisfies(bits) for bits in range(1 << variables)) else UNSAT
                self.assertEqual(verdict, expected, (variables, clauses))
                if verdict == SAT:
                    self.assertTrue(satisfies(model))

    def test_watched_solver_finishes_long_chains_in_both_clause_orders(self):
        chain = [(2,), *((2 * index + 1, 2 * (index + 1)) for index in range(1, 4096)), (8193,)]
        for clauses in (chain, chain[::-1]):
            self.assertEqual(self.native.solve_sparse(4096, clauses, steps=24_573, watched=True),
                             (UNKNOWN, 0, 24_573))
            self.assertEqual(self.native.solve_sparse(4096, clauses, steps=50_000, watched=True),
                             (UNSAT, 0, 24_574))

    def test_native_circuit_matches_boolean_truth_tables(self):
        rng = random.Random(393072)
        for _ in range(200):
            nodes = [(1, 1, 0, 0, 0)] * 4
            for _ in range(12):
                op = rng.randrange(2, 9)
                left = rng.randrange(len(nodes)) if op != 2 else 0
                right = rng.randrange(len(nodes)) if op not in (2, 6) else 0
                nodes.append((op, 1, left, right, rng.randrange(2) if op == 2 else 0))
            left, right = rng.sample(range(len(nodes)), 2)

            def differ(assignment):
                known = [bool(assignment & (1 << index)) for index in range(4)]
                for op, _, one, two, value in nodes[4:]:
                    if op == 2:
                        known.append(bool(value))
                        continue
                    a, b = known[one], known[two]
                    known.append({3: a and b, 4: a or b, 5: a != b, 6: not a, 7: a == b, 8: a != b}[op])
                return known[left] != known[right]

            verdict, model, *_ = self.native.solve_circuit(nodes, [(left, right)], steps=10000)
            expected = any(differ(assignment) for assignment in range(16))
            self.assertEqual(verdict, SAT if expected else UNSAT)
            if expected:
                self.assertTrue(differ(model >> 1))  # Variable 1 is the circuit's true constant.

        with self.assertRaisesRegex(ValueError, 'circuit representation'):
            self.native.solve_circuit([(6, 1, 0, 0, 0)], [(0, 0)], steps=10)

    def test_native_wrapping_arithmetic_matches_independent_words(self):
        rng = random.Random(862910)
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            operands = [(0, 0), (0, 1), (mask, 1), (mask, mask),
                        (1, 1 << (width - 1)), (1 << (width - 1), 1 << (width - 1))]
            operands.extend((rng.getrandbits(width), rng.getrandbits(width)) for _ in range(48))
            for left, right in operands:
                for op, expected in ((9, (left + right) & mask), (10, (left - right) & mask)):
                    nodes = [(2, width, 0, 0, left), (2, width, 0, 0, right),
                             (op, width, 0, 1, 0), (2, width, 0, 0, expected),
                             (2, width, 0, 0, expected ^ 1)]
                    self.assertEqual(self.native.solve_circuit(nodes, [(2, 3)], steps=8)[0], UNSAT)
                    self.assertEqual(self.native.solve_circuit(nodes, [(2, 4)], steps=8)[0], SAT)
        for op in (9, 10):
            with self.assertRaisesRegex(ValueError, 'circuit representation'):
                self.native.solve_circuit([(1, 1, 0, 0, 0), (op, 1, 0, 0, 0)], [(1, 1)], steps=8)

    def test_order_cast_and_select_match_independent_words(self):
        rng = random.Random(224941)
        for width in (8, 16, 32, 64):
            mask = (1 << width) - 1
            signed_minimum = 1 << (width - 1)
            operands = [(0, 0), (0, mask), (mask, 0), (1, signed_minimum),
                        (signed_minimum, 1), (signed_minimum, mask), (mask, mask)]
            operands.extend((rng.getrandbits(width), rng.getrandbits(width)) for _ in range(32))
            for a, b in operands:
                signed_a = (a ^ signed_minimum) - signed_minimum
                signed_b = (b ^ signed_minimum) - signed_minimum
                for form, compare in enumerate((lt, le, gt, ge)):
                    for signed in (False, True):
                        left, right = (signed_a, signed_b) if signed else (a, b)
                        expected = int(compare(left, right))
                        values = [(2, width, 0, 0, a), (2, width, 0, 0, b),
                                  (12 + form + 4 * signed, 1, 0, 1, 0),
                                  (11, width, 2, 0, 1),
                                  (2, 1, 0, 0, expected),
                                  (2, width, 0, 0, a if expected else b)]
                        self.assertEqual(self.native.solve_circuit(values, [(2, 4), (3, 5)], steps=8)[0], UNSAT)
                for destination in (8, 16, 32, 64):
                    for signed in (False, True):
                        value = (signed_a if signed else a) % (1 << destination)
                        values = [(2, width, 0, 0, a), (20 + signed, destination, 0, 0, 0),
                                  (2, destination, 0, 0, value)]
                        self.assertEqual(self.native.solve_circuit(values, [(1, 2)], steps=8)[0], UNSAT)
        for malformed in ([(1, 8, 0, 0, 0), (11, 8, 0, 0, 0)],
                          [(1, 1, 0, 0, 0), (12, 1, 0, 0, 0)],
                          [(1, 8, 0, 0, 0), (20, 1, 0, 0, 0)]):
            with self.assertRaisesRegex(ValueError, 'circuit representation'):
                self.native.solve_circuit(malformed, [(1, 1)], steps=8)

    def test_guarded_add_and_subtract_observe_overflow_and_returns(self):
        rng = random.Random(987281)
        for width in (8, 16, 32, 64):
            high = 1 << (width - 1)
            mask = 2 * high - 1
            operands = [(0, 0), (0, 1), (mask, 1), (high - 1, 1),
                        (high, 1), (high, mask), (0, high), (1, 0)]
            operands.extend((rng.getrandbits(width), rng.getrandbits(width)) for _ in range(24))
            for a, b in operands:
                for signed in (False, True):
                    low, limit = (-high, high - 1) if signed else (0, mask)
                    left, right = ((a ^ high) - high, (b ^ high) - high) if signed else (a, b)
                    for subtract, mathematical in enumerate((left + right, left - right)):
                        overflow = int(not low <= mathematical <= limit)
                        nodes = [(2, width, 0, 0, a), (2, width, 0, 0, b),
                                 (9 + subtract, width, 0, 1, 0),
                                 (22 + 2 * signed + subtract, 1, 0, 1, 0),
                                 (2, 1, 0, 0, overflow), (2, 1, 0, 0, overflow ^ 1),
                                 (2, width, 0, 0, mathematical & mask),
                                 (2, width, 0, 0, (mathematical & mask) ^ 1)]
                        same = self.native.solve_circuit(nodes, [(2, 6)], traps=(3, 4), steps=8)
                        wrong_trap = self.native.solve_circuit(nodes, [(2, 6)], traps=(3, 5), steps=8)
                        different_word = self.native.solve_circuit(nodes, [(2, 7)], traps=(3, 4), steps=8)
                        self.assertEqual((same[0], wrong_trap[0], different_word[0]),
                                         (UNSAT, SAT, UNSAT if overflow else SAT))
        with self.assertRaisesRegex(ValueError, 'circuit representation'):
            self.native.solve_circuit([(1, 8, 0, 0, 0)], [(0, 0)], traps=(0, 0), steps=8)

    def test_actual_optimizer_discharge_and_legacy_counterexample(self):
        try:
            import z3
        except ImportError:
            self.skipTest('the transitional bit-blast front end requires the pinned Z3 binding')
        from hepta.hia_optimization import fold_constants, verify_optimization
        from tests.test_hia_optimization import arithmetic, constant_program

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

        old = verify_optimization(arithmetic(typ='u32'), arithmetic('int.add.wrap', 'u32'))
        self.assertEqual(old['status'], 'rejected', old)
        self.assertIn('counterexample', old['obligations'][-1])

    def test_wide_core_and_public_verification_do_not_import_z3(self):
        from copy import deepcopy
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_optimization import NATIVE_CORE_SCHEMA, verify_optimization
        from hepta.hia_proof_contract import proof_result
        from tests.test_hia_optimization import arithmetic
        from tests.test_hia_program import b, branch, c, f, i, jump, m, resource_program, ret
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program

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
        signed = [('left', 'i64'), ('enabled', 'bool')]
        only_negative_five = m(f('predicate', signed, ['bool'], [], [b('entry', signed, [
            c('target', 'i64', -5),
            i('compare.eq', ['left', 'target'], [('at_target', 'bool')]),
            i('bool.and', ['at_target', 'enabled'], [('out', 'bool')]),
        ], ret('out'))]))
        incorrect = m(f('predicate', signed, ['bool'], [], [b('entry', signed, [
            c('out', 'bool', False),
        ], ret('out'))]))
        incoming = [('remaining', 'u64'), ('value', 'u64')]
        loop = m(f('count', [('n', 'u64')], ['u64'], ['trap'], [
            b('entry', [('n', 'u64')], [c('zero', 'u64', 0)], jump('loop', 'n', 'zero')),
            b('loop', incoming, [c('stop', 'u64', 0),
                i('compare.ne', ['remaining', 'stop'], [('more', 'bool')])],
                branch('more', ('step', 'remaining', 'value'), ('done', 'value'))),
            b('step', [('prior_remaining', 'u64'), ('prior_value', 'u64')], [
                c('one', 'u64', 1), c('two', 'u64', 2),
                i('int.sub.checked', ['two', 'one'], [('step_size', 'u64')]),
                i('int.sub.checked', ['prior_remaining', 'step_size'], [('next_remaining', 'u64')]),
                i('int.add.checked', ['prior_value', 'step_size'], [('next_value', 'u64')])],
                jump('loop', 'next_remaining', 'next_value')),
            b('done', [('answer', 'u64')], [], ret('answer')),
        ]))
        simplified_loop = deepcopy(loop)
        simplified_loop['functions'][0]['blocks'][2]['ops'][2] = c('step_size', 'u64', 1)
        word_pair = [('x', 'u64'), ('y', 'u64')]
        kernel = f('kernel', word_pair, ['u64'], [], [b('entry', word_pair, [
            i('int.add.wrap', ['x', 'y'], [('answer', 'u64')]),
        ], ret('answer'))])
        caller = f('caller', word_pair, ['u64'], [], [b('entry', word_pair, [
            c('zero', 'u64', 0),
            i('int.add.wrap', ['x', 'zero'], [('carried', 'u64')]),
            i('int.add.wrap', ['y', 'zero'], [('argument', 'u64')]),
            i('call', ['x', 'argument'], [('returned', 'u64')], function='kernel'),
            i('int.add.wrap', ['carried', 'returned'], [('out', 'u64')]),
        ], ret('out'))])
        nested = {**m(kernel, caller), 'schema': NATIVE_CORE_SCHEMA}
        simplified_nested = deepcopy(nested)
        call_ops = simplified_nested['functions'][1]['blocks'][0]['ops']
        call_ops[1]['op'] = call_ops[2]['op'] = 'bit.or'
        original_import = builtins.__import__

        def without_z3(name, *args, **kwargs):
            if name == 'z3' or name.startswith('z3.'):
                raise AssertionError('the native circuit route imported Z3')
            return original_import(name, *args, **kwargs)

        workload = {"schema": "hepta.hia.agent.workload.v1", "warmup_iterations": 0,
                    "repetitions": 1, "cases": [
                        {"function": "check", "arguments": [1, 2],
                         "expected": {"status": "returned", "values": [False]}}]}
        with TemporaryDirectory(prefix='hia-circuit-agent-') as temporary:
            state = Path(temporary) / 'state'
            service = HIAAgentService(state)
            try:
                client = ToolClient(service.call)
                session = Session(client, prefix='hia-circuit-native')
                session.freeze(workload)
                base = session.import_program(wide)
                session.freeze(workload, baseline=base)
                candidate = session.import_program(constant)
                with patch('builtins.__import__', side_effect=without_z3), \
                        patch('hepta.hia_optimization.bitblast_clauses',
                              side_effect=AssertionError('foreign bit-blast invoked')):
                    report = verify_optimization(wide, constant)
                    result = session.verify(candidate, base=base, claims=['behavior_equivalence'])
                    actual = result['checks'][0]
                    evidence = session.read_json(actual['evidence_artifact'])
                    self.assertEqual(actual['status'], 'proved')
                    self.assertEqual(actual['checker']['solver'], report['solver'])
                    self.assertEqual(evidence['obligations'], report['obligations'])
                    self.assertIn('identified_hia_circuit_solver',
                                  {item['id'] for item in actual['assumptions']})
                    altered = deepcopy(evidence)
                    altered['obligations'][0]['cnf_frame_hex'] += '00'
                    with self.assertRaisesRegex(AgentRejected, 'native circuit proof formula identity differs'):
                        proof_result(claim=actual['claim'], status=actual['status'],
                                     domain=actual['domain'], subject=actual['subject'],
                                     profile=actual['profile'], installation=service.identities, evidence=altered)
                    request = next(item for item in client.records if item['tool'] == 'hia_verify')
                    service.close()
                    service = HIAAgentService(state)
                    client = ToolClient(service.call)
                    self.assertEqual(client.result('hia_verify', request['arguments']), result)
                    session = Session(client, prefix='hia-circuit-witness')
                    workload['cases'] = [
                        {'function': 'predicate', 'arguments': [0, True],
                         'expected': {'status': 'returned', 'values': [False]}}]
                    session.freeze(workload)
                    original = session.import_program(only_negative_five)
                    session.freeze(workload, baseline=original)
                    changed = session.import_program(incorrect)
                    refutation = session.verify(changed, base=original, claims=['behavior_equivalence'])
                    check = refutation['checks'][0]
                    self.assertEqual(check['status'], 'refuted')
                    self.assertEqual(check['checker']['solver'], report['solver'])
                    counterexample = session.read_json(check['evidence_artifact'])['obligations'][-1]
                    self.assertEqual(counterexample['result'], 'sat')
                    self.assertEqual(counterexample['counterexample'], {
                        'f0.b0.input:left': str((1 << 64) - 5), 'f0.b0.input:enabled': 'True'})
                    replay = counterexample['counterexample_replay']
                    self.assertEqual(replay['arguments'], [-5, True])
                    self.assertEqual(replay['base_values'], [True])
                    self.assertEqual(replay['candidate_values'], [False])
                    arithmetic_workload = {**workload, 'cases': [
                        {'function': 'transform', 'arguments': [(1 << 64) - 1],
                         'expected': {'status': 'returned', 'values': [6]}}]}
                    session.freeze(arithmetic_workload)
                    arithmetic_base = session.import_program(add_program(typ='u64', redundant_additions=3))
                    session.freeze(arithmetic_workload, baseline=arithmetic_base)
                    arithmetic_candidate = session.import_program(add_program(typ='u64', optimized=True))
                    arithmetic_proof = session.verify(arithmetic_candidate, base=arithmetic_base,
                                                      claims=['behavior_equivalence'])['checks'][0]
                    self.assertEqual(arithmetic_proof['status'], 'proved')
                    self.assertEqual(arithmetic_proof['checker']['solver']['name'], 'HIA')
                    signed_words = [('x', 'i64'), ('y', 'i64')]

                    def choose(reversed_order):
                        comparison, left, right = ('compare.ge', 'y', 'x') if reversed_order else ('compare.lt', 'x', 'y')
                        return m(f('minimum', signed_words, ['i64'], [], [b('entry', signed_words, [
                            i(comparison, ['x', 'y'], [('take_first', 'bool')]),
                            i('select', ['take_first', left, right], [('out', 'i64')]),
                        ], ret('out'))]))

                    ordered = verify_optimization(choose(False), choose(True))
                    self.assertEqual(ordered['status'], 'verified', ordered)
                    self.assertEqual(ordered['solver'], report['solver'])
                    checked = arithmetic('int.add.checked', 'u64')
                    wrapped = arithmetic('int.add.wrap', 'u64')
                    same_guarded = verify_optimization(checked, checked)
                    self.assertEqual(same_guarded['status'], 'verified')
                    self.assertEqual(same_guarded['solver'], report['solver'])
                    lost_overflow = verify_optimization(checked, wrapped)
                    self.assertEqual(lost_overflow['status'], 'rejected', lost_overflow)
                    guard_witness = lost_overflow['obligations'][-1]['counterexample_replay']
                    self.assertEqual(guard_witness['base_trap'], 'overflow')
                    self.assertIsNone(guard_witness['candidate_trap'])
                    self.assertIsNone(guard_witness['base_values'])
                    self.assertEqual(guard_witness['candidate_values'], [sum(guard_witness['arguments']) % (1 << 64)])
                    control_flow = verify_optimization(loop, simplified_loop)
                    self.assertEqual(control_flow['status'], 'verified', control_flow)
                    self.assertEqual(control_flow['solver'], report['solver'])
                    self.assertEqual(len(control_flow['obligations']), 4)
                    by_block = {row['block']: row['observed'] for row in control_flow['obligations']}
                    self.assertEqual(by_block['loop'], ['more', 'remaining', 'value', 'value'])
                    self.assertEqual(by_block['step'], ['next_remaining', 'next_value'])
                    loop['schema'] = simplified_loop['schema'] = NATIVE_CORE_SCHEMA
                    with patch('hepta.hia_optimization.selected_cnf', return_value=None):
                        self.assertEqual(verify_optimization(loop, simplified_loop)['status'], 'unknown')
                    loop_workload = {**workload, 'cases': [
                        {'function': 'count', 'arguments': [3],
                         'expected': {'status': 'returned', 'values': [3]}}]}
                    session.freeze(loop_workload)
                    loop_base = session.import_program(loop)
                    session.freeze(loop_workload, baseline=loop_base)
                    loop_candidate = session.import_program(simplified_loop)
                    loop_proof = session.verify(loop_candidate, base=loop_base,
                                                claims=['behavior_equivalence'])['checks'][0]
                    self.assertEqual(loop_proof['status'], 'proved')
                    self.assertEqual(loop_proof['checker']['solver'], report['solver'])
                    unsupported_v8 = deepcopy(loop)
                    unsupported_v8['functions'][0]['blocks'][2]['ops'][2]['op'] = 'int.mul.checked'
                    unsupported = verify_optimization(unsupported_v8, unsupported_v8)
                    self.assertEqual(unsupported['status'], 'unknown', unsupported)
                    self.assertNotIn('solver', unsupported)
                    calls = verify_optimization(nested, simplified_nested)
                    self.assertEqual(calls['status'], 'verified', calls)
                    self.assertEqual(calls['solver'], report['solver'])
                    call_obligations = [row for row in calls['obligations'] if row['function'] == 'caller']
                    self.assertEqual([row['observed'] for row in call_obligations],
                                     [['x', 'argument', 'carried'], ['out']])
                    changed_carry = deepcopy(simplified_nested)
                    changed_carry['functions'][1]['blocks'][0]['ops'][1]['args'][0] = 'y'
                    self.assertEqual(verify_optimization(nested, changed_carry)['status'], 'unknown')
                    owned = {**resource_program(), 'schema': NATIVE_CORE_SCHEMA}
                    folded = deepcopy(owned)
                    operations = owned['functions'][0]['blocks'][0]['ops']
                    operations[2:3] = [
                        c('one', 'usize', 1),
                        i('int.sub.wrap', ['one', 'one'], [('zero', 'usize')]),
                    ]
                    owned_workload = {**workload, 'cases': [
                        {'function': 'owned', 'arguments': [4, 21],
                         'expected': {'status': 'returned', 'values': [21]}}]}
                    session.freeze(owned_workload)
                    original = session.import_program(owned)
                    session.freeze(owned_workload, baseline=original)
                    proposed = session.import_program(folded)
                    resource_proof = session.verify(proposed, base=original,
                                                    claims=['behavior_equivalence'])['checks'][0]
                    self.assertEqual(resource_proof['status'], 'proved', resource_proof)
                    self.assertEqual(resource_proof['checker']['solver'], report['solver'])
                    resource_evidence = session.read_json(resource_proof['evidence_artifact'])
                    self.assertTrue(resource_evidence['resource_delta'][
                        'allocation_failure_sequence_preserved_under_core_model'])
                    self.assertEqual(len(resource_evidence['obligations']), 10)
                    self.assertIn('zero', resource_evidence['obligations'][2]['observed'])
                    changed_index = deepcopy(folded)
                    changed_index['functions'][0]['blocks'][0]['ops'][2]['attrs']['value'] = 1
                    denied_proof = verify_optimization(owned, changed_index)
                    self.assertEqual(denied_proof['status'], 'unknown', denied_proof)
            finally:
                service.close()
        self.assertEqual(report['status'], 'verified', report)
        self.assertEqual(report['solver']['name'], 'HIA')
        obligation = report['obligations'][0]
        discharge = obligation['discharge']
        self.assertEqual(discharge['method'], 'native_hia_core_circuit')
        self.assertGreater(discharge['variables'], 128)
        self.assertNotIn('smt2', obligation)
        frame = bytes.fromhex(obligation['cnf_frame_hex'])
        self.assertEqual(discharge['formula_sha256'], sha256(frame).hexdigest())
        self.assertEqual(frame[24:32], bytes(8))

    def test_checked_negation_precedes_a_matching_explicit_trap(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_optimization import NATIVE_CORE_SCHEMA, verify_optimization
        from tests.test_hia_program import b, c, f, i, m
        from tools.hia_agent_native_qualification import Session, ToolClient

        def program(kind, code, operations):
            parameters = [('x', kind)]
            document = m(f('stop', parameters, [], ['trap'], [
                b('entry', parameters, operations, {'op': 'trap', 'code': code}),
            ]))
            document['schema'] = NATIVE_CORE_SCHEMA
            return document

        importer = builtins.__import__

        def no_z3(name, *args, **kwargs):
            if name == 'z3' or name.startswith('z3.'):
                raise AssertionError('foreign solver imported')
            return importer(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=no_z3):
            for kind in ('i64', 'u64'):
                with self.subTest(kind=kind):
                    with_negation = program(kind, 'user', [
                        i('int.neg.checked', ['x'], [('discarded', kind)]),
                    ])
                    with_subtraction = program(kind, 'user', [
                        c('zero', kind, 0),
                        i('int.sub.checked', ['zero', 'x'], [('discarded', kind)]),
                    ])
                    proved = verify_optimization(with_negation, with_subtraction)
                    self.assertEqual(proved['status'], 'verified', proved)
                    self.assertEqual(proved['solver']['name'], 'HIA')

                    explicit_only = program(kind, 'user', [])
                    rejected = verify_optimization(with_negation, explicit_only)
                    self.assertEqual(rejected['status'], 'rejected', rejected)
                    witness = rejected['obligations'][-1]['counterexample_replay']
                    self.assertEqual((witness['base_trap'], witness['candidate_trap']), ('overflow', 'user'))
                    value, = witness['arguments']
                    if kind == 'i64':
                        self.assertEqual(value, -(1 << 63))
                    else:
                        self.assertGreater(value, 0)

            with TemporaryDirectory(prefix='hia-terminal-trap-agent-') as temporary:
                service = HIAAgentService(Path(temporary) / 'state')
                try:
                    session = Session(ToolClient(service.call), prefix='hia-trap-witness')
                    workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [
                        {'function': 'stop', 'arguments': [0],
                         'expected': {'status': 'trapped'}}],
                        'warmup_iterations': 0, 'repetitions': 1}
                    session.freeze(workload)
                    original = session.import_program(program('i64', 'user', [
                        i('int.neg.checked', ['x'], [('discarded', 'i64')]),
                    ]))
                    session.freeze(workload, baseline=original)
                    proposed = session.import_program(program('i64', 'user', []))
                    check = session.verify(proposed, base=original,
                                           claims=['behavior_equivalence'])['checks'][0]
                    self.assertEqual(check['status'], 'refuted', check)
                    evidence = session.read_json(check['evidence_artifact'])
                    witness = evidence['obligations'][-1]['counterexample_replay']
                    self.assertEqual((witness['base_trap'], witness['candidate_trap']), ('overflow', 'user'))
                finally:
                    service.close()
