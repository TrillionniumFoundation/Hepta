"""Production CFG renaming, bounded model correspondence and hostile maps."""
from __future__ import annotations

from itertools import permutations
import unittest
from unittest.mock import patch

from hepta.hia_capability_flow import Capability as C, CapabilityFlowRejected, rename_capabilities
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import joined_loan_program


class CapabilityFlowTests(unittest.TestCase):
    def test_actual_cfg_uses_the_independently_specified_boundary(self):
        with patch('hepta.hia_program.rename_capabilities', wraps=rename_capabilities) as boundary:
            module = verify_program(joined_loan_program())
            self.assertGreaterEqual(boundary.call_count, 2)
        for cond in (False, True):
            result = execute_program(module, 'join', [cond])
            self.assertEqual(result['result'], 0)
            self.assertEqual(result['resources']['live_owners'], 0)
            self.assertEqual(result['resources']['live_local_loans'], 0)

    def test_root_parent_suspension_type_and_parameter_origin_survive(self):
        # Nested reborrow is a graph, not a mere aggregate resource count.
        caps = {'owner': C('buffer', 'owner'),
                'mut': C('mutbuf', 'owner', 'owner', False, 'formal_arg'),
                'read': C('readbuf', 'owner', 'mut', False, 'formal_arg')}
        for targets in permutations(('owner', 'mut', 'read')):
            mapping = dict(zip(caps, targets))
            result = rename_capabilities(caps, mapping)
            self.assertEqual(len(result), len(caps))
            for name, cap in caps.items():
                changed = result[mapping[name]]
                self.assertEqual((changed.typ, changed.external, changed.origin),
                                 (cap.typ, cap.external, cap.origin))
                for other, other_cap in caps.items():
                    self.assertEqual(cap.root == other_cap.root,
                                     changed.root == result[mapping[other]].root)
                    self.assertEqual(cap.parent == other,
                                     changed.parent == mapping[other])

    def test_two_successive_edges_equal_the_composed_renaming(self):
        caps = {'a': C('buffer', 'a'), 'b': C('buffer', 'b'),
                'loan': C('readbuf', 'b', 'b', False, 'argument')}
        first = {'a': 'middle_b', 'b': 'middle_a', 'loan': 'middle_l'}
        second = {'middle_a': 'last', 'middle_b': 'first', 'middle_l': 'view'}
        self.assertEqual(rename_capabilities(rename_capabilities(caps, first), second),
                         rename_capabilities(caps, {k: second[v] for k, v in first.items()}))

    def test_local_capability_loss_and_noninjective_names_are_rejected(self):
        caps = {'a': C('buffer', 'a'), 'b': C('buffer', 'b')}
        for mapping in ({'a': 'new'}, {'a': 'new', 'b': 'new'},
                        {'a': 'a', 'b': 'b', 'ghost': 'c'}):
            with self.subTest(mapping=mapping), self.assertRaises(CapabilityFlowRejected):
                rename_capabilities(caps, mapping)

    def test_selected_loan_requires_both_parent_and_root(self):
        caps = {'root': C('readbuf', 'root', external=True),
                'parent': C('readbuf', 'root', 'root', external=True),
                'leaf': C('readbuf', 'root', 'parent')}
        for mapping in ({'leaf': 'l'}, {'root': 'r', 'leaf': 'l'}):
            with self.subTest(mapping=mapping), self.assertRaises(CapabilityFlowRejected) as caught:
                rename_capabilities(caps, mapping)
            self.assertEqual(caught.exception.code, 'E_HIA_LOAN')

    def test_unselected_external_parameter_can_be_forgotten_without_renaming_origin(self):
        caps = {'one': C('readbuf', 'one', external=True, origin='one'),
                'two': C('readbuf', 'two', external=True, origin='two')}
        self.assertEqual(rename_capabilities(caps, {'one': 'two'}),
                         {'two': C('readbuf', 'two', external=True, origin='one')})
        self.assertEqual(rename_capabilities(caps, {}), {})

    def test_noninternal_input_types_are_rejected_before_hash_or_iteration(self):
        class Hostile(dict):
            def items(self):
                raise AssertionError('untrusted iteration')
        for caps, mapping in ((Hostile(), {}), ({}, Hostile()), ({'x': object()}, {})):
            with self.assertRaises(CapabilityFlowRejected):
                rename_capabilities(caps, mapping)


if __name__ == '__main__':
    unittest.main()
