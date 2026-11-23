"""Check the original Journal transitions for a rejected, unkeyed Evaluate call."""
import ast
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import execute_program, verify_program
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_evaluate_unkeyed_flow import SOURCE, program

ROOT = Path(__file__).resolve().parents[1]


class UnkeyedEvaluateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = program()
        nodes = ast.parse(source).body
        cls.edge = 'f' + str(next(i for i, node in enumerate(nodes) if node.name == 'artifact_edge'))
        cls.policy = document(source, SOURCE.stem)
        cls.verified = verify_program(cls.policy)

    def test_checked_in_assembly_matches_the_role_and_journal_policy(self):
        self.assertEqual((ROOT / SOURCE).read_text(), render_assembly(self.policy))

    def test_only_unkeyed_rejection_can_reach_the_cost_write(self):
        cases = [
            ((9, 0, 0, 0), True), ((0, 11, 0, 0), True),
            ((14, 17, 0, 192), True), ((8, 18, 2, 0), True),
            ((0, 1, 0, 0), False), ((1, 2, 0, 0), False),
            ((3, 19, 0, 0), False), ((14, 17, 0, 193), False),
            ((8, 20, 2, 0), False), ((8, 18, 1, 0), False),
        ]
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                observed = execute_program(self.verified, self.edge, list(arguments))
                self.assertEqual(observed['status'], 'returned')
                self.assertEqual(observed['values'], [expected])
