"""Check the original Journal transitions for a rejected, unkeyed Evaluate call."""
import ast
from pathlib import Path
import struct
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_flow import policy_constants
from tools.generate_hia_worker_evaluate_intake_flow import program as intake_program
from tools.generate_hia_worker_evaluate_run_input_flow import SOURCE as RUN_INPUT_SOURCE
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

    def test_only_failed_unkeyed_or_observed_journal_routes_can_reach_cost(self):
        cases = [
            ((9, 0, 0, 0), True), ((0, 11, 0, 0), True),
            ((14, 17, 0, 192), True), ((8, 18, 2, 0), True),
            ((0, 1, 0, 0), True), ((1, 14, 0, 0), True),
            ((1, 3, 0, 0), False), ((1, 2, 0, 0), False),
            ((3, 19, 0, 0), False), ((14, 17, 0, 193), False),
            ((8, 20, 2, 0), False), ((8, 18, 1, 0), False),
        ]
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                observed = execute_program(self.verified, self.edge, list(arguments))
                self.assertEqual(observed['status'], 'returned')
                self.assertEqual(observed['values'], [expected])


class ObservedEvaluateHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checked = assemble_program((ROOT / RUN_INPUT_SOURCE).read_bytes())
        functions = {fn['name']: fn for fn in cls.checked.as_dict()['functions']}
        nodes = ast.parse(intake_program(claim=True, run_input=True)).body
        cls.functions = {node.name: functions[f'f{i}'] for i, node in enumerate(nodes)}

    def test_only_frozen_running_and_completed_rows_can_reach_single_fd_publication(self):
        constants = policy_constants()
        entered, raw_size, frozen_fd = 613, 701, 41
        for observed in (0, 94, 95, 96, 97, 98):
            with self.subTest(observed=observed):
                vm = _Machine(self.checked, 1_000_000, 16 << 20, None, 128)
                private = _Owner(-3, bytearray(4096))
                work = _View(private, True)
                output = _Owner(-2, bytearray(2048))
                for offset, value in ((64, entered), (constants['LOOKUP_AT'], 40),
                                      (constants['LOOKUP_BYTES'], observed)):
                    struct.pack_into('<Q', private.data, offset, value)
                vm.invoke(self.functions['keep'], [work, constants['ORIGINAL'], 0, raw_size])
                vm.invoke(self.functions['keep'], [work, constants['LOOKUP_FD'], frozen_fd, 2000])
                count, = vm.invoke(self.functions['publish_observed_rejection'], [_View(output, True), work])
                if observed not in (95, 97):
                    self.assertEqual(count, constants['BAD'])
                    continue
                self.assertEqual(count, 536)
                self.assertEqual(struct.unpack_from('<Q', output.data, 16)[0], 11)
                self.assertEqual(struct.unpack_from('<2Q', output.data, 40), (2, 24))
                self.assertEqual(struct.unpack_from('<6Q', output.data, 64), (0, 0, raw_size, frozen_fd, 40, observed))
                self.assertEqual(struct.unpack_from('<8s2Q', output.data, 512), (b'HIAEKL01', entered, raw_size))
