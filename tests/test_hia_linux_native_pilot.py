"""Reject the concrete native-pilot false-positive observations found in review."""
import copy
import itertools
import json
import unittest

from tools import qualify_hia_linux_native_pilot as pilot


class NativePilotEvidence(unittest.TestCase):
    def test_changed_sum_counts_types_or_fields_are_not_performance_evidence(self):
        expected = {'arm': 1, 'cases': 2, 'cycles': 3, 'calls': 6,
                    'input_digest': 'abc', 'sum': 9, 'failures': 0,
                    'abi_checks': 64, 'status': 'PASS', 'cpu': 0}
        good = {**expected, 'comparisons': 8, 'has_popcnt': True, 'wall_ns': 100, 'cpu_ns': 90}
        pilot.validate_observation(good, expected, 2)
        mutations = [{'sum': 10}, {'failures': False}, {'arm': True}, {'cpu': False},
                     {'has_popcnt': 1}, {'comparisons': True}, {'wall_ns': True},
                     {'cpu_ns': 0}, {'extra': 1}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                pilot.validate_observation({**good, **mutation}, expected, 2)
        missing = copy.deepcopy(good)
        del missing['sum']
        with self.assertRaises(ValueError):
            pilot.validate_observation(missing, expected, 2)

    def test_failed_process_lifecycle_cannot_become_a_success_or_hardware_skip(self):
        normal = {'timed_out': False}
        self.assertTrue(pilot.clean_command(normal))
        for mutation in ({'timed_out': True}, {'timed_out': 0},
                         {'interruption': {'type': 'KeyboardInterrupt'}},
                         {'incomplete_process_group': True}, {'incomplete_process_group': 0},
                         {'process_group_cleanup': {'drained': False}},
                         {'process_group_cleanup': {'drained': 1}}):
            with self.subTest(mutation=mutation):
                self.assertFalse(pilot.clean_command({**normal, **mutation}))

    def test_registration_retains_all_four_arms_in_every_order_position(self):
        plan = json.loads(pilot.PLAN.read_bytes())
        self.assertEqual(plan['arms'], ['linux-software-asm', 'hia-preserving-bridge',
                                       'hia-raw-c-abi', 'hardware-popcnt-call'])
        orders = list(itertools.permutations(range(4)))
        self.assertEqual(len(orders), plan['blocks'])
        for arm in range(4):
            for position in range(4):
                self.assertEqual(sum(order[position] == arm for order in orders), 6)
        self.assertEqual(plan['ndu_calls'], 0)
        self.assertFalse(plan['production_activation'])


if __name__ == '__main__':
    unittest.main()
