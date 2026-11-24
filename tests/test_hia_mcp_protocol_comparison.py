"""Guard independent protocol admission against hiding changed responses."""
import copy
import json
from pathlib import Path
import unittest
from tools.qualify_hia_mcp_service_protocol import compare_case

class ProtocolComparisonGuardTests(unittest.TestCase):
    def setUp(self):
        self.profiles = json.loads((Path(__file__).parent / 'fixtures/hia_mcp_sdk_wire_profiles.json').read_text())
        self.left = {'returncode': 0, 'messages': [
            {'jsonrpc': '2.0', 'id': 'init', 'result': self.profiles['reference_initialization_profile']},
            {'jsonrpc': '2.0', 'id': 1, 'result': {}},
            {'jsonrpc': '2.0', 'id': 2, 'error': {'code': -32602, 'message': 'invalid'}}]}
        self.right = copy.deepcopy(self.left)
        self.right['messages'][0]['result'] = copy.deepcopy(self.profiles['native_initialization_profile'])

    def test_order_is_relaxed_only_for_explicit_pipelined_cases(self):
        self.right['messages'][1:] = self.right['messages'][1:][::-1]
        self.assertTrue(compare_case('stream/two-independent-requests', self.left, self.right, self.profiles))
        self.assertFalse(compare_case('ordinary/two-requests', self.left, self.right, self.profiles))

    def test_changed_ids_values_errors_and_multiplicity_are_rejected(self):
        mutations = [lambda v: v['messages'][1].update(id=3),
                     lambda v: v['messages'][1].update(result={'changed': True}),
                     lambda v: v['messages'][2]['error'].update(message='different'),
                     lambda v: v['messages'].append(copy.deepcopy(v['messages'][1])),
                     lambda v: v['messages'].pop(),
                     lambda v: v.update(returncode=1)]
        for mutation in mutations:
            changed = copy.deepcopy(self.right)
            mutation(changed)
            self.assertFalse(compare_case('stream/guard', self.left, changed, self.profiles))

    def test_initialization_must_be_first_and_exactly_profiled(self):
        reordered = copy.deepcopy(self.right)
        reordered['messages'][0], reordered['messages'][1] = reordered['messages'][1], reordered['messages'][0]
        self.assertFalse(compare_case('stream/guard', self.left, reordered, self.profiles))
        changed = copy.deepcopy(self.right)
        changed['messages'][0]['result']['capabilities']['unknown'] = {}
        self.assertFalse(compare_case('stream/guard', self.left, changed, self.profiles))

    def test_discovery_requires_both_complete_frozen_profiles(self):
        left = {'returncode': 0, 'messages': [{'jsonrpc': '2.0', 'id': 7, 'result': self.profiles['reference_discovery_profile']}]}
        right = {'returncode': 0, 'messages': [{'jsonrpc': '2.0', 'id': 7, 'result': copy.deepcopy(self.profiles['native_discovery_profile'])}]}
        self.assertTrue(compare_case('control/discover', left, right, self.profiles))
        right['messages'][0]['result']['cacheScope'] = 'public'
        self.assertFalse(compare_case('control/discover', left, right, self.profiles))
