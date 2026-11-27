"""Supplemental controls for the explicit Bootstrap word profile.

The original Source3, fixed helper tests, packet controls and budgets are intact.
These tests grant no complete finite or native-stack qualification.
"""
from __future__ import annotations
import ast
import copy
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ServiceBootstrapWordSourceTests(unittest.TestCase):
    def test_exact_reference_generation_complete_fallbacks_and_original_profile_limits(self):
        from tools import generate_hia_service_bootstrap as original
        from tools import generate_hia_service_bootstrap_word as word
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        source, proof = word.transformed_source()
        raw = (ROOT / word.SOURCE_NAME).read_bytes()
        self.assertEqual(raw, render_assembly(word.document()).encode())
        self.assertEqual(sha256((ROOT / word.REFERENCE_AUTHOR).read_bytes()).hexdigest(),
                         word.REFERENCE_AUTHOR_SHA256)
        self.assertEqual(sha256((ROOT / word.REFERENCE_SOURCE).read_bytes()).hexdigest(),
                         word.REFERENCE_SOURCE_SHA256)
        self.assertTrue(proof['original_first_length_refusal_preserved'])
        self.assertEqual(proof['unrolled_exact_loops'],
                         {'request_reserved': 8, 'initial_zero_words': 24,
                          'state_reserved': 11, 'checksum_nonself_words': 23})
        self.assertEqual(len(proof['complete_range_sites']), 167)
        before = {node.name: node for node in ast.parse(original.source_program()).body}
        after = {node.name: node for node in ast.parse(source).body}
        for name in word.HELPERS:
            length = len(before[name].body)
            self.assertEqual([ast.dump(node, include_attributes=False) for node in after[name].body[-length:]],
                             [ast.dump(node, include_attributes=False) for node in before[name].body])
        program = assemble_program(raw).as_dict()
        self.assertEqual(program['schema'], 'hepta.hia.program.v9')
        self.assertLessEqual(len(raw), 1 << 20)
        self.assertLessEqual(len(raw.splitlines()), 16384)
        self.assertLessEqual(len(program['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in program['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in program['functions'] for b in f['blocks']), 8192)
        for function in program['functions']:
            self.assertLessEqual(len(function['blocks']), 256)
            names = {p['name'] for p in function['params']}
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']), 16)
                names.update(p['name'] for p in block['params'])
                names.update(value['name'] for op in block['ops'] for value in op['out'])
            self.assertLessEqual(len(names), 2048)

    def test_complete_original_270_partial_trap_and_wrapped_index_VM_outcomes(self):
        from tools.qualify_hia_service_bootstrap_word import helper_comparisons
        rows = helper_comparisons()
        self.assertEqual(len(rows), 270)
        self.assertTrue(any(row['VM']['reference']['outcome']['kind'] == 'trap' for row in rows))
        self.assertTrue(any(row['VM']['reference']['outcome']['kind'] == 'trap'
                            and row['VM']['reference']['complete_buffer'] != row['before'] for row in rows))
        self.assertTrue(any(row['index'] == (1 << 64) - 1 for row in rows))

    def test_all_original_22_packets_and_complete_shared_backing_aliases_in_three_VM_profiles(self):
        from tools.qualify_hia_service_bootstrap_word import (
            controller_sources, packet_comparisons, alias_comparisons)
        sources = controller_sources()
        report = packet_comparisons(sources)
        self.assertEqual(report['packets_per_engine'], 22)
        self.assertEqual(report['supplied_engines'], ['original_loop_VM', 'retained_fixed_VM', 'word_VM'])
        self.assertFalse(report['actual_native_executed'])
        self.assertTrue(report['full_buffers_and_original_canaries_equal'])
        for index in (0, 19, 20):
            self.assertLess(report['VM_steps']['word_VM'][index],
                            report['VM_steps']['retained_fixed_VM'][index])
        self.assertEqual(len(alias_comparisons(sources)), 10)

    def test_declared_source_suite_preserves_original_six_and_both_reviewed_additions(self):
        from unittest.mock import patch
        from tests import hia_service_bootstrap_suite as suite
        from tools import read_hia_service_bootstrap as reader
        captured = []
        actual = suite.declared_ids('source')
        self.assertEqual(actual, reader.method_ids('source', captured))
        self.assertEqual(len(suite.ORIGINAL_SOURCE_METHOD_IDS), 6)
        self.assertEqual(len(suite.SUPPLEMENTAL_SOURCE_METHOD_IDS), 2)
        self.assertEqual(len(actual), 8)
        for changed in (actual[:-1], actual + ['unreviewed.addition'],
                        ['unreviewed.same-length-replacement', *actual[1:]]):
            with self.subTest(ids=changed), patch.object(suite, 'static_ids', return_value=changed):
                with self.assertRaises(ValueError):
                    suite.declared_ids('source')
        reader.unchanged(captured)

    def test_complete_source_relation_and_current_control_domain_refuse_changed_inputs(self):
        from tools import hia_bootstrap_source_history as history
        from tools.read_hia_service_bootstrap import _read_current_dispatch_control
        historical, proof, captured = history.capture(ROOT)
        binding = history.graph_bindings(captured[history.SOURCE], historical)
        self.assertEqual(binding['import_port_count'], 40)
        self.assertTrue(proof['complete_current_forward_replay_verified'])
        for path in (history.SOURCE, history.FIXTURE):
            for offset in (0, len(captured[path]) // 2, len(captured[path]) - 1):
                changed = dict(captured)
                value = bytearray(changed[path]); value[offset] ^= 1; changed[path] = bytes(value)
                with self.subTest(path=path, offset=offset), self.assertRaises(ValueError):
                    history.restore(changed[history.SOURCE], changed[history.FIXTURE])
        for lane in ('unselected', 'vm'):
            code = ("import sys,json;sys.path.insert(0," + repr(str(ROOT)) + ");"
                    "from tests.hia_service_bootstrap_observer import Backend,UnselectedBackend;"
                    "from tests.hia_bootstrap_current_dispatch import current_dispatch_controls;"
                    "lane=" + repr(lane) + ";"
                    "backend=UnselectedBackend() if lane=='unselected' else Backend('vm',None);"
                    "print(json.dumps(current_dispatch_controls(backend,lane),sort_keys=True))")
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('HEPTA_HIA_', 'PYTHON'))}
            child = subprocess.run([sys.executable, '-I', '-B', '-c', code], cwd=ROOT,
                                   env=environment, capture_output=True, timeout=90)
            self.assertEqual(child.returncode, 0, child.stderr.decode())
            self.assertEqual(child.stderr, b'')
            value = json.loads(child.stdout)
            _read_current_dispatch_control(value, binding['current_code'], lane)
            for mutation in ('domain', 'complete_current_semantics_qualified', 'program_cases',
                             'case_order', 'getter', 'zero_entry', 'missing_option'):
                altered = copy.deepcopy(value)
                if mutation == 'domain':
                    altered['domain'] = 'HISTORICAL_FIVE_BODY_COMPATIBILITY'
                elif mutation == 'complete_current_semantics_qualified':
                    altered[mutation] = True
                elif mutation == 'program_cases':
                    altered[mutation] = 11
                elif mutation == 'case_order':
                    altered['program_rows'][0], altered['program_rows'][1] = (
                        altered['program_rows'][1], altered['program_rows'][0])
                elif mutation == 'getter':
                    altered['program_rows'][5]['current']['events'].pop(1)
                elif mutation == 'zero_entry':
                    altered['init_rows'][0]['current']['entries'] = 1 if lane == 'unselected' else 0
                else:
                    altered['init_rows'].pop()
                with self.subTest(lane=lane, mutation=mutation), self.assertRaises((ValueError, KeyError)):
                    _read_current_dispatch_control(altered, binding['current_code'], lane)
        history.unchanged(ROOT, captured)


if __name__ == '__main__':
    unittest.main()
