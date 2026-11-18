"""Check source-generated Agent schemas against the existing service behavior."""
from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_contract import catalog, validate
from hepta.hia_agent_schema_native import SELECTOR, SOURCE, installed_agent_schema
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected


class AgentSchemaSourceTests(unittest.TestCase):
    def test_generated_source_matches_catalog(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_schema import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))


class AgentSchemaNativeTests(unittest.TestCase):
    manifest = None
    test_root = None

    def setUp(self):
        if self.manifest is None:
            self.skipTest('provide the matching native Agent input schema image')
        self.image = installed_agent_schema(str(self.manifest))

    def test_every_tool_valid_and_mutated_arguments_match_reference(self):
        doc, pin = catalog()
        common = {'catalog_sha256': pin, 'request_key': 'fixture:request'}
        context = {'id': 'fixture:context', 'sha256': 'c' * 64}
        profile = {'id': 'fixture:profile', 'sha256': 'b' * 64}
        ref = {'id': 'fixture:artifact', 'sha256': 'a' * 64,
               'uri': 'hia://artifacts/fixture-artifact'}
        current = {'generation': '1', 'epoch': '2'}
        bound = {**common, 'context': context}
        tools = {
            'hia_describe': {'section': 'manifest'},
            'hia_artifact': {**common, 'artifact_profile': profile,
                             'source': {'kind': 'utf8', 'text': '葡萄'}},
            'hia_read': {'catalog_sha256': pin, 'artifact': ref, 'max_bytes': 512.0},
            'hia_context': {**common, 'compiler_profile': profile, 'target_profile': profile,
                             'baseline_program': None, 'workload': ref, 'objective': ref,
                             'budget': {'max_candidates': 8, 'max_model_tokens': -0.0,
                                        'max_total_wall_ms': 60000, 'max_native_wall_ms': 1000,
                                        'max_memory_bytes': '16777216', 'cost_policy': ref}},
            'hia_inspect': {'catalog_sha256': pin, 'context': context,
                             'program': ref, 'view': 'summary'},
            'hia_candidate': {**bound, 'change': {'kind': 'patch', 'base_program': ref,
                             'patch_schema': 'hepta.hia.patch.v2', 'patch': ref}},
            'hia_verify': {**bound, 'candidate': ref, 'base_program': ref,
                           'validation_profile': profile, 'subject': {'kind': 'core'},
                           'claims': ['core_admission', 'behavior_equivalence']},
            'hia_emit': {**bound, 'candidate': ref, 'backend_profile': profile, 'output_kind': 'object',
                         'codegen': {'kind': 'canonical', 'lowering_profile': profile},
                         'verification_receipts': [ref]},
            'hia_evaluate': {**bound, 'baseline_artifact': ref, 'candidate_artifact': ref,
                             'build_receipt': ref, 'verification_receipts': [ref]},
            'hia_adopt': {**bound, 'target_slot': 'fixture:slot', 'expected_current': current,
                          'candidate_artifact': ref, 'evaluation_receipt': ref,
                          'verification_receipts': [ref]},
            'hia_rollback': {**bound, 'target_slot': 'fixture:slot', 'expected_current': current,
                             'retained_generation': '1', 'reason': 'fixture only'},
        }
        self.assertEqual(set(tools), {tool['name'] for tool in doc['tools']})
        for role, tool in enumerate(doc['tools'], 1):
            name, schema = tool['name'], tool['inputSchema']
            args = tools[name]
            self.assertTrue(self.image.accepts(args, role, pin), name)
            cases = [args, [], None, dict(args, not_a_catalog_field=3)]
            for key in args:
                cases.append({k: v for k, v in args.items() if k != key})
                cases += [dict(args, **{key: value}) for value in (None, [], {}, False, '\n', 512.5)]
            if name == 'hia_read':
                cases.extend(dict(args, max_bytes=value) for value in (0, 511.99, 512, 65536.0,
                             65536.00000000001, True, 1 << 91, 5e-324))
                cases.append(dict(args, artifact=dict(ref, sha256='a' * 64 + '\n')))
            if name == 'hia_verify':
                cases += [dict(args, claims=['core_admission', 'core_admission']),
                          dict(args, claims=['behavior_equivalence'], base_program=None)]
            for case in cases:
                try:
                    validate(case, schema)
                except AgentRejected:
                    expected = False
                else:
                    expected = True
                with self.subTest(name=name, case=case):
                    self.assertEqual(self.image.accepts(case, role, pin), expected)
        with self.assertRaisesRegex(ValueError, 'authenticate'):
            self.image.accepts(tools['hia_describe'], 1, '0' * 64)

    def test_selected_ordinary_service_uses_native_decisions(self):
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                bad = {'section': 'nonsense'}
                old = service.call('hia_describe', bad)
                with patch.dict('os.environ', {SELECTOR: str(self.manifest)}):
                    self.assertEqual(service.call('hia_describe', bad), old)

                    def output_only(value, schema, label='arguments'):
                        if label != 'result':
                            raise AssertionError('hosted input validator selected for admitted request')
                        return validate(value, schema, label)

                    with patch('hepta.hia_agent_service.validate', output_only):
                        result = service.call('hia_describe', {'section': 'manifest'})
                        self.assertEqual(result['status'], 'completed', result)
                with patch.dict('os.environ', {SELECTOR: str(Path(root) / 'missing.json')}):
                    result = service.call('hia_describe', {'section': 'manifest'})
                    self.assertEqual(result['status'], 'rejected')
            finally:
                service.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    args = parser.parse_args()
    AgentSchemaNativeTests.manifest = args.manifest.resolve()
    AgentSchemaNativeTests.test_root = args.test_root.resolve()
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(cls)
                              for cls in (AgentSchemaSourceTests, AgentSchemaNativeTests))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
