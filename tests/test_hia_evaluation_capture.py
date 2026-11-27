"""Exact candidate capture, original public caller, and real selected owners.

CI constructs both owners from the original matching cold admission. An
external component observer may explicitly supply development manifests;
that separate scope is not an installed whole-source qualification.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_evaluation_native as native
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.hia_evaluation_capture_successor import original_reference
from tests.hia_evaluation_oracle import reference_method

ROOT = Path(__file__).resolve().parents[1]
EVALUATION = 'HEPTA_HIA_EVALUATION_CAPTURE_DEVELOPMENT_MANIFEST'
ADMISSION = 'HEPTA_HIA_EVALUATION_CAPTURE_ADMISSION_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_EVALUATION_CAPTURE_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_EVALUATION_CAPTURE_EVIDENCE'
WORKLOAD = {'schema': 'hepta.hia.agent.workload.v1',
            'cases': [{'function': 'transform', 'arguments': [250]}],
            'warmup_iterations': 0, 'repetitions': 1}


class CaptureSourceTests(unittest.TestCase):
    def test_exact_successor_reconstructs_the_complete_original_reference_AST(self):
        module = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(node for node in module.body if isinstance(node, ast.ClassDef)
                       and node.name == 'HIAAgentService')
        body = next(node for node in service.body if isinstance(node, ast.FunctionDef)
                    and node.name == '_hia_evaluate_reference')
        restored = original_reference(body)
        restored.name = '_hia_evaluate'
        expected = ast.parse((ROOT / 'tests/fixtures/hia_evaluate_19065.py.txt').read_bytes()).body[0]
        self.assertEqual(ast.dump(restored), ast.dump(expected))
        changed = deepcopy(body)
        capture = next(node for node in changed.body if isinstance(node, ast.If)
                       and isinstance(node.test, ast.Call)
                       and isinstance(node.test.func, ast.Name)
                       and node.test.func.id == '_evaluation_owns_build_inputs')
        capture.body.pop()
        with self.assertRaisesRegex(AssertionError, 'exact reviewed successor'):
            original_reference(changed)
        changed = deepcopy(body)
        changed.body.append(ast.parse('raise RuntimeError("unreviewed")').body[0])
        other = original_reference(changed)
        other.name = '_hia_evaluate'
        self.assertNotEqual(ast.dump(other), ast.dump(expected))


class EvaluationCaptureTests(AgentToolCase):
    @classmethod
    def setUpClass(cls):
        cls.cold_manifests = None
        cold = os.environ.get(COLD)
        if cold is None:
            return
        evidence = os.environ.get(EVIDENCE)
        if (not cold or not evidence
                or any(name in os.environ for name in (EVALUATION, ADMISSION))):
            raise ValueError('cold capture controls require evidence and no development manifests')
        from tools.build_hia_evaluation import build as build_evaluation
        from tools.build_hia_native_build_admission import build as build_admission
        from tools.build_hia_json_preflight import admit_cold_build, current_sources
        cold_path = Path(cold)
        cold_raw = cold_path.read_bytes()
        outer = json.loads(cold_raw)
        nested = json.loads(Path(outer['nested_report']).read_bytes())
        compiler = Path(nested['generations'][-1]['produced_image'])
        compiler_raw = compiler.read_bytes()
        # This is the existing cold domain, without a development override or
        # native-v2 alias. Unsupported current cold evidence must still refuse.
        sources = admit_cold_build(compiler_raw, cold_raw)
        root = Path(evidence).absolute()
        root.mkdir(mode=0o700, exist_ok=False)
        evaluation = build_evaluation(root / 'evaluation', compiler, cold_path)
        admission = build_admission(root / 'admission', compiler, cold_path)
        if (cold_path.read_bytes() != cold_raw or compiler.read_bytes() != compiler_raw
                or current_sources() != sources):
            raise ValueError('cold capture construction inputs changed')
        cls.cold_manifests = {EVALUATION: str(evaluation), ADMISSION: str(admission)}

    @contextmanager
    def route(self, mode):
        # Keep the public request, Store, real builders and execution budgets.
        # Only route selection differs between these independently run cases.
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            os.environ.pop('HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST', None)
            if mode in ('native', 'native-admission'):
                manifest = (self.cold_manifests[EVALUATION] if self.cold_manifests is not None
                            else os.environ.get(EVALUATION))
                if not manifest:
                    raise ValueError('a real evaluation manifest is required')
                os.environ[native.SELECTOR] = manifest
            if mode == 'native-admission':
                manifest = (self.cold_manifests[ADMISSION] if self.cold_manifests is not None
                            else os.environ.get(ADMISSION))
                if not manifest:
                    raise ValueError('a real admission manifest is required')
                os.environ['HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST'] = manifest
            if mode == 'reference':
                store = self.service.store
                class OriginalStoreView:
                    # The original Store object protocol has no typed-wire
                    # capability. All real persistence methods still delegate
                    # to the same actual Store; no ledger value is fabricated.
                    def __getattr__(self, name):
                        return getattr(store, name)
                with patch.object(self.service, 'store', new=OriginalStoreView()):
                    yield
            else:
                yield

    def original_public_caller(self, mode):
        # f587's original workload and business assertions are retained. The
        # method-name assertion follows the explicit two-stage capture owner.
        workload = {"schema": "hepta.hia.agent.workload.v1",
            "cases": [{"function": "transform", "arguments": [250]}],
            "warmup_iterations": 0, "repetitions": 1}
        _base, _candidate, baseline, build, receipts = self.build_pair(workload=workload)
        native_provider = self.service._native
        calls = []
        def observe(ref, context=None):
            caller = sys._getframe(1)
            calls.append((caller.f_globals.get('__name__'), caller.f_code.co_name, ref))
            return native_provider(ref, context)
        with self.route(mode), patch.object(self.service, '_native', new=observe):
            evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertIn(evaluation["outcome"], {"improved", "unchanged", "regressed"})
        self.assertTrue(evaluation["termination_confirmed"])
        self.assertTrue(evaluation["planned_workload_complete"])
        direct = [ref for module, owner, ref in calls if
                  module == 'hepta.hia_agent_service' and owner in (
                      '_hia_evaluate_reference', '_hia_evaluate_with_components')
                  or module == 'hepta.hia_evaluation_native' and owner == 'effect']
        self.assertEqual(direct, [baseline["native_artifact"]])
        self.assertIn(('hepta.hia_agent_service', '_capture_evaluation_build_inputs', build["native_artifact"]), calls)
        self.assertEqual([ref for _module, owner, ref in calls if owner == '_capture_evaluation_build_inputs'],
                         [build['native_artifact']])

    def test_evaluation_candidate_uses_exact_build_bound_native_observation(self):
        self.original_public_caller('components')

    def test_original_public_caller_in_hosted_reference_branch(self):
        self.original_public_caller('reference')

    def test_original_public_caller_with_actual_native_evaluation(self):
        self.original_public_caller('native')

    def test_original_public_caller_with_both_actual_native_owners(self):
        self.original_public_caller('native-admission')

    def test_unbound_first_candidate_cannot_be_hidden_by_a_second_native_read(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(workload=WORKLOAD)
        provider = self.service._native
        baseline_bytes = provider(baseline['native_artifact'], self.session.context)[0]
        for mode in ('reference', 'components', 'native', 'native-admission'):
            with self.subTest(mode=mode):
                observed = []
                def first_unbound(ref, context=None):
                    values = provider(ref, context)
                    if ref == build['native_artifact']:
                        observed.append(values)
                        if len(observed) == 1:
                            return baseline_bytes, values[1], values[2]
                    return values
                with self.route(mode), patch.object(self.service, '_native', new=first_unbound), \
                        patch('hepta.hia_agent_runner.run_reference_batch') as reference, \
                        patch('hepta.hia_agent_runner.run_native_batch') as runner:
                    args = self.session.arguments(baseline_artifact=baseline['native_artifact'],
                        candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                        verification_receipts=receipts)
                    rejected = self.reject('hia_evaluate', args)
                self.assertEqual(rejected['error']['code'], 'E_HIA_RECEIPT_BINDING')
                self.assertEqual(len(observed), 1)
                reference.assert_not_called()
                runner.assert_not_called()

    def test_corrupt_candidate_still_precedes_wrong_receipt_type(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(workload=WORKLOAD)
        candidate = build['native_artifact']
        path = self.state_root / 'artifacts' / candidate['sha256']
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b'corrupt-original-candidate')
        original_get = self.service.store.get
        for mode in ('reference', 'components', 'native', 'native-admission'):
            with self.subTest(mode=mode):
                observed = []
                def get(ref, **kwargs):
                    observed.append((ref, kwargs.get('kind')))
                    return original_get(ref, **kwargs)
                with self.route(mode), patch.object(self.service.store, 'get', new=get):
                    args = self.session.arguments(baseline_artifact=baseline['native_artifact'],
                        candidate_artifact=candidate, build_receipt=baseline['native_artifact'],
                        verification_receipts=receipts)
                    rejected = self.reject('hia_evaluate', args)
                self.assertEqual(rejected['error']['code'], 'E_HIA_ARTIFACT_CORRUPT')
                self.assertNotIn((baseline['native_artifact'], 'build-receipt'), observed)

    def test_capture_is_bound_to_service_refs_thread_and_one_consumption(self):
        _base, _candidate, _baseline, build, _receipts = self.build_pair(workload=WORKLOAD)
        context, artifact, ref = self.session.context, build['native_artifact'], build['build_receipt']
        capture = lambda: api._capture_evaluation_build_inputs(self.service, artifact, context)
        observed = capture()
        built = observed.admit(self.service, ref, context, artifact)
        self.assertEqual(built['native_artifact'], artifact)
        with self.assertRaisesRegex(api.AgentRejected, 'already consumed'):
            observed.admit(self.service, ref, context, artifact)
        for service, ctx, art in ((object(), context, artifact),
                                  (self.service, dict(context), artifact),
                                  (self.service, context, dict(artifact))):
            with self.subTest(service=service is self.service, context=ctx is context, artifact=art is artifact):
                observed = capture()
                with self.assertRaisesRegex(api.AgentRejected, 'changed before admission'):
                    observed.admit(service, ref, ctx, art)
        observed = capture()
        changed = artifact['sha256']
        artifact['sha256'] = '0' * 64
        try:
            with self.assertRaisesRegex(api.AgentRejected, 'changed before admission'):
                observed.admit(self.service, ref, context, artifact)
        finally:
            artifact['sha256'] = changed
        observed = capture()
        failures = []
        def foreign_thread():
            try:
                observed.admit(self.service, ref, context, artifact)
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=foreign_thread)
        thread.start()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], api.AgentRejected)
        observed = capture()
        with patch.object(self.service, '_build_inputs_reference', side_effect=AssertionError('provider escaped')):
            with self.assertRaisesRegex(api.AgentRejected, 'changed before admission'):
                observed.admit(self.service, ref, context, artifact)

    def test_dynamic_providers_and_reference_protocols_keep_the_original_first_effect(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(workload=WORKLOAD)
        arguments = self.session.arguments(baseline_artifact=baseline['native_artifact'],
            candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
            verification_receipts=receipts)
        original = reference_method(ROOT / 'tests/fixtures/hia_evaluate_19065.py.txt', api,
                                    ROOT / 'tests/fixtures/hia_evaluation_value_19065.py.txt')
        observed = []
        def claims(*_args):
            observed.append('claims')
            raise ValueError('original-claims-boundary')
        def dynamic_provider(*_args):
            observed.append('dynamic_build_provider')
            raise ValueError('original-dynamic-build-provider-refusal')
        class Items(dict):
            def items(self):
                observed.append('unexpected_reference_items')
                raise ValueError('new reference protocol must not be invoked')
        class Arguments(dict):
            def get(self, *_args):
                observed.append('unexpected_argument_get')
                raise ValueError('new argument protocol must not be invoked')
        provider, context_provider = self.service._native, self.service._context
        def native_provider(reference, context=None):
            return provider(dict(reference), None if context is None else dict(context))
        def retained_context(reference):
            return context_provider(dict(reference))
        for kind in ('dynamic_receipt', 'dynamic_inputs', 'candidate_items', 'context_items', 'argument_get'):
            if kind.startswith('dynamic_'):
                target = '_build_receipt' if kind == 'dynamic_receipt' else '_build_inputs'
                class Dynamic(api.HIAAgentService):
                    def __getattribute__(self, name):
                        if name == target:
                            return dynamic_provider
                        return object.__getattribute__(self, name)
                self.service.__class__ = Dynamic
            else:
                self.service.__class__ = api.HIAAgentService
            args = dict(arguments)
            if kind == 'candidate_items':
                args['candidate_artifact'] = Items(args['candidate_artifact'])
            elif kind == 'context_items':
                args['context'] = Items(args['context'])
            elif kind == 'argument_get':
                args = Arguments(args)
            try:
                for mode in ('reference', 'components', 'native', 'native-admission'):
                    with self.subTest(kind=kind, mode=mode), self.route(mode), ExitStack() as stack:
                        stack.enter_context(patch.object(self.service, '_required_claims', new=claims))
                        stack.enter_context(patch.object(self.service, '_native', new=native_provider))
                        stack.enter_context(patch.object(self.service, '_context', new=retained_context))
                        stack.enter_context(patch.object(api, '_capture_evaluation_build_inputs',
                            side_effect=AssertionError('custom provider entered the capture path')))
                        self.assertFalse(api._evaluation_owns_build_inputs(self.service, args))
                        results = []
                        for invoke in (lambda: original(self.service, args),
                                       lambda: self.service._hia_evaluate(args)):
                            observed.clear()
                            with self.assertRaises(ValueError) as failure:
                                invoke()
                            results.append((type(failure.exception), str(failure.exception), tuple(observed)))
                        self.assertEqual(results[0], results[1])
                        self.assertNotIn('unexpected_reference_items', observed)
                        self.assertNotIn('unexpected_argument_get', observed)
            finally:
                self.service.__class__ = api.HIAAgentService


if __name__ == '__main__':
    unittest.main()
