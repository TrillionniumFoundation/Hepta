"""Mock admission controls only; no Lean checker or native code is executed."""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import check_core_syntax_lean as proof
from tools import qualify_hia_selected_formal as checker


class CoreSyntaxRunnerTests(unittest.TestCase):
    def run_mock(self, behavior='success', changed_bytes=False):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            executable = root/'fake-lean'
            executable.write_bytes(b'never execute')
            (root/'formal').mkdir()
            (root/'formal/toolchain-lock.json').write_text(json.dumps({
                'lean_binary_sha256':sha256(executable.read_bytes()).hexdigest()}))
            prepared = {'positive':'mock text', 'canonical_bytes':b'{}',
                        'expected_theorems':{'Mock.expected'},
                        'manifest':{'core_sha256':sha256(b'{}').hexdigest()},
                        'negatives':{'bad':{'source':'mock negative','kind':'mock', 'failure_lines':[4,4]}}}
            calls=[]
            def invoke(exe,path):
                calls.append(path.name)
                if path.name == 'positive.lean':
                    if behavior == 'missing':
                        raise FileNotFoundError('mock missing checker')
                    if behavior == 'positive_fail':
                        return {'returncode':1,'stdout':'error: rejected','stderr':''}
                    if behavior == 'bad_axiom':
                        return {'returncode':0,'stdout':"'Mock.expected' depends on axioms: [sorryAx]",'stderr':''}
                    return {'returncode':0,'stdout':"'Mock.expected' does not depend on any axioms",'stderr':''}
                line = 1 if behavior == 'wrong_location' else 4
                return {'returncode':1,'stdout':f"{path}:{line}:1: error: tactic 'decide' proved that the proposition\n  False\nis false\n",'stderr':''}
            stack.enter_context(patch.object(proof,'ROOT',root))
            stack.enter_context(patch.object(proof,'source_identity',return_value={'fixed':'mock'}))
            stack.enter_context(patch.object(proof,'build_inputs',return_value=prepared))
            stack.enter_context(patch.object(proof,'fixed_input',side_effect=[{'bytes':b'{}'},
                {'bytes':b'[]' if changed_bytes else b'{}'}]))
            stack.enter_context(patch.object(checker,'_support_identity',return_value={'mock':'support'}))
            stack.enter_context(patch.object(checker,'_run_lean',side_effect=invoke))
            report = proof.qualify(executable,root/'output')
            self.assertEqual(json.loads((root/'output/RESULT.json').read_text()),report)
            self.assertEqual(report['authority'],'DENY_ALL')
            for key in ('actual_core_bridge_proved','python_exporter_refinement_proved',
                        'body_prefix_refinement_proved','all_edge_transfer_proved',
                        'initialization_elision_authorized','native_admission',
                        'production_admission','performance_qualified','quota_equivalence'):
                self.assertFalse(report[key])
            self.assertEqual(len(report['obligations']),12)
            self.assertTrue(all(o['status']=='unproved' for o in report['obligations']))
            return report,calls

    def test_mock_success_preserves_all_denials(self):
        r,calls=self.run_mock()
        self.assertEqual(r['status'],'passed')
        self.assertTrue(r['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls,['positive.lean','bad.lean'])

    def test_rejected_positive_stops_before_negatives(self):
        for behavior in ('missing','positive_fail','bad_axiom'):
            with self.subTest(behavior=behavior):
                r,calls=self.run_mock(behavior)
                self.assertEqual(r['status'],'failed')
                self.assertFalse(r['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls,['positive.lean'])
                self.assertEqual(r['negative_controls'],[])

    def test_unrelated_error_location_never_counts_as_expected_negative(self):
        r,_=self.run_mock('wrong_location')
        self.assertEqual(r['status'],'failed')
        self.assertFalse(r['kernel_core_syntax_connection_checked'])

    def test_exact_core_bytes_changed_fails_even_with_same_manifest(self):
        r,_=self.run_mock(changed_bytes=True)
        self.assertEqual(r['status'],'failed')
        self.assertEqual(r['error'],'Core bytes changed')
        self.assertFalse(r['kernel_core_syntax_connection_checked'])

    def test_missing_or_unpinned_checker_does_not_prepare_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(FileNotFoundError):
                proof.qualify(root/'missing',root/'output')
            fake=root/'fake';fake.write_bytes(b'not Lean')
            with patch.object(proof,'build_inputs') as prepare, patch.object(checker,'_run_lean') as run:
                with self.assertRaisesRegex(ValueError,'pinned Lean'):
                    proof.qualify(fake,root/'output')
                prepare.assert_not_called();run.assert_not_called()
            self.assertFalse((root/'output').exists())

    def test_emitted_bytes_checked_independently_of_renderer(self):
        fixed=proof.fixed_input()
        with patch.object(proof,'render_bytes',return_value='[256]'):
            with self.assertRaisesRegex(ValueError,'emitted exact byte'):
                proof._definitions(fixed['tree'],fixed['bytes'],fixed['hint'])
        with patch.object(proof,'render_bytes',return_value='[0]'):
            with self.assertRaisesRegex(ValueError,'emitted exact byte'):
                proof._definitions(fixed['tree'],fixed['bytes'],fixed['hint'])


if __name__ == '__main__':
    unittest.main()


class CoreSyntaxGeneratedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = proof.build_inputs()

    def test_one_real_slice_and_distinguishable_arms_are_bound(self):
        p=self.prepared
        self.assertEqual(p['manifest']['core_sha256'],
                         'c7b8b9ef7619700fd9c5ec0dedb06fbf7ecc801563813b6cb7abaf7e08a467d3')
        self.assertEqual(p['canonical_bytes'],proof.fixed_input()['bytes'])
        self.assertEqual(len(p['expected_theorems']),65)
        for name in ('linear_transport','linear_extraction','linear_relation',
                     'parallel_transport','parallel_extraction'):
            self.assertIn('HiaCoreSyntaxSlice.'+name,p['expected_theorems'])
        self.assertIn('def parallelRaw : Raw :=',p['positive'])
        self.assertIn('theorem linear_0_small',p['positive'])
        self.assertIn('theorem linear_0_upper',p['positive'])

    def test_negative_failure_ranges_and_semantic_mutation_are_explicit(self):
        p=self.prepared
        self.assertEqual(len(p['negatives']),10)
        for name,n in p['negatives'].items():
            self.assertNotIn('#print axioms',n['source'])
            a,b=n['failure_lines']
            self.assertEqual(a,b)
            self.assertTrue(n['source'].splitlines()[a-1].startswith('theorem intended_negative'))
        for name in ('wrong_phi','literal_two','wrong_condition'):
            text=p['negatives'][name]['source']
            self.assertLess(text.index('theorem mutated_transport'), text.index('theorem intended_negative'))
        mutant=p['negatives']['wrong_arm_implementation']['source']
        self.assertIn('let edge := field (field header "term") "else" -- MUTATION_SITE_SELECT_THEN',mutant)
        self.assertIn('let thenEdge := field term "then"',mutant)
        self.assertIn('decode [48,49]',p['negatives']['leading_zero']['source'])

    def test_aggregate_proof_budget_rejects_before_execution(self):
        with patch.object(proof,'MAX_TOTAL_PROOF_BYTES',10):
            with self.assertRaisesRegex(ValueError,'total proof input budget'):
                proof.build_inputs()

    def test_source_closure_includes_new_model_and_runner(self):
        identity=proof.source_identity()
        for path in ('tools/check_core_syntax_lean.py',
                     'experiments/hia_initialization_frontiers_20261103/CoreSyntaxSlice.lean',
                     '.github/workflows/hia-core-syntax-kernel-research.yml',
                     'tools/check_guarded_slice_lean.py'):
            self.assertEqual(identity[path],sha256((proof.ROOT/path).read_bytes()).hexdigest())


class CoreSyntaxNegativeClassificationTests(unittest.TestCase):
    def test_only_complete_decide_false_error_qualifies(self):
        path=Path('/tmp/negative.lean')
        good=f"{path}:42:3: error: tactic 'decide' proved that the proposition\n  False\nis false\n"
        self.assertTrue(proof.decide_negative_rejected({'returncode':1,'stdout':good,'stderr':''},path,[42,42]))
        for message in ('unexpected token', 'unknown identifier',
                        '(deterministic) timeout at isDefEq, maximum number of heartbeats exceeded',
                        'maximum recursion depth has been reached', 'unsolved goals'):
            bad=f'{path}:42:3: error: {message}\n'
            for log in (bad, good+bad, bad+good):
                with self.subTest(message=message,log=log):
                    self.assertFalse(proof.decide_negative_rejected(
                        {'returncode':1,'stdout':log,'stderr':''},path,[42,42]))
        self.assertFalse(proof.decide_negative_rejected({'returncode':True,'stdout':good,'stderr':''},path,[42,42]))
        self.assertFalse(proof.decide_negative_rejected({'returncode':1,'stdout':good,'stderr':'extra error'},path,[42,42]))
