"""D5 source and real-provider controls; full retained callers stay separate."""
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tests.hia_artifact_delivery_fixture import (
    ROOT, COLD, DEVELOPMENT, EVIDENCE, clean_environment, encoded, prepare, source_pins)


class ArtifactDeliverySourceTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, clean_environment(), clear=True)
        self.environment.start(); self.addCleanup(self.environment.stop)

    def test_original_complete_63_ids_bodies_and_public_policy_are_preserved(self):
        from tools.run_hia_unittest_gate import load_declared_suite
        raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_original_5da589f0.json').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), '3b6fb4c69e5923d0483b01bd368525d1e7a71575865a9913c69705001f009a42')
        original = json.loads(raw); modules = []
        for name in original['direct_caller_modules']:
            data = (ROOT / name).read_bytes(); pin = original['source_files'][name]
            self.assertEqual({'bytes': len(data), 'sha256': sha256(data).hexdigest()},
                             {key: pin[key] for key in ('bytes', 'sha256')})
            modules.append(name[:-3].replace('/', '.'))
        suite, planned = load_declared_suite(modules)
        self.assertEqual(suite.countTestCases(), 63)
        self.assertEqual(list(planned), original['declared_original_test_ids'])
        old = (ROOT / 'tests/fixtures/hia_artifact_delivery_generator_5da589f0.py.txt').read_bytes()
        self.assertEqual(sha256(old).hexdigest(), '80f66021e7b3fdb97360bab5d2624561822937d3952a4d36972a17ffdffcf56b')
        def policy(raw):
            module = ast.parse(raw)
            source = next(node.value.value for node in module.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'POLICY_SOURCE' for target in node.targets))
            return ast.parse(source)
        before = policy(old)
        after = policy((ROOT / 'tools/generate_hia_artifact_publication.py').read_bytes())
        terminal, = [node for node in after.body if node.name == 'delivery_terminal']
        after.body.remove(terminal)
        gate, = [node for node in after.body[0].body if isinstance(node, ast.If)
                 and ast.dump(node.test) == ast.dump(ast.parse('phase == 21', mode='eval').body)]
        self.assertEqual(ast.dump(gate.body[0]), ast.dump(ast.parse('return delivery_terminal(o, w)').body[0]))
        after.body[0].body.remove(gate)
        self.assertEqual(ast.dump(before), ast.dump(after))

    def test_96_frozen_original_bridge_observations_and_reentrant_paths_match(self):
        from tests.hia_artifact_delivery_oracle import observe_case, canonical, public_observation, NONCE
        from hepta import artifact_publication_native as api
        from hepta import hia_artifact_delivery as delivery
        cases_raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_bridge_cases.json').read_bytes()
        expected_raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_bridge_expected.json').read_bytes()
        self.assertEqual(sha256(cases_raw).hexdigest(), '6e37bf81a16572bd9448850fe31c5959f71665b96a56be49b2bae07061a33ef5')
        self.assertEqual(sha256(expected_raw).hexdigest(), '91394b830f8546901c4e6e32c2056678194af830d4fcc8d3e7fc242404207f6f')
        cases = json.loads(cases_raw)['cases']; self.assertEqual(len(cases), 96)
        def owner(fixture, args, kwargs):
            name = 'invoke_artifact_store' if fixture.case['operation'].startswith('store-') else 'invoke_native'
            with fixture.providers(api.__dict__, candidate=True):
                return getattr(api, name)(*args, **kwargs)
        with patch('subprocess.Popen', side_effect=AssertionError('fake original oracle launched a process')), \
                patch.object(delivery.os, 'urandom', return_value=NONCE):
            originals = [observe_case(case) for case in cases]
            actual = [observe_case(case, owner) for case in cases]
        self.assertEqual(canonical(originals) + b'\n', expected_raw)
        for old, new in zip(originals, actual, strict=True):
            self.assertEqual(canonical(public_observation(old)), canonical(public_observation(new)), old['name'])
        # Separate pre-fix original observations preserve the accepted str
        # subclass domain without editing any of the original 96 cases.
        from tests.hia_artifact_delivery_operation_oracle import observe_case as observe_operation
        operation_raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_operation_cases.json').read_bytes()
        operation_expected = (ROOT / 'tests/fixtures/hia_artifact_delivery_operation_expected.json').read_bytes()
        self.assertEqual(sha256(operation_raw).hexdigest(), 'bfe2c946858572f1670503129e80d1ecc19d02db38a8609be91e83466f754159')
        self.assertEqual(sha256(operation_expected).hexdigest(), '9e357ebdea40cf7ffa33d9f1cef4bbf2ad7bf5a0cfdb394c77c749b643ed3b18')
        operations = json.loads(operation_raw)['cases']; self.assertEqual(len(operations), 5)
        with patch('subprocess.Popen', side_effect=AssertionError('operation oracle launched a process')), \
                patch.object(delivery.os, 'urandom', return_value=NONCE):
            originals = [observe_operation(case) for case in operations]
            actual = [observe_operation(case, owner) for case in operations]
        self.assertEqual(canonical(originals) + b'\n', operation_expected)
        for old, new in zip(originals, actual, strict=True):
            self.assertEqual(canonical(public_observation(old)), canonical(public_observation(new)), old['name'])

    def test_private_capability_and_complete_ack_are_explicit_and_strict(self):
        from tests.hia_artifact_delivery_oracle import exact_image, fake_ack, NONCE
        from hepta.hia_artifact_delivery_protocol import private_executable, public_executable, acknowledgement
        public = exact_image(); private = private_executable(public)
        self.assertEqual(private, exact_image(True))
        self.assertEqual(private_executable(public), private)
        self.assertEqual(public_executable(private), public)
        changed = {i for i, (a, b) in enumerate(zip(public, private)) if a != b}
        self.assertTrue(changed and changed <= set(range(24, 32)))
        for offset in (0, 16, 56, 64, 120, 176, 232, 244, 256, 264, 288, 304, 320, 336, 344):
            bad = bytearray(public); bad[offset] ^= 1
            with self.assertRaises(ValueError): private_executable(bytes(bad))
        raw = fake_ack('publish', 0, b'x', 1)
        self.assertEqual(acknowledgement(raw, NONCE, 0, b'x').outcome, 1)
        for bad in (b'', raw[:-1], raw + b'!', bytes(128)):
            with self.assertRaises(ValueError): acknowledgement(bad, NONCE, 0, b'x')
        for position, value in ((0, 0), (1, 2), (4, 7), (5, 4), (6, 1), (7, 64),
                                (9, 2), (10, 32768), (11, 64), (12, 64), (15, 0)):
            bad = bytearray(raw); struct.pack_into('<Q', bad, position * 8, value)
            bad[104:120] = sha256(bad[:104]).digest()[:16]
            with self.assertRaises(ValueError): acknowledgement(bytes(bad), NONCE, 0, b'x')
        with self.assertRaises(ValueError): acknowledgement(raw, NONCE[::-1], 0, b'x')
        with self.assertRaises(ValueError): acknowledgement(raw, NONCE, False, b'x')
        with self.assertRaises(ValueError): acknowledgement(raw, NONCE, 0, bytearray(b'x'))


class ArtifactDeliveryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching current cold or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-artifact-delivery-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute(); cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.cold = cold; cls.cold_raw = None if cold is None else Path(cold).read_bytes()
        if cold is None:
            cls.compiler = Path(development)
        else:
            cls.nested = Path(json.loads(cls.cold_raw)['nested_report'])
            cls.nested_raw = cls.nested.read_bytes()
            cls.compiler = Path(json.loads(cls.nested_raw)['generations'][-1]['produced_image'])
        cls.compiler_raw = cls.compiler.read_bytes(); cls.before = source_pins()
        cls.manifests = prepare(cls.root, cls.compiler, cold)
        cls.built = {str(path): sha256(path.read_bytes()).hexdigest()
                     for folder in (cls.root / 'artifact', *(cls.root / ('build-' + name)
                         for name in ('store_artifact_profile', 'service_context', 'store_lifecycle', 'agent_journal')))
                     for path in folder.rglob('*') if path.is_file()}

    @classmethod
    def tearDownClass(cls):
        after = source_pins()
        stable = (after == cls.before and cls.compiler.read_bytes() == cls.compiler_raw
            and all(sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in cls.built.items())
            and (cls.cold is None or (Path(cls.cold).read_bytes() == cls.cold_raw
                                      and cls.nested.read_bytes() == cls.nested_raw)))
        record = {'schema': 'hepta.hia.artifact-delivery-component-custody.v1',
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'matching_cold_report': cls.cold,
            'matching_cold_sha256': None if cls.cold_raw is None else sha256(cls.cold_raw).hexdigest(),
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(), 'manifests': cls.manifests,
            'source_before': cls.before, 'source_after': after, 'build_files': cls.built,
            'inputs_stable': stable, 'original_132_and_Store_130_qualified_by_this_record': False,
            'whole_native_stack_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None: cls.temporary.cleanup()
        if not stable: raise AssertionError('artifact delivery component custody changed')

    def child(self, kind):
        folder = self.root / kind; folder.mkdir(mode=0o700)
        command = [sys.executable, '-I', '-B', '-c',
            'import sys;sys.path.insert(0,sys.argv[1]);from tests.hia_artifact_delivery_cases import run_child;run_child(sys.argv[2],sys.argv[3],sys.argv[4])',
            str(ROOT), kind, str(folder), json.dumps(self.manifests, sort_keys=True)]
        try:
            result = subprocess.run(command, cwd=folder, env=clean_environment(), capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            (folder / 'stdout.log').write_bytes(error.stdout or b'')
            (folder / 'stderr.log').write_bytes(error.stderr or b'')
            raise
        (folder / 'stdout.log').write_bytes(result.stdout); (folder / 'stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
        value = json.loads((folder / 'observations.json').read_bytes())
        self.assertEqual(value['schema'], 'hepta.hia.artifact-delivery-child.v1')
        self.assertEqual(value['status'], 'PASS'); self.assertEqual(value['kind'], kind)

    def test_complete_terminal_44_native_VM_and_canaries(self):
        self.child('terminal')

    def test_public_six_operations_private_ack_and_original_payload_domain(self):
        self.child('cli')

    def test_real_fsync_negative_ack_preserves_refusal_and_allowed_residue(self):
        self.child('negative')

    def test_actual_lost_ack_retains_exact_Store_and_forbids_replay_close(self):
        self.child('loss')

    def test_preentry_post_terminal_and_same_named_foreign_errors(self):
        self.child('boundaries')

    def test_precise_resource_lifetime_thread_context_and_resume_obligation(self):
        self.child('lifetimes')

    def test_reentrant_path_preserves_fixed_sealed_bytes_and_one_shot_token(self):
        self.child('reentrant')

    def test_actual_installed_worker_provider_Store_peer_journal_and_scope_custody(self):
        self.child('installed')
