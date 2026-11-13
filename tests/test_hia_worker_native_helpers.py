"""Actual native-helper worker calls plus custody and interruption controls.

CI requires the shared matching-source cold gate before building selected
images. Explicit development manifests and local seed builds remain developer
observations, not a completed cold replay or a whole-language compiler proof.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_native_helpers import (
    ABI, HELPERS, SCHEMA, TARGET, NativeHelpersBinding, native_helpers_identity,
    native_helpers_scope,
)
from hepta.hia_agent_identity_native import (
    SCHEMA as IMAGE_SCHEMA, SOURCE, SELECTOR, installed_agent_identity,
)

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_WORKER_HELPERS_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_WORKER_HELPERS_COLD_REPORT'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def selected_compiler(cold):
    report = json.loads(Path(cold).read_bytes())
    nested = json.loads(Path(report['nested_report']).read_bytes())
    return Path(nested['generations'][-1]['produced_image'])


class WorkerHelperSourceTests(unittest.TestCase):
    """No image mapping or native execution in these ownership controls."""

    def setUp(self):
        self.clean = {key: value for key, value in os.environ.items()
                      if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        self.environment = patch.dict(os.environ, self.clean, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_empty_authority_selectors_refuse_before_ordinary_reference_or_effects(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_native_retirement import PathIdentityPin
        from hepta.hia_program import verify_program
        from tests.test_hia_core_admission_native import VALID
        from copy import deepcopy

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'must-not-be-created'
            with patch.dict(os.environ, {'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST': ''}), \
                    patch('sqlite3.connect', side_effect=AssertionError('SQLite entered')), \
                    patch('hepta.hia_execution_budget._ReferenceExecutionBudgetStore',
                          side_effect=AssertionError('reference budget entered')):
                with self.assertRaisesRegex(ValueError, 'execution budget selector must not be empty'):
                    AgentStore(root)
            self.assertFalse(root.exists())

        with patch.dict(os.environ, {'HEPTA_HIA_RETIREMENT_STATE_MANIFEST': ''}), \
                patch('hepta.hia_native_retirement._ReferencePathIdentityPin',
                      side_effect=AssertionError('reference retirement entered')):
            with self.assertRaisesRegex(ValueError, 'retirement state selector must not be empty'):
                PathIdentityPin(Path('/unused-no-effects'))

        with patch.dict(os.environ, {'HEPTA_HIA_CORE_ADMISSION_MANIFEST': ''}), \
                patch('hepta.hia_program._primitive_structure',
                      side_effect=AssertionError('reference Core entered')):
            with self.assertRaisesRegex(ValueError, 'Core admission selector must not be empty'):
                verify_program(VALID)

        primitive = deepcopy(VALID)
        primitive['functions'][0]['blocks'][0]['ops'] = [
            {'op': 'const', 'args': [], 'out': [{'name': 'n', 'type': 'u8'}],
             'attrs': {'value': 1}}]
        with patch.dict(os.environ, {'HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST': ''}), \
                patch('hepta.hia_program.check_instruction',
                      side_effect=AssertionError('reference instruction entered')):
            with self.assertRaisesRegex(ValueError, 'instruction policy selector must not be empty'):
                verify_program(primitive)

    def test_allowlist_has_real_single_image_contracts_and_packaged_sources(self):
        import importlib
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.assertEqual(len(HELPERS), 26)
        for selector, (name, factory_name) in HELPERS.items():
            with self.subTest(selector=selector):
                module = importlib.import_module('hepta.' + name)
                factory = getattr(module, factory_name)
                self.assertTrue(issubclass(factory, NativeHiaJsonImage))
                self.assertIn(module.SOURCE.relative_to(ROOT).as_posix(), NATIVE_SOURCE_FILES)
                self.assertTrue(module.SOURCE.is_file())
                self.assertEqual(module.SOURCE.suffix, '.hepta')
                self.assertIsInstance(module.SCHEMA, str)
        from hepta.hia_agent_journal_native import SCHEMA as journal_schema
        self.assertEqual(journal_schema, 'hepta.hia.agent-journal-native.v2')
        from hepta.hia_execution_budget_native import SCHEMA as budget_schema
        self.assertEqual(budget_schema, 'hepta.hia.execution-budget-native.v1')
        # The ordinary buffer caller requests this descriptor ABI. The raw JSON
        # snapshot is a separate standalone image, with no selector in that caller.
        from hepta.hia_agent_snapshot_native import NativeAgentSnapshot
        module_name, factory_name = HELPERS['HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST']
        self.assertIs(getattr(importlib.import_module('hepta.' + module_name), factory_name),
                      NativeAgentSnapshot)

    def test_patch_factory_view_identity_refuses_before_any_mapping(self):
        import hepta.hia_agent_candidate_native as candidate
        import hepta.hia_core_admission_native as admission
        import hepta.hia_core_patch_native as core_patch
        with tempfile.TemporaryDirectory(prefix='hia-view-source-control-') as temporary:
            folder = Path(temporary)
            # These are deliberately non-executable bytes. This control must
            # refuse the mismatched view contract before any factory runs.
            image = folder / 'unmapped.bin'
            image.write_bytes(b'pre-mapping source control; not native code')
            entries = []
            for module, filename in ((core_patch, 'manifest.json'),
                                     (admission, 'admission-manifest.json')):
                manifest = folder / filename
                manifest.write_bytes(encoded({'schema': module.SCHEMA,
                    'source_sha256': sha256(module.SOURCE.read_bytes()).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': '0' * 64}))
                entries.append({'selector': module.SELECTOR, 'manifest_path': str(manifest),
                                'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()})
            bundle = folder / 'bundle.json'
            bundle.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
                                        'helpers': entries}))
            for field, wrong in (('SCHEMA', 'unregistered-view-schema'),
                                 ('SOURCE', admission.SOURCE)):
                with self.subTest(field=field), patch.object(candidate, field, wrong), \
                        patch.object(core_patch.NativeCorePatch, '__init__',
                                     side_effect=AssertionError('mapped before view identity check')):
                    with self.assertRaisesRegex(ValueError, 'factory view identity'):
                        NativeHelpersBinding(str(bundle), sha256(bundle.read_bytes()).hexdigest())

    def test_unselected_scope_rejects_nested_and_foreign_thread_requests(self):
        with native_helpers_scope():
            with self.assertRaisesRegex(ValueError, 'another request'):
                with native_helpers_scope():
                    self.fail('nested worker scope entered')
            def foreign():
                with self.assertRaisesRegex(ValueError, 'original process and thread'):
                    native_helpers_identity()
                with self.assertRaisesRegex(ValueError, 'another request'):
                    with native_helpers_scope():
                        self.fail('concurrent request entered')
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(foreign).result(timeout=10)
            self.assertEqual(native_helpers_identity(), {})
        with native_helpers_scope():
            self.assertEqual(native_helpers_identity(), {})

    def test_unselected_scope_refuses_new_image_and_restores_complete_environment(self):
        empty = 'HEPTA_HIA_UNKNOWN_MANIFEST'
        os.environ[empty] = ''
        before = dict(os.environ)
        with native_helpers_scope():
            os.environ[SELECTOR] = '/must/not/be/opened.json'
            os.environ[empty] = 'changed-empty-value'
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                native_helpers_identity()
            with patch('hepta.hia_json_preflight_native._load_manifest',
                       side_effect=AssertionError('unlisted image reached general loader')):
                with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                    installed_agent_identity(os.environ[SELECTOR])
        self.assertEqual(dict(os.environ), before)

    def test_any_ambient_selector_and_incomplete_pair_refuse_and_restore(self):
        for selector in (SELECTOR, 'HEPTA_HIA_UNKNOWN_MANIFEST'):
            with patch.dict(os.environ, {selector: '/ambient'}):
                before = dict(os.environ)
                for path, digest in ((None, None), ('/explicit', '0' * 64)):
                    with self.assertRaisesRegex(ValueError, 'explicit pinned bundle'):
                        with native_helpers_scope(path, digest):
                            self.fail('ambient executable selection admitted')
                    self.assertEqual(dict(os.environ), before)
        for path, digest in (('/missing', None), (None, '0' * 64)):
            with self.assertRaisesRegex(ValueError, 'supplied together'):
                with native_helpers_scope(path, digest):
                    self.fail('unpaired bundle admitted')
        with native_helpers_scope():
            self.assertEqual(native_helpers_identity(), {})

    def test_fork_cannot_reuse_parent_scope_or_release_its_owner(self):
        with native_helpers_scope():
            child = os.fork()
            if child == 0:
                try:
                    native_helpers_identity()
                except ValueError:
                    os._exit(0)
                os._exit(1)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            self.assertEqual(native_helpers_identity(), {})


class NativeWorkerHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override a requested cold report')
        cls.native_fixture = None
        cls.cold_temp = None
        if cold:
            from tools.build_hia_agent_identity import build
            cls.cold_temp = tempfile.TemporaryDirectory(prefix='hia-helper-cold-')
            manifest = build(Path(cls.cold_temp.name) / 'build', selected_compiler(cold), Path(cold))
            native = installed_agent_identity(str(manifest))
        elif development:
            # Explicit development custody only; this is not a cold build.
            manifest = Path(development)
            native = installed_agent_identity(str(manifest))
        else:
            from tests.test_hia_agent_identity_native import AgentIdentityNativeTests
            cls.native_fixture = AgentIdentityNativeTests
            cls.native_fixture.setUpClass()
            manifest, native = cls.native_fixture.manifest, cls.native_fixture.native
        cls.image = bytes(native._mapping)
        cls.compiler_sha256 = json.loads(manifest.read_text())["compiler_sha256"]

    @classmethod
    def tearDownClass(cls):
        if cls.native_fixture is not None:
            cls.native_fixture.tearDownClass()
        if cls.cold_temp is not None:
            cls.cold_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-pinned-worker-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image_path = self.root / "identity.bin"
        self.image_path.write_bytes(self.image)
        self.manifest = self.root / "identity.json"
        self.manifest.write_bytes(encoded({
            "schema": IMAGE_SCHEMA, "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
            "image_path": self.image_path.name, "image_sha256": sha256(self.image).hexdigest(),
            "compiler_sha256": self.compiler_sha256,
        }))
        self.value = {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": [{
            "selector": SELECTOR, "manifest_path": self.manifest.name,
            "manifest_sha256": sha256(self.manifest.read_bytes()).hexdigest(),
        }]}
        self.bundle = self.root / "helpers.json"
        self.write_bundle()
        self.clean_env = {key: value for key, value in os.environ.items()
                          if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}

    def write_bundle(self):
        self.bundle.write_bytes(encoded(self.value))
        self.digest = sha256(self.bundle.read_bytes()).hexdigest()

    def flags(self):
        return ["--native-helpers-manifest", str(self.bundle),
                "--expected-native-helpers-sha256", self.digest]

    def worker(self, request=None, *, flags=None, script=None, env=None):
        argv = flags if flags is not None else self.flags()
        if request is None:
            argv = ["--installation-manifest", *argv]
        else:
            argv = ["--state-root", str(self.root / "state"), "--request-json-stdin", *argv]
        command = [sys.executable, "-B", "-E", "-s"]
        command += ["-c", script] if script else ["-m", "hepta.hia_agent_worker"]
        return subprocess.run([*command, *argv], input=encoded(request) if request is not None else b"",
                              capture_output=True, cwd=ROOT, env=env or self.clean_env, timeout=60)

    def pins(self):
        run = self.worker()
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        result = json.loads(run.stdout)
        self.assertEqual(result["native_helpers_sha256"], self.digest)
        return result

    def envelope(self, pins, tool, arguments):
        value = {"schema": "hia-agent-worker-request-v1", "tool": tool, "arguments": arguments,
                 "profile_sha256": "a" * 64, "catalog_sha256": pins["catalog_sha256"]}
        value["request_sha256"] = sha256(encoded(value)).hexdigest()
        return value

    def call(self, request, **kwargs):
        run = self.worker(request, **kwargs)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        report = json.loads(run.stdout)
        self.assertEqual(report["request_sha256"], request["request_sha256"])
        self.assertEqual(report["native_helpers_sha256"], self.digest)
        self.assertIs(report["complete"], True)
        return report

    def artifact_request(self):
        pins = self.pins()
        describe = self.call(self.envelope(pins, "hia_describe", {"section": "manifest"}))
        self.assertEqual(describe["response"]["status"], "completed")
        profile = describe["response"]["result"]["artifact_profiles"][0]
        arguments = {"catalog_sha256": pins["catalog_sha256"],
                     "artifact_profile": profile, "request_key": "native-worker-artifact",
                     "source": {"kind": "utf8", "text": "retained by the actual native-selected worker"}}
        return pins, self.envelope(pins, "hia_artifact", arguments)

    def test_actual_native_guard_has_no_host_fallback(self):
        from hepta import hia_agent_store as store
        with patch.dict(os.environ, self.clean_env, clear=True):
            with native_helpers_scope(str(self.bundle), self.digest):
                with patch.object(store, "_reference_digest", side_effect=AssertionError("host fallback")), \
                     patch.object(store, "_reference_uint64", side_effect=AssertionError("host fallback")):
                    self.assertTrue(store.canonical_digest("f" * 64))
                    self.assertFalse(store.canonical_digest("F" * 64))
                    self.assertEqual(store.uint64(str((1 << 64) - 1), "epoch"), (1 << 64) - 1)
                self.assertEqual(native_helpers_identity(), {"native_helpers_sha256": self.digest})
            self.assertEqual(native_helpers_identity(), {})
            self.assertNotIn(SELECTOR, os.environ)

    def test_actual_worker_restart_and_same_mutation_observe_original_result(self):
        pins, request = self.artifact_request()
        first = self.call(request)
        second = self.call(request)
        self.assertEqual(first["response"]["status"], "completed")
        self.assertEqual(second["response"], first["response"])
        changed = deepcopy(request["arguments"])
        changed["source"]["text"] = "changed body under the same mutation key"
        conflict = self.call(self.envelope(pins, "hia_artifact", changed))
        self.assertEqual(conflict["response"]["error"]["code"], "E_HIA_REQUEST_CONFLICT")

    def test_worker_post_effect_image_drift_is_unknown_then_original_is_observed(self):
        _, request = self.artifact_request()
        script = """import os,pathlib,sys
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
original=HIAAgentService.call
def changed(self,tool,args):
    result=original(self,tool,args)
    path=pathlib.Path(os.environ["HIA_TEST_IMAGE"])
    path.write_bytes(path.read_bytes()+b"X")
    return result
HIAAgentService.call=changed
raise SystemExit(main(sys.argv[1:]))
"""
        report = self.call(request, script=script,
                           env={**self.clean_env, "HIA_TEST_IMAGE": str(self.image_path)})
        self.assertEqual(report["response"]["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
        self.assertEqual(report["response"]["error"]["retry_action"], "observe_original")
        # A new process can only re-enter after the operator restores the pinned
        # bytes. It observes the same durable request; it does not repeat its effect.
        self.image_path.write_bytes(self.image)
        observed = self.call(request)
        again = self.call(request)
        self.assertEqual(observed["response"]["status"], "completed")
        self.assertEqual(observed["response"], again["response"])

    def test_legacy_worker_has_no_extra_identity_field(self):
        run = self.worker(flags=[])
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        self.assertEqual(set(json.loads(run.stdout)), {"worker_sha256", "backend_sha256", "catalog_sha256"})

    def test_pin_mismatch_pair_missing_and_ambient_selection_refuse_before_state(self):
        for flags, env in [
            (["--native-helpers-manifest", str(self.bundle)], self.clean_env),
            (["--expected-native-helpers-sha256", self.digest], self.clean_env),
            (["--native-helpers-manifest", str(self.bundle), "--expected-native-helpers-sha256", "0" * 64], self.clean_env),
            ([], {**self.clean_env, SELECTOR: str(self.manifest)}),
        ]:
            with self.subTest(flags=flags):
                run = self.worker(flags=flags, env=env)
                self.assertEqual(run.returncode, 2)
                self.assertEqual(run.stdout, b"")
                self.assertFalse((self.root / "state").exists())

    def test_bundle_target_abi_unknown_and_duplicate_refuse(self):
        original = deepcopy(self.value)
        cases = []
        for field, value in [("target", "windows"), ("abi", "unknown"), ("helpers", [])]:
            candidate = deepcopy(original); candidate[field] = value; cases.append(candidate)
        candidate = deepcopy(original); candidate["helpers"] *= 2; cases.append(candidate)
        candidate = deepcopy(original); candidate["helpers"][0]["selector"] = "HEPTA_HIA_UNKNOWN_MANIFEST"; cases.append(candidate)
        candidate = deepcopy(original); candidate["unexpected"] = 1; cases.append(candidate)
        for value in cases:
            self.value = value; self.write_bundle()
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    NativeHelpersBinding(str(self.bundle), self.digest)

    def test_core_patch_missing_or_wrong_adjacent_admission_refuses_before_mapping(self):
        # The manifest content need not claim a valid patch image: admission
        # must reject this incomplete set before it imports or maps any owner.
        original = deepcopy(self.value)
        for with_wrong_admission in (False, True):
            self.value = deepcopy(original)
            self.value["helpers"][0]["selector"] = "HEPTA_HIA_CORE_PATCH_MANIFEST"
            if with_wrong_admission:
                entry = deepcopy(original["helpers"][0])
                entry["selector"] = "HEPTA_HIA_CORE_ADMISSION_MANIFEST"
                self.value["helpers"].append(entry)
            self.write_bundle()
            with self.subTest(wrong_admission=with_wrong_admission):
                with patch("hepta.hia_native_helpers.importlib.import_module",
                           side_effect=AssertionError("incomplete set imported an owner")):
                    with self.assertRaisesRegex(ValueError, "exact adjacent admission"):
                        NativeHelpersBinding(str(self.bundle), self.digest)

    def test_wrong_manifest_source_and_image_identities_refuse(self):
        original = self.manifest.read_bytes()
        for field in ("source_sha256", "image_sha256"):
            value = json.loads(original); value[field] = "0" * 64
            self.manifest.write_bytes(encoded(value))
            self.value["helpers"][0]["manifest_sha256"] = sha256(self.manifest.read_bytes()).hexdigest()
            self.write_bundle()
            with self.subTest(field=field), self.assertRaises(ValueError):
                NativeHelpersBinding(str(self.bundle), self.digest)
        self.manifest.write_bytes(original)
        self.value["helpers"][0]["manifest_sha256"] = "0" * 64; self.write_bundle()
        with self.assertRaises(ValueError):
            NativeHelpersBinding(str(self.bundle), self.digest)

    def test_duplicate_json_symlink_and_nonregular_input_refuse(self):
        raw = self.bundle.read_bytes()
        self.bundle.write_bytes(raw[:-1] + b',"schema":"duplicate"}')
        with self.assertRaises(ValueError):
            NativeHelpersBinding(str(self.bundle), sha256(self.bundle.read_bytes()).hexdigest())
        self.bundle.write_bytes(raw)
        link = self.root / "bundle-link"; link.symlink_to(self.bundle)
        with self.assertRaises(OSError):
            NativeHelpersBinding(str(link), sha256(raw).hexdigest())
        pipe = self.root / "pipe"; os.mkfifo(pipe)
        with self.assertRaises(ValueError):
            NativeHelpersBinding(str(pipe), sha256(raw).hexdigest())

    def test_warm_mapping_remains_exact_and_changed_inputs_cannot_attest_success(self):
        with patch.dict(os.environ, self.clean_env, clear=True):
            with native_helpers_scope(str(self.bundle), self.digest):
                before = installed_agent_identity(str(self.manifest))
                self.image_path.write_bytes(self.image + b"changed")
                after = installed_agent_identity(str(self.manifest))
                self.assertIs(after, before)
                self.assertEqual(bytes(after._mapping), self.image)
                with self.assertRaisesRegex(ValueError, "changed"):
                    native_helpers_identity()

    def test_unlisted_or_changed_selection_never_gets_a_native_mapping(self):
        with patch.dict(os.environ, self.clean_env, clear=True):
            with native_helpers_scope(str(self.bundle), self.digest):
                other = self.root / "other.json"; other.write_bytes(self.manifest.read_bytes())
                with self.assertRaisesRegex(ValueError, "outside"):
                    installed_agent_identity(str(other))
                os.environ[SELECTOR] = str(other)
                with self.assertRaisesRegex(ValueError, "selection changed"):
                    native_helpers_identity()
            self.assertNotIn(SELECTOR, os.environ)

    def test_selected_mapping_identity_and_scope_cannot_cross_thread_or_process(self):
        with patch.dict(os.environ, self.clean_env, clear=True):
            with native_helpers_scope(str(self.bundle), self.digest) as binding:
                def foreign():
                    for operation in (binding.check, native_helpers_identity,
                                      lambda: installed_agent_identity(str(self.manifest))):
                        with self.assertRaisesRegex(ValueError, 'original process and thread'):
                            operation()
                    with self.assertRaisesRegex(ValueError, 'another request'):
                        with native_helpers_scope(str(self.bundle), self.digest):
                            self.fail('concurrent scope entered')
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(foreign).result(timeout=10)
                child = os.fork()
                if child == 0:
                    try:
                        installed_agent_identity(str(self.manifest))
                    except ValueError:
                        os._exit(0)
                    os._exit(1)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertTrue(installed_agent_identity(str(self.manifest)).digest('a' * 64))
                self.assertEqual(native_helpers_identity()['native_helpers_sha256'], self.digest)


class NativeWorkerRequestBundleTests(unittest.TestCase):
    """The retained request owner enters only through the explicit bundle."""

    @classmethod
    def setUpClass(cls):
        from tests.test_hia_worker_request_native import WorkerRequestNativeTests
        WorkerRequestNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        from tests.test_hia_worker_request_native import WorkerRequestNativeTests
        WorkerRequestNativeTests.tearDownClass.__func__(cls)

    def setUp(self):
        from tests.test_hia_worker_request_native import WorkerRequestNativeTests
        WorkerRequestNativeTests.setUp(self)
        self.clean_env = {key: value for key, value in os.environ.items()
                          if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        self.image = bytes(self.native._mapping)
        self.image_path = self.case / 'request.bin'
        self.image_path.write_bytes(self.image)
        record = json.loads(self.manifest.read_bytes())
        record['image_path'] = self.image_path.name
        self.local_manifest = self.case / 'request.json'
        self.local_manifest.write_bytes(encoded(record))
        from hepta.hia_worker_request_native import SELECTOR as REQUEST_SELECTOR
        self.bundle = self.case / 'helpers.json'
        self.bundle.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
            'helpers': [{'selector': REQUEST_SELECTOR, 'manifest_path': self.local_manifest.name,
                         'manifest_sha256': sha256(self.local_manifest.read_bytes()).hexdigest()}]}))
        self.digest = sha256(self.bundle.read_bytes()).hexdigest()

    def call_worker(self, raw, state):
        from tests.test_hia_worker_request_native import WorkerRequestNativeTests
        return WorkerRequestNativeTests.call_worker(self, raw, state, manifest=self.local_manifest)

    def test_actual_request_owner_uses_bundle_mapping_before_general_cache(self):
        from hepta import hia_json_preflight_native as loader
        from hepta.hia_worker_request_native import installed_worker_request
        from tests.test_hia_worker_request_native import request
        # First warm the ordinary cache, then require the independently pinned
        # bundle mapping to win without consulting that cache or revalidating
        # the request through hosted worker policy.
        ordinary = installed_worker_request(str(self.local_manifest))
        with patch.dict(os.environ, self.clean_env, clear=True):
            with native_helpers_scope(str(self.bundle), self.digest) as binding:
                with patch.object(loader, '_load_manifest', side_effect=AssertionError('general cache used')):
                    pinned = installed_worker_request(str(self.local_manifest))
                    self.assertIsNot(pinned, ordinary)
                    self.assertIn(pinned, binding.images.values())
                    value = request()
                    self.assertEqual(pinned.admit(encoded(value), value['catalog_sha256']), value)
                    self.image_path.write_bytes(self.image + b'changed')
                    self.assertIs(installed_worker_request(str(self.local_manifest)), pinned)
                    self.assertEqual(bytes(pinned._mapping), self.image)
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        native_helpers_identity()

    def test_ambient_request_selection_still_refuses_with_or_without_bundle(self):
        from hepta.hia_worker_request_native import SELECTOR as REQUEST_SELECTOR
        state = self.case / 'unentered-state'
        flags = ['--native-helpers-manifest', str(self.bundle),
                 '--expected-native-helpers-sha256', self.digest]
        for selected in ([], flags):
            with self.subTest(explicit=bool(selected)):
                run = subprocess.run([sys.executable, '-B', '-E', '-s', '-m',
                    'hepta.hia_agent_worker', '--state-root', str(state),
                    '--request-json-stdin', *selected], input=b'{}', capture_output=True,
                    cwd=ROOT, env={**self.clean_env, REQUEST_SELECTOR: str(self.local_manifest)}, timeout=60)
                self.assertEqual((run.returncode, run.stdout), (2, b''))
                self.assertIn(b'explicit pinned bundle', run.stderr)
                self.assertFalse(state.exists())

    def test_actual_worker_request_mapping_drift_after_effect_stays_unknown(self):
        from hepta.hia_agent_service import HIAAgentService
        from tests.test_hia_worker_request_native import request
        state = self.case / 'state'
        service = HIAAgentService(state)
        catalog, profile = service.catalog_sha256, service.profiles['artifact']
        service.close()
        value = request({'catalog_sha256': catalog, 'request_key': 'pinned-request-effect',
            'artifact_profile': profile, 'source': {'kind': 'utf8', 'text': 'one durable effect'}},
            tool='hia_artifact', catalog=catalog)
        raw = encoded(value)
        original = HIAAgentService.call
        calls = []

        def changed(owner, tool, arguments):
            result = original(owner, tool, arguments)
            calls.append(result)
            self.image_path.write_bytes(self.image + b'after-effect')
            return result

        with patch.object(HIAAgentService, 'call', changed):
            code, report, error = self.call_worker(raw, state)
        self.assertEqual(code, 0, error)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['status'], 'completed')
        self.assertEqual(report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
        self.assertEqual(report['response']['error']['retry_action'], 'observe_original')
        self.image_path.write_bytes(self.image)
        first = self.call_worker(raw, state)
        second = self.call_worker(raw, state)
        self.assertEqual(first[0], 0, first)
        self.assertEqual(first[1]['response'], calls[0])
        self.assertEqual(second[1]['response'], calls[0])
        import sqlite3
        with sqlite3.connect(state / 'state.sqlite3') as database:
            self.assertEqual(database.execute('SELECT count(*) FROM requests').fetchone()[0], 1)


class NativeWorkerJournalBundleTests(unittest.TestCase):
    """The current v2 journal and existing scalar helper share one bundle."""

    @classmethod
    def setUpClass(cls):
        NativeWorkerHelperTests.setUpClass.__func__(cls)
        from hepta.hia_agent_journal_native import SOURCE as journal_source, SCHEMA as journal_schema
        cls.journal_temp = tempfile.TemporaryDirectory(prefix='hia-helper-journal-')
        folder = Path(cls.journal_temp.name)
        cold = os.environ.get(COLD) or os.environ.get('HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST')
        if cold and development:
            raise AssertionError('development journal cannot override a requested cold report')
        if cold:
            from tools.build_hia_json_preflight import build
            manifest = build(folder / 'qualified', selected_compiler(cold), Path(cold), candidate='agent-journal')
        elif development:
            manifest = Path(development).resolve(strict=True)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(folder)
            compiler_source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(folder, 'B1', seed, compiler_source, image_format='seed-shared')
            compiler, _ = compile_stage(folder, 'B2', first, compiler_source)
            assert first.read_bytes() == compiler.read_bytes()
            image, _ = compile_stage(folder, 'journal', compiler, journal_source.read_bytes())
            manifest = folder / 'manifest.json'
            manifest.write_bytes(encoded({'schema': journal_schema,
                'source_sha256': sha256(journal_source.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}))
        from hepta.hia_agent_journal_native import installed_agent_journal
        cls.journal_image = bytes(installed_agent_journal(str(manifest))._mapping)
        cls.journal_record = json.loads(manifest.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.journal_temp.cleanup()
        NativeWorkerHelperTests.tearDownClass.__func__(cls)

    def setUp(self):
        NativeWorkerHelperTests.setUp(self)
        from hepta.hia_agent_journal_native import SELECTOR as journal_selector
        image = self.root / 'journal.bin'; image.write_bytes(self.journal_image)
        self.journal_manifest = self.root / 'journal.json'
        self.journal_manifest.write_bytes(encoded({**self.journal_record, 'image_path': image.name}))
        self.value['helpers'].append({'selector': journal_selector,
            'manifest_path': self.journal_manifest.name,
            'manifest_sha256': sha256(self.journal_manifest.read_bytes()).hexdigest()})
        self.write_bundle()

    write_bundle = NativeWorkerHelperTests.write_bundle
    flags = NativeWorkerHelperTests.flags
    worker = NativeWorkerHelperTests.worker
    pins = NativeWorkerHelperTests.pins
    envelope = NativeWorkerHelperTests.envelope
    call = NativeWorkerHelperTests.call

    def test_original_service_and_restarted_worker_use_v2_without_host_journal(self):
        import sqlite3
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_journal_native import JournalSession
        state = self.root / 'state'
        pins = self.pins()
        outer_environment = dict(os.environ)
        stages = []
        original_stage = JournalSession._run
        def observed(session, number, *args, **kwargs):
            result = original_stage(session, number, *args, **kwargs)
            stages.append(number)
            return result
        with patch.dict(os.environ, self.clean_env, clear=True), \
                native_helpers_scope(str(self.bundle), self.digest), \
                patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('host journal entered')), \
                patch.object(JournalSession, '_run', observed):
            service = HIAAgentService(state)
            try:
                arguments = {'catalog_sha256': service.catalog_sha256,
                    'artifact_profile': service.profiles['artifact'], 'request_key': 'same-bundle-v2',
                    'source': {'kind': 'utf8', 'text': 'native journal and identity'}}
                self.assertEqual(service.store.db.execute('SELECT count(*) FROM requests').fetchone()[0], 0)
                first = service.call('hia_artifact', arguments)
                self.assertEqual(first['status'], 'completed', first)
            finally:
                service.close()
            restarted = HIAAgentService(state)
            try:
                self.assertEqual(restarted.call('hia_artifact', arguments), first)
                changed = {**arguments, 'source': {'kind': 'utf8', 'text': 'different'}}
                self.assertEqual(restarted.call('hia_artifact', changed)['error']['code'], 'E_HIA_REQUEST_CONFLICT')
                self.assertEqual(restarted.store.db.execute('SELECT count(*) FROM requests').fetchone()[0], 1)
            finally:
                restarted.close()
            self.assertEqual(native_helpers_identity()['native_helpers_sha256'], self.digest)
        self.assertIn(0, stages)
        self.assertGreater(len(stages), 5)
        self.assertEqual(dict(os.environ), outer_environment)
        script = '''import sys
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
def forbidden(*args,**kwargs): raise AssertionError("host journal entered")
HIAAgentService._reference_call=forbidden
raise SystemExit(main(sys.argv[1:]))
'''
        report = self.call(self.envelope(pins, 'hia_artifact', arguments), script=script)
        self.assertEqual(report['response'], first)
        with sqlite3.connect(state / 'state.sqlite3') as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM requests').fetchone()[0], 1)

    def test_old_journal_schema_refuses_before_worker_state(self):
        record = json.loads(self.journal_manifest.read_bytes())
        record['schema'] = 'hepta.hia.agent-journal-native.v1'
        self.journal_manifest.write_bytes(encoded(record))
        self.value['helpers'][1]['manifest_sha256'] = sha256(self.journal_manifest.read_bytes()).hexdigest()
        self.write_bundle()
        run = self.worker()
        self.assertEqual((run.returncode, run.stdout), (2, b''))
        self.assertIn(b'does not match its selected contract', run.stderr)
        self.assertFalse((self.root / 'state').exists())


class NativeWorkerBudgetBundleTests(NativeWorkerJournalBundleTests):
    """Actual ordinary service/worker continuity with both selected HIA owners."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from tests.test_hia_execution_budget_native import ExecutionBudgetNativeTests
        cls.budget_fixture = type('WorkerBundleBudgetFixture', (), {})
        cold = os.environ.get(COLD)
        environment = {'HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT': cold} if cold else {}
        with patch.dict(os.environ, environment):
            ExecutionBudgetNativeTests.setUpClass.__func__(cls.budget_fixture)
        cls.budget_manifest = cls.budget_fixture.manifest

    @classmethod
    def tearDownClass(cls):
        from tests.test_hia_execution_budget_native import ExecutionBudgetNativeTests
        ExecutionBudgetNativeTests.tearDownClass.__func__(cls.budget_fixture)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        from hepta.hia_execution_budget_native import SELECTOR as budget_selector
        self.value['helpers'].append({'selector': budget_selector,
            'manifest_path': str(self.budget_manifest),
            'manifest_sha256': sha256(self.budget_manifest.read_bytes()).hexdigest()})
        self.write_bundle()

    def forbidden_references(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta import hia_execution_budget as reference
        stack = ExitStack()
        stack.enter_context(patch.object(HIAAgentService, '_reference_call',
                                        side_effect=AssertionError('host journal entered')))
        for cls, names in (
                (reference._ReferenceExecutionBudgetStore, ('__init__', 'create', 'claim', 'observe')),
                (reference._ReferenceBudgetClaim, ('__init__', 'run', 'complete'))):
            for name in names:
                stack.enter_context(patch.object(cls, name, side_effect=AssertionError('host budget entered')))
        return stack

    def test_actual_native_evaluation_budget_and_worker_replay_share_one_bundle(self):
        import sqlite3
        from hepta.hia_agent_contract import installation_manifest
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_execution_budget_native import BudgetState
        from hepta import hia_agent_runner
        from tests.test_hia_agent_native_tools import AgentToolCase
        before_environment = dict(os.environ)
        case = AgentToolCase('runTest')
        try:
            with patch.dict(os.environ, self.clean_env, clear=True), \
                    native_helpers_scope(str(self.bundle), self.digest), self.forbidden_references():
                case.setUp()
                pins = installation_manifest()
                _base, _candidate, baseline, build, receipts = case.build_pair()
                arguments = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                    candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                    verification_receipts=receipts)
                context = arguments['context']['id']
                before = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context,)).fetchone())
                count_before = case.service.store.db.execute('SELECT count(*) FROM requests').fetchone()[0]
                self.assertEqual((before['used_native_ns'], before['owner']), ('0', None))
                actual, events = [], []
                run_native, call_budget = hia_agent_runner.run_native_batch, BudgetState.call
                def observed(*args, **kwargs):
                    result = run_native(*args, **kwargs)
                    if kwargs.get('_mode') != 'reference': actual.append(result)
                    return result
                def budget_event(state, event, **kwargs):
                    result = call_budget(state, event, **kwargs)
                    events.append(event)
                    return result
                with patch.object(hia_agent_runner, 'run_native_batch', side_effect=observed), \
                        patch.object(BudgetState, 'call', budget_event):
                    first = case.service.call('hia_evaluate', arguments)
                self.assertEqual(first['status'], 'completed', first)
                self.assertGreaterEqual(len(actual), 1)
                self.assertTrue(all(row['started'] and row['termination_confirmed'] for row in actual))
                self.assertIn(6, events)
                after = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context,)).fetchone())
                self.assertGreater(int(after['used_native_ns']), 0)
                self.assertIsNone(after['owner'])
                count_after = case.service.store.db.execute('SELECT count(*) FROM requests').fetchone()[0]
                self.assertEqual(count_after, count_before + 1)
                case.service.close()
                case.service = HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
                with patch.object(hia_agent_runner, 'run_native_batch', side_effect=AssertionError('replayed effect')):
                    self.assertEqual(case.service.call('hia_evaluate', arguments), first)
                self.assertEqual(dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context,)).fetchone()), after)
                self.assertEqual(case.service.store.db.execute('SELECT count(*) FROM requests').fetchone()[0], count_after)
                self.assertEqual(native_helpers_identity()['native_helpers_sha256'], self.digest)
                case.service.close()
            self.assertEqual(dict(os.environ), before_environment)
            script = '''import sys
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
from hepta import hia_execution_budget as reference,hia_agent_runner
def forbidden(*args,**kwargs): raise AssertionError("host policy or replayed native effect")
HIAAgentService._reference_call=forbidden
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
hia_agent_runner.run_native_batch=forbidden
raise SystemExit(main(sys.argv[1:]))
'''
            request = self.envelope(pins, 'hia_evaluate', arguments)
            run = subprocess.run([sys.executable, '-B', '-E', '-s', '-c', script,
                '--state-root', str(case.state_root), '--request-json-stdin', *self.flags()],
                input=encoded(request), capture_output=True, cwd=ROOT, env=self.clean_env, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr.decode())
            report = json.loads(run.stdout)
            self.assertEqual(report['native_helpers_sha256'], self.digest)
            self.assertEqual(report['response'], first)
            with sqlite3.connect(case.state_root / 'state.sqlite3') as connection:
                connection.row_factory = sqlite3.Row
                self.assertEqual(dict(connection.execute('SELECT * FROM execution_budgets WHERE context_id=?',
                                                        (context,)).fetchone()), after)
                self.assertEqual(connection.execute('SELECT count(*) FROM requests').fetchone()[0], count_after)
        finally:
            if hasattr(case, 'service'): case.tearDown()

    def test_external_budget_or_journal_selector_refuses_before_worker_state(self):
        for selector in ('HEPTA_HIA_AGENT_JOURNAL_MANIFEST', 'HEPTA_HIA_EXECUTION_BUDGET_MANIFEST'):
            with self.subTest(selector=selector):
                result = self.worker(env={**self.clean_env, selector: '/ambient/cannot/override.json'})
                self.assertEqual((result.returncode, result.stdout), (2, b''))
                self.assertIn(b'explicit pinned bundle', result.stderr)
                self.assertFalse((self.root / 'state').exists())

    def test_installed_bundle_uses_packaged_journal_budget_and_original_service(self):
        from tests.test_hia_agent_installed_resources import AgentInstalledResourceTests as fixture
        fixture.setUpClass()
        try:
            program = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed bundle imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_journal_native import SOURCE as JOURNAL_SOURCE
from hepta.hia_execution_budget_native import SOURCE as BUDGET_SOURCE
from hepta import hia_execution_budget as reference
for source in (JOURNAL_SOURCE,BUDGET_SOURCE): assert Path(sys.argv[1]) in source.parents,source
def forbidden(*args,**kwargs): raise AssertionError('installed bundle used hosted policy')
HIAAgentService._reference_call=forbidden
reference._ReferenceExecutionBudgetStore.__init__=forbidden
reference._ReferenceBudgetClaim.__init__=forbidden
context='ctx-'+'1'*32
before=dict(os.environ)
with native_helpers_scope(sys.argv[2],sys.argv[3]):
    service=HIAAgentService(sys.argv[4])
    args={'catalog_sha256':service.catalog_sha256,'artifact_profile':service.profiles['artifact'],
          'request_key':'installed-bundle','source':{'kind':'utf8','text':'native journal and budget'}}
    first=service.call('hia_artifact',args)
    assert first['status']=='completed',first
    budget=service.store.execution_budgets
    budget.create(context)
    claim=budget.claim(context,'a'*64,1000,0)
    # An explicit host-outcome fixture checks accounting transport; the separate
    # ordinary evaluation control executes the actual HIA native child.
    claim.run(lambda **kwargs:{'wall_ns':'7','termination_confirmed':True},now=0,total_ms=1000)
    claim.complete()
    after=budget.observe(context)
    assert after['used_native_ns']=='7' and after['owner'] is None,after
    service.close()
    assert native_helpers_identity()['native_helpers_sha256']==sys.argv[3]
assert dict(os.environ)==before
with native_helpers_scope(sys.argv[2],sys.argv[3]):
    service=HIAAgentService(sys.argv[4])
    assert service.call('hia_artifact',args)==first
    assert service.store.execution_budgets.observe(context)==after
    assert service.store.db.execute('SELECT count(*) FROM requests').fetchone()[0]==1
    service.close()
assert dict(os.environ)==before
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
print(json.dumps({'artifact_response':first,'budget':after,'helper_sha256':sys.argv[3],
                  'budget_outcome_is_explicit_fixture':True},sort_keys=True))
'''
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program,
                str(fixture.installed), str(self.bundle), self.digest, str(self.root / 'installed-state')],
                capture_output=True, cwd=self.root, env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C'}, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads(result.stdout)
            self.assertEqual(report['helper_sha256'], self.digest)
            self.assertEqual(report['budget']['used_native_ns'], '7')
            self.assertIs(report['budget_outcome_is_explicit_fixture'], True)
        finally:
            fixture.tearDownClass()


class NativeWorkerCallerViewTests(unittest.TestCase):
    """Real ordinary buffer and Agent patch calls through one pinned bundle."""

    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_snapshot_native import SOURCE as snapshot_source, SCHEMA as snapshot_schema
        development = os.environ.get('HEPTA_HIA_WORKER_CALLER_VIEWS_DEVELOPMENT_DIR')
        cold = os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development caller images cannot override a requested cold report')
        temporary = tempfile.TemporaryDirectory(prefix='hia-caller-view-images-')
        cls.addClassCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        if development:
            # Explicit real-image custody only. No current-source cold claim is
            # inferred from these earlier artifacts or from their compiler hash.
            supplied = Path(development).resolve(strict=True)
            snapshot = supplied / 'descriptor-snapshot/manifest.json'
            patch_manifest = supplied / 'patch/manifest.json'
            admission_manifest = supplied / 'patch/admission-manifest.json'
        elif cold:
            from tools.build_hia_json_preflight import build
            from tools.build_hia_core_patch_cli import build as build_patch
            compiler = selected_compiler(cold)
            snapshot = build(folder / 'snapshot', compiler, Path(cold), candidate='agent-snapshot')
            build_patch(folder / 'patch', compiler, Path(cold))
            patch_manifest = folder / 'patch/manifest.json'
            admission_manifest = folder / 'patch/admission-manifest.json'
        else:
            # Preserve the existing explicit local seed development path. The
            # patch fixture observes the independent VM before its real B0/B1/B2.
            from tests.test_hia_core_patch_native import CorePatchNativeTests
            from tools.qualify_hia_selfhost import compile_stage
            fixture = type('_CallerPatchFixture', (), {})
            CorePatchNativeTests.setUpClass.__func__(fixture)
            cls.addClassCleanup(fixture.temp.cleanup)
            patch_manifest, admission_manifest = fixture.manifest, fixture.admission_manifest
            image, receipt = compile_stage(folder, 'snapshot', fixture.compiler, snapshot_source.read_bytes())
            snapshot = folder / 'manifest.json'
            snapshot.write_bytes(encoded({'schema': snapshot_schema,
                'source_sha256': sha256(snapshot_source.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(fixture.compiler.read_bytes()).hexdigest()}))
            (folder / 'development-compile.json').write_bytes(encoded(receipt))
        import hepta.hia_agent_snapshot_native as snapshot_module
        import hepta.hia_core_patch_native as patch_module
        import hepta.hia_core_admission_native as admission_module
        cls.assets = {}
        for name, module, manifest in (
                ('snapshot', snapshot_module, snapshot),
                ('patch', patch_module, patch_manifest),
                ('admission', admission_module, admission_manifest)):
            record = json.loads(manifest.read_bytes())
            image = manifest.parent / record['image_path']
            raw = image.read_bytes()
            assert record['schema'] == module.SCHEMA
            assert record['source_sha256'] == sha256(module.SOURCE.read_bytes()).hexdigest()
            assert record['image_sha256'] == sha256(raw).hexdigest()
            cls.assets[name] = record, raw

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-caller-view-case-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        environment = patch.dict(os.environ, clean, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.manifests = {}
        for name, (record, raw) in self.assets.items():
            folder = self.root / ('snapshot' if name == 'snapshot' else 'patch')
            folder.mkdir(exist_ok=True)
            (folder / record['image_path']).write_bytes(raw)
            manifest = folder / ('admission-manifest.json' if name == 'admission' else 'manifest.json')
            manifest.write_bytes(encoded(record))
            self.manifests[name] = manifest
        self.value = {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
            {'selector': selector, 'manifest_path': str(self.manifests[name]),
             'manifest_sha256': sha256(self.manifests[name].read_bytes()).hexdigest()}
            for name, selector in (('patch', 'HEPTA_HIA_CORE_PATCH_MANIFEST'),
                                   ('admission', 'HEPTA_HIA_CORE_ADMISSION_MANIFEST'),
                                   ('snapshot', 'HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST'))]}
        self.bundle = self.root / 'bundle.json'
        self.bundle.write_bytes(encoded(self.value))

    def scope(self):
        return native_helpers_scope(str(self.bundle), sha256(self.bundle.read_bytes()).hexdigest())

    @contextmanager
    def service_session(self):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient, exhaustive_u8_workload
        with self.scope():
            self.service = HIAAgentService(self.root / 'state')
            try:
                session = Session(ToolClient(self.service.call), prefix=self._testMethodName)
                session.freeze(exhaustive_u8_workload())
                yield session
            finally:
                self.service.close()

    def arguments(self, session, program, request, *, declared_schema=None):
        return session.arguments(change={'kind': 'patch',
            'base_program': session.artifact(program), 'patch': session.artifact(request),
            'patch_schema': request['schema'] if declared_schema is None else declared_schema})

    def test_original_buffer_callers_execute_native_boundaries_and_refusals(self):
        from hepta.hia_agent_buffers import buffer_size, buffer_bytes
        from hepta.hia_agent_snapshot_native import MAX_EXTENT
        from hepta.hia_agent_store import AgentRejected
        with self.scope(), \
                patch('hepta.hia_agent_buffers._buffer_size_reference', side_effect=AssertionError('host size policy')), \
                patch('hepta.hia_agent_buffers._buffer_bytes_reference', side_effect=AssertionError('host materializer')):
            for value, expected in (({'bytes_hex': ''}, b''),
                    ({'bytes_hex': '012aff'}, bytes.fromhex('012aff')),
                    ({'byte_length': 0, 'fill_byte': 255}, b''),
                    ({'byte_length': MAX_EXTENT, 'fill_byte': 255}, b'\xff' * MAX_EXTENT)):
                with self.subTest(descriptor=value):
                    self.assertEqual(buffer_size(value), len(expected))
                    self.assertEqual(buffer_bytes(value), expected)
            for value in ({'bytes_hex': '0'}, {'bytes_hex': 'AA'},
                    {'byte_length': True, 'fill_byte': 0},
                    {'byte_length': MAX_EXTENT + 1, 'fill_byte': 0},
                    {'byte_length': -1, 'fill_byte': 0},
                    {'byte_length': 1, 'fill_byte': 256}, {'extra': 0}, []):
                with self.subTest(refused=value):
                    for function in (buffer_size, buffer_bytes):
                        with self.assertRaises(AgentRejected) as caught:
                            function(value)
                        self.assertEqual(caught.exception.code, 'E_HIA_ARGUMENTS')

    def test_two_exact_patch_views_execute_cli_and_original_service_payloads(self):
        from hepta.hia_agent_candidate_native import NativeAgentCandidatePatch, installed_agent_candidate_patch
        from hepta.hia_core_patch_native import NativeCorePatch, installed_core_patch
        from hepta.hia_program_tools import apply_program_patch
        from hepta.hia_agent_store import wire
        from tests.test_hia_agent_candidate_native import AgentCandidateNativeTests
        from tests.test_hia_core_patch_native import four_kinds
        program, requests = four_kinds()
        expected = [apply_program_patch(program, request) for request in requests]
        calls = []
        original = NativeAgentCandidatePatch.result
        def observed(image, *args, **kwargs):
            calls.append('native-agent-result')
            return original(image, *args, **kwargs)
        with self.service_session() as session:
            primary = installed_core_patch(str(self.manifests['patch']))
            agent = installed_agent_candidate_patch(str(self.manifests['patch']))
            self.assertIs(type(primary), NativeCorePatch)
            self.assertIs(type(agent), NativeAgentCandidatePatch)
            self.assertIsNot(primary, agent)
            self.assertEqual(bytes(primary._mapping), bytes(agent._mapping))
            # The ordinary CLI patch consumer still uses its original view.
            self.assertEqual(apply_program_patch(program, requests[0])[0].canonical_bytes,
                             expected[0][0].canonical_bytes)
            with patch.object(NativeAgentCandidatePatch, 'result', observed):
                for request, (wanted, diagnostic) in zip(requests, expected):
                    args = self.arguments(session, program, request)
                    payloads = (wire(program), wire(request), wanted.canonical_bytes, wire(diagnostic))
                    with AgentCandidateNativeTests.forbid_payload_owners(self, payloads):
                        response = self.service.call('hia_candidate', args)
                    self.assertEqual(response['status'], 'completed', response)
                    result = response['result']
                    actual, metadata = self.service.store.get(result['candidate'], kind='core')
                    details, _ = self.service.store.get(result['diagnostics'], kind='candidate-diagnostics')
                    self.assertEqual((actual, details), (wanted.canonical_bytes, wire(diagnostic)))
                    self.assertEqual(metadata, {'context': session.context})
                    self.assertTrue(result['core_admitted'])
                    self.assertFalse(result['adopted'])
        self.assertEqual(calls, ['native-agent-result'] * len(requests))

    def test_original_service_refusal_is_durable_without_candidate_or_host_fallback(self):
        from hepta.hia_agent_candidate_native import NativeAgentCandidatePatch
        from hepta.hia_core_patch_native import NativeCorePatch
        from tests.test_hia_agent_candidate_native import AgentCandidateNativeTests
        from tests.test_hia_program_tools import scalar_program, add_two_patch
        program = scalar_program()
        request = add_two_patch(program)
        request['expected_sha256'] = '0' * 64
        calls = []
        original = NativeCorePatch.transform
        def observed(image, *args, **kwargs):
            calls.append('native-extract')
            return original(image, *args, **kwargs)
        with self.service_session() as session:
            args = self.arguments(session, program, request)
            before = self.service.store.db.execute(
                "SELECT COUNT(*) FROM artifacts WHERE kind IN ('core','candidate-diagnostics')").fetchone()[0]
            with patch.object(NativeCorePatch, 'transform', observed), \
                    AgentCandidateNativeTests.forbid_payload_owners(self):
                response = self.service.call('hia_candidate', args)
            self.assertEqual(response['status'], 'rejected', response)
            self.assertIn('snapshot', response['error']['message'].lower())
            self.assertEqual(calls, ['native-extract'])
            self.assertEqual(self.service.store.db.execute(
                "SELECT COUNT(*) FROM artifacts WHERE kind IN ('core','candidate-diagnostics')").fetchone()[0], before)
            attempts = self.service.store.db.execute('SELECT attempts FROM contexts WHERE id=?',
                                                    (session.context['id'],)).fetchone()[0]
            with patch.object(NativeAgentCandidatePatch, 'result', side_effect=AssertionError('replayed patch')), \
                    patch.object(NativeCorePatch, 'transform', side_effect=AssertionError('replayed extract')):
                self.assertEqual(self.service.call('hia_candidate', args), response)
            self.assertEqual(self.service.store.db.execute('SELECT attempts FROM contexts WHERE id=?',
                (session.context['id'],)).fetchone()[0], attempts)

    def test_unknown_factories_and_wrong_adjacent_admission_never_use_general_loader(self):
        from hepta.hia_agent_candidate_native import NativeAgentCandidatePatch
        from hepta.hia_core_patch_native import SOURCE as patch_source, SCHEMA as patch_schema
        from hepta.hia_json_preflight_native import _installed_json_image
        class UnlistedPatchView(NativeAgentCandidatePatch):
            pass
        with self.scope(), patch('hepta.hia_json_preflight_native._load_manifest',
                                 side_effect=AssertionError('unlisted factory reached general loader')):
            with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                _installed_json_image(str(self.manifests['patch']), patch_source, patch_schema, UnlistedPatchView)
        for missing in (True, False):
            value = deepcopy(self.value)
            if missing:
                value['helpers'] = [row for row in value['helpers']
                                    if row['selector'] != 'HEPTA_HIA_CORE_ADMISSION_MANIFEST']
            else:
                wrong = self.root / 'wrong-admission.json'
                wrong.write_bytes(self.manifests['admission'].read_bytes())
                value['helpers'][1]['manifest_path'] = str(wrong)
            self.bundle.write_bytes(encoded(value))
            with patch('hepta.hia_native_helpers.importlib.import_module',
                       side_effect=AssertionError('dependency refusal happened after import')):
                with self.assertRaisesRegex(ValueError, 'exact adjacent admission'):
                    with self.scope():
                        self.fail('unbound adjacent admission accepted')


if __name__ == "__main__":
    unittest.main()
