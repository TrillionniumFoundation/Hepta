"""Actual native-helper worker calls plus custody and interruption controls.

The real HIA scalar-identity image is compiled through B0/B1/B2 below. These
tests qualify this integration path; they are not the full cold replay or a
whole-language compiler refinement proof.
"""
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
    ABI, SCHEMA, TARGET, NativeHelpersBinding, native_helpers_identity,
    native_helpers_scope,
)
from hepta.hia_agent_identity_native import (
    SCHEMA as IMAGE_SCHEMA, SOURCE, SELECTOR, installed_agent_identity,
)

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_WORKER_HELPERS_DEVELOPMENT_MANIFEST'
COLD_REPORT = 'HEPTA_HIA_AGENT_IDENTITY_COLD_REPORT'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class NativeWorkerHelperFixtureTests(unittest.TestCase):
    def test_development_helper_cannot_override_requested_cold_before_fixture_work(self):
        with patch.dict(os.environ, {DEVELOPMENT: '/unread-helper-manifest', COLD_REPORT: '/unread-cold'}), \
                patch('tempfile.TemporaryDirectory', side_effect=AssertionError('fixture work before admission')):
            with self.assertRaisesRegex(ValueError, 'development helper cannot override'):
                NativeWorkerHelperTests.setUpClass()


class NativeWorkerHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development = os.environ.get(DEVELOPMENT)
        if development and os.environ.get(COLD_REPORT):
            raise ValueError('development helper cannot override the requested identity cold report')
        cls.native_fixture = None
        if development:
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


if __name__ == "__main__":
    unittest.main()
