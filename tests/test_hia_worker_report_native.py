"""Independent worker byte/order comparisons and native continuation controls."""
from __future__ import annotations

import ast
import argparse
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import io
import json
import math
import os
from pathlib import Path
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import zipfile

from hepta import hia_agent_worker as worker
from hepta.hia_agent_store import wire, digest
from hepta.hia_worker_report_native import (
    SOURCE, SELECTOR, MAGIC, NativeWorkerReport, WorkerSession, installed_worker_report,
)

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_WORKER_REPORT_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_WORKER_REPORT_DEVELOPMENT_MANIFEST'
FIXTURE_EVIDENCE = 'HEPTA_HIA_WORKER_REPORT_FIXTURE_EVIDENCE'
IDENTITIES = {'worker_sha256': 'a' * 64, 'backend_sha256': 'b' * 64, 'catalog_sha256': 'c' * 64}


def envelope(arguments=None, *, tool='hia_describe', catalog='c' * 64):
    value = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
             'arguments': {'section': 'manifest'} if arguments is None else arguments,
             'profile_sha256': 'd' * 64, 'catalog_sha256': catalog}
    value['request_sha256'] = sha256(wire(value)).hexdigest()
    return value


class Fixture:
    """Lower-level policy differential, NOT ordinary worker custody acceptance.

    Foreign callback exceptions are observed outside main's outer handler;
    separate tests below exercise the real main with its pinned v2 bundle.
    """
    def __init__(self):
        self.events = []
        self.identities = dict(IDENTITIES)
        self.after = dict(IDENTITIES)
        self.request = envelope()
        self.raw = wire(self.request)
        self.response = {'status': 'completed', 'result': {'z': -0.0, 'a': '雪'}}
        self.argv = ['--state-root', '/unused-native-worker-state', '--request-json-stdin']
        self.environment = {}
        self.initial_error = self.construct_error = self.call_error = self.close_error = self.after_error = None
        self.on_construct = self.on_call = self.on_close = self.on_after = None
        self.on_read = None
        self.on_output = None
        self.decoded = None
        self.extra_patches = []

    def run(self, manifest=None):
        output, errors = io.BytesIO(), io.StringIO()
        fixture = self
        class Input:
            def read(self, size):
                fixture.events.append(('read', size))
                if fixture.on_read:
                    fixture.on_read()
                return fixture.raw[:size]
        class Output:
            def write(self, value):
                fixture.events.append(('stdout', len(value)))
                if fixture.on_output:
                    fixture.on_output()
                return output.write(value)
        class Service:
            def __init__(self, state, *, artifact_roots):
                fixture.events.append(('construct', str(state), tuple(artifact_roots)))
                if fixture.on_construct:
                    fixture.on_construct()
                if fixture.construct_error is not None:
                    raise fixture.construct_error
            def call(self, tool, arguments):
                fixture.events.append(('call', tool))
                if fixture.on_call:
                    fixture.on_call()
                if fixture.call_error is not None:
                    raise fixture.call_error
                return fixture.response
            def close(self):
                fixture.events.append(('close',))
                if fixture.on_close:
                    fixture.on_close()
                if fixture.close_error is not None:
                    raise fixture.close_error
        reads = 0
        def installation():
            nonlocal reads
            reads += 1
            fixture.events.append(('manifest', reads))
            if reads == 1:
                if fixture.initial_error is not None:
                    raise fixture.initial_error
                return fixture.identities
            if fixture.on_after:
                fixture.on_after()
            if fixture.after_error is not None:
                raise fixture.after_error
            return fixture.after
        decoder = worker.decode_data
        def decode(raw):
            value = decoder(raw)
            fixture.decoded = value
            return value
        def fixed_uuid():
            fixture.events.append(('uuid',))
            return uuid.UUID(int=1)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.environment, clear=True))
            if manifest is not None:
                os.environ[SELECTOR] = str(manifest)
                stack.enter_context(patch.object(worker, '_reference_run',
                    side_effect=AssertionError('retained worker report/control owner entered')))
                original_wire = worker.wire
                def admission_only(value):
                    if type(value) is dict and value.get('schema') == 'hia-agent-worker-report-v1':
                        raise AssertionError('hosted report wire entered')
                    return original_wire(value)
                stack.enter_context(patch.object(worker, 'wire', admission_only))
            stack.enter_context(patch.object(worker, 'installation_manifest', installation))
            stack.enter_context(patch.object(worker, 'decode_data', decode))
            stack.enter_context(patch.object(worker.uuid, 'uuid4', fixed_uuid))
            stack.enter_context(patch('hepta.hia_agent_service.HIAAgentService', Service))
            stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=Input())))
            stack.enter_context(patch.object(sys, 'stdout', SimpleNamespace(buffer=Output())))
            stack.enter_context(patch.object(sys, 'stderr', errors))
            for context in self.extra_patches:
                stack.enter_context(context)
            try:
                parser = argparse.ArgumentParser(description=worker.__doc__)
                for name in ('installation-manifest', 'request-json-stdin'):
                    parser.add_argument('--' + name, action='store_true')
                for name in ('state-root', 'expected-worker-sha256', 'expected-backend-sha256',
                             'expected-catalog-sha256', 'native-helpers-manifest',
                             'expected-native-helpers-sha256'):
                    parser.add_argument('--' + name)
                parser.add_argument('--artifact-root', action='append', default=[])
                args = parser.parse_args(self.argv)
                selected = worker._run if manifest is not None else worker._reference_run
                result = ('return', selected(parser, args))
            except BaseException as exc:
                result = ('raise', type(exc).__name__, str(exc))
        return result, output.getvalue(), errors.getvalue(), self.events


class WorkerReportSourceTests(unittest.TestCase):
    def test_generated_source_resource_and_no_unqualified_build_output(self):
        from tools.generate_hia_worker_report import document
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from tools.build_hia_worker_report import build
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertIn('examples/hia_bootstrap/worker_report.hepta', NATIVE_SOURCE_FILES)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'compiler').write_bytes(b'not a qualified compiler')
            (folder / 'cold').write_bytes(b'{}')
            with self.assertRaises(ValueError):
                build(folder / 'out', folder / 'compiler', folder / 'cold')
            self.assertFalse((folder / 'out').exists())

    def test_independent_core_vm_policy_emits_native_virtual_report(self):
        # Wire encoding has its own independent VM witness. This witness runs
        # the policy in Core and inspects its native virtual graph directly.
        script = r'''
import ctypes,io,json,resource,sys
from types import SimpleNamespace
from unittest.mock import patch
resource.setrlimit(resource.RLIMIT_AS,(384 << 20,384 << 20))
from hepta import hia_agent_worker as worker
from hepta.hia_agent_store import wire
from hashlib import sha256
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from hepta.hia_worker_report_native import SOURCE,NativeWorkerReport
program=assemble_program(SOURCE.read_bytes())
class VM:
 def __init__(self):self.calls=0
 def _entry(self,s,ns,o,no,w,nw):
  owners=[_Owner(-1,bytearray(ctypes.string_at(s,ns))),_Owner(-2,bytearray(ctypes.string_at(o,no))),_Owner(-3,bytearray(ctypes.string_at(w,nw)))]
  machine=_Machine(program,25000000,64 << 20,None,128)
  result=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
  ctypes.memmove(o,bytes(owners[1].data),no);ctypes.memmove(w,bytes(owners[2].data),nw)
  self.calls+=1
  return result
class Graph:
 def encode_observed(self,observer,root,*args,**kwargs):
  assert root >= 1 << 63
  count=10 if sys.argv[1]=='helper' else 9
  assert observer.summary(root)==(7,count,0,0)
  keys=[observer.value(observer.child(root,i,0)) for i in range(count)]
  assert keys==['schema','tool','request_sha256','profile_sha256','catalog_sha256','backend_sha256','worker_sha256','complete','response']+(['native_helpers_sha256'] if count==10 else [])
  if count==10:assert observer.value(observer.child(root,9,1))=='e'*64
  assert observer.value(observer.child(root,8,1))=={'status':'completed'}
  try:observer.value(root)
  except RuntimeError:pass
  else:raise AssertionError('virtual report became a host dictionary')
  return b'GRAPH_WITNESS'
ids={'worker_sha256':'a'*64,'backend_sha256':'b'*64,'catalog_sha256':'c'*64}
if sys.argv[1]=='helper':ids['native_helpers_sha256']='e'*64
request={'schema':'hia-agent-worker-request-v1','tool':'hia_describe','arguments':{},'profile_sha256':'d'*64,'catalog_sha256':'c'*64}
request['request_sha256']=sha256(wire(request)).hexdigest();raw=wire(request)
args=SimpleNamespace(installation_manifest=False,request_json_stdin=True,state_root='/unused',artifact_root=[],expected_worker_sha256=None,expected_backend_sha256=None,expected_catalog_sha256=None)
class Service:
 def __init__(self,*args,**kwargs):pass
 def call(self,*args):return {'status':'completed'}
 def close(self):pass
vm=VM();output=io.BytesIO()
with patch.dict('os.environ',{},clear=True),patch('hepta.hia_agent_service.HIAAgentService',Service),patch.object(worker,'installation_manifest',return_value=dict(ids)),patch.object(worker.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch.object(worker.sys,'stdout',SimpleNamespace(buffer=output)),patch.object(worker,'_reference_run',side_effect=AssertionError('retained worker')):
 assert NativeWorkerReport(vm,Graph()).run(args,None,ids,worker)==0
assert output.getvalue()==b'GRAPH_WITNESS\n'
print(json.dumps({'native_policy_image_loaded':False,'calls':vm.calls,'virtual_report_fields':10 if sys.argv[1]=='helper' else 9}))
'''
        for profile, fields in (('plain', 9), ('helper', 10)):
            with self.subTest(profile=profile):
                result = subprocess.run([sys.executable, '-B', '-c', script, profile], cwd=ROOT,
                                        capture_output=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)['virtual_report_fields'], fields)


class WorkerReportNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError('development cannot override current cold selection')
        if not cold and not development:
            raise unittest.SkipTest('requires explicit worker report cold report or development bundle')
        cls.temporary = None
        evidence = os.environ.get(FIXTURE_EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).absolute()
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-worker-report-tests-')
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        if cold:
            from tools.build_hia_worker_report import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', cls.compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            request = json.loads((cls.manifest.parent / 'policy/worker-report.request.json').read_bytes())
            cls.compiler = Path(request['image'])
            expected = json.loads((cls.manifest.parent / 'policy/manifest.json').read_bytes())['compiler_sha256']
            if sha256(cls.compiler.read_bytes()).hexdigest() != expected:
                raise AssertionError('development compiler identity drifted')
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.owner = installed_worker_report(str(cls.manifest))
        # Ordinary-main tests use real request + policy + wire images, not a
        # selector bypass or a mocked native-helper scope.
        from tools.build_hia_json_preflight import build as build_request
        from tools.qualify_hia_selfhost import compile_stage
        from tools.build_hia_worker_report import bind_worker_bundle
        from hepta import hia_native_helpers as authority
        from hepta.hia_worker_request_native import SOURCE as REQUEST_SOURCE, SCHEMA as REQUEST_SCHEMA
        request_folder = cls.folder / 'custody-request'
        if cold:
            request_manifest = build_request(request_folder, cls.compiler, Path(cold), candidate='worker-request')
        else:
            request_folder.mkdir(mode=0o700)
            image, _ = compile_stage(request_folder, 'worker-request', cls.compiler, REQUEST_SOURCE.read_bytes())
            request_manifest = request_folder / 'manifest.json'
            request_manifest.write_text(json.dumps({'schema': REQUEST_SCHEMA,
                'source_sha256': sha256(REQUEST_SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest()}))
        request_manifest.chmod(0o600)
        base = cls.folder / 'helpers-v1.json'
        base.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': [{'selector': 'HEPTA_HIA_WORKER_REQUEST_MANIFEST',
                'manifest_path': str(request_manifest),
                'manifest_sha256': sha256(request_manifest.read_bytes()).hexdigest()}]}))
        base.chmod(0o600)
        cls.worker_bundle, cls.worker_pin = bind_worker_bundle(
            cls.folder / 'worker-v2.json', base, cls.manifest)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def same(self, configure=lambda fixture: None):
        old, new = Fixture(), Fixture()
        configure(old); configure(new)
        expected, actual = old.run(), new.run(self.manifest)
        self.assertEqual(actual, expected)
        return actual, new

    def test_ordinary_success_and_service_close_exception_order(self):
        success, _ = self.same()
        self.assertEqual(success[0], ('return', 0))
        for location in ('construct', 'call', 'close', 'after', 'initial'):
            for exception in (ValueError, TypeError, OSError, RuntimeError, KeyboardInterrupt, SystemExit, MemoryError):
                with self.subTest(location=location, exception=exception.__name__):
                    def configure(f, location=location, exception=exception):
                        setattr(f, location + '_error', exception('injected-' + location))
                    actual, _ = self.same(configure)
                    events = [entry[0] for entry in actual[3]]
                    if location == 'call':
                        self.assertIn('close', events)
                        self.assertEqual(events.count('manifest'), 1)
                    if location in ('construct', 'initial'):
                        self.assertNotIn('close', events)
        def override(f):
            f.call_error = RuntimeError('call-original')
            f.close_error = ValueError('close-overrides')
        actual, _ = self.same(override)
        self.assertEqual(json.loads(actual[1])['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')

    def test_modes_pins_and_malformed_request_correlation(self):
        for args in (['--installation-manifest'], ['--installation-manifest', '--request-json-stdin'],
                     [], ['--request-json-stdin'], ['--state-root', ''],
                     ['--state-root', '/unused', '--request-json-stdin', '--expected-worker-sha256', 'wrong'],
                     ['--state-root', '/unused', '--request-json-stdin', '--expected-backend-sha256', 'wrong'],
                     ['--state-root', '/unused', '--request-json-stdin', '--expected-catalog-sha256', 'wrong']):
            with self.subTest(args=args):
                actual, _ = self.same(lambda f, args=args: setattr(f, 'argv', args))
                self.assertNotIn('construct', [e[0] for e in actual[3]])
        cases = [b'{', b'{"a":1,"a":2}', b'1e9999', b'"\\ud800"', b'null', b'{}', b'[]']
        for missing in ('tool', 'request_sha256', 'profile_sha256', 'catalog_sha256'):
            value = envelope(); del value[missing]; cases.append(wire(value))
        for raw in cases:
            with self.subTest(raw=raw[:80]):
                actual, _ = self.same(lambda f, raw=raw: setattr(f, 'raw', raw))
                self.assertEqual(actual[0], ('return', 2))
                self.assertEqual(actual[1], b'')
                self.assertNotIn('uuid', [e[0] for e in actual[3]])
        def correlated(f):
            value = envelope(); value['schema'] = 'wrong'; f.raw = wire(value)
        actual, _ = self.same(correlated)
        self.assertEqual(json.loads(actual[1])['response']['error']['code'], 'E_HIA_WORKER_SCHEMA')

    def test_entire_manifest_equality_and_latest_identity_adoption(self):
        pairs = [({'extra': 1}, {}), ({'extra': [1, {'z': '雪', 'a': True}]}, {'extra': [1.0, {'a': 1, 'z': '雪'}]}),
                 ({'extra': (1, 2)}, {'extra': [1, 2]}), ({'extra': -0.0}, {'extra': 0}),
                 ({'extra': 2 ** 100}, {'extra': float(2 ** 100)}),
                 ({'extra': 2 ** 100 + 1}, {'extra': float(2 ** 100)}),
                 ({'extra': float('nan')}, {'extra': float('nan')}),
                 ({'extra': float('inf')}, {'extra': float('inf')}),
                 ({'extra': '\ud800'}, {'extra': '\ud800'})]
        for left, right in pairs:
            with self.subTest(left=repr(left), right=repr(right)):
                self.same(lambda f, left=left, right=right: (f.identities.update(left), f.after.update(right)))
        def changed(f):
            f.after.update(worker_sha256='e' * 64, backend_sha256='f' * 64, catalog_sha256='0' * 64, extra=1)
        actual, _ = self.same(changed)
        report = json.loads(actual[1])
        self.assertEqual((report['worker_sha256'], report['backend_sha256'], report['catalog_sha256']),
                         ('e' * 64, 'f' * 64, 'c' * 64))
        self.assertEqual(report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
        # Child identity shortcuts include a shared NaN exactly as Python's
        # container comparison does, while independently created NaNs differ.
        def shared_nan(f):
            value = float('nan'); f.identities['extra'] = [value]; f.after['extra'] = [value]
        self.same(shared_nan)

    def test_optional_helper_identity_presence_adoption_and_unknown_report_order(self):
        cases = ((None, None), ('1' * 64, '1' * 64), ('1' * 64, '2' * 64),
                 (None, '2' * 64), ('1' * 64, None))
        for before, after in cases:
            with self.subTest(before=before, after=after):
                def configure(f):
                    if before is not None:
                        f.identities['native_helpers_sha256'] = before
                    if after is not None:
                        f.after['native_helpers_sha256'] = after
                actual, _ = self.same(configure)
                report = json.loads(actual[1])
                self.assertEqual('native_helpers_sha256' in report, after is not None)
                if after is not None:
                    self.assertEqual(report['native_helpers_sha256'], after)
                if before != after:
                    self.assertEqual(report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                    self.assertEqual(report['response']['error']['retry_action'], 'observe_original')

    def test_manifest_numeric_unicode_and_container_random_differential(self):
        randomizer = random.Random(714209)
        numbers = [None, False, True, 0, 1, -1, 2 ** 53, 2 ** 53 + 1, 2 ** 200,
                   -0.0, 0.5, -1.5, 1e200, math.inf, -math.inf, math.nan]
        for _ in range(80):
            bits = randomizer.getrandbits(64)
            value = struct.unpack('<d', struct.pack('<Q', bits))[0]
            numbers.append(value)
            if math.isfinite(value):
                numbers.append(int(value))
        for index in range(160):
            a, b = randomizer.choice(numbers), randomizer.choice(numbers)
            if index % 4 == 0 and type(a) in (int, bool):
                b = float(a)
            def configure(f, a=a, b=b, index=index):
                f.identities['extension'] = [{'☃': [a, index]}]
                f.after['extension'] = [{'☃': [b, index]}]
            with self.subTest(index=index, a=repr(a), b=repr(b)):
                self.same(configure)

    def test_foreign_leaf_effects_and_list_mutation_order(self):
        def configure(f):
            class Leaf:
                def __init__(self, label): self.label = label
                def __eq__(self, other):
                    f.events.append(('equal', self.label, other.label))
                    f.after['tail'] = 7
                    f.identities['tail'] = 7
                    return True
                def __ne__(self, other):
                    raise AssertionError('container child used inequality')
            f.identities['extension'] = {'key': Leaf('right')}
            f.after['extension'] = {'key': Leaf('left')}
            f.events.clear()
        self.same(configure)
        def lists(f):
            left, right = [], []
            class Leaf:
                def __eq__(self, other):
                    f.events.append(('append',))
                    left.append(3); right.append(3)
                    return True
            left.append(Leaf()); right.append(Leaf())
            f.after['extension'] = left; f.identities['extension'] = right
        self.same(lists)

    def test_stored_hash_foreign_key_capability_and_public_builtin_profile(self):
        from hepta.hia_worker_report_native import _dict_primitives
        def foreign(f):
            class Key:
                def __hash__(self):
                    f.events.append(('foreign-hash',)); return 17
                def __eq__(self, other):
                    f.events.append(('key-equal',)); return True
            f.identities['extension'] = {Key(): 7}
            f.after['extension'] = {Key(): 7}
            f.events.clear()
        if _dict_primitives()[2]:
            actual, _ = self.same(foreign)
            self.assertNotIn(('foreign-hash',), actual[3])
        else:
            f = Fixture(); foreign(f)
            actual = f.run(self.manifest)
            self.assertEqual(actual[0][0:2], ('raise', 'RuntimeError'))
            self.assertIn('stored hash', actual[0][2])
            self.assertNotIn(('foreign-hash',), actual[3])
            self.assertEqual(actual[1], b'')
        # Exercise the real public C function even on a runtime that exports
        # the private one. This is a profile refusal, not a parity claim for
        # foreign keys on runtimes lacking the stored-hash observation.
        with patch.object(ctypes.pythonapi, '_PyDict_Next', None, create=True):
            for key in ('snow-雪', b'bytes', 7, 1.25, False, None):
                with self.subTest(public_key=repr(key)):
                    def builtin(f, key=key):
                        f.identities['extension'] = {key: [True, -0.0]}
                        f.after['extension'] = {key: [1, 0]}
                    self.same(builtin)
            f = Fixture(); foreign(f)
            actual = f.run(self.manifest)
            self.assertEqual(actual[0][0:2], ('raise', 'RuntimeError'))
            self.assertIn('stored hash', actual[0][2])
            self.assertNotIn(('foreign-hash',), actual[3])
            self.assertEqual(actual[1], b'')

    def test_error_callbacks_order_mutation_and_unicode_slice(self):
        def configure(f):
            class Error(ValueError):
                @property
                def code(self):
                    f.events.append(('code',)); f.decoded['tool'] = 'changed-in-code'; return 'CUSTOM'
                def __str__(self):
                    f.events.append(('message',)); f.decoded['profile_sha256'] = 'e' * 64; return '雪' * 4096 + '\ud800'
                @property
                def retry_action(self):
                    f.events.append(('retry',)); f.decoded['catalog_sha256'] = 'f' * 64; return 'stop'
            f.construct_error = Error()
        actual, _ = self.same(configure)
        report = json.loads(actual[1]); error = report['response']['error']
        self.assertEqual((error['code'], error['message'], report['tool']), ('CUSTOM', '雪' * 4096, 'changed-in-code'))
        order = [e[0] for e in actual[3]]
        self.assertLess(order.index('uuid'), order.index('code'))
        self.assertLess(order.index('code'), order.index('message'))
        self.assertLess(order.index('message'), order.index('retry'))
        for count in (0, 4095, 4096, 4097):
            with self.subTest(count=count):
                def message(f, count=count):
                    f.construct_error = ValueError('雪' * count)
                self.same(message)
        def entered(f):
            class Unreadable(ValueError):
                def __getattribute__(self, name):
                    if name in ('code', 'retry_action', '__class__'):
                        raise AssertionError('entered error attributes read')
                    return super().__getattribute__(name)
                def __str__(self): raise AssertionError('entered error message read')
            f.call_error = Unreadable()
        self.same(entered)

    def test_error_callback_failure_and_output_encoding_remain_outside_catch(self):
        for location in ('code', 'message', 'retry'):
            def configure(f, location=location):
                class Error(ValueError):
                    @property
                    def code(self):
                        if location == 'code': raise OSError('callback-code')
                        return 'CUSTOM'
                    def __str__(self):
                        if location == 'message': raise OSError('callback-message')
                        return 'error'
                    @property
                    def retry_action(self):
                        if location == 'retry': raise OSError('callback-retry')
                        return 'stop'
                f.construct_error = Error()
            with self.subTest(location=location):
                actual, _ = self.same(configure)
                self.assertEqual(actual[0][0:2], ('raise', 'OSError'))
                self.assertEqual(actual[1], b'')
        for response in ({'bad': '\ud800'}, {'bad': math.inf}, {1: 1, '1': 2}, {'bad': object()}):
            with self.subTest(response=repr(response)):
                actual, _ = self.same(lambda f, response=response: setattr(f, 'response', response))
                self.assertEqual(actual[0][0], 'raise')
                self.assertNotIn('uuid', [e[0] for e in actual[3]])
        def cycle(f):
            f.response = []; f.response.append(f.response)
        self.same(cycle)

    def test_active_exception_intervals_chains_and_same_object_reraise(self):
        def observe(native, case, ambient):
            f = Fixture()
            observations = []
            tracked = None
            original = None
            def tag(exc):
                return None if exc is None else (type(exc).__name__, exc.args)
            def mark(name):
                observations.append((name, tag(sys.exception())))
            f.on_output = lambda: mark('output-outside-handler')
            if case in ('close-chain', 'close-getter', 'close-same'):
                original = KeyboardInterrupt('original-call')
                tracked = original if case == 'close-same' else SystemExit('close-replacement')
                if case != 'close-same':
                    tracked.__cause__ = ValueError('deliberate-cause')
                f.call_error, f.close_error = original, tracked
                f.on_close = lambda: mark('close-call')
                if case == 'close-getter':
                    class Service:
                        def __init__(self, *args, **kwargs): pass
                        def call(self, *args): raise original
                        @property
                        def close(self):
                            mark('close-getter')
                            raise tracked
                    f.extra_patches.append(patch('hepta.hia_agent_service.HIAAgentService', Service))
            else:
                replacement = OSError('callback-replacement')
                class Error(ValueError):
                    @property
                    def code(self):
                        mark('code')
                        if case == 'callback-chain': raise replacement
                        if case == 'callback-same': raise self
                        return 'OBSERVED'
                    def __str__(self):
                        mark('message'); return 'observed-message'
                    @property
                    def retry_action(self):
                        mark('retry'); return 'stop'
                original = Error('original-error')
                tracked = replacement if case == 'callback-chain' else original
                if case == 'entered-handler':
                    f.call_error = original
                    parent = worker.AgentRejected
                    class ReportedUnknown(parent):
                        def __getattribute__(self, name):
                            if name in ('code', 'retry_action'):
                                mark('unknown-' + name)
                            return super().__getattribute__(name)
                        def __str__(self):
                            mark('unknown-message'); return super().__str__()
                    f.extra_patches.append(patch.object(worker, 'AgentRejected', ReportedUnknown))
                elif case == 'uncorrelated-handler':
                    f.extra_patches.append(patch.object(worker, 'decode_data', side_effect=original))
                else:
                    f.construct_error = original
                def identifier():
                    mark('uuid'); return uuid.UUID(int=1)
                f.extra_patches.append(patch.object(worker.uuid, 'uuid4', identifier))
            def invoke():
                result = f.run(self.manifest if native else None)
                mark('returned-to-caller')
                return result
            if ambient:
                try:
                    raise OSError('ambient-caller')
                except OSError:
                    result = invoke()
            else:
                result = invoke()
            frames = []
            traceback = BaseException.__dict__['__traceback__'].__get__(tracked, BaseException)
            while traceback is not None:
                frames.append(traceback.tb_frame.f_code.co_name)
                traceback = traceback.tb_next
            # Activating a saved exception may only remove its synthetic frame;
            # a real callback raising the same object must retain its new frame.
            if case == 'callback-same': self.assertIn('code', frames)
            if case == 'close-same': self.assertIn('close', frames)
            return (result, observations, tag(tracked.__context__), tag(tracked.__cause__),
                    tracked.__suppress_context__, tracked.__context__ is original)
        cases = ('close-chain', 'close-getter', 'close-same', 'constructor-handler',
                 'entered-handler', 'uncorrelated-handler', 'callback-chain', 'callback-same')
        for case in cases:
            for ambient in (False, True):
                with self.subTest(case=case, ambient=ambient):
                    self.assertEqual(observe(True, case, ambient), observe(False, case, ambient))

    def test_foreign_callback_ambient_chain_mutations_survive_next_activation(self):
        context = BaseException.__dict__['__context__']
        def observe(native, mutation, indirect, callback_raises):
            fixture, observations = Fixture(), []
            ambient, middle = OSError('ambient'), RuntimeError('middle')
            original = None
            def label(value):
                return ('A' if value is ambient else 'B' if value is middle else
                        'E' if value is original else None if value is None else type(value).__name__)
            def mark(stage):
                observations.append((stage, label(sys.exception()),
                    label(context.__get__(ambient, BaseException)),
                    label(context.__get__(middle, BaseException)),
                    label(context.__get__(original, BaseException))))
            def mutate():
                context.__set__(ambient, middle if indirect else original)
                if indirect:
                    context.__set__(middle, original)
            class Error(ValueError):
                @property
                def code(self):
                    if mutation == 'code': mutate()
                    mark('code')
                    return 'OBSERVED'
                def __str__(self):
                    mark('message')
                    if callback_raises:
                        raise SystemExit('callback-after-mutation')
                    return 'original-message'
                @property
                def retry_action(self):
                    mark('retry'); return 'stop'
            original = Error('original')
            fixture.construct_error = original
            fixture.on_output = lambda: mark('output')
            def identifier():
                if mutation == 'uuid': mutate()
                mark('uuid'); return uuid.UUID(int=1)
            fixture.extra_patches.append(patch.object(worker.uuid, 'uuid4', identifier))
            try:
                raise ambient
            except OSError:
                result = fixture.run(self.manifest if native else None)
                mark('returned')
            for exception in (ambient, middle, original):
                context.__set__(exception, None)
            return result, observations
        for mutation in ('uuid', 'code'):
            for indirect in (False, True):
                for callback_raises in (False, True):
                    with self.subTest(mutation=mutation, indirect=indirect, callback_raises=callback_raises):
                        self.assertEqual(observe(True, mutation, indirect, callback_raises),
                                         observe(False, mutation, indirect, callback_raises))

    def test_parent_graph_byte_depth_and_node_budgets(self):
        # The response alone fits; including the report's nine fields crosses
        # the actual 8 MiB boundary. Parent nodes must also count at the ceiling.
        empty, _ = self.same(lambda f: setattr(f, 'response', ''))
        overhead = len(empty[1]) - 1
        for extra in (0, 1):
            size = (8 << 20) - overhead + extra
            with self.subTest(bytes=size):
                actual, _ = self.same(lambda f, size=size: setattr(f, 'response', 'x' * size))
                self.assertEqual(actual[0][0], 'return' if extra == 0 else 'raise')
        def deep(f, count):
            value = None
            for _ in range(count): value = [value]
            f.response = value
        for depth in (126, 127, 128):
            with self.subTest(depth=depth): self.same(lambda f, depth=depth: deep(f, depth))
        for children in (262134, 262135):
            with self.subTest(nodes=children):
                self.same(lambda f, children=children: setattr(f, 'response', [None] * children))

    def test_formatter_selection_failure_precedes_report_graph_validation(self):
        def configure(f):
            f.response = {'bad': object()}
            f.on_after = lambda: os.environ.__setitem__('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST', str(self.folder / 'missing-format'))
        actual, _ = self.same(configure)
        self.assertEqual(actual[0][0:2], ('raise', 'FileNotFoundError'))
        self.assertNotIn('uuid', [e[0] for e in actual[3]])

    def test_request_selector_is_observed_after_stdin_and_stays_independent(self):
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_worker_request_native import SOURCE as REQUEST_SOURCE, SCHEMA as REQUEST_SCHEMA
        folder = self.folder / 'request-image'; folder.mkdir()
        if os.environ.get(COLD):
            from tools.build_hia_json_preflight import build
            selected = build(folder / 'qualified', self.compiler, Path(os.environ[COLD]), candidate='worker-request')
        else:
            image, receipt = compile_stage(folder, 'request', self.compiler, REQUEST_SOURCE.read_bytes())
            selected = folder / 'manifest.json'
            selected.write_text(json.dumps({'schema': REQUEST_SCHEMA,
                'source_sha256': sha256(REQUEST_SOURCE.read_bytes()).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(self.compiler.read_bytes()).hexdigest()}))
        def configure(f):
            f.on_read = lambda: os.environ.__setitem__('HEPTA_HIA_WORKER_REQUEST_MANIFEST', str(selected))
            f.extra_patches.append(patch.object(worker, '_reference_admission',
                side_effect=AssertionError('retained request admission entered under selected request image')))
            f.extra_patches.append(patch.object(worker, 'decode_data',
                side_effect=AssertionError('retained request decoder entered under selected request image')))
        actual, _ = self.same(configure)
        self.assertEqual(actual[0], ('return', 0))
        def invalid(f):
            configure(f)
            value = envelope(); value['request_sha256'] = '0' * 64; f.raw = wire(value)
        actual, _ = self.same(invalid)
        self.assertEqual(json.loads(actual[1])['response']['error']['code'], 'E_HIA_WORKER_IDENTITY')
        def missing(f):
            f.on_read = lambda: os.environ.__setitem__('HEPTA_HIA_WORKER_REQUEST_MANIFEST', str(folder / 'missing'))
        actual, _ = self.same(missing)
        self.assertEqual(actual[0], ('return', 2))
        self.assertEqual(actual[1], b'')

    def test_uncorrelated_empty_message_and_foreign_text_subclass_behavior(self):
        def empty(f):
            f.raw = b'{}'
            f.extra_patches.append(patch.object(worker, 'decode_data', side_effect=ValueError('')))
        actual, _ = self.same(empty)
        self.assertEqual(actual[2], '\n')
        def foreign(f):
            class Text(str):
                def __getitem__(self, key):
                    f.events.append(('slice', key.start, key.stop, key.step))
                    return 'foreign-message'
            class Error(ValueError):
                def __str__(self): return Text('original')
            f.construct_error = Error()
        self.same(foreign)
        def fallback(f):
            class Error(ValueError):
                def __str__(self): return ''
            Error.__name__ = 'Z' * 4100
            f.construct_error = Error()
        actual, _ = self.same(fallback)
        self.assertEqual(len(json.loads(actual[1])['response']['error']['message']), 4100)

    def test_ordinary_sqlite_reopen_replay_conflict_and_unknown(self):
        from hepta.hia_agent_service import HIAAgentService
        state = self.folder / 'ordinary-state'
        service = HIAAgentService(state)
        catalog, profile = service.catalog_sha256, service.profiles['artifact']
        service.close()
        arguments = {'catalog_sha256': catalog, 'request_key': 'native-report-replay',
                     'artifact_profile': profile, 'source': {'kind': 'utf8', 'text': 'native report actual SQLite'}}
        def call(arguments, native=True):
            raw = wire(envelope(arguments, tool='hia_artifact', catalog=catalog))
            output, errors = io.BytesIO(), io.StringIO()
            with ExitStack() as stack:
                clean = {k: v for k, v in os.environ.items()
                         if not (k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST'))}
                stack.enter_context(patch.dict(os.environ, clean, clear=True))
                stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw))))
                stack.enter_context(patch.object(sys, 'stdout', SimpleNamespace(buffer=output)))
                stack.enter_context(patch.object(sys, 'stderr', errors))
                if native:
                    stack.enter_context(patch.object(worker, '_reference_run', side_effect=AssertionError('old report owner')))
                else:
                    # Explicit retained oracle under the SAME custody and pin.
                    stack.enter_context(patch.object(worker, '_run', worker._reference_run))
                code = worker.main(['--state-root', str(state), '--request-json-stdin',
                    '--native-helpers-manifest', str(self.worker_bundle),
                    '--expected-native-helpers-sha256', self.worker_pin])
            self.assertEqual((code, errors.getvalue()), (0, ''))
            return output.getvalue()
        def snapshot():
            db = sqlite3.connect(state / 'state.sqlite3')
            try:
                tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                return {table: db.execute('SELECT * FROM "' + table.replace('"', '""') + '" ORDER BY rowid').fetchall()
                        for table in tables}
            finally:
                db.close()
        first = call(arguments)
        self.assertEqual(json.loads(first)['response']['status'], 'completed')
        before = snapshot()
        self.assertEqual(call(arguments, native=False), first)
        self.assertEqual(snapshot(), before)
        self.assertEqual(call(arguments), first)
        self.assertEqual(snapshot(), before)
        changed = {**arguments, 'source': {'kind': 'utf8', 'text': 'different'}}
        conflict = json.loads(call(changed))
        self.assertEqual(conflict['response']['error']['code'], 'E_HIA_REQUEST_CONFLICT')
        self.assertEqual(snapshot()['requests'], before['requests'])
        held = {**arguments, 'request_key': 'native-report-running'}
        key = digest({'tool': 'hia_artifact', 'key': held['request_key']})
        request_digest = digest({'tool': 'hia_artifact', 'arguments': held})
        db = sqlite3.connect(state / 'state.sqlite3')
        db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                   (key, request_digest, 'hia_artifact', 'running', None, '0'))
        db.commit(); db.close()
        for _ in range(2):
            unknown = json.loads(call(held))
            self.assertEqual(unknown['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(unknown['response']['error']['retry_action'], 'observe_original')
        rows = snapshot()['requests']
        self.assertEqual([row[3:5] for row in rows if row[0] == key], [('running', None)])

    def test_installed_wheel_ordinary_entry_and_both_source_resources(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        directory = self.folder / 'wheel-case'; directory.mkdir()
        source = directory / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        names = [*('docs/' + name for name in DISCOVERY_FILES), *NATIVE_SOURCE_FILES,
                 *PUBLICATION_BUILD_FILES, *SOURCE_BUILD_FILES, *COMPILER_BUILD_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in', 'README.md', *BACKEND_BUILD_FILES, *EMITTER_BUILD_FILES, *BYTE_WRAPPER_BUILD_FILES, *MACHINE_OBJECT_BUILD_FILES, *EXECUTION_OBSERVATION_BUILD_FILES, *CONTINUATION_BUILD_FILES, *ENTRY_BUILD_FILES]
        for name in names:
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging_python = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        result = subprocess.run([packaging_python, '-B', 'setup.py', 'bdist_wheel',
                                 '--dist-dir', str(directory / 'wheels')], cwd=source,
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        wheel, = (directory / 'wheels').glob('*.whl')
        # The source and build copies are reproducible temporary inputs. Release
        # them before extracting the real wheel to limit shared filesystem use.
        shutil.rmtree(source)
        installed = directory / 'installed'
        with zipfile.ZipFile(wheel) as archive:
            for name in ('worker_report.hepta', 'json_wire.hepta'):
                self.assertEqual(archive.read('hepta/_data/examples/hia_bootstrap/' + name),
                                 (ROOT / 'examples/hia_bootstrap' / name).read_bytes())
            archive.extractall(installed)
        script = r'''
import builtins,io,json,os,pathlib,sys
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from hepta import hia_agent_worker as worker
from hepta.hia_agent_store import wire
from hepta.hia_worker_report_native import SOURCE,SELECTOR,installed_worker_report
from hepta.hia_agent_contract import installation_manifest
from hashlib import sha256
assert '_data' in SOURCE.parts
identities=installation_manifest()
request={'schema':'hia-agent-worker-request-v1','tool':'hia_describe','arguments':{'section':'manifest'},'profile_sha256':'d'*64,'catalog_sha256':identities['catalog_sha256']}
request['request_sha256']=sha256(wire(request)).hexdigest();raw=wire(request)
real_import=builtins.__import__
def no_tools(name,*args,**kwargs):
 if name=='tools' or name.startswith('tools.'):raise AssertionError('installed worker imported development tools')
 return real_import(name,*args,**kwargs)
output=io.BytesIO();errors=io.StringIO()
with patch('builtins.__import__',no_tools),patch.object(worker,'_reference_run',side_effect=AssertionError('retained worker owner')),patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))),patch.object(sys,'stdout',SimpleNamespace(buffer=output)),patch.object(sys,'stderr',errors):
 code=worker.main(['--state-root',sys.argv[3],'--request-json-stdin','--native-helpers-manifest',sys.argv[4],'--expected-native-helpers-sha256',sys.argv[5]])
assert code==0 and errors.getvalue()==''
report=json.loads(output.getvalue());assert report['native_helpers_sha256']==sys.argv[5];assert report['complete'] is True and report['response']['status']=='completed',report
original=SOURCE.read_bytes();SOURCE.write_bytes(original+b'\n')
try:installed_worker_report(sys.argv[2])
except ValueError as exc:assert 'source identity' in str(exc)
else:raise AssertionError('selected installed source drift fell back')
SOURCE.write_bytes(original)
print(json.dumps({'installed_entry':True,'retained_report_owner_entered':False,'source_drift_refused':True,'ordinary_service_status':report['response']['status']}))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed), str(self.manifest),
                                 str(directory / 'state'),str(self.worker_bundle),self.worker_pin], cwd=directory, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)['installed_entry'])

    def test_real_v2_scope_reuses_only_captured_images_and_preserves_ownership(self):
        from concurrent.futures import ThreadPoolExecutor
        from hepta import hia_native_helpers as authority
        from hepta.hia_json_wire_native import installed_json_wire
        selectors = lambda: {k: v for k, v in os.environ.items()
                             if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST')}
        before = selectors()
        with authority.native_helpers_scope(str(self.worker_bundle), self.worker_pin) as binding:
            self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': self.worker_pin})
            selected = os.environ[SELECTOR]
            captured = installed_worker_report(selected)
            # Neither cached executable may reach the general loader.
            with patch('hepta.hia_worker_report_native._load_manifest',
                       side_effect=AssertionError('uncaptured report loader')):
                self.assertIs(installed_worker_report(selected), captured)
            self.assertIs(installed_json_wire(os.environ['HEPTA_HIA_JSON_WIRE_MANIFEST']), captured.wire)
            def foreign():
                with self.assertRaisesRegex(ValueError, 'original process and thread'):
                    installed_worker_report(selected)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(foreign).result(timeout=10)
            child = os.fork()
            if child == 0:
                try:
                    installed_worker_report(selected)
                except ValueError:
                    os._exit(0)
                os._exit(1)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            with self.assertRaisesRegex(ValueError, 'another request'):
                with authority.native_helpers_scope():
                    self.fail('nested worker was admitted')
            # No direct ambient image is admitted by the ordinary main.
            os.environ['HEPTA_HIA_UNKNOWN_MANIFEST'] = '/unused-unpinned'
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                authority.native_helpers_identity()
        self.assertEqual(selectors(), before)

    def test_real_v2_scope_refuses_unregistered_schedulers_before_native_mapping(self):
        import importlib
        from hepta import hia_native_helpers as authority
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_json_wire_native import installed_json_wire
        before=dict(os.environ)
        with authority.native_helpers_scope(str(self.worker_bundle),self.worker_pin):
            captured=installed_worker_report(os.environ[SELECTOR])
            with patch.object(NativeHiaJsonImage,'__init__',side_effect=AssertionError('unregistered image mapping')):
                for family in ('core_lowering','core_emitter','byte_wrapper','machine_object','execution_observation'):
                    module=importlib.import_module('hepta.hia_'+family+'_selection')
                    with self.subTest(family=family):
                        with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):getattr(module,'installed_'+family)('/must-not-open',{})
            self.assertIs(installed_worker_report(os.environ[SELECTOR]),captured)
            self.assertIs(installed_json_wire(os.environ['HEPTA_HIA_JSON_WIRE_MANIFEST']),captured.wire)
            self.assertEqual(authority.native_helpers_identity(),{'native_helpers_sha256':self.worker_pin})
        self.assertEqual(dict(os.environ),before)

    def test_real_v2_wrong_pin_child_drift_and_environment_restore(self):
        from hepta import hia_native_helpers as authority
        before = dict(os.environ)
        with patch.object(authority, 'NativeHelpersBinding', side_effect=AssertionError('mapped before pin')):
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                with authority.native_helpers_scope(str(self.worker_bundle), '0' * 64):
                    self.fail('wrong pin admitted')
        self.assertEqual(dict(os.environ), before)
        child = self.manifest.parent / 'wire/manifest.json'
        raw = child.read_bytes()
        try:
            with authority.native_helpers_scope(str(self.worker_bundle), self.worker_pin):
                child.write_bytes(raw + b'\n')
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    authority.native_helpers_identity()
        finally:
            child.write_bytes(raw)
        self.assertEqual(dict(os.environ), before)

    def test_continuation_sequence_packet_lengths_and_output_canary(self):
        args = SimpleNamespace(installation_manifest=False, request_json_stdin=True, state_root='/unused', artifact_root=[],
            expected_worker_sha256=None, expected_backend_sha256=None, expected_catalog_sha256=None)
        for mutate in ('magic', 'sequence', 'opcode', 'error', 'short', 'long'):
            with self.subTest(mutate=mutate):
                session = WorkerSession(self.owner, args, None, dict(IDENTITIES), worker)
                canary = ctypes.create_string_buffer(b'\xa5' * 64, 64)
                session.output = canary
                self.assertEqual(session.step(), 1)
                raw = bytearray(session.observe())
                if mutate == 'short': raw.pop()
                elif mutate == 'long': raw.append(0)
                else:
                    offset = {'magic': 0, 'sequence': 8, 'opcode': 16, 'error': 24}[mutate]
                    struct.pack_into('<Q', raw, offset, 2 if mutate == 'error' else 0)
                self.assertEqual(session.step(bytes(raw)), 199)
                self.assertEqual(canary.raw, b'\xa5' * 64)
                with self.assertRaises(RuntimeError): session.step(bytes(raw))

    def test_bundle_exact_bytes_source_rebinding_and_no_fallback(self):
        original = json.loads(self.manifest.read_bytes())
        folder = self.folder / 'binding'; folder.mkdir()
        shutil.copytree(self.manifest.parent / 'policy', folder / 'policy')
        shutil.copytree(self.manifest.parent / 'wire', folder / 'wire')
        manifest = folder / 'manifest.json'; manifest.write_bytes(self.manifest.read_bytes())
        installed_worker_report(manifest)
        child = folder / 'policy/manifest.json'
        exact = child.read_bytes(); child.write_bytes(exact + b'\n')
        with self.assertRaisesRegex(ValueError, 'child manifest identity'):
            installed_worker_report(manifest)
        child.write_bytes(exact)
        with patch('hepta.hia_worker_report_native.SOURCE', self.folder / 'missing-source'):
            with self.assertRaises(FileNotFoundError): installed_worker_report(manifest)
        from hepta import hia_worker_report_native as module
        loader = module._load_manifest
        calls = []
        def changed(path, raw, source_sha, schema, factory):
            calls.append(raw)
            value = loader(path, raw, source_sha, schema, factory)
            if len(calls) == 1:
                child.write_bytes(exact + b'\n')
            return value
        with patch.object(module, '_load_manifest', changed):
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                installed_worker_report(manifest)
        self.assertEqual(calls[0], exact)
        child.write_bytes(exact)
        original['policy_manifest'] = '../escape'
        manifest.write_text(json.dumps(original))
        with self.assertRaisesRegex(ValueError, 'child identity'):
            installed_worker_report(manifest)


if __name__ == '__main__':
    unittest.main()
