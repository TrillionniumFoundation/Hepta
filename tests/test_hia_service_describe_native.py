"""Complete original describe comparisons, real ABI and installed worker gates.

The ordinary 112-caller suite stays a separate complete gate. These new methods
do not relabel its history or replace any prior method, fixture or deadline.
"""
from __future__ import annotations

import ast
import base64
from collections import Counter
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from hepta import hia_agent_service as api
from hepta import hia_service_describe_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests import hia_service_describe_oracle as oracle
from tools import generate_hia_service_describe as generator

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_DESCRIBE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_SERVICE_DESCRIBE_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_SERVICE_DESCRIBE_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_DESCRIBE_SOURCE_EVIDENCE'


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def child(directory, label, arguments, *, body=None, timeout=60, environment=None):
    directory.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, '-B', *map(str, arguments)]
    (directory / (label + '-command.json')).write_bytes(oracle.canonical({
        'command': command, 'timeout_seconds': timeout, 'cleanup_seconds': 3}))
    before = time.monotonic()
    process = subprocess.Popen(command, cwd=directory,
        env=clean_environment() if environment is None else environment,
        stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    def group_absent():
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        return False
    signal_sent, timed_out = None, False
    try:
        stdout, stderr = process.communicate(body, timeout=timeout)
    except BaseException as error:
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signal_sent = 'SIGKILL'
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=3)
        (directory / (label + '.stdout')).write_bytes(stdout)
        (directory / (label + '.stderr')).write_bytes(stderr)
        (directory / (label + '-supervision.json')).write_bytes(oracle.canonical({
            'returncode': process.returncode, 'timed_out': timed_out, 'signal_sent': signal_sent,
            'wall_seconds': time.monotonic() - before, 'terminal_wait_completed': True,
            'owned_group_observed_absent': group_absent()}))
        raise
    (directory / (label + '.stdout')).write_bytes(stdout)
    (directory / (label + '.stderr')).write_bytes(stderr)
    absent = group_absent()
    (directory / (label + '-supervision.json')).write_bytes(oracle.canonical({
        'returncode': process.returncode, 'timed_out': timed_out, 'signal_sent': signal_sent,
        'wall_seconds': time.monotonic() - before, 'terminal_wait_completed': True,
        'owned_group_observed_absent': absent}))
    if not absent:
        raise AssertionError('describe child exited with its owned process group still present')
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def bundle(path, manifest):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    path.write_bytes(oracle.canonical({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
        'helpers': [{'selector': native.SELECTOR, 'manifest_path': str(manifest),
                     'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}]}))
    return sha256(path.read_bytes()).hexdigest()


def validate_runtime_ast(test, directory, report):
    identity = report['original_ast_identity']
    test.assertEqual(identity['dump_file'], 'original-runtime-ast.txt')
    raw = (directory / identity['dump_file']).read_bytes()
    test.assertEqual(raw, oracle.ORIGINAL_RUNTIME_AST_DUMP.encode())
    test.assertEqual(len(raw), identity['dump_bytes'])
    test.assertEqual(sha256(raw).hexdigest(), identity['dump_sha256'])
    test.assertEqual(identity['runtime'], sys.version)
    test.assertEqual(identity['implementation'], sys.implementation.name)
    test.assertEqual(identity['method_bytes'], oracle.ORIGINAL_BYTES)
    test.assertEqual(identity['method_sha256'], oracle.ORIGINAL_SHA256)
    test.assertEqual(identity['method_git_blob'], oracle.ORIGINAL_GIT_BLOB_SHA1)
    test.assertEqual(identity['authoring_ast_sha256'], oracle.ORIGINAL_AST_SHA256)


def validate_finite(test, directory, mode):
    report = json.loads((directory / 'report.json').read_bytes())
    validate_runtime_ast(test, directory, report)
    original = (directory / 'originals.json').read_bytes()
    actual = (directory / 'actuals.json').read_bytes()
    test.assertEqual(report['status'], 'PASS', report['differences'])
    test.assertEqual(report['mode'], mode)
    test.assertEqual(report['original_count'], 291)
    test.assertEqual(report['actual_count'], 291)
    test.assertEqual(report['actual_frames'], 291)
    test.assertEqual(report['ordered_ids'], [case['id'] for case in oracle.original_inputs()])
    test.assertEqual(original, actual)
    test.assertEqual(sha256(original).hexdigest(), report['originals_sha256'])
    test.assertEqual(sha256(actual).hexdigest(), report['actuals_sha256'])
    test.assertEqual(report['differences'], [])
    test.assertEqual(report['all_late_events'], [])
    test.assertEqual(report['remaining_delivery_custody'], [])
    test.assertEqual(report['retained_reference_calls'], [])
    test.assertTrue(report['expected_written_before_candidate_imports'])
    test.assertTrue(report['source_image_manifest_and_originals_unchanged'])
    entries = report['actual_entry_events']
    test.assertEqual(entries['0'], 291)
    test.assertEqual(entries['1'], entries['2'] + entries['3'])
    complete = json.loads((directory / 'complete-observations.json').read_bytes())
    test.assertEqual([row['case'] for row in complete], report['ordered_ids'])
    test.assertEqual([row['expected'] for row in complete], json.loads(original))
    test.assertEqual([row['actual'] for row in complete], json.loads(actual))
    test.assertTrue(all(row['equal'] for row in complete))
    packets = [json.loads(row) for row in (directory / 'complete-packets.jsonl').read_bytes().splitlines()]
    test.assertEqual(len(packets), report['complete_packet_count'])
    test.assertEqual(len(packets), sum(entries.values()))
    for index, packet in enumerate(packets, 1):
        test.assertEqual(packet['index'], index)
        test.assertEqual(len(bytes.fromhex(packet['request'])), 80)
        test.assertEqual(len(bytes.fromhex(packet['output_after'])), 96)
        test.assertEqual(len(bytes.fromhex(packet['state_after'])), 128)
    return report


class ServiceDescribeSourceTests(unittest.TestCase):
    def test_exact_original_body_generated_graph_and_registered_scope(self):
        cases = oracle.original_inputs()
        raw = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        tree, lines = ast.parse(raw), raw.splitlines(keepends=True)
        service = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                       and node.name == 'HIAAgentService')
        method = next(node for node in service.body if isinstance(node, ast.FunctionDef)
                      and node.name == '_hia_describe')
        original = b''.join(lines[method.lineno - 1:method.end_lineno])
        self.assertEqual(original, oracle.ORIGINAL.read_bytes())
        self.assertEqual(sha256(original).hexdigest(), oracle.ORIGINAL_SHA256)
        self.assertEqual(ast.dump(method, include_attributes=False), oracle.ORIGINAL_RUNTIME_AST_DUMP)
        identity = json.loads((oracle.ROOT / 'source-identity.json').read_bytes())
        self.assertEqual(identity['method_ast_sha256'], oracle.ORIGINAL_AST_SHA256)
        import hashlib
        self.assertEqual(hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest(),
                         identity['method_git_blob'])
        self.assertIs(api.HIAAgentService._hia_describe, api._service_describe_dispatch)
        self.assertIsNot(api.HIAAgentService._hia_describe, api._NATIVE_SERVICE_DESCRIBE_REFERENCE)
        self.assertEqual(native.SOURCE.read_bytes(), render_assembly(generator.document()).encode())
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions'] for block in fn['blocks']), 16)
        self.assertLessEqual(len(native.SOURCE.read_bytes()), 1 << 20)
        self.assertLessEqual(len(native.SOURCE.read_text().splitlines()), 16384)
        for fn in document['functions']:
            definitions = {item['name'] for item in fn['params']}
            for block in fn['blocks']:
                definitions.update(item['name'] for item in block['params'])
                definitions.update(item['name'] for op in block['ops'] for item in op['out'])
            self.assertLessEqual(len(fn['blocks']), 256)
            self.assertLessEqual(len(definitions), 2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR], ('hia_service_describe_native', 'NativeServiceDescribe'))
        self.assertEqual(len(cases), 291)

    def run_fresh(self, mode, timeout):
        evidence = os.environ.get(SOURCE_EVIDENCE)
        if evidence == '':
            raise ValueError('describe Source evidence must not be empty')
        with tempfile.TemporaryDirectory(prefix='hia-describe-source-') as temporary:
            parent = Path(evidence).absolute() if evidence is not None else Path(temporary)
            parent.mkdir(parents=True, exist_ok=True)
            directory = parent / (self._testMethodName + '-' + str(os.getpid()))
            result = child(parent, self._testMethodName,
                ['-I', ROOT / 'tests/hia_service_describe_oracle.py', '--mode', mode,
                 '--output', directory], timeout=timeout)
            report_path = directory / 'report.json'
            details = report_path.read_bytes() if report_path.exists() else result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, details)
            if mode != 'original':
                report = validate_finite(self, directory, mode)
                self.assertEqual(report['actual_native_entries'], 0)
                self.assertGreater(report['actual_VM_entries'], 0)
            else:
                report = json.loads(details)
                validate_runtime_ast(self, directory, report)
                self.assertEqual(report['status'], 'PASS')
                self.assertEqual(report['count'], 291)
                self.assertEqual(report['original_late_events'], [])
                self.assertTrue(report['source_unchanged'])
                self.assertFalse(report['selected_or_native_or_VM_execution'])
                self.assertEqual(report['ordered_ids'], [case['id'] for case in oracle.original_inputs()])

    def test_all_originals_in_fresh_process_without_product_execution(self):
        self.run_fresh('original', 60)

    def test_all_291_original_observations_against_independent_VM(self):
        self.run_fresh('vm', 300)

    def test_unselected_original_and_explicit_empty_selection_refusal(self):
        calls = []
        with patch.dict(os.environ, clean_environment(), clear=True), patch.object(api,
                '_NATIVE_SERVICE_DESCRIBE_REFERENCE', side_effect=lambda s, a: calls.append((s, a)) or 'original'), \
                patch.object(native, 'installed_service_describe', side_effect=AssertionError('unselected mapping')):
            service, arguments = object(), {'section': 'manifest'}
            self.assertEqual(api.HIAAgentService._hia_describe(service, arguments), 'original')
            self.assertEqual(calls, [(service, arguments)])
        calls.clear()
        with patch.dict(os.environ, {native.SELECTOR: ''}), patch.object(api,
                '_NATIVE_SERVICE_DESCRIBE_REFERENCE', side_effect=AssertionError('selected fallback')):
            with self.assertRaises(ValueError):
                api.HIAAgentService._hia_describe(object(), {'section': 'manifest'})
        self.assertEqual(calls, [])


class ServiceDescribeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_describe import build, INPUTS
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching describe cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-describe-native-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw = compiler.read_bytes()
        cls.inputs = tuple(INPUTS)
        cls.sources = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_service_describe(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in cls.inputs}
        stable = cls.sources == after and cls.compiler.read_bytes() == cls.compiler_raw
        (cls.root / 'component-custody.json').write_bytes(oracle.canonical({
            'schema': 'hepta.hia.service-describe-component-custody.v1', 'runtime': sys.version,
            'source_before': cls.sources, 'source_after': after, 'source_and_compiler_unchanged': stable,
            'manifest': str(cls.manifest), 'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'matching_cold_report': cls.cold,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'original_finite_cases': 291, 'test_results_owned_by_outer_runner': True,
            'original_112_callers_are_separate_complete_gate': True,
            'object_protocols_catalog_and_SQLite_effects_still_hosted': True,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}))
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('describe component source or compiler changed')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()

    def test_all_291_frozen_originals_against_actual_image_in_fresh_process(self):
        result = child(self.case, 'finite', ['-I', ROOT / 'tests/hia_service_describe_oracle.py',
            '--mode', 'native', '--manifest', self.manifest, '--output', self.case / 'finite'], timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = validate_finite(self, self.case / 'finite', 'native')
        self.assertGreater(report['actual_native_entries'], 0)
        self.assertEqual(report['actual_VM_entries'], 0)

    def test_complete_actual_provider_ABI_and_resource_fault_controls(self):
        launcher = ('import runpy,sys;sys.path.insert(0,' + repr(str(ROOT)) +
                    ');runpy.run_module("tests.hia_service_describe_faults",run_name="__main__")')
        result = child(self.case, 'faults', ['-I', '-c', launcher,
            '--manifest', self.manifest, '--output', self.case / 'faults'], timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.case / 'faults/report.json').read_bytes())
        self.assertEqual(report['status'], 'PASS', report)
        self.assertEqual(report['control_count'], 170)
        self.assertEqual(len(report['controls']), 170)
        self.assertTrue(all(row['passed'] for row in report['controls']), report)

    def test_manifest_source_and_image_mismatch_refuse_without_fallback(self):
        original = json.loads(self.manifest.read_bytes())
        source_image = self.manifest.parent / original['image_path']
        rows = []
        for label, changes in (
                ('schema', {'schema': 'unrecognized'}),
                ('source', {'source_sha256': '0' * 64}),
                ('image', {'image_sha256': '0' * 64}),
                ('path-parent', {'image_path': '../image.bin'}),
                ('extra-field', {'unclaimed': 1})):
            directory = self.case / label
            directory.mkdir()
            target = directory / 'manifest.json'
            shutil.copyfile(source_image, directory / original['image_path'])
            target.write_bytes(oracle.canonical({**original, **changes}))
            with patch.dict(os.environ, {native.SELECTOR: str(target)}), patch.object(api,
                    '_NATIVE_SERVICE_DESCRIBE_REFERENCE', side_effect=AssertionError('selected fallback')):
                with self.assertRaises((ValueError, OSError)) as caught:
                    api.HIAAgentService._hia_describe(object(), {'section': 'manifest'})
            rows.append({'case': label, 'error': type(caught.exception).__name__, 'args': list(caught.exception.args)})
        (self.case / 'refusals.json').write_bytes(oracle.canonical(rows))
        self.assertEqual(len(rows), 5)

    def test_actual_installed_wheel_worker_all_six_sections_without_authoring(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        staging = self.case / 'source'
        staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment() | {'PYTHONDONTWRITEBYTECODE': '1'}
        for label, arguments in (
            ('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                       '--wheel-dir', self.case / 'wheels', staging]),):
            result = child(self.case, label, arguments, environment=environment, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        result = child(self.case, 'install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
            '--target', installed, wheel], environment=environment, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        files, wheel_rows = {}, []
        with zipfile.ZipFile(wheel) as archive:
            record_name, = [name for name in archive.namelist() if name.endswith('.dist-info/RECORD')]
            for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode())):
                raw = archive.read(name)
                if digest:
                    self.assertEqual(digest, 'sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode())
                    self.assertEqual(size, str(len(raw)))
                wheel_rows.append([name, digest, size])
                if name != record_name:
                    self.assertEqual((installed / name).read_bytes(), raw, name)
                    files[name] = sha256(raw).hexdigest()
        resource = installed / 'hepta/_data/examples/hia_bootstrap/service_describe.hepta'
        self.assertEqual(resource.read_bytes(), native.SOURCE.read_bytes())
        record = {row[0]: row[1:] for row in csv.reader(io.StringIO((installed / record_name).read_text()))}
        for name in ('hepta/hia_agent_service.py', 'hepta/hia_service_describe_native.py',
                     'hepta/hia_service_describe_protocol.py', str(resource.relative_to(installed))):
            raw = (installed / name).read_bytes()
            self.assertEqual(record[name], ['sha256=' + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b'=').decode(), str(len(raw))])
        selection = self.case / 'bundle.json'
        pin = bundle(selection, self.manifest)
        script = r'''import ctypes,importlib.abc,io,json,os,struct,sys
from pathlib import Path
from hashlib import sha256
installed,bundle,pin,state,output=sys.argv[1:]
sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):
            raise AssertionError('installed describe runtime imported authoring: '+name)
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_service_describe_native as native
from hepta import hia_agent_service as api
from hepta.hia_agent_worker import main
from hepta.hia_agent_contract import installation_manifest,wire
from hepta.hia_native_helpers import native_helpers_scope
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
sections=('manifest','language','backend','examples','diagnostics','plans')
original=api._NATIVE_SERVICE_DESCRIBE_REFERENCE
expected={}
with native_helpers_scope(bundle,pin):
    ids=installation_manifest()
    service=api.HIAAgentService(state)
    try:
        for section in sections:expected[section]=original(service,{'section':section})
    finally:service.close()
calls=[];events={};initializer=native.NativeServiceDescribe.__init__
def counted_initialize(image,*args,**kwargs):
    initializer(image,*args,**kwargs)
    actual=image._entry
    def entry(source,size,out,capacity,workspace,extent):
        event=struct.unpack('<2Q',ctypes.string_at(source,16))[1]
        events[str(event)]=events.get(str(event),0)+1
        return actual(source,size,out,capacity,workspace,extent)
    image._entry=entry
native.NativeServiceDescribe.__init__=counted_initialize
def forbidden(*args,**kwargs):
    calls.append(True)
    raise AssertionError('installed retained describe handler executed')
api._NATIVE_SERVICE_DESCRIBE_REFERENCE=forbidden
reports=[]
for section in sections:
    request={'schema':'hia-agent-worker-request-v1','tool':'hia_describe',
        'arguments':{'section':section},'profile_sha256':'a'*64,'catalog_sha256':ids['catalog_sha256']}
    request['request_sha256']=sha256(wire(request)).hexdigest()
    source=io.TextIOWrapper(io.BytesIO(wire(request)))
    destination=io.TextIOWrapper(io.BytesIO())
    oldin,oldout=sys.stdin,sys.stdout
    try:
        sys.stdin,sys.stdout=source,destination
        code=main(['--state-root',state,'--request-json-stdin',
            '--native-helpers-manifest',bundle,'--expected-native-helpers-sha256',pin,
            '--expected-worker-sha256',ids['worker_sha256'],
            '--expected-backend-sha256',ids['backend_sha256'],
            '--expected-catalog-sha256',ids['catalog_sha256']])
        destination.flush()
        raw=destination.buffer.getvalue()
    finally:sys.stdin,sys.stdout=oldin,oldout
    response=json.loads(raw)
    assert code==0 and response['complete'] and response['native_helpers_sha256']==pin
    assert response['response']['status']=='completed',response
    assert response['response']['result']==expected[section],section
    reports.append({'section':section,'request':request,'raw_response_hex':raw.hex(),
        'response':response,'expected':expected[section]})
assert not calls
assert events.get('0')==6 and events.get('1')==events.get('2',0)+events.get('3',0)
value={'status':'PASS','sections':list(sections),'reports':reports,'retained_calls':calls,
       'native_events':events,'installed_source':str(native.SOURCE),'identities':ids,
       'authoring_imports_forbidden':True,'ordinary_worker_entry_executed':True}
Path(output).write_text(json.dumps(value,ensure_ascii=True,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':'PASS','sections':len(reports),'events':events},sort_keys=True))
'''
        result = child(self.case, 'installed-worker', ['-I', '-c', script, installed, selection, pin,
            self.case / 'state', self.case / 'installed-worker.json'], environment=environment, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads((self.case / 'installed-worker.json').read_bytes())
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['sections'], ['manifest', 'language', 'backend', 'examples', 'diagnostics', 'plans'])
        self.assertEqual(report['retained_calls'], [])
        self.assertEqual(report['native_events']['0'], 6)
        (self.case / 'installation.json').write_bytes(oracle.canonical({
            'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'wheel_rows': wheel_rows, 'all_wheel_member_hashes': files,
            'installed_RECORD_sha256': sha256((installed / record_name).read_bytes()).hexdigest(),
            'new_source_sha256': sha256(resource.read_bytes()).hexdigest(),
            'installed_worker_report_sha256': sha256((self.case / 'installed-worker.json').read_bytes()).hexdigest(),
            'all_six_actual_worker_sections': True, 'retained_handler_forbidden': True,
            'whole_native_delivery_qualified': False}))


if __name__ == '__main__':
    unittest.main()
