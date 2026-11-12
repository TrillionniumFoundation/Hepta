"""Ordinary Agent patch requests with HIA-owned payloads and durable replay."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_candidate_native import (DECLARED_SCHEMA_ERROR, MAX_RESULT,
    RESULT_MAGIC, apply_candidate_patch, installed_agent_candidate_patch, result_payloads)
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected, wire
from hepta.hia_core_patch_native import MAX_COMPONENT, SELECTOR, envelope, scratch_sizes
from hepta.hia_program import verify_program
from hepta.hia_program_tools import HIAEditRejected, PATCH_SCHEMA, PATCH_SCHEMA_V2, apply_program_patch
from tests import test_hia_core_patch_native as patch_tests
from tests.test_hia_core_patch_native import four_kinds, interpreted, request_wire
from tests.test_hia_program_tools import scalar_program, add_two_patch
from tools.hia_agent_native_qualification import Session, ToolClient, exhaustive_u8_workload


class AgentCandidateNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development = os.environ.get('HEPTA_HIA_AGENT_CANDIDATE_DEVELOPMENT_MANIFEST')
        if development and os.environ.get('HEPTA_HIA_CORE_PATCH_COLD_REPORT'):
            raise AssertionError('a development fixture cannot override requested cold qualification')
        # The new result mode has an independent VM witness before any image is
        # invoked. An explicitly supplied development fixture saves redundant
        # compiler work; it is never labeled a matching-source cold build.
        program = scalar_program()
        request = add_two_patch(program)
        expected, diagnostics = apply_program_patch(program, request)
        code, output = interpreted(request_wire(program,request), result_schema=1)
        assert code == 32 + len(expected.canonical_bytes) + len(wire(diagnostics))
        assert result_payloads(output) == (expected.canonical_bytes, wire(diagnostics))
        if development:
            cls.temp = tempfile.TemporaryDirectory(prefix='hia-agent-candidate-development-')
            cls.folder = Path(cls.temp.name)
            supplied = Path(development)
            # The production loaders below independently bind each copied image
            # to exact current source bytes; this fixture grants no qualification.
            for name in ('manifest.json','admission-manifest.json'):
                source = supplied if name == 'manifest.json' else supplied.parent/name
                record = json.loads(source.read_bytes())
                image = record['image_path']
                assert type(image) is str and Path(image).name == image
                shutil.copyfile(source.parent/image,cls.folder/image)
                (cls.folder/name).write_bytes(source.read_bytes())
            cls.manifest = cls.folder/'manifest.json'
            cls.admission_manifest = cls.folder/'admission-manifest.json'
        else:
            patch_tests.CorePatchNativeTests.setUpClass.__func__(cls)
        cls.native = installed_agent_candidate_patch(str(cls.manifest))
        from hepta.hia_core_admission_native import installed_core_admission
        cls.admission = installed_core_admission(str(cls.admission_manifest))
        cls.serial = 0

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder/('case-'+str(self.serial))
        self.case.mkdir()
        self.service = HIAAgentService(self.case/'state')
        self.addCleanup(self.service.close)
        self.session = Session(ToolClient(self.service.call),prefix=self._testMethodName)
        self.session.freeze(exhaustive_u8_workload())

    def arguments(self, program, request, *, raw_base=None):
        base = self.session.artifact(program if raw_base is None else raw_base.decode('utf-8'))
        request_ref = self.session.artifact(request)
        return self.session.arguments(change={'kind':'patch','base_program':base,
            'patch':request_ref,'patch_schema':request['schema']})

    def selected_call(self, arguments):
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}):
            return self.service.call('hia_candidate',arguments)

    @contextmanager
    def forbid_payload_owners(self, payloads=()):
        forbidden = set(payloads)
        def guard(original):
            def checked(value,*args,**kwargs):
                raw = value.encode('utf-8') if type(value) is str else value
                if type(raw) is bytes and raw in forbidden:
                    raise AssertionError('host parsed an HIA-owned candidate payload')
                return original(value,*args,**kwargs)
            return checked
        with ExitStack() as stack:
            for target in ('hepta.hia_program.verify_program',
                'hepta.hia_agent_service.verify_program',
                'hepta.hia_agent_service.decode_json',
                'hepta.hia_program_tools.decode_json',
                'hepta.hia_program_tools.apply_program_patch',
                'hepta.hia_program_tools._prepare_program_patch',
                'hepta.hia_program_tools._check_patch_interface',
                'hepta.hia_program_tools.function_signature'):
                stack.enter_context(patch(target,side_effect=AssertionError('old payload owner '+target)))
            stack.enter_context(patch.object(self.service,'_program',side_effect=AssertionError('host program snapshot')))
            stack.enter_context(patch('json.loads',side_effect=guard(json.loads)))
            original_decode = json.JSONDecoder.decode
            def decode(decoder,value,*args,**kwargs):
                return guard(lambda text,*a,**kw:original_decode(decoder,text,*a,**kw))(value,*args,**kwargs)
            stack.enter_context(patch.object(json.JSONDecoder,'decode',decode))
            yield

    def payloads(self, response):
        self.assertEqual(response['status'],'completed',response)
        result = response['result']
        self.assertTrue(result['core_admitted'])
        self.assertFalse(result['behavior_equivalence_proved'])
        self.assertFalse(result['adopted'])
        candidate, metadata = self.service.store.get(result['candidate'],kind='core')
        diagnostics, _ = self.service.store.get(result['diagnostics'],kind='candidate-diagnostics')
        self.assertEqual(metadata,{'context':self.session.context})
        return candidate, diagnostics

    def test_actual_agent_all_four_edits_forbid_old_payload_owners(self):
        program, requests = four_kinds()
        for request in requests:
            expected, diagnostics = apply_program_patch(program,request)
            args = self.arguments(program,request)
            blocked = [wire(program),wire(request),expected.canonical_bytes,wire(diagnostics)]
            with self.forbid_payload_owners(blocked):
                response = self.selected_call(args)
            self.assertEqual(self.payloads(response),(expected.canonical_bytes,wire(diagnostics)))
            self.assertEqual(response['result']['base_program'],args['change']['base_program'])

    def test_actual_installed_wheel_agent_path_forbids_tools_and_refuses_selected_drift(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES
        root = Path(__file__).resolve().parents[1]
        source = self.case/'wheel-source';source.mkdir()
        shutil.copytree(root/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/'+name for name in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES
        for name in (*resources,'setup.py','pyproject.toml','MANIFEST.in'):
            destination = source/name;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/name,destination)
        wheels = self.case/'wheels'
        build = subprocess.run([sys.executable,'-B','-m','pip','wheel','--no-deps','--no-index',
            '--no-build-isolation','--wheel-dir',str(wheels),str(source)],cwd=source,
            capture_output=True,timeout=120,env={**os.environ,'PIP_DISABLE_PIP_VERSION_CHECK':'1'})
        self.assertEqual(build.returncode,0,build.stdout+build.stderr)
        wheel, = wheels.glob('*.whl');installed = self.case/'installed'
        install = subprocess.run([sys.executable,'-B','-m','pip','install','--no-deps','--no-index',
            '--target',str(installed),str(wheel)],cwd=self.case,capture_output=True,timeout=120,
            env={**os.environ,'PIP_DISABLE_PIP_VERSION_CHECK':'1'})
        self.assertEqual(install.returncode,0,install.stdout+install.stderr)
        program = scalar_program();request = add_two_patch(program)
        expected, diagnostics = apply_program_patch(program,request)
        original_args = self.arguments(program,request)
        arguments_path = self.case/'installed-args.json'
        child = r'''import importlib.abc,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed Agent candidate imported checkout tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_agent_service as agent,hia_program as program,hia_program_tools as edit
from hepta.hia_agent_candidate_native import SOURCE
from hepta.hia_agent_store import wire
assert Path(sys.argv[1]) in SOURCE.parents
arguments=json.loads(Path(sys.argv[3]).read_bytes())
def forbidden(*args,**kwargs):raise AssertionError('old Agent payload owner invoked')
try:
    service=agent.HIAAgentService(sys.argv[2])
    service._program=forbidden
    program.verify_program=agent.verify_program=forbidden
    edit.apply_program_patch=edit._prepare_program_patch=edit._check_patch_interface=forbidden
    edit.decode_json=agent.decode_json=forbidden
    try:response=service.call('hia_candidate',arguments)
    finally:service.close()
except (ValueError,OSError):
    if sys.argv[4]!='refuse':raise
    print('REFUSED')
else:
    if sys.argv[4]=='refuse':
        assert response['status']=='rejected',response
        print('REFUSED')
    else:
        assert response['status']=='completed',response
        sys.stdout.buffer.write(wire(response))
'''
        serial = 0
        def run(mode):
            nonlocal serial
            serial += 1
            arguments_path.write_bytes(wire({**original_args,'request_key':original_args['request_key']+'-'+str(serial)}))
            return subprocess.run([sys.executable,'-I','-S','-B','-c',child,str(installed),
                str(self.service.store.root),str(arguments_path),mode],cwd=self.case,
                capture_output=True,timeout=30,
                env={'PATH':'','LANG':'C','LC_ALL':'C',SELECTOR:str(self.manifest)})
        result = run('accept')
        self.assertEqual((result.returncode,result.stderr),(0,b''),result.stdout+result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(self.payloads(response),(expected.canonical_bytes,wire(diagnostics)))
        resource = installed/'hepta/_data/examples/hia_bootstrap/core_patch.hepta'
        original = resource.read_bytes()
        try:
            resource.unlink()
            result = run('refuse')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'REFUSED\n',b''))
        finally:resource.write_bytes(original)
        original = self.manifest.read_bytes()
        try:
            self.manifest.write_text('{}')
            result = run('refuse')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'REFUSED\n',b''))
        finally:self.manifest.write_bytes(original)
        image = self.manifest.parent/json.loads(original)['image_path']
        original = image.read_bytes()
        try:
            image.write_bytes(b'not the admitted native image')
            # Each installed child starts with an empty image cache. This does
            # not change the established immutable-RX cache's lifetime contract.
            result = run('refuse')
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'REFUSED\n',b''))
        finally:image.write_bytes(original)

    def test_canonical_snapshot_identity_and_large_candidate_result_extent(self):
        program = scalar_program()
        operations = program['functions'][0]['blocks'][0]['ops']
        operations[:] = [{'op':'const','args':[],'out':[{'name':'n'+str(i),'type':'u32'}],
                         'attrs':{'value':i}} for i in range(160)]
        program['functions'][0]['blocks'][0]['term'] = {'op':'ret','values':['n159']}
        request = {'schema':PATCH_SCHEMA,'expected_sha256':verify_program(program).sha256,
            'edits':[{'action':'replace_terminator','function':'increment','block':'entry',
                      'term':{'op':'ret','values':['x']}}]}
        expected, diagnostics = apply_program_patch(program,request)
        raw_base = json.dumps(program,indent=2).encode().replace(b'"module"',b'"modul\\u0065"')
        self.assertNotEqual(sha256(raw_base).hexdigest(),request['expected_sha256'])
        # For canonical input the old candidate-only allocation can be too
        # small once this result includes a complete diagnostics document.
        self.assertGreater(len(expected.canonical_bytes)+len(wire(diagnostics)),
                           len(envelope(wire(program),wire(request))))
        args = self.arguments(program,request,raw_base=raw_base)
        with self.forbid_payload_owners((raw_base,wire(request),expected.canonical_bytes,wire(diagnostics))):
            response = self.selected_call(args)
        actual, diagnostic_bytes = self.payloads(response)
        self.assertEqual((actual,diagnostic_bytes),(expected.canonical_bytes,wire(diagnostics)))
        self.assertEqual(json.loads(diagnostic_bytes)['original_input_sha256'],request['expected_sha256'])

    def test_native_result_migration_order_default_loans_and_64_changes(self):
        program = scalar_program()
        request = {**add_two_patch(program),'schema':PATCH_SCHEMA_V2,'interface_policy':'migrate','edits':[]}
        for index in range(63,-1,-1):
            name = 'added_'+str(index).zfill(2)
            definition = copy.deepcopy(program['functions'][0]);definition['name'] = name
            request['edits'].append({'action':'add_function','function':name,'definition':definition})
        expected, diagnostics = apply_program_patch(program,request)
        candidate, actual = apply_candidate_patch(str(self.manifest),wire(program),wire(request),PATCH_SCHEMA_V2)
        self.assertEqual((candidate,actual),(expected.canonical_bytes,wire(diagnostics)))
        self.assertEqual(json.loads(actual)['interface_changes'],sorted(edit['function'] for edit in request['edits']))
        program['schema'] = 'hepta.hia.program.v8'
        definition = copy.deepcopy(program['functions'][0]);definition['return_loans'] = [None]
        request = {**add_two_patch(program),'schema':PATCH_SCHEMA_V2,'interface_policy':'migrate',
                   'edits':[{'action':'replace_function','function':'increment','definition':definition}]}
        expected, diagnostics = apply_program_patch(program,request)
        actual = apply_candidate_patch(str(self.manifest),wire(program),wire(request),PATCH_SCHEMA_V2)
        self.assertEqual(actual,(expected.canonical_bytes,wire(diagnostics)))
        self.assertEqual(diagnostics['interface_changes'],[])
        self.assertTrue(diagnostics['claims']['interface_preserved'])

    def test_schema_semantic_and_composite_refusals_issue_no_candidate_refs(self):
        program = scalar_program()
        request = add_two_patch(program)
        cases = []
        args = self.arguments(program,request);args['change']['patch_schema'] = PATCH_SCHEMA_V2
        cases.append((args,'E_HIA_PATCH_SCHEMA'))
        invalid = copy.deepcopy(request)
        invalid['edits'][0]['operation']['op'] = 'int.add.wrap'
        invalid['edits'][0]['operation']['args'] = ['x','missing']
        invalid['edits'][0]['operation']['attrs'] = {}
        cases.append((self.arguments(program,invalid),None))
        bad_base = copy.deepcopy(program)
        bad_base['functions'][0]['blocks'][0]['ops'][1]['args'] = ['x','undefined']
        repair = {'schema':PATCH_SCHEMA,'expected_sha256':sha256(wire(bad_base)).hexdigest(),
            'edits':[{'action':'replace_operation','function':'increment','block':'entry','index':1,
                      'operation':program['functions'][0]['blocks'][0]['ops'][1]}]}
        cases.append((self.arguments(bad_base,repair),None))
        from tests.test_hia_program_composite import scalar_task_program
        composite = scalar_task_program()
        verify_program(composite)
        cases.append((self.arguments(composite,request),None))
        for arguments, code in cases:
            before = self.service.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0]
            with self.forbid_payload_owners():response = self.selected_call(arguments)
            self.assertEqual(response['status'],'rejected',response)
            if code:self.assertEqual(response['error']['code'],code)
            self.assertEqual(self.service.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],before)

    def test_exact_replay_precedes_bad_manifest_context_work_and_attempt_charge(self):
        program = scalar_program();args = self.arguments(program,add_two_patch(program))
        first = self.selected_call(args);self.payloads(first)
        attempts = self.service.store.db.execute('SELECT attempts FROM contexts WHERE id=?',
                                                 (self.session.context['id'],)).fetchone()[0]
        missing = self.case/'missing.json'
        with patch.dict(os.environ,{SELECTOR:str(missing)}), \
             patch('hepta.hia_agent_candidate_native.apply_candidate_patch',side_effect=AssertionError('effect replayed')), \
             patch.object(self.service,'_context',side_effect=AssertionError('completed request rechecked context')):
            self.assertEqual(self.service.call('hia_candidate',args),first)
        restarted = HIAAgentService(self.service.store.root)
        try:
            with patch.dict(os.environ,{SELECTOR:str(missing)}):
                self.assertEqual(restarted.call('hia_candidate',args),first)
                changed = copy.deepcopy(args);changed['change']['patch_schema'] = PATCH_SCHEMA_V2
                conflict = restarted.call('hia_candidate',changed)
                self.assertEqual(conflict['error']['code'],'E_HIA_REQUEST_CONFLICT')
                fresh = {**args,'request_key':args['request_key']+'-fresh'}
                self.assertEqual(restarted.call('hia_candidate',fresh)['status'],'rejected')
        finally:restarted.close()
        self.assertEqual(self.service.store.db.execute('SELECT attempts FROM contexts WHERE id=?',
            (self.session.context['id'],)).fetchone()[0],attempts+1)

    def test_identical_bytes_keep_context_metadata_and_namespace_authority(self):
        program = scalar_program();request = add_two_patch(program)
        first = self.selected_call(self.arguments(program,request))
        second = self.selected_call(self.arguments(program,request))
        self.assertEqual(first['result']['candidate'],second['result']['candidate'])
        self.session.freeze(exhaustive_u8_workload())
        other = self.selected_call(self.arguments(program,request))
        self.assertEqual(first['result']['candidate']['sha256'],other['result']['candidate']['sha256'])
        self.assertNotEqual(first['result']['candidate']['id'],other['result']['candidate']['id'])
        self.assertEqual(first['result']['diagnostics'],other['result']['diagnostics'])
        forged = self.arguments(program,request)
        forged['change']['base_program']['uri'] += '-forged'
        with patch('hepta.hia_agent_candidate_native.apply_candidate_patch',side_effect=AssertionError('unauthorized payload access')):
            response = self.selected_call(forged)
        self.assertEqual(response['error']['code'],'E_HIA_ARTIFACT_IDENTITY')

    def test_mode2_configuration_and_untrusted_frame_extents_are_refused(self):
        good = struct.pack('<4Q',RESULT_MAGIC,2,2,0)+b'{}{}'
        self.assertEqual(result_payloads(good),(b'{}',b'{}'))
        for output in (b'',good[:-1],good+b'x',struct.pack('<4Q',0,2,2,0)+b'{}{}',
                       struct.pack('<4Q',RESULT_MAGIC,1,3,0)+b'{}{}',
                       struct.pack('<4Q',RESULT_MAGIC,2,2,1)+b'{}{}',
                       struct.pack('<4Q',RESULT_MAGIC,MAX_COMPONENT+1,2,0)+b'{}{}'):
            with self.assertRaises(HIAEditRejected):result_payloads(output)
        raw = request_wire(scalar_program(),add_two_patch(scalar_program()))
        out_size,arena_size = scratch_sizes(len(raw))
        source = ctypes.create_string_buffer(raw);output = ctypes.create_string_buffer(out_size)
        for declared in (0,3,(1<<64)-1):
            arena = ctypes.create_string_buffer(arena_size);struct.pack_into('<2Q',arena,0,2,declared)
            self.assertEqual(self.native._entry(source,len(raw),output,out_size,arena,arena_size),0xfffffffd)
        with self.assertRaises(AgentRejected) as error:self.native.result(raw,2)
        self.assertEqual(error.exception.code,'E_HIA_PATCH_SCHEMA')

    def test_killed_candidate_stages_retain_unknown_and_terminal_reply_replays(self):
        program = scalar_program();request = add_two_patch(program)
        script = r'''import json,os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire
import hepta.hia_agent_candidate_native as native
service=HIAAgentService(sys.argv[2]);stage=sys.argv[4];marker=Path(sys.argv[5])
def stop(value):
    marker.write_bytes(wire(value))
    print('checkpoint',flush=True)
    signal.pause()
if stage=='before':
    original=native.apply_candidate_patch
    def before(*args,**kwargs):
        stop({'before_payload':True})
        return original(*args,**kwargs)
    native.apply_candidate_patch=before
else:
    original=service.store.put
    def put(data,kind,metadata=None):
        ref=original(data,kind,metadata)
        if kind=={'candidate':'core','diagnostics':'candidate-diagnostics'}.get(stage):stop(ref)
        return ref
    service.store.put=put
response=service.call('hia_candidate',json.loads(Path(sys.argv[3]).read_bytes()))
if stage=='completed':stop(response)
raise AssertionError('missed checkpoint')
'''
        root = Path(__file__).resolve().parents[1]
        for stage in ('before','candidate','diagnostics','completed'):
            arguments = self.arguments(program,request)
            arguments_path = self.case/(stage+'-args.json');arguments_path.write_bytes(wire(arguments))
            marker = self.case/(stage+'-checkpoint.json')
            child = subprocess.Popen([sys.executable,'-I','-S','-B','-c',script,str(root),
                str(self.service.store.root),str(arguments_path),stage,str(marker)],
                cwd=self.case,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env={**os.environ,SELECTOR:str(self.manifest),'PYTHONDONTWRITEBYTECODE':'1'})
            try:
                ready,_,_ = select.select([child.stdout],[],[],30)
                self.assertTrue(ready,'fault checkpoint was not reached')
                self.assertEqual(child.stdout.readline(),b'checkpoint\n')
                child.kill();stdout,stderr = child.communicate(timeout=10)
                self.assertEqual(stderr,b'')
            finally:
                if child.poll() is None:
                    child.kill();child.communicate(timeout=10)
            retained = json.loads(marker.read_bytes())
            with patch('hepta.hia_agent_candidate_native.apply_candidate_patch',side_effect=AssertionError('unknown effect replayed')):
                recovered = self.selected_call(arguments)
            if stage=='completed':self.assertEqual(recovered,retained)
            else:
                self.assertEqual(recovered['error']['code'],'E_HIA_REQUEST_UNKNOWN')
                self.assertEqual(recovered['error']['retry_action'],'observe_original')
                self.assertEqual(self.selected_call(arguments)['error']['code'],'E_HIA_REQUEST_UNKNOWN')
                changed = copy.deepcopy(arguments);changed['change']['patch_schema'] = PATCH_SCHEMA_V2
                self.assertEqual(self.selected_call(changed)['error']['code'],'E_HIA_REQUEST_CONFLICT')
                if stage!='before':self.service.store.get(retained)


if __name__ == '__main__':
    unittest.main()
