"""Actual retained emission image, independent originals, and complete frames.

The controlled-port corpus is explicitly separate from real linker/filesystem
effects. No retained compiler is represented as current-source cold authority.
"""
from __future__ import annotations
import ast
import ctypes
from contextlib import ExitStack
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace, MethodType
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_service_emission_native as native
from tests import hia_service_emission_fixtures as fixtures

ROOT=Path(__file__).resolve().parents[1]


class ServiceEmissionSourceTests(unittest.TestCase):
    def test_retained_original_three_bodies_are_exact(self):
        original=json.loads(fixtures.ORIGINAL.read_bytes())
        self.assertEqual(sha256(fixtures.ORIGINAL.read_bytes()).hexdigest(),fixtures.ORIGINAL_SHA)
        self.assertTrue(all(function.__globals__ is vars(api) for function in fixtures.REFERENCE.values()))
        module=ast.parse((ROOT/'hepta/hia_agent_service.py').read_bytes())
        for old,name in [('_compile','_compile_reference'),('_hia_emit','_hia_emit_reference'),('_signatures','_signatures')]:
            with self.subTest(name=name):
                node=next(n for n in ast.walk(module) if isinstance(n,ast.FunctionDef) and n.name==name)
                node.name=old
                self.assertEqual(ast.dump(node,include_attributes=False),
                    ast.dump(ast.parse(original['functions'][old]['source']).body[0],include_attributes=False))

    def test_hia_asset_regenerates_from_independent_authoring(self):
        from tools.generate_hia_service_emission import document
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        raw=render_assembly(document()).encode()
        self.assertEqual(raw,native.SOURCE.read_bytes())
        verified=assemble_program(raw)
        self.assertLessEqual(len(verified.as_dict()['functions']),128)

    def test_effect_ports_do_not_call_retained_business_bodies(self):
        source=ast.parse((ROOT/'hepta/hia_service_emission_native.py').read_bytes())
        names={node.attr for node in ast.walk(source) if isinstance(node,ast.Attribute)}
        self.assertFalse(names & {'_compile_reference','_hia_emit_reference','_signatures'})
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS,NATIVE_OWNERS
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR],('hia_service_emission_native','NativeEmissionImage'))
        self.assertEqual(HELPERS[native.SELECTOR],HELD_NATIVE_OWNERS[native.SELECTOR])
        self.assertNotIn(native.SELECTOR,NATIVE_OWNERS)

    def test_public_selected_routes_cover_shared_signature_callers(self):
        module=ast.parse((ROOT/'hepta/hia_agent_service.py').read_bytes())
        service=next(n for n in module.body if isinstance(n,ast.ClassDef) and n.name=='HIAAgentService')
        methods={n.name:n for n in service.body if isinstance(n,ast.FunctionDef)}
        for name,count in (('_behavior_equivalence',2),('_native_reference',1)):
            calls=[n for n in ast.walk(methods[name]) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='_signature_values']
            self.assertEqual(len(calls),count,name)
        for name in ('_compile','_hia_emit','_signature_values_reference'):
            self.assertTrue(any(isinstance(n,ast.Constant) and n.value=='_native_emission' for n in ast.walk(methods[name])))


class ServiceEmissionNativeTests(unittest.TestCase):
    def identity_files(self, label, *, suffix=b''):
        case=self.folder/(self._testMethodName+'-'+label);case.mkdir(mode=0o700)
        value=json.loads(self.manifest_path.read_bytes());image=case/'emission.image.bin'
        image.write_bytes((self.manifest_path.parent/value['image_path']).read_bytes()+suffix)
        value.update(image_path=image.name,image_sha256=sha256(image.read_bytes()).hexdigest())
        manifest=case/'manifest.json';manifest.write_text(json.dumps(value,sort_keys=True)+'\n')
        source=case/'source.hiaasm';source.write_bytes(native.SOURCE.read_bytes())
        return SimpleNamespace(case=case,manifest=manifest,image=image,source=source,value=value)

    def independent_environment(self, manifest=None):
        env={key:'' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
        env[native.SELECTOR]='' if manifest is None else str(manifest)
        return patch.dict(os.environ,env)

    def public_session(self, service, prefix):
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program
        session=Session(ToolClient(service.call),prefix=prefix)
        session.freeze({'schema':'hepta.hia.agent.workload.v1','cases':[{'function':'transform','arguments':[0]}],
            'warmup_iterations':0,'repetitions':1})
        candidate=session.import_program(add_program())
        return session,candidate

    @staticmethod
    def forbidden(*args,**kwargs):
        raise AssertionError('selected emission called retained business policy')

    def poison_references(self, stack):
        stack.enter_context(patch.object(api.HIAAgentService,'_compile_reference',self.forbidden))
        stack.enter_context(patch.object(api.HIAAgentService,'_hia_emit_reference',self.forbidden))
        stack.enter_context(patch.object(api,'_signatures',self.forbidden))

    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_emission as builder
        cold=os.environ.get('HEPTA_HIA_SERVICE_EMISSION_COLD_REPORT')
        compiler_choice=os.environ.get('HEPTA_HIA_SERVICE_EMISSION_DEVELOPMENT_COMPILER')
        manifest_choice=os.environ.get('HEPTA_HIA_SERVICE_EMISSION_DEVELOPMENT_MANIFEST')
        if sum(bool(x) for x in (cold,compiler_choice,manifest_choice))!=1:
            raise ValueError('service emission requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs={}
        if cold:
            cold=Path(cold).resolve();cold_bytes=cold.read_bytes()
            report=json.loads(cold_bytes,object_pairs_hook=builder._pairs)
            try:
                nested_path=Path(report['nested_report']);nested_bytes=nested_path.read_bytes()
                compiler=Path(json.loads(nested_bytes)['generations'][-1]['produced_image']).resolve()
            except (KeyError,IndexError,TypeError) as error:
                raise ValueError('service-emission cold report lacks a compiler') from error
            compiler_bytes=compiler.read_bytes();sources=builder.admit_cold_build(compiler_bytes,cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds']!=180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds']!=3
                    or any(sources.get(name)!=sha256((ROOT/name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-emission fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold):sha256(cold_bytes).hexdigest(),str(nested_path):sha256(nested_bytes).hexdigest(),str(compiler):sha256(compiler_bytes).hexdigest()})
        cls.temporary=None;evidence=os.environ.get('HEPTA_HIA_SERVICE_EMISSION_EVIDENCE')
        if evidence:
            base=Path(evidence);base.mkdir(mode=0o700,parents=True,exist_ok=True)
            cls.folder=base/cls.__name__;cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary=tempfile.TemporaryDirectory(prefix='hia-emission-native-');cls.folder=Path(cls.temporary.name)
        if cold:
            cls.manifest_path=builder.build(cls.folder/'current-cold-build',compiler,cold);mode='MATCHING_CURRENT_SOURCE_COLD'
        elif compiler_choice:
            compiler=Path(compiler_choice).resolve();cls.manifest_path=builder.build_development(cls.folder/'development-build',compiler)
            cls.inputs[str(compiler)]=sha256(compiler.read_bytes()).hexdigest();mode='EXPLICIT_COMPILER_DEVELOPMENT'
        else:
            cls.manifest_path=Path(manifest_choice).resolve();mode='EXPLICIT_MANIFEST_DEVELOPMENT'
        raw=cls.manifest_path.read_bytes();record=json.loads(raw,object_pairs_hook=builder._pairs)
        cls.image=native.installed_emission(cls.manifest_path)
        cls.inputs.update({str(cls.manifest_path):sha256(raw).hexdigest(),str(cls.manifest_path.parent/record['image_path']):record['image_sha256']})
        cls.inputs.update({str(ROOT/name):sha256((ROOT/name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES})
        cls.entries={};cls.original_entry=cls.image._entry
        def counted(source,size,output,capacity,work,extent):
            result=cls.original_entry(source,size,output,capacity,work,extent)
            raw=ctypes.string_at(source,size)
            if size==64 and int.from_bytes(raw[:8],'little')==native.REQUEST_MAGIC:
                mode=str(int.from_bytes(raw[48:56],'little'));cls.entries[mode]=cls.entries.get(mode,0)+1
            return result
        cls.image._entry=counted
        (cls.folder/'fixture.json').write_text(json.dumps({'mode':mode,'inputs':cls.inputs,'manifest_path':str(cls.manifest_path),
            'current_source_cold':bool(cold),'whole_stack_native':False},indent=2)+'\n')

    @classmethod
    def tearDownClass(cls):
        cls.image._entry=cls.original_entry
        for name,expected in cls.inputs.items():
            if sha256(Path(name).read_bytes()).hexdigest()!=expected:raise AssertionError('held emission input changed: '+name)
        (cls.folder/'actual-entries.json').write_text(json.dumps(cls.entries,indent=2)+'\n')
        if cls.temporary is not None:cls.temporary.cleanup()

    def record(self,name,value):
        (self.folder/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')

    def test_original_with_protocol_and_suppressed_local_errors(self):
        rows=[]
        def selected(service,*args,**kwargs):return native.NativeEmissionService(service,self.image).compile(*args,**kwargs)
        for outer in (False,True):
            for phase,suppressed in [('success',False),('emit',False),('enter',False),('compile',False),('compile',True),('read',False),('read',True),('exit',False)]:
                with self.subTest(phase=phase,suppressed=suppressed,outer=outer):
                    expected=fixtures.stable(fixtures.compile_fixture(phase,suppressed,outer))
                    actual=fixtures.stable(fixtures.compile_fixture(phase,suppressed,outer,implementation=selected))
                    rows.append({'phase':phase,'suppressed':suppressed,'outer':outer,'expected':expected,'actual':actual})
                    self.assertEqual(actual,expected)
        self.record('original-with-16',rows)

    def test_original_signature_order_aliases_generator_traceback_and_pep479(self):
        rows=[];owners=[]
        def selected(program,exports):
            owner=native.NativeEmissionService(None,self.image);owners.append(owner);return owner.signatures(program,exports)
        cases=[(p,r,s,e,None,False) for p in [[],['i32'],['readbuf'],['bool','u64']] for r in [[],['unit'],['u64','u64']] for s in [set(),{'f0'}] for e in [(),(('f0',64),)]]
        cases += [([],[],{'f0'},(),fault,outer) for fault in ('missing','stop') for outer in (False,True)]
        for index,(params,returns,scalar,exports,fault,outer) in enumerate(cases):
            with self.subTest(index=index):
                expected=fixtures.signature_fixture(fixtures.REFERENCE['_signatures'],params,returns,scalar,exports,fault=fault,outer=outer)
                actual=fixtures.signature_fixture(selected,params,returns,scalar,exports,fault=fault,outer=outer)
                rows.append({'case':index,'expected':expected,'actual':actual});self.assertEqual(actual,expected)
        self.assertTrue(all(not o.active and not o.unknown for o in owners))
        self.record('original-signature-52',rows)

    def test_original_emit_any_double_truth_partial_effects_and_errors(self):
        rows=[]
        for case in ('canonical','plan','missing','stop','truth','put-error','receipt-error'):
            for outer in (False,True):
                with self.subTest(case=case,outer=outer):
                    expected,_=fixtures.emit_fixture(False,self.image,case,outer)
                    actual,owner=fixtures.emit_fixture(True,self.image,case,outer)
                    rows.append({'case':case,'outer':outer,'expected':expected,'actual':actual})
                    self.assertEqual(actual,expected);self.assertFalse(owner.active);self.assertFalse(owner.unknown)
        self.record('original-emit-14',rows)

    def test_real_emitter_linker_files_sqlite_publication_and_machine_result(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        self.assertIsNotNone(shutil.which('ld'))
        program=verify_program(minimal_document());rows=[]
        for kind in ('object','shared'):
            outputs=[]
            for selected in (False,True):
                case=self.folder/('real-'+kind+str(selected));case.mkdir(mode=0o700)
                store=AgentStore(case/'store');service=SimpleNamespace(store=store,identities={'emission-control':'same'})
                try:
                    if selected:
                        owner=native.NativeEmissionService(service,self.image);data,built=owner.compile(program,kind,None,10000)
                        self.assertFalse(owner.active);self.assertFalse(owner.unknown)
                    else:data,built=fixtures.REFERENCE['_compile'](service,program,kind,None,10000)
                    saved,metadata=store.get(built['object_artifact'],kind='build-object')
                    self.assertEqual(sha256(saved).hexdigest(),built['object_sha256'])
                    self.assertEqual(sha256(data).hexdigest(),built['artifact_sha256'])
                    self.assertEqual(metadata['core_sha256'],program.sha256)
                    self.assertEqual([tuple(x) for x in store.db.execute('SELECT kind FROM artifacts')],[('build-object',)])
                    result=None
                    if kind=='shared':
                        path=case/'program.so';path.write_bytes(data);library=ctypes.CDLL(str(path));call=library.answer;call.argtypes=[ctypes.c_uint64];call.restype=ctypes.c_uint64
                        result=call(30);self.assertEqual(result,37)
                    outputs.append((data,saved,{k:v for k,v in built.items() if k not in ('object_artifact','commands')},metadata))
                    rows.append({'kind':kind,'selected':selected,'data_sha256':sha256(data).hexdigest(),'object_sha256':sha256(saved).hexdigest(),'machine_result':result,'receipt':built})
                finally:store.close()
            self.assertEqual(outputs[0],outputs[1])
        self.record('real-emitter-linker-store',rows)

    def test_public_reference_chain_is_independent_and_selected_policy_is_native(self):
        rows=[];artifacts=[]
        for selected in (False,True):
            case=self.folder/('public-chain-'+str(selected));case.mkdir(mode=0o700)
            with self.independent_environment(self.manifest_path if selected else None),ExitStack() as stack:
                service=api.HIAAgentService(case/'state');stack.callback(service.close)
                if selected:
                    self.poison_references(stack)
                    self.assertIs(service._native_emission.image,self.image)
                else:
                    service._compile=MethodType(fixtures.REFERENCE['_compile'],service)
                    service._hia_emit=MethodType(fixtures.REFERENCE['_hia_emit'],service)
                    stack.enter_context(patch.object(api,'_signatures',fixtures.REFERENCE['_signatures']))
                    for name in ('emit','compile','signatures'):
                        stack.enter_context(patch.object(native.NativeEmissionService,name,self.forbidden))
                    self.assertIs(service._compile.__func__.__code__,fixtures.REFERENCE['_compile'].__code__)
                    self.assertIs(service._hia_emit.__func__.__code__,fixtures.REFERENCE['_hia_emit'].__code__)
                    self.assertIs(api._signatures.__code__,fixtures.REFERENCE['_signatures'].__code__)
                session,candidate=self.public_session(service,'emission-public-'+str(selected))
                before=service.store.db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifacts').fetchone()[0]
                built=session.emit(candidate)
                actual,metadata,program=service._native(built['native_artifact'],session.context)
                receipt=session.read_json(built['build_receipt'])
                object_bytes,_=service.store.get(receipt['object_artifact'],kind='build-object')
                kinds=[row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))]
                self.assertEqual(kinds,['build-object','native','build-receipt'])
                self.assertEqual(metadata['signatures'],{'transform':{'params':['u8'],'returns':['u8']}})
                path=case/'actual.so';path.write_bytes(actual);library=ctypes.CDLL(str(path))
                call=library.transform;call.argtypes=[ctypes.c_uint8];call.restype=ctypes.c_uint8
                self.assertEqual(call(250),1)
                artifacts.append((actual,object_bytes,metadata['signatures']))
                if selected:
                    self.assertFalse(service._native_emission.active);self.assertFalse(service._native_emission.unknown)
                rows.append({'selected':selected,'artifact_sha256':sha256(actual).hexdigest(),
                    'object_sha256':sha256(object_bytes).hexdigest(),'kinds_in_original_order':kinds,
                    'machine_result':call(250),'reference_chain_original':not selected,'old_three_policies_poisoned':selected})
        self.assertEqual(artifacts[0],artifacts[1]);self.record('public-chain',rows)

    def test_late_known_error_and_lost_native_ack_preserve_real_object_publication(self):
        rows=[]
        for selected in (False,True):
            case=self.folder/('late-known-'+str(selected));case.mkdir(mode=0o700);failure=LookupError('late signature failure')
            with self.independent_environment(self.manifest_path if selected else None),ExitStack() as stack:
                service=api.HIAAgentService(case/'state');stack.callback(service.close)
                if selected:
                    self.poison_references(stack)
                    stack.enter_context(patch.object(service._native_emission,'signatures',side_effect=failure))
                else:
                    service._compile=MethodType(fixtures.REFERENCE['_compile'],service)
                    service._hia_emit=MethodType(fixtures.REFERENCE['_hia_emit'],service)
                    stack.enter_context(patch.object(api,'_signatures',side_effect=failure))
                session,candidate=self.public_session(service,'late-signature-'+str(selected))
                args=session.arguments(candidate=candidate,backend_profile=session.backend,output_kind='object',
                    codegen={'kind':'canonical','lowering_profile':session.profiles['lowering']},verification_receipts=[])
                before=service.store.db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifacts').fetchone()[0]
                with self.assertRaises(LookupError) as caught:service._hia_emit(args)
                self.assertIs(caught.exception,failure)
                kinds=[row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))]
                self.assertEqual(kinds,['build-object'])
                if selected:self.assertFalse(service._native_emission.active);self.assertFalse(service._native_emission.unknown)
                rows.append({'case':'known-after-object','selected':selected,'kinds':kinds,'original_error_identity':True})
        case=self.folder/'late-ack';case.mkdir(mode=0o700);failure=KeyboardInterrupt('lost object publication ACK')
        with self.independent_environment(self.manifest_path),ExitStack() as stack:
            service=api.HIAAgentService(case/'state');stack.callback(service.close);self.poison_references(stack)
            session,candidate=self.public_session(service,'lost-object-ack')
            args=session.arguments(candidate=candidate,backend_profile=session.backend,output_kind='object',
                codegen={'kind':'canonical','lowering_profile':session.profiles['lowering']},verification_receipts=[])
            before=service.store.db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifacts').fetchone()[0]
            owner=service._native_emission;actual=owner.image._entry;hits=[]
            def interrupted(source,size,output,capacity,state,extent):
                request=struct.unpack('<8Q',ctypes.string_at(source,size))
                previous=struct.unpack('<16Q',ctypes.string_at(state,extent))
                result=actual(source,size,output,capacity,state,extent)
                if request[1]==2 and request[6]==2 and previous[3]==223:
                    hits.append({'request':list(request),'before':list(previous),'after':list(struct.unpack('<16Q',ctypes.string_at(state,extent)))})
                    raise failure
                return result
            with patch.object(owner.image,'_entry',interrupted):
                with self.assertRaises(KeyboardInterrupt) as caught:service._hia_emit(args)
            self.assertIs(caught.exception,failure);self.assertEqual(len(hits),1)
            kinds=[row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))]
            self.assertEqual(kinds,['build-object']);self.assertEqual(len(owner.unknown),2)
            for state in owner.unknown.values():
                state.fenced=False
                with self.assertRaises(native.EmissionUnknown):state.invoke(state.receipt)
                state.fenced=True
            self.assertEqual([row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))],kinds)
            rows.append({'case':'actual-native-object-ack-loss','kinds':kinds,'original_error_identity':True,
                         'unknown_states':len(owner.unknown),'native_handoff':hits})
        self.record('late-publication-errors',rows)

    def test_reentrant_independent_call_and_original_error_do_not_reissue_permission(self):
        rows=[]
        for selected in (False,True):
            trace=[];failure=LookupError('outer profile error');owner=None
            program=SimpleNamespace(as_dict=lambda:{'functions':[]},scalar_entrypoints=set())
            service=SimpleNamespace()
            def profile(*args):
                trace.append('profile')
                if selected:
                    parent=next(state for state in owner.active.values() if state.mode==1)
                    with self.assertRaises(native.EmissionUnknown):parent.invoke(parent.receipt)
                    observed=owner.signatures(program)
                else:observed=fixtures.REFERENCE['_signatures'](program)
                self.assertEqual(observed,{});trace.append('nested-signatures');raise failure
            service._profile=profile;service._context=lambda value:trace.append('unreached-context')
            if selected:owner=native.NativeEmissionService(service,self.image)
            invoke=owner.emit if selected else lambda args:fixtures.REFERENCE['_hia_emit'](service,args)
            with self.assertRaises(LookupError) as caught:invoke({'backend_profile':'p'})
            self.assertIs(caught.exception,failure);self.assertEqual(trace,['profile','nested-signatures'])
            if selected:
                self.assertFalse(owner.active);self.assertFalse(owner.unknown)
                self.assertEqual(owner.signatures(program),{})
            rows.append({'selected':selected,'trace':trace,'original_error_identity':True})
        self.record('reentrant-original-error',rows)

    def test_actual_proof_binds_held_emission_and_rejects_other_owner_after_restart(self):
        from hepta import hia_checker_identity as checker
        from hepta.hia_agent_store import AgentRejected,digest
        a=self.identity_files('A');b=self.identity_files('B-explicit-trailing-byte-mutant',suffix=b'\x90')
        rows=[]
        with self.independent_environment(a.manifest),patch.object(native,'SOURCE',a.source),ExitStack() as stack:
            self.poison_references(stack);service=api.HIAAgentService(a.case/'state')
            try:
                session,candidate=self.public_session(service,'held-emission-proof')
                held=service._native_emission.checker_owner()
                expected=checker.checker_native_selection(held_owners=(held,))
                for label,selection in [('original',str(a.manifest)),('different-image',str(b.manifest)),('cleared','')]:
                    os.environ[native.SELECTOR]=selection
                    build=session.emit(candidate,kind='object');result=session.encoding(candidate,build)
                    evidence=session.read_json(result['checks'][0]['evidence_artifact'])
                    self.assertEqual(evidence['native_checker_selection'],expected)
                    self.assertEqual(result['checks'][0]['checker']['native_selection_sha256'],digest(expected))
                    service._verification(result['verification_receipt'],session.context,candidate)
                    self.assertIs(service._native_emission.image,held.image)
                    rows.append({'selector_state':label,'held_identity':expected[native.SELECTOR],
                                 'real_emit_and_encoding_check':'proved'})
                with self.assertRaises(ValueError):
                    checker.checker_native_selection(held_owners=(evidence['native_checker_selection'][native.SELECTOR],))
            finally:service.close()
            os.environ[native.SELECTOR]=str(b.manifest)
            other=api.HIAAgentService(a.case/'state')
            try:
                with self.assertRaises(AgentRejected) as rejected:
                    other._verification(result['verification_receipt'],session.context,candidate)
                self.assertEqual(rejected.exception.code,'E_HIA_PROOF_SCOPE')
            finally:other.close()
            os.environ[native.SELECTOR]=str(a.manifest)
            restored=api.HIAAgentService(a.case/'state')
            try:
                restored._verification(result['verification_receipt'],session.context,candidate)
                self.assertIs(restored._native_emission.image,held.image)
            finally:restored.close()
        self.record('actual-held-proof-and-restart',{'observations':rows,'other_owner_rejected':'E_HIA_PROOF_SCOPE'})

    def test_actual_claim_and_ack_loss_do_not_repeat_foreign_effect(self):
        rows=[]
        for event in (1,2):
            calls=[];fault=KeyboardInterrupt('handoff-'+str(event));base=self.image
            class FaultImage:
                delivery=base.delivery
                def _entry(self,source,size,output,capacity,state,extent):
                    answer=base._entry(source,size,output,capacity,state,extent)
                    if struct.unpack('<8Q',ctypes.string_at(source,size))[1]==event:raise fault
                    return answer
            owner=native.NativeEmissionService(SimpleNamespace(_profile=lambda *args:calls.append(args)),FaultImage())
            state=owner._new_state(1,{'args':{'backend_profile':'p'}});receipt=state.call(0)
            with self.assertRaises(KeyboardInterrupt) as caught:state.invoke(receipt)
            self.assertIs(caught.exception,fault);self.assertEqual(len(calls),0 if event==1 else 1)
            state.fenced=False
            with self.assertRaises(native.EmissionUnknown):state.invoke(receipt)
            self.assertEqual(len(calls),0 if event==1 else 1)
            rows.append({'event':event,'calls':len(calls),'state':list(struct.unpack('<16Q',state.buffer.raw))})
        self.record('actual-claim-ack-loss',rows)

    def test_exact_issued_receipt_and_cross_instance_refuse_before_effect(self):
        calls=[];owner=native.NativeEmissionService(SimpleNamespace(_profile=lambda *args:calls.append(args)),self.image)
        first=owner._new_state(1,{'args':{'backend_profile':'p'}});second=owner._new_state(1,{'args':{'backend_profile':'p'}})
        a=first.call(0);b=second.call(0)
        for receipt in (replace(a),b):
            with self.assertRaises(native.EmissionUnknown):first.invoke(receipt)
        altered=list(a.words);altered[4]=True
        object.__setattr__(a,'words',tuple(altered))
        with self.assertRaises(native.EmissionUnknown):first.invoke(a)
        self.assertEqual(calls,[])

    def test_unconfirmed_generator_ack_cannot_be_replayed(self):
        base=self.image;calls=[];fault=KeyboardInterrupt('generator-ack')
        class FaultImage:
            delivery=base.delivery
            def _entry(self,source,size,output,capacity,state,extent):
                raw=struct.unpack('<8Q',ctypes.string_at(source,size));before=struct.unpack('<16Q',ctypes.string_at(state,extent))
                result=base._entry(source,size,output,capacity,state,extent)
                if raw[6]==5 and raw[1]==2 and before[3]==802:raise fault
                return result
        class Parameter(dict):
            def __getitem__(self,key):calls.append(key);return super().__getitem__(key)
        program=SimpleNamespace(scalar_entrypoints={'f0'},as_dict=lambda:{'functions':[{'name':'f0','params':[Parameter(type='u32')],'returns':[]}]})
        owner=native.NativeEmissionService(None,FaultImage())
        with self.assertRaises(KeyboardInterrupt) as caught:owner.signatures(program)
        self.assertIs(caught.exception,fault);self.assertEqual(calls,['type']);self.assertTrue(owner.unknown)
        for state in owner.unknown.values():
            with self.assertRaises(native.EmissionUnknown):state.invoke(state.receipt)
        self.assertEqual(calls,['type'])

    def test_same_size_exception_and_business_requests_are_distinct(self):
        from hepta.hia_exception_delivery import EMIT_REQUEST,EMIT_MAGIC,CODE_BYTES,CODE_SHA256
        raw=struct.pack('<8Q',native.REQUEST_MAGIC,0,0,11,22,0,1,native._runtime_profile())
        self.assertEqual(len(raw),len(EMIT_REQUEST));self.assertNotEqual(native.REQUEST_MAGIC,EMIT_MAGIC)
        for name,request,expected in [('business',raw,144),('delivery',EMIT_REQUEST,CODE_BYTES),
                ('mixed',struct.pack('<8Q',EMIT_MAGIC,0,0,11,22,0,1,0),0xfffffffd)]:
            source=ctypes.create_string_buffer(request+b'\xa5'*16,80);output=ctypes.create_string_buffer(b'\xb7'*176,176);work=ctypes.create_string_buffer(b'\0'*128+b'\xc9'*16,144)
            self.assertEqual(self.image._entry(source,64,output,160,work,128),expected)
            self.assertEqual(source.raw,request+b'\xa5'*16);self.assertEqual(output.raw[160:],b'\xb7'*16);self.assertEqual(work.raw[128:],b'\xc9'*16)
            if name=='delivery':self.assertEqual(sha256(output.raw[:CODE_BYTES]).hexdigest(),CODE_SHA256)
            if name!='business':self.assertEqual(work.raw[:128],b'\0'*128)

    def test_partial_image_constructor_retires_own_mapping_with_original_error_held(self):
        value=json.loads(self.manifest_path.read_bytes());raw=(self.manifest_path.parent/value['image_path']).read_bytes()
        observations=[]
        for kind in (MemoryError,KeyboardInterrupt):
            error=kind('delivery construction');references=[]
            def refused(image):
                references.append(weakref.ref(image._mapping))
                raise error
            with patch.object(native.ExceptionDelivery,'from_hia',side_effect=refused):
                caught=None
                try:native.NativeEmissionImage(raw,sha256(raw).hexdigest())
                except BaseException as observed:caught=observed
                else:self.fail('injected constructor failure was not propagated')
            self.assertIs(caught,error)
            self.assertIsNotNone(error.__traceback__)
            self.assertIsNotNone(references[0]())
            self.assertTrue(references[0]().closed)
            observations.append({'error':kind.__name__,'original_error_preserved':True,'actual_mmap_closed':True,'no_gc':True})
        self.record('partial-image-constructor',observations)

    def test_full_native_frames_match_independent_vm_all_seven_modes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        program=assemble_program(native.SOURCE.read_bytes());entry=program.as_dict()['functions'][0];base=self.image;states={};counts={}
        class Mirror:
            delivery=base.delivery
            def _entry(self,source,size,output,capacity,state,extent):
                raw=ctypes.string_at(source,size);fields=struct.unpack('<8Q',raw);identity=fields[3:5]
                retained=states.setdefault(identity,bytearray(extent))
                if bytes(retained)!=ctypes.string_at(state,extent):raise AssertionError('independent retained prestate differs')
                src=ctypes.create_string_buffer(raw+b'\xa5'*16,len(raw)+16);out=ctypes.create_string_buffer(b'\xb7'*(capacity+16),capacity+16);work=ctypes.create_string_buffer(bytes(retained)+b'\xc9'*16,extent+16)
                actual=base._entry(src,size,out,capacity,work,extent)
                owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(b'\xb7'*capacity)),_Owner(-3,retained)]
                expected=_Machine(program,10000000,16<<20,None,128).invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                if (actual!=expected or out.raw[:capacity]!=bytes(owners[1].data) or work.raw[:extent]!=bytes(retained)
                        or src.raw!=raw+b'\xa5'*16 or out.raw[capacity:]!=b'\xb7'*16 or work.raw[extent:]!=b'\xc9'*16):
                    raise AssertionError('complete native/VM output, retained state or canary differs')
                ctypes.memmove(output,out,capacity);ctypes.memmove(state,work,extent);counts[fields[6]]=counts.get(fields[6],0)+1
                return actual
        mirror=Mirror()
        expected,_=fixtures.emit_fixture(False,mirror,'truth')
        actual,_=fixtures.emit_fixture(True,mirror,'truth');self.assertEqual(actual,expected)
        selected=lambda p,e:native.NativeEmissionService(None,mirror).signatures(p,e)
        self.assertEqual(fixtures.signature_fixture(selected,['i32'],['unit'],{'f0'},()),fixtures.signature_fixture(fixtures.REFERENCE['_signatures'],['i32'],['unit'],{'f0'},()))
        def compile_selected(service,*args,**kwargs):return native.NativeEmissionService(service,mirror).compile(*args,**kwargs)
        self.assertEqual(fixtures.stable(fixtures.compile_fixture('success',implementation=compile_selected)),fixtures.stable(fixtures.compile_fixture('success')))
        self.assertEqual(set(counts),set(range(1,8)));self.record('complete-vm-native-frames',{'actual_entries':counts,'instances':len(states)})

    def test_held_image_scope_survives_paths_and_selector_drift(self):
        from hepta import hia_checker_identity as checker
        case=self.folder/'held-scope';case.mkdir(mode=0o700)
        record=json.loads(self.manifest_path.read_bytes());image=case/'image.bin';image.write_bytes((self.manifest_path.parent/record['image_path']).read_bytes());record['image_path']=image.name
        manifest=case/'manifest.json';manifest.write_text(json.dumps(record));source=case/'source.hiaasm';source.write_bytes(native.SOURCE.read_bytes())
        env={key:'' for key in checker.NATIVE_OWNERS};env[native.SELECTOR]=str(manifest)
        with patch.dict(os.environ,env),patch.object(native,'SOURCE',source):
            held=native.admitted_emission(capture_identity=True);owner=native.NativeEmissionService(None,held.image,checker_custody=held)
            before=checker.checker_native_selection(held_owners=(owner.checker_owner(),))
            for path in (source,image,manifest):path.write_bytes(path.read_bytes()+b'changed')
            os.environ[native.SELECTOR]='/different-current-environment'
            with self.assertRaises((OSError,ValueError)):native.installed_emission(manifest)
            self.assertEqual(checker.checker_native_selection(held_owners=(owner.checker_owner(),)),before)
            program=SimpleNamespace(as_dict=lambda:{'functions':[]},scalar_entrypoints=set())
            self.assertEqual(owner.signatures(program),{})
            self.assertFalse(owner.active);self.assertFalse(owner.unknown)
            with self.assertRaises(ValueError):checker.checker_native_selection(held_owners=(before[native.SELECTOR],))
            with self.assertRaises(ValueError):checker.checker_native_selection(held_owners=(held,held))
        self.record('held-scope',before[native.SELECTOR])

    def test_installed_wheel_real_public_emission_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES,NATIVE_SOURCE_FILES,
            SOURCE_BUILD_FILES,COMPILER_BUILD_FILES,PUBLICATION_BUILD_FILES)
        from tests.test_hia_program_native import minimal_document
        self.assertIn('examples/hia_bootstrap/service_emission.hiaasm',NATIVE_SOURCE_FILES)
        case=self.folder/'installed-wheel';case.mkdir(mode=0o700);source=case/'source';source.mkdir()
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        resources=(tuple('docs/'+item for item in DISCOVERY_FILES)+NATIVE_SOURCE_FILES
                   +SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES)
        self.assertEqual(len(resources),len(set(resources)))
        for name in (*resources,'setup.py','pyproject.toml','MANIFEST.in'):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        packaging=os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON',sys.executable)
        wheels,installed=case/'wheels',case/'installed'
        built=subprocess.run([packaging,'-B','-m','pip','wheel','--no-deps','--no-index','--no-build-isolation',
            '--wheel-dir',str(wheels),str(source)],cwd=case,capture_output=True,timeout=120)
        (case/'wheel-build.stdout').write_bytes(built.stdout);(case/'wheel-build.stderr').write_bytes(built.stderr)
        self.assertEqual(built.returncode,0,built.stdout+built.stderr);wheel,=wheels.glob('*.whl')
        copied=subprocess.run([packaging,'-B','-m','pip','install','--no-deps','--no-index','--target',str(installed),str(wheel)],
            cwd=case,capture_output=True,timeout=120)
        (case/'wheel-install.stdout').write_bytes(copied.stdout);(case/'wheel-install.stderr').write_bytes(copied.stderr)
        self.assertEqual(copied.returncode,0,copied.stdout+copied.stderr)
        selection=case/'selection';selection.mkdir(mode=0o700);manifest=json.loads(self.manifest_path.read_bytes())
        shutil.copyfile(self.manifest_path.parent/manifest['image_path'],selection/manifest['image_path'])
        (selection/'manifest.json').write_text(json.dumps(manifest,sort_keys=True)+'\n')
        (case/'program.json').write_text(json.dumps(minimal_document(),sort_keys=True)+'\n')
        program=r'''import ctypes,hashlib,importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed emission imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_service as api
from hepta.hia_service_emission_native import SOURCE,SELECTOR,admitted_emission,REQUEST_MAGIC
from hepta.hia_checker_identity import checker_native_selection
from hepta.hia_program import verify_program
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed emission used old policy')
api.HIAAgentService._compile_reference=forbidden
api.HIAAgentService._hia_emit_reference=forbidden
api._signatures=forbidden
manifest=Path(sys.argv[2]);os.environ[SELECTOR]=str(manifest)
service=api.HIAAgentService(sys.argv[3]);owner=service._native_emission
assert owner is not None
held=checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]
calls={};entry=owner.image._entry
def counted(source,size,output,capacity,work,extent):
    raw=ctypes.string_at(source,size)
    result=entry(source,size,output,capacity,work,extent)
    if size==64 and int.from_bytes(raw[:8],'little')==REQUEST_MAGIC:
        mode=str(int.from_bytes(raw[48:56],'little'));calls[mode]=calls.get(mode,0)+1
    return result
owner.image._entry=counted
examples=service._examples()
workload=service.store.json(examples['workload'],'workload')
objective=service.store.json(examples['objective'],'objective')
cost=service.store.json(examples['cost_policy'],'cost-policy')
frozen=service._hia_context({'compiler_profile':service.profiles['compiler'],'target_profile':service.profiles['target'],
    'baseline_program':None,'workload':workload,'objective':objective,
    'budget':{'max_candidates':3,'max_model_tokens':10,'max_total_wall_ms':300000,
              'max_native_wall_ms':1000,'max_memory_bytes':str(64*1024**2),'cost_policy':cost}})
verified=verify_program(Path(sys.argv[4]).read_bytes())
candidate=service.store.put(verified.canonical_bytes,'core',{'context':frozen['context']})
args={'candidate':candidate,'context':frozen['context'],'backend_profile':service.profiles['backend'],
    'output_kind':'shared','codegen':{'kind':'canonical','lowering_profile':service.profiles['lowering']},
    'verification_receipts':[]}
before=service.store.db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifacts').fetchone()[0]
build=service._hia_emit(args)
actual,metadata,_=service._native(build['native_artifact'],frozen['context'])
kinds=[row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))]
assert kinds==['build-object','native','build-receipt'],kinds
output=Path(sys.argv[3]).parent/'actual.so';output.write_bytes(actual)
library=ctypes.CDLL(str(output));function=library.answer
function.argtypes=[ctypes.c_uint64];function.restype=ctypes.c_uint64
assert function(30)==37
assert metadata['signatures']=={'answer':{'params':['u64'],'returns':['u64']}}
os.environ[SELECTOR]=''
assert service._signature_values(verified)==metadata['signatures']
assert checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]==held
os.environ[SELECTOR]=str(manifest);assert admitted_emission() is owner.image
value=json.loads(manifest.read_bytes());image=manifest.parent/value['image_path']
refusals=[]
for label,path in [('image',image),('source',SOURCE)]:
    raw=path.read_bytes();path.write_bytes(raw+b'changed');new_state=Path(sys.argv[3]+'-refused-'+label)
    try:
        try:api.HIAAgentService(new_state)
        except ValueError:refusals.append(label)
        else:raise AssertionError('changed selected '+label+' was admitted')
        assert not new_state.exists()
        assert service._signature_values(verified)==metadata['signatures']
        assert checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]==held
    finally:path.write_bytes(raw)
assert refusals==['image','source']
assert {'1','2','3','4'}<=set(calls) and all(value>0 for value in calls.values()),calls
assert owner.active=={} and owner.unknown=={}
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
owner.image._entry=entry;service.close()
print(json.dumps({'actual_entries':calls,'artifact_sha256':hashlib.sha256(actual).hexdigest(),
    'machine_result':37,'kinds':kinds,'warm_refusals':refusals,'installed_source':str(SOURCE),
    'held_owner':held,'reference_called':False,'authoring_imported':False,'whole_stack_native':False},sort_keys=True))
'''
        env={key:value for key,value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        child=subprocess.run([sys.executable,'-I','-S','-B','-c',program,str(installed),str(selection/'manifest.json'),
            str(case/'state'),str(case/'program.json')],cwd=case,env=env,capture_output=True,text=True,timeout=30)
        (case/'actual.stdout').write_text(child.stdout);(case/'actual.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode,0,child.stderr)
        result=json.loads(child.stdout);self.assertEqual(result['machine_result'],37)
        self.assertEqual(result['kinds'],['build-object','native','build-receipt'])
        self.record('installed-wheel',{'wheel':{'path':str(wheel),'bytes':wheel.stat().st_size,
            'sha256':sha256(wheel.read_bytes()).hexdigest()},'result':result})
