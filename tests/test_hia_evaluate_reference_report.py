"""Qualify public VM observation materialization on actual native batch results."""

import json
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_service import _vm_observation
from hepta.hia_agent_store import wire
from hepta.hia_program import verify_program
from tests.test_hia_program import b,c,f,i,m,ret
from tools.generate_hia_evaluate_reference_report import SOURCE,PACKER,MAGIC
from tools.qualify_hia_selfhost import compile_stage

ROOT=Path(__file__).resolve().parents[1]


class ReferenceObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_evaluate_reference_batch import NativeReferenceBatchTests
        NativeReferenceBatchTests.setUpClass()
        cls.addClassCleanup(NativeReferenceBatchTests.doClassCleanups)
        cls.reference=NativeReferenceBatchTests()
        out=cls.reference.owned.parent.parent
        compiler=out/'B2.image.bin'
        image,_=compile_stage(out,'public-ref',compiler,(ROOT/SOURCE).read_bytes())
        packer,_=compile_stage(out,'public-ref-packer',compiler,(ROOT/PACKER).read_bytes())
        raw=image.read_bytes()
        cls.exe,_=compile_stage(out,'public-reference-observations',packer,
                    struct.pack('<2Q',MAGIC,len(raw))+raw,output_extension='.elf')
        cls.exe.chmod(0o500)

    def observe(self,core,workload,batch,*,bounds=None):
        text=b'['+core+b','+wire(workload)+b']'
        authorization=(b'' if bounds is None else struct.pack('<2Q',*bounds)+self.reference.owned.read_bytes())
        data=text+batch+authorization+struct.pack('<8s2Q',b'HIAERJ01' if bounds is None else b'HIAERJ02',
                                                   len(text),len(batch))
        p=subprocess.run([self.exe],input=data,capture_output=True,timeout=8)
        self.assertEqual(p.stderr,b'')
        return p.returncode,p.stdout

    def shared(self,program,cases,*,exports=()):
        checked=verify_program(verify_program(program).canonical_bytes)
        workload=dict(schema='hepta.hia.agent.workload.v1',cases=cases,warmup_iterations=0,repetitions=1)
        if exports:
            workload.update(schema='hepta.hia.agent.workload.v2',
                foreign_buffer_exports=[{'function':name,'max_buffer_bytes':n} for name,n in exports])
        code,raw,err=self.reference.invoke(checked,workload)
        self.assertEqual((code,err),(0,b''))
        expected=[]
        for case in cases:
            row=_vm_observation(checked,case,foreign_buffer_exports=exports)
            expected.append(row)
            if row['status']=='budget_exceeded':
                break
        got=self.observe(checked.canonical_bytes,workload,raw)
        self.assertEqual(got,(0,wire(expected)),(got[0],got[1][:1800],wire(expected)[:1800]))
        return checked,workload,raw

    def check_outcome(self,core,work,raw,start,end):
        from hepta.hia_agent_runner import _reference_batch_receipt
        checked=verify_program(core)
        rows=[]
        exports=tuple((item['function'],item['max_buffer_bytes']) for item in work.get('foreign_buffer_exports',[]))
        for case in work['cases']:
            rows.append(_vm_observation(checked,case,foreign_buffer_exports=exports))
            if rows[-1]['status']=='budget_exceeded':
                break
        owned=sha256(self.reference.owned.read_bytes()).hexdigest()
        report=_reference_batch_receipt(checked.sha256,work['cases'],rows,0,1,None,None,(owned,len(rows)))
        expected=dict(report=report,started=True,returncode=0,status='returned',stdout_sha256=sha256(raw).hexdigest(),
                      stderr_sha256=sha256(b'').hexdigest(),termination_confirmed=True,wall_ns=str(end-start))
        self.assertEqual(self.observe(core,work,raw,bounds=(start,end)),(0,wire(expected)))
        self.assertEqual(self.observe(core,work,raw,bounds=(end,start)),(2,b''))

    def test_scalar_signed_boolean_unit_and_empty(self):
        for typ,values in (('i8',[-127,112]),('i64',[-(1<<63),0]),('u64',[0,(1<<64)-1]),
                           ('bool',[False,True]),('unit',[None])):
            if typ=='unit':
                params=[]
                prog=m(f('answer',[],['unit'],[],[b('entry',[],[c('v','unit',None)],ret('v'))]))
                cases=[{'function':'answer','arguments':[]}]
            else:
                params=[('v',typ)]
                prog=m(f('answer',params,[typ],[],[b('entry',params,[],ret('v'))]))
                cases=[{'function':'answer','arguments':[v]} for v in values]
            with self.subTest(typ=typ):
                self.shared(prog,cases)
        self.shared(m(f('answer',[],[],[],[b('entry',[],[],ret())])),[{'function':'answer','arguments':[]}])

    def test_real_resources_typed_traps_and_external_hashes(self):
        from tests.test_hia_agent_buffer_lifecycle import byte_program,trap_program
        checked,work,raw=self.shared(byte_program(),[{'function':'copy_bytes','arguments':[{'bytes_hex':'005aff'},
                      {'byte_length':5,'fill_byte':165}]}],exports=(('copy_bytes',16),))
        altered=bytearray(raw)
        altered[-8]^=1
        self.assertEqual(self.observe(checked.canonical_bytes,work,altered),(2,b''))
        self.shared(trap_program(),[{'function':'write_then_trap','arguments':[{'bytes_hex':'0807'}]},
                      {'function':'write_then_trap','arguments':[{'bytes_hex':''}]}],exports=(('write_then_trap',16),))
        base=m(f('yes',[],['u32'],['alloc','write','trap'],[b('entry',[],[
            c('n','usize',3),i('buffer.new',['n'],[('o','buffer')]),i('owner.drop',['o']),c('ok','u32',1)],ret('ok'))]))
        self.shared(base,[{'function':'yes','arguments':[]}])
        from hepta.hia_schema import PRIMITIVE_PROFILES,supports_feature
        chained=dict(base,schema=next(k for k in PRIMITIVE_PROFILES if supports_feature(k,'recursive_chain')))
        self.shared(chained,[{'function':'yes','arguments':[]}])

    def test_explicit_and_arithmetic_stops_and_ledger_rejection(self):
        for trap in ('user','overflow','division_by_zero','bounds','allocation'):
            prog=m(f('answer',[],['u32'],['trap'],[b('entry',[],[],{'op':'trap','code':trap})]))
            self.shared(prog,[{'function':'answer','arguments':[]}])
        params=[('x','i8')]
        prog=m(f('answer',params,['i8'],['trap'],[b('entry',params,[c('one','i8',1),
                  i('int.add.checked',['x','one'],[('result','i8')])],ret('result'))]))
        checked,work,raw=self.shared(prog,[{'function':'answer','arguments':[127]}])
        damaged=bytearray(raw)
        struct.pack_into('<Q',damaged,40+32+16,1)
        self.assertEqual(self.observe(checked.canonical_bytes,work,damaged),(2,b''))
        self.assertEqual(self.observe(checked.canonical_bytes,work,raw+b'x'),(2,b''))

    def test_v9_typed_word_bounds_preserve_the_public_error_and_resources(self):
        from tools.hia_word_memory_cases import owned_program
        cases=[{'function':operation+'_'+order,'arguments':[n,0,0x123456789ABC,0]}
               for operation in ('load','store') for order in ('le','be') for n in (7,8)]
        self.shared(owned_program(),cases)

    def test_call_budget_reports_one_observed_prefix_and_stops(self):
        params=[('v','u32')]
        prog=m(f('again',params,['u32'],[],[b('entry',params,[
                i('call',['v'],[('other','u32')],function='again')],ret('other'))]))
        checked,work,raw=self.shared(prog,[{'function':'again','arguments':[1]},
                                          {'function':'again','arguments':[2]}])
        self.assertEqual(struct.unpack_from('<2Q',raw,8),(2,1))
        self.assertEqual(json.loads(self.observe(checked.canonical_bytes,work,raw)[1])[0]['budget_code'],'calls')
        self.check_outcome(checked.canonical_bytes,work,raw,900,2000)

    @unittest.skipUnless(os.environ.get('HIA_TEST_FRESH_HANDOFF'),'physical HIAEFI04 input required')
    def test_both_live_nominal_core_matches_actual_frozen_workload(self):
        raw=Path(os.environ['HIA_TEST_FRESH_HANDOFF']).read_bytes()
        h=struct.unpack_from('<8s13Q',raw)
        at=112+h[6]
        facts=[]
        for i in range(h[1]):
            ordinal,kind,meta,body=struct.unpack_from('<4Q',raw,at)
            at+=208
            facts.append((raw[at:at+meta],raw[at+meta:at+meta+body]))
            at+=meta+body
        work=json.loads(facts[-1][1])
        for arm,(core,n) in enumerate(zip((facts[-5][0],facts[-4][0]),h[8:10],strict=True)):
            batch=raw[at:at+n]
            at+=n
            expected=[_vm_observation(verify_program(core),case) for case in work['cases']]
            self.assertEqual(self.observe(core,work,batch),(0,wire(expected)))
            self.check_outcome(core,work,batch,h[10+2*arm],h[11+2*arm])
