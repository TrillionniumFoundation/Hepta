"""Compare published native runs to the original direct-call report decoder."""

from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import time
import unittest

from hepta.hia_agent_buffers import buffer_bytes,buffer_observation
from hepta.hia_agent_runner import _direct_call_report
from hepta.hia_agent_service import _vm_observation,_value_observation
from hepta.hia_agent_store import wire
from hepta.hia_program import verify_program
from tests.test_hia_program import b,c,f,i,jump,m,ret
from tests.test_hia_evaluate_paired_batch import PairedMeasurementTests,run_pair
from tools.generate_hia_evaluate_native_report import SOURCE,PACKER,MAGIC
from tools.qualify_hia_selfhost import compile_stage

ROOT=Path(__file__).resolve().parents[1]


class NativeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PairedMeasurementTests.setUpClass()
        cls.addClassCleanup(PairedMeasurementTests.doClassCleanups)
        cls.pair=PairedMeasurementTests()
        out=cls.pair.reference.owned.parent.parent
        compiler=out/'B2.image.bin'
        image,_=compile_stage(out,'actual-native-json',compiler,(ROOT/SOURCE).read_bytes())
        packer,_=compile_stage(out,'actual-native-json-packer',compiler,(ROOT/PACKER).read_bytes())
        raw=image.read_bytes()
        cls.exe,_=compile_stage(out,'native-run-report',packer,
                    struct.pack('<2Q',MAGIC,len(raw))+raw,output_extension='.elf')
        cls.exe.chmod(0o500)

    def archive(self,inputs):
        inputs=list(inputs)
        inputs[5]=b'HIAEPL03'+inputs[5][8:]
        rc,data,err=run_pair(self.pair.pair,inputs)
        self.assertEqual((rc,err),(0,b''))
        return data

    def materialize(self,inputs,archive):
        sizes=list(map(len,(archive,*inputs[1:4])))
        req=archive+b''.join(inputs[1:4])+struct.pack('<8s4Q',b'HIAENJ01',*sizes)
        result=subprocess.run([self.exe],input=req,capture_output=True,timeout=8)
        self.assertEqual(result.stderr,b'')
        return result.returncode,result.stdout

    def decoded(self,inputs):
        archive=self.archive(inputs)
        rc,raw=self.materialize(inputs,archive)
        self.assertEqual(rc,0)
        magic,width,remaining=struct.unpack_from('<8s2Q',raw)
        self.assertEqual((magic,len(raw)),(b'HIAENR01',24+width+remaining))
        return archive,raw,json.loads(raw[24:24+width]),json.loads(raw[24+width:])

    def events(self,archive):
        _,pair_size,event_size,count=struct.unpack_from('<8s3Q',archive)
        pos=32+pair_size
        events=[]
        for _ in range(count):
            header=struct.unpack_from('<8s11Q',archive,pos)
            pos+=96
            size=header[9]+header[10] if header[1]==2 else header[7] if header[1]==3 else 0
            events.append((header,archive[pos:pos+size]));pos+=size
        self.assertEqual(pos,len(archive))
        return events

    def equivalent(self,inputs,program,*,exports=()):
        archive,raw,runs,observations=self.decoded(inputs)
        signature,work=json.loads(inputs[0]); cases=work['cases']
        expected=[_vm_observation(verify_program(program),case,foreign_buffer_exports=exports) for case in cases]
        owner=sha256(inputs[3]).hexdigest()
        for arm,name in enumerate(('baseline','candidate')):
            these=[(ev,body) for ev,body in self.events(archive) if ev[3]==arm]
            normal=[idx for idx,row in enumerate(expected) if row['status']=='returned']
            if normal:
                prep=[dict(cases[idx],expected=_value_observation(expected[idx])) for idx in normal]
                receipts=[];snapshots=[];initial={};stderr=b''
                for j,idx in enumerate(normal):
                    events=[(ev,body) for ev,body in these if ev[2]==idx]
                    header,stream=next(row for row in events if row[0][1]==2)
                    receipts.append(stream[:header[9]])
                    stderr+=stream[header[9]:]
                    buffers=[buffer_observation(ev[5],'readbuf' if ev[6]==1 else 'mutbuf',body)
                             for ev,body in events if ev[1]==3]
                    snapshots.append({'case':j,'buffers':buffers})
                    for buf in buffers:
                        if buf['kind']=='readbuf':
                            initial[j,buf['argument']]=sha256(buffer_bytes(cases[idx]['arguments'][buf['argument']])).hexdigest()
                normal_report=_direct_call_report(receipts,signature,prep,snapshots,initial,
                    sha256(inputs[1+arm]).hexdigest(),owner,5,work['warmup_iterations'],work['repetitions'])
                began=next(ev[4] for ev,_ in these if ev[1]==1 and ev[2]==normal[0])
                ended=next(ev[4] for ev,_ in these if ev[1]==4 and ev[2]==normal[-1])
                complete=dict(status='returned',started=True,termination_confirmed=True,wall_ns=str(ended-began),
                              returncode=0,stdout_sha256=sha256(b''.join(receipts)).hexdigest(),
                              stderr_sha256=sha256(stderr).hexdigest(),report=normal_report,direct_call_executable_sha256=owner)
                if any(x['buffers'] for x in snapshots):
                    complete['buffer_snapshots']=snapshots
                self.assertEqual(runs[name]['normal'],complete)
                self.assertEqual(runs[name]['total_native_ns'],normal_report['total_native_ns'])
                for j,idx in enumerate(normal):
                    self.assertEqual(observations[idx][name+'_native'],normal_report['observations'][j])
            for trap in runs[name]['traps']:
                idx=trap['index']
                self.assertEqual((trap['status'],trap['returncode'],trap['report']),('trapped',-6,None))
                events=[(ev,body) for ev,body in these if ev[2]==idx]
                self.assertEqual(trap['wall_ns'],str(events[-1][0][4]-events[0][0][4]))
                view=dict(status='trapped',returncode=-6)
                if trap.get('buffer_snapshots'):
                    view['buffers']=trap['buffer_snapshots'][0]['buffers']
                self.assertEqual(observations[idx][name+'_native'],view)
        return archive,raw,runs,observations

    def test_scalar_multicase_original_report_and_complete_arms(self):
        params=[('x','i8')]
        base=m(f('answer',params,['i8'],[],[b('entry',params,[],ret('x'))]))
        cases=[{'function':'answer','arguments':[-127]},{'function':'answer','arguments':[101]}]
        inputs=self.pair.fixture(base,cases,double=True)
        archive,_,_,_=self.equivalent(inputs,base)
        bad=bytearray(archive)
        pos=32+struct.unpack_from('<Q',bad,8)[0]+96+96+8
        bad[pos]^=1
        self.assertEqual(self.materialize(inputs,bad),(2,b''))

    def test_original_report_distinguishes_wrong_bytes_and_trap_snapshots(self):
        params=[('out','mutbuf')]
        def program(v):
            return m(f('write',params,['u32'],['write','trap'],[b('entry',params,[c('at','usize',0),
                        c('v','u8',v),i('buffer.store',['out','at','v']),c('ret','u32',0)],ret('ret'))]))
        cases=[{'function':'write','arguments':[{'bytes_hex':'0401'}]},
               {'function':'write','arguments':[{'bytes_hex':''}]}]
        exports=(('write',16),)
        inputs=self.pair.fixture(program(41),cases,other=program(42),exports=exports,double=True)
        self.equivalent(inputs,program(41),exports=exports)

    def test_reaped_timeout_and_aborted_normal_keep_no_fabricated_observation(self):
        params=[('x','u64')]
        base=m(f('id',params,['u64'],[],[b('entry',params,[],ret('x'))]))
        cases=[{'function':'id','arguments':[9]}]
        loop=m(f('id',params,['u64'],[],[b('entry',params,[],jump('forever')),b('forever',[],[],jump('forever'))]))
        inputs=self.pair.fixture(base,cases,double=True)
        from hepta.hia_program_native import emit_program_machine
        inputs[2]=self.pair.linker.link(emit_program_machine(verify_program(loop)).object_bytes)
        inputs[5]=struct.pack('<8s2Q',b'HIAEPL03',64<<20,time.monotonic_ns()+300_000_000)
        archive,raw,runs,rows=self.decoded(inputs)
        self.assertEqual(runs['candidate']['normal']['status'],'budget_exceeded')
        self.assertTrue(runs['candidate']['normal']['termination_confirmed'])
        self.assertIsNone(runs['candidate']['normal']['report'])
        self.assertEqual(set(rows[0]),{'baseline_native'})
        wrong=m(f('id',params,['u64'],['trap'],[b('entry',params,[],{'op':'trap','code':'user'})]))
        inputs=self.pair.fixture(base,cases,other=wrong,double=True)
        _,_,runs,rows=self.decoded(inputs)
        self.assertEqual((runs['candidate']['normal']['status'],set(rows[0])),('trapped',{'baseline_native'}))

    @unittest.skipUnless(os.environ.get('HIA_TEST_FRESH_HANDOFF'),'physical HIAEFI04 input required')
    def test_real_installed_artifacts_and_physical_reports(self):
        raw=Path(os.environ['HIA_TEST_FRESH_HANDOFF']).read_bytes()
        h=struct.unpack_from('<8s13Q',raw);at=112+h[6]
        facts=[]
        for i in range(h[1]):
            idx,kind,m,n=struct.unpack_from('<4Q',raw,at);at+=208
            facts.append((raw[at:at+m],raw[at+m:at+m+n]));at+=m+n
        core=[facts[-5][0],facts[-4][0]]; work=json.loads(facts[-1][1])
        inputs=[wire([json.loads(facts[1][0])['signatures'],work]),facts[1][1],facts[2][1],self.pair.owner,
                raw[at:at+h[8]],struct.pack('<8s2Q',b'HIAEPL03',h[5],time.monotonic_ns()+5_000_000_000),
                raw[at+h[8]:],*core]
        archive,out,runs,observations=self.equivalent(inputs,core[0])
        proof=os.environ.get('HIA_TEST_EVALUATE_PUBLIC_EVIDENCE')
        if proof:
            folder=Path(proof);folder.mkdir(exist_ok=True)
            (folder/'physical-paired-archive.bin').write_bytes(archive)
            (folder/'public-native-evidence.bin').write_bytes(out)
            (folder/'native-runs.json').write_bytes(wire(runs))
            (folder/'native-observations.json').write_bytes(wire(observations))
