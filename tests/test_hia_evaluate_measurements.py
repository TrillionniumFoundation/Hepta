"""Issue and compare whole publicly consumable measurement records."""

from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest

from hepta.hia_agent_identity_native import NativeAgentIdentity,EVALUATION_OUTCOMES
from hepta.hia_agent_store import AgentStore,wire
from hepta.hia_evaluation_native import EvaluationFrame
from hepta.hia_program import verify_program
from hepta.hia_execution_budget_native import NativeExecutionBudgetImage
from tests.test_hia_execution_budget_native import Machine,witnesses,CONTEXT,OWNER
from tests.test_hia_program import b,c,f,i,m,ret
from tools.qualify_hia_selfhost import compile_stage

ROOT=Path(__file__).resolve().parents[1]


def typed(frame):
    h=struct.unpack_from('<8s13Q',frame);args=json.loads(frame[112:112+h[6]])
    at=112+h[6];rows=[]
    for _ in range(h[1]):
        idx,kind,m,n=struct.unpack_from('<4Q',frame,at);at+=32
        ref=json.loads(frame[at:at+176]);at+=176
        rows.append((ref,frame[at:at+m],frame[at+m:at+m+n]));at+=m+n
    return h,args,rows,(frame[at:at+h[8]],frame[at+h[8]:])


class MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_evaluate_native_report import NativeReportTests
        from tools import generate_hia_evaluate_measurements as measurements
        from tools import generate_hia_evaluate_reference_report as report
        from tools import generate_hia_evaluate_settlement as settle
        NativeReportTests.setUpClass()
        cls.addClassCleanup(NativeReportTests.doClassCleanups)
        cls.direct=NativeReportTests()
        cls.pair=cls.direct.pair
        out=cls.pair.reference.owned.parent.parent
        compiler=out/'B2.image.bin'
        for role,name in ((measurements,'measure'),(report,'reference'),(settle,'settle')):
            image,_=compile_stage(out,'whole-'+name,compiler,(ROOT/role.SOURCE).read_bytes())
            packer,_=compile_stage(out,'whole-pack-'+name,compiler,(ROOT/role.PACKER).read_bytes())
            raw=image.read_bytes()
            exe,_=compile_stage(out,'whole-elf-'+name,packer,struct.pack('<2Q',role.MAGIC,len(raw))+raw,
                                output_extension='.elf')
            exe.chmod(0o500);setattr(cls,name,exe)
        def image(name):
            return compile_stage(out,'whole-image-'+name,compiler,(ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes())[0].read_bytes()
        im=image('agent_identity')
        cls.identity=NativeAgentIdentity(im,sha256(im).hexdigest())
        im=image('execution_budget')
        cls.budget=NativeExecutionBudgetImage(im,sha256(im).hexdigest())

    def run_role(self,role,data):
        p=subprocess.run([role],input=data,capture_output=True,timeout=12)
        self.assertEqual((p.returncode,p.stderr),(0,b''),str(role))
        return p.stdout

    def specimen(self,baseline,candidate,cases,metric,*,exports=()):
        options=dict(other=candidate,double=True,exports=exports)
        inputs=self.pair.fixture(baseline,cases,**options)
        sign,work=json.loads(inputs[0])
        with tempfile.TemporaryDirectory() as temp:
            store=AgentStore(Path(temp)/'store')
            self.addCleanup(store.close)
            def put(data): return store.put(data,'input')
            clock=[];batches=[]
            cores=(verify_program(baseline),verify_program(candidate))
            for core in cores:
                clock.append(time.monotonic_ns())
                rc,raw,err=self.pair.reference.invoke(core,work)
                clock.append(time.monotonic_ns())
                self.assertEqual((rc,err),(0,b''))
                batches.append(raw)
            work_body=wire(work);obj_body=wire(dict(metric=metric,min_improvement_ratio=.1))
            ctx_body=wire(dict(workload=put(work_body),objective=put(obj_body),installation={}))
            ctx=dict(id=CONTEXT.decode(),sha256=sha256(ctx_body).hexdigest())
            rows=[]
            def append(kind,body,meta=b''):
                ref=put(body);rows.append(struct.pack('<4Q',len(rows),kind,len(meta),len(body))+wire(ref)+meta+body)
                return ref
            append(3,ctx_body)
            args=dict(context=ctx,request_key='public-observation-test')
            for label,art,core in zip(('baseline','candidate'),inputs[1:3],cores,strict=True):
                args[label+'_artifact']=append(7,art,wire(dict(core_sha256=core.sha256,context=ctx,
                                                              installation={},signatures=sign)))
            args['build_receipt']=append(5,b'build')
            args['verification_receipts']=[append(8,b'proof')]
            for core in cores: append(0,core.canonical_bytes,core.canonical_bytes)
            append(6,b'object');append(0,obj_body);append(0,work_body)
            req=wire(dict(arguments=args,request_sha256=sha256(wire(args)).hexdigest()));r=b''.join(rows)
            h=struct.pack('<8s13Q',b'HIAEFI04',len(rows),time.time_ns(),time.time_ns()+60_000_000_000,
                    5000,64<<20,len(req),len(r),*(len(bb) for bb in batches),*clock)
        frame=h+req+r+b''.join(batches)
        archive=self.direct.archive(inputs)
        paid=witnesses(Machine(self.budget))[-1][1][1]
        return frame,archive,paid,self.pair.owner,self.pair.reference.owned.read_bytes()

    def issue(self,frame,archive,paid,direct,owned,*,evidence=None):
        h,request,rows,batches=typed(frame)
        req=request['arguments']
        obj=json.loads(rows[-2][2]);work=json.loads(rows[-1][2]);ctx=json.loads(rows[0][2])
        baseline,candidate=(r[2] for r in rows[1:3])
        n=struct.unpack_from('<Q',archive,8)[0];pair=archive[32:32+n]
        header=struct.unpack_from('<8s9Q',pair)
        ctxid=req['context']['id'].encode()
        b=struct.unpack_from('<16Q',paid);at=128+b[8]+b[9];owner=paid[at:at+b[10]]
        ref_wall=h[13]-h[10]
        ref_results=[]
        for arm in range(2):
            core=rows[-5+arm][1]
            text=b'['+core+b','+rows[-1][2]+b']'
            data=text+batches[arm]+struct.pack('<2Q',h[10+2*arm],h[11+2*arm])+owned
            data+=struct.pack('<8s2Q',b'HIAERJ02',len(text),len(batches[arm]))
            ref_results.append(self.run_role(self.reference,data))
        native=self.run_role(self.direct.exe, b''.join((archive,baseline,candidate,direct))+
                 struct.pack('<8s4Q',b'HIAENJ01',len(archive),len(baseline),len(candidate),len(direct)))
        reported=time.monotonic_ns()
        elapsed=reported-h[10]
        ctxkey=sha256(wire({'tool':'hia_evaluate','key':req['request_key']})).hexdigest().encode()
        terms=(struct.pack('<8s3Qd5Q',b'HIAEST01',len(baseline),len(candidate),
                           1 if obj['metric']=='artifact_bytes' else 2,obj['min_improvement_ratio'],
                           len(pair),len(paid),0,ref_wall,elapsed)+ctxid+owner+ctxkey+
                           b'r-'+sha256(wire({'arguments':req,'tool':'hia_evaluate'})).hexdigest().encode()+pair+paid)
        decision=self.run_role(self.settle,terms)
        sections=[frame,decision,native,*ref_results,archive]
        packed=struct.pack('<8s6Q',b'HIAEMJ01',*(len(x) for x in sections))+b''.join(sections)
        result=self.run_role(self.measure,packed)
        dec=struct.unpack_from('<8s8Q',decision)
        ratio=struct.unpack('<d',struct.pack('<Q',dec[5]))[0]
        nr=struct.unpack_from('<8s2Q',native);native_runs=json.loads(native[24:24+nr[1]])
        ns=json.loads(native[24+nr[1]:]);rs=dict(zip(('baseline','candidate'),map(json.loads,ref_results),strict=True))
        observations=[]
        if rs['baseline']['report']['complete'] and rs['candidate']['report']['complete']:
            count=header[8] if header[1]==2 and header[9]==2 else len(work['cases'])
            for k,case in enumerate(work['cases'][:count]):
                observations.append(dict(index=k,function=case['function'],arguments=case['arguments'],
                      baseline_vm=rs['baseline']['report']['observations'][k],candidate_vm=rs['candidate']['report']['observations'][k],**ns[k]))
        if not rs['baseline']['report']['complete']: del rs['candidate']
        expected=self.identity.measurement_record(req,ctx,before=dec[3],after=dec[4],ratio=ratio,
               scope=EvaluationFrame._measurement_scope(native_runs),metric=obj['metric'],native_runs=native_runs,
               observations=observations,outcome=EVALUATION_OUTCOMES[dec[1]-1],planned_cases=header[2],complete=bool(dec[2]),
               reference_runs=rs,reference_ns=dec[6])
        self.assertEqual(result,expected,(len(result),len(expected),result[:200],expected[:200]))
        if evidence:
            root=Path(evidence);root.mkdir(parents=True,exist_ok=True)
            products={'fresh.bin':frame,'paid.bin':paid,'archive.bin':archive,'pair.bin':pair,'decision.bin':decision,
                      'settlement-input.bin':terms,'public-native-evidence.bin':native,'reference-baseline.json':ref_results[0],
                      'reference-candidate.json':ref_results[1],'measurements.json':result,'measurement-input.bin':packed,
                      'clock.json':wire(dict(reference_start_mono_ns=h[10],report_mono_ns=reported,
                          evaluation_wall_ns=elapsed,reference_wall_ns=ref_wall))}
            for name,data in products.items(): (root/name).write_bytes(data)
        return packed,result

    def test_public_metrics_wrong_values_and_atomic_hash_drift(self):
        params=[('v','u32')]
        def program(n):
            return m(f('answer',params,['u32'],[],[b('entry',params,[c('d','u32',n),
                i('int.add.wrap',['v','d'],[('y','u32')])],ret('y'))]))
        for metric,other in (('artifact_bytes',0),('latency_ns',0),('artifact_bytes',1)):
            with self.subTest(metric=metric,other=other):
                spec=self.specimen(program(0),program(other),[dict(function='answer',arguments=[11])],metric)
                packet,result=self.issue(*spec)
                bad=bytearray(packet);bad[packet.index(b'HIAEBT01')+24+16+32]^=1
                failed=subprocess.run([self.measure],input=bad,capture_output=True,timeout=5)
                self.assertEqual((failed.returncode,failed.stdout,failed.stderr),(2,b'',b''))

    def test_reordered_public_envelope_and_committed_projections(self):
        params=[('v','u32')]
        program=m(f('answer',params,['u32'],[],[b('entry',params,[],ret('v'))]))
        specimen=self.specimen(program,program,[dict(function='answer',arguments=[11])],'artifact_bytes')
        packet,original=self.issue(*specimen)
        sizes=list(struct.unpack_from('<6Q',packet,8))
        fresh=packet[56:56+sizes[0]]
        old_n=struct.unpack_from('<Q',fresh,48)[0]
        args=json.loads(fresh[112:112+old_n])['arguments']
        admitted=dict(tool='hia_evaluate',profile_sha256='a'*64,catalog_sha256='b'*64,
                      schema='hia-agent-worker-request-v1',arguments=args)
        unsigned=wire(admitted)
        call=wire(dict(arguments=args,tool='hia_evaluate'))
        raw=json.dumps({**admitted,'request_sha256':sha256(unsigned).hexdigest()},indent=2).encode()
        raw=raw.replace(b'ctx-',b'ctx' + bytes((92,)) + b'u002d',1)
        actual=fresh[:48]+struct.pack('<Q',len(raw))+fresh[56:112]+raw+fresh[112+old_n:]
        def replace_evidence(evidence):
            return struct.pack('<8s6Q',b'HIAEMJ01',len(evidence),*sizes[1:])+evidence+packet[56+sizes[0]:]
        self.assertEqual(self.run_role(self.measure,replace_evidence(actual)),original)
        journal=bytearray(512)
        key=sha256(call).hexdigest().encode()
        owner=sha256(wire(dict(key=args['request_key'],tool='hia_evaluate'))).hexdigest().encode()
        struct.pack_into('<8s5Q',journal,0,b'HIAJRN02',3,9,1,0,1)
        journal[64:128]=key
        journal[128:192]=owner
        journal[192:258]=b'r-'+key
        command=struct.pack('<8s7Q',b'HIAJMO01',2,11,0,48,0,48,512)
        claim=struct.pack('<8s7Q',b'HIAEJC01',len(actual),3,7,19,512,64,8)+journal+command+b'HIASTCP1'+actual
        admitted_tick=struct.unpack_from('<Q',actual,80)[0]-1
        half=struct.pack('<8s4Q',b'HIAEFH01',admitted_tick,len(claim),len(unsigned),len(call))+claim+unsigned+call
        self.assertEqual(self.run_role(self.measure,replace_evidence(half)),original)
        for offset in (40+128,40+len(claim)+13,40+len(claim)+len(unsigned)+13,
                       40+648+112+raw.index(b'"request_sha256": "')+19):
            altered=bytearray(half)
            altered[offset]^=1
            run=subprocess.run([self.measure],input=replace_evidence(altered),capture_output=True,timeout=10)
            self.assertEqual((run.returncode,run.stdout,run.stderr),(2,b'',b''))

    def test_public_resource_trap_with_actual_post_write_bytes(self):
        from tests.test_hia_agent_buffer_lifecycle import trap_program
        spec=self.specimen(trap_program(),trap_program(),[dict(function='write_then_trap',
             arguments=[dict(bytes_hex='0807')])],'latency_ns',exports=(('write_then_trap',16),))
        _,raw=self.issue(*spec)
        self.assertEqual(json.loads(raw)['outcome'],'inconclusive')

    @unittest.skipUnless(os.environ.get('HIA_TEST_CLAIM_WITH_PAID_PAIR'),'real claimed and settled archive required')
    def test_actual_public_context_receipts_and_immutable_elves(self):
        root=Path(os.environ['HIA_TEST_CLAIM_WITH_PAID_PAIR'])
        gates=Path(os.environ['HIA_TEST_PAID_GATE_DIR'])
        data=root.read_bytes();at=data.find(b'HIAEFI04');self.assertGreater(at,0)
        role=Path(os.environ['HIA_TEST_ACTUAL_SUPERVISORS'])
        _,result=self.issue(data[at:],(gates/'gate-measurements.bin').read_bytes(),(gates/'settled.bin').read_bytes(),
                            (role/'hia-direct-call').read_bytes(),(role/'hia-owned-reference-wire').read_bytes(),
                            evidence=os.environ.get('HIA_TEST_SETTLED_PUBLIC_PRODUCTS'))
        for arm in ('baseline_native','candidate_native'):
            self.assertEqual(json.loads(result)['observations'][0][arm]['values'],[7])
