"""Compare atomic terminal publication with the independent installed ABI."""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_identity_native import NativeAgentIdentity
from hepta.hia_agent_store import AgentStore, wire
from hepta.hia_execution_budget_native import NativeExecutionBudgetImage
from tests.test_hia_execution_budget_native import CONTEXT, OWNER, Machine, witnesses
from tools.generate_hia_evaluate_settlement import MAGIC, PACKER, SOURCE
from tools.qualify_hia_selfhost import build_seed, compile_stage

ROOT=Path(__file__).resolve().parents[1]
KEY=b'd'*64
REQUEST=b'r-'+b'8'*64


def request(pair, budget, *, issued=b'', before=100, after=80, metric=1, threshold=.1):
    return (struct.pack('<8s3Qd5Q',b'HIAEST01',before,after,metric,threshold,len(pair),len(budget),
                       len(issued),777,10_000_000) + CONTEXT + OWNER + KEY + REQUEST + pair + budget + issued)


def observation(status=0, *, count=1, value=7, trap=False):
    samples=[] if status in (2,5) else [(0,arm,7 if trap else 0,2**64-6 if trap else 0,
                       0 if trap else value,0 if trap else 20+arm,0,0) for arm in (0,1)]
    times=(0,0) if not samples or trap else (20,21)
    return struct.pack('<8s9Q',b'HIAEPM01',status,count,len(samples),*times,
                      *( (1,1) if samples and not trap else (0,0)),0,2 if status==5 else 0)+b''.join(
                          struct.pack('<8Q',*sample) for sample in samples)


class SettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp=tempfile.TemporaryDirectory(prefix='hia-evaluate-settlement-')
        cls.addClassCleanup(temp.cleanup)
        cls.work=Path(temp.name)
        b0,_=build_seed(cls.work)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        b1,_=compile_stage(cls.work,'B1',b0,source,image_format='seed-shared')
        b2,_=compile_stage(cls.work,'B2',b1,source)
        assert b1.read_bytes()==b2.read_bytes()
        def image(name):
            out,_=compile_stage(cls.work,name,b2,(ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes())
            return out
        runtime=image(SOURCE.stem).read_bytes()
        packer=image(PACKER.stem)
        cls.exe,_=compile_stage(cls.work,'settlement',packer,
                struct.pack('<2Q',MAGIC,len(runtime))+runtime,output_extension='.elf')
        cls.exe.chmod(0o500)
        raw=image('agent_identity').read_bytes()
        cls.identity=NativeAgentIdentity(raw,sha256(raw).hexdigest())
        raw=image('execution_budget').read_bytes()
        cls.owner=NativeExecutionBudgetImage(raw,sha256(raw).hexdigest())
        rows=witnesses(Machine(cls.owner))
        cls.budget=rows[-1][1][1]
        cls.pending=rows[-2][1][1]

    def invoke(self,raw):
        p=subprocess.run([self.exe],input=raw,capture_output=True,timeout=5)
        self.assertEqual(p.stderr,b'')
        return p.returncode,p.stdout

    def test_cost_binding_and_original_outcomes(self):
        for status,before,after,metric,trap in (
            (0,100,80,1,False),(0,100,110,1,False),(0,100,99,1,False),
            (0,100,90,2,False),(0,100,90,2,True),(1,100,90,1,False),(2,100,90,1,False)):
            pair=observation(status,trap=trap)
            with self.subTest(status=status,metric=metric,trap=trap,before=before,after=after):
                code,raw=self.invoke(request(pair,self.budget,before=before,after=after,metric=metric))
                self.assertEqual(code,0)
                h=struct.unpack_from('<8s8Q',raw)
                self.assertEqual(h[0],b'HIAESD01')
                complete=status<2
                b,a=(before,after) if metric==1 else ((0,0) if trap else (20,21))
                ratio,outcome=self.identity.evaluation_measurement(b,a,.1,budget_exceeded=status==2,
                            correct=status==0,complete=complete,latency=metric==2,trapping=trap)
                from hepta.hia_agent_identity_native import EVALUATION_OUTCOMES
                self.assertEqual(h[1:6],(EVALUATION_OUTCOMES.index(outcome)+1,int(complete),b,a,
                                         struct.unpack('<Q',struct.pack('<d',ratio))[0]))
                self.assertEqual((h[6:],raw[72:]),((777,10_000_000,7),b'8888888'))

    def test_unknown_owner_never_issues_output(self):
        pair=observation()
        wrong=bytearray(self.budget)
        wrong[-1]^=1
        for budget in (self.pending,self.budget[:-1],bytes(wrong),self.budget.replace(OWNER,b'c'*64)):
            self.assertEqual(self.invoke(request(pair,budget)),(2,b''))
        tampered=bytearray(pair)
        struct.pack_into('<Q',tampered,32,100)
        self.assertEqual(self.invoke(request(tampered,self.budget)),(2,b''))

    def products(self, *, outcome="improved", complete=True, ratio=.2):
        directory=tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store=AgentStore(Path(directory.name)/'store')
        self.addCleanup(store.close)
        base=store.put(b'controlled baseline','build-artifact')
        other=store.put(b'controlled candidate','build-artifact')
        ctx={'id':CONTEXT.decode(),'sha256':'0'*64}
        args=dict(baseline_artifact=base,candidate_artifact=other,context=ctx,build_receipt=base,
                  verification_receipts=[other])
        context={'objective':store.put(b'objective','input'),'workload':store.put(b'workload','input')}
        observations=[{'index':0,'function':'answer','arguments':[7],
                       'baseline_vm':{'status':'returned','values':[7]},
                       'candidate_vm':{'status':'returned','values':[7]}}]
        if complete:
            observations[0].update(baseline_native={'status':'returned','values':[7],'elapsed_ns':'20'},
                                   candidate_native={'status':'returned','values':[7],'elapsed_ns':'21'})
        measurement=self.identity.measurement_record(args,context,before=100,after=80,ratio=ratio,
                                     scope='retained native calls',metric='artifact_bytes',
                                     native_runs={'baseline':{'total_native_ns':'20' if complete else '0'},
                                                  'candidate':{'total_native_ns':'21' if complete else '0'}},
                                     observations=observations,
                                     outcome=outcome,planned_cases=1,
                                     complete=complete,reference_runs={'baseline':{},'candidate':{}},reference_ns=777)
        measure=store.put(measurement,'measurements')
        policy={'external_costs':{'discovery_wall_ns':None,'model_tokens':None,'model_wall_ns':None},
                'external_costs_complete':False,'expected_invocations':'0'}
        costs=self.identity.cost_ledger_record(ctx,0,policy,(0,0),10_000_000,8888888,[])
        ledger=store.put(costs,'cost-ledger')
        assessment=self.identity.evaluation_record(args,'1'*64,'2'*64,{},measure,ledger,outcome,complete)
        receipt=store.put(assessment,'evaluation-receipt')
        issued=b''.join(wire(x) for x in (base,other,receipt,ledger,measure))
        for ref,kind in ((receipt,'evaluation-receipt'),(ledger,'cost-ledger'),(measure,'measurements')):
            record=store.get(ref,kind=kind)[0]
            issued+=struct.pack('<Q',len(record))+record
        result=self.identity.evaluation_result(args,receipt,measure,ledger,outcome,complete)
        return issued,result

    def issuer_proof(self, *, physical=None, claimed=None):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store=AgentStore(Path(tmp.name)/'store')
        self.addCleanup(store.close)
        if claimed is not None:
            physical=claimed[648:]
        if physical is None:
            typed=[]
            def retain(kind,body,meta=b''):
                ref=store.put(body,'issue-input')
                typed.append(struct.pack('<4Q',len(typed),kind,len(meta),len(body))+wire(ref)+meta+body)
                return ref
            installation={'backend_sha256':'2'*64,'worker_sha256':'3'*64}
            objective_body=wire({'metric':'artifact_bytes','min_improvement_ratio':.1})
            workload_body=wire({'cases':[{'function':'answer','arguments':[7]}]})
            ctxbody=wire({'installation':installation,'objective':store.put(objective_body,'issue-input'),
                          'workload':store.put(workload_body,'issue-input')})
            retain(3,ctxbody)
            ctx={'id':CONTEXT.decode(),'sha256':sha256(ctxbody).hexdigest()}
            args={'context':ctx}
            canonical=[wire({'module':k}) for k in ('baseline','candidate')]
            for arm,size,core in zip(('baseline','candidate'),(100,80),canonical,strict=True):
                args[arm+'_artifact']=retain(7,(arm.encode()*13)[:size].ljust(size,b'!'),
                    wire({'core_sha256':sha256(core).hexdigest(),'installation':installation,'context':ctx}))
            args['build_receipt']=retain(5,wire({'input':'build'}))
            args['verification_receipts']=[retain(8,wire({'input':'first'})),retain(8,wire({'input':'second'}))]
            for raw in canonical:
                retain(0,raw,raw)
            retain(6,b'object')
            retain(0,objective_body)
            retain(0,workload_body)
            outer={'arguments':args,'catalog_sha256':'a'*64,'profile_sha256':'b'*64,
                   'schema':'hia-agent-worker-request-v1','tool':'hia_evaluate'}
            whole=wire({**outer,'request_sha256':sha256(wire(outer)).hexdigest()})
            rows=b''.join(typed)
            batch=struct.pack('<8s2Q',b'HIAEBT01',1,1)
            physical=(struct.pack('<8s13Q',b'HIAEFI04',len(typed),999,1999,4000,1<<26,
                                  len(whole),len(rows),len(batch),len(batch),100,180,181,877)
                      +whole+rows+batch+batch)
        h=struct.unpack_from('<8s13Q',physical)
        at=112
        req=json.loads(physical[at:at+h[6]])
        args=req['arguments']; call=wire({'arguments':args,'tool':req['tool']})
        unsigned=wire({k:v for k,v in req.items() if k!='request_sha256'})
        key=b'r-'+sha256(call).hexdigest().encode()
        journal_key=KEY if claimed is None else claimed[192:256]
        if claimed is None:
            state=bytearray(512)
            struct.pack_into('<8s7Q',state,0,b'HIAJRN02',3,9,1,0,1,1,0)
            state[64:128]=key[2:]; state[128:192]=journal_key; state[192:258]=key
            route=struct.pack('<8s7Q',b'HIAJMO01',2,11,0,48,0,48,512)
            claimed=struct.pack('<8s7Q',b'HIAEJC01',len(physical),3,134,123456,512,64,8)+state+route+b'HIASTCP1'+physical
        ctx=args['context']; at+=h[6]; facts=[]
        for i in range(h[1]):
            index,kind,m,n=struct.unpack_from('<4Q',physical,at)
            self.assertEqual(i,index)
            at+=32
            ref=json.loads(physical[at:at+176]);at+=176
            meta=physical[at:at+m];at+=m
            body=physical[at:at+n];at+=n
            facts.append((ref,meta,body))
        installation=json.loads(facts[0][2])['installation']
        coredig=[sha256(row[1]).hexdigest() for row in facts[-5:-3]]
        before,after=(len(row[2]) for row in facts[1:3])
        reference=h[13]-h[10]
        elapsed=max(reference+1,10_000_000)
        threshold=json.loads(facts[-2][2])['min_improvement_ratio']
        ratio,outcome=self.identity.evaluation_measurement(before,after,threshold,budget_exceeded=False,correct=True,
                                           complete=True,latency=False,trapping=False)
        engine=Machine(self.owner)
        steps=witnesses(Machine(self.owner))
        for original,_state in steps:
            # Parameterize independent admitted HIA state-machine traffic with
            # the actual Context and budget identity, leaving events unchanged.
            n,terminal,_=engine.call(original.replace(OWNER,journal_key).replace(CONTEXT,ctx['id'].encode()))
        pair=observation()
        cases=json.loads(facts[-1][2])['cases'];case=cases[0]
        rows=[{'index':0,'function':case['function'],'arguments':case['arguments'],
               'baseline_vm':{'status':'returned','values':[7]},'candidate_vm':{'status':'returned','values':[7]},
               'baseline_native':{'status':'returned','values':[7],'elapsed_ns':'20'},
               'candidate_native':{'status':'returned','values':[7],'elapsed_ns':'21'}}]
        meas=self.identity.measurement_record(args,{'workload':facts[-1][0],'objective':facts[-2][0]},
                  before=before,after=after,ratio=ratio,scope='physical observations',metric='artifact_bytes',
                  native_runs={'baseline':{'total_native_ns':'20'},'candidate':{'total_native_ns':'21'}},
                  observations=rows,outcome=outcome,planned_cases=1,complete=True,
                  reference_runs={'baseline':{},'candidate':{}},reference_ns=reference)
        measure=store.put(meas,'measurements')
        policy={'external_costs':{'discovery_wall_ns':None,'model_tokens':None,'model_wall_ns':None},
                'external_costs_complete':False,'expected_invocations':'0'}
        cost=self.identity.cost_ledger_record(ctx,0,policy,(0,0),elapsed,8888888,[])
        ledger=store.put(cost,'cost-ledger')
        issued=b''.join(wire(x) for x in (args['baseline_artifact'],args['candidate_artifact'],args['build_receipt'],ledger,measure))
        issued+=b''.join(struct.pack('<Q',len(x))+x for x in (store.get(ledger,kind='cost-ledger')[0],
                                                                store.get(measure,kind='measurements')[0],claimed,call,unsigned))
        request=(struct.pack('<8s3Qd5Q',b'HIAEPR01',before,after,1,threshold,len(pair),len(terminal),len(issued),
                            reference,elapsed)+ctx['id'].encode()+journal_key+journal_key+key+pair+terminal+issued)
        expected=self.identity.evaluation_record(args,*coredig,installation,measure,ledger,outcome,True)
        return request,expected

    def test_issue_public_evaluation_receipt_from_typed_original(self):
        raw,expected=self.issuer_proof()
        self.assertEqual(self.invoke(raw),(0,expected))
        for broken in (raw[:-1],raw.replace(b'{"module":"candidate"}',b'{"module":"candidatz"}',1),
                       raw.replace(b'HIAEFI04',b'HIAEFI03'),raw.replace(b'"native_child_wall_ns":"8888888"',
                       b'"native_child_wall_ns":"8888889"')):
            self.assertEqual(self.invoke(broken),(2,b''))

    @unittest.skipUnless(os.environ.get('HIA_TEST_FRESH_HANDOFF'),'physical HIAEFI04 input required')
    def test_issue_from_real_public_fresh_intake(self):
        raw,expected=self.issuer_proof(physical=Path(os.environ['HIA_TEST_FRESH_HANDOFF']).read_bytes())
        self.assertEqual(self.invoke(raw),(0,expected))

    @unittest.skipUnless(os.environ.get('HIA_TEST_JOURNAL_CLAIM'),'live HIA Journal claim required')
    def test_issued_receipt_binds_the_live_public_id_and_the_distinct_envelope_pin(self):
        claim=Path(os.environ['HIA_TEST_JOURNAL_CLAIM']).read_bytes()
        packet,expected=self.issuer_proof(claimed=claim)
        self.assertEqual(self.invoke(packet),(0,expected))
        n=struct.unpack_from('<Q',claim,648+48)[0]
        request=json.loads(claim[760:760+n])
        transport=request['request_sha256'].encode()
        self.assertNotEqual(transport,packet[246:310])
        bad=bytearray(packet);bad[246:310]=transport
        self.assertEqual(self.invoke(bytes(bad)),(2,b''))
        for old,new in ((b'HIASTCP1',b'BADSTCP1'),(b'HIAJRN02',b'HIAJRN01'),(transport,b'0'*64)):
            self.assertEqual(self.invoke(packet.replace(old,new,1)),(2,b''))

    def check_terminal(self,raw,status,payload):
        magic,state,n,side,command,reserved=struct.unpack_from('<8s5Q',raw)
        self.assertEqual((magic,state,reserved),(b'HIAESTR1',status,0))
        self.assertEqual(len(raw),48+n+side+command)
        terminal=raw[48:48+n]
        expected={'contract_version':'hepta.hia.agent-native.v1','request_id':REQUEST.decode(),
                  'status':'completed' if status==1 else 'rejected',
                  'result' if status==1 else 'error':payload}
        self.assertEqual(terminal,wire(expected))
        self.assertEqual(raw[48+n:48+n+side],struct.pack('<8s3Q',b'HIAIND01',status,36,len(wire(payload)))+
                         CONTEXT+wire(payload))
        stmt=raw[48+n+side:]
        self.assertEqual(stmt[:88],struct.pack('<8s10Q',b'HIAUPB01',1,1,0,2,3,88,len(terminal),3,88+n,64))
        self.assertEqual(stmt[88:],terminal+KEY)
        return stmt

    def test_verified_issued_documents_and_immutable_journal_command(self):
        issued,result=self.products()
        code,raw=self.invoke(request(observation(),self.budget,issued=issued))
        self.assertEqual(code,0,raw)
        self.check_terminal(raw,1,result)
        for altered in (issued[:-1],issued[:-2]+b'!}',issued.replace(b'"outcome":"improved"',b'"outcome":"regressed"',1)):
            self.assertEqual(self.invoke(request(observation(),self.budget,issued=altered)),(2,b''))

    def test_incorrect_and_budget_terminals_only_after_budget_ack(self):
        for status,outcome,complete in ((1,'incorrect',True),(2,'budget_exceeded',False)):
            issued,result = self.products(outcome=outcome,complete=complete)
            code,raw=self.invoke(request(observation(status),self.budget,issued=issued))
            self.assertEqual(code,0)
            self.check_terminal(raw,1,result)
            self.assertEqual(self.invoke(request(observation(status),self.pending,issued=issued)),(2,b''))
        issued,_=self.products(ratio=.3)
        self.assertEqual(self.invoke(request(observation(),self.budget,issued=issued)),(2,b''))

    @unittest.skipUnless(os.environ.get('HIA_TEST_SETTLEMENT_STORE'), 'installed HIA Store required')
    def test_native_journal_rollback_commit_and_reopen(self):
        from tests.test_hia_agent_store_runtime import NativeStoreArgv,command,text_bindings
        kernel=NativeStoreArgv()
        stage=Path(os.environ['HIA_TEST_SETTLEMENT_STORE'])
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            kernel.run_native([stage/'hia-agent-store-init',root,'store'])
            argv=[stage/'hia-agent-store',root,'store',stage]
            reserved=(KEY.decode(), 'a'*64,'hia_evaluate','running',None,'1234')
            insert=text_bindings(b'HIAINS01',reserved,insert_table=6)
            self.assertEqual(kernel.replies(kernel.run_native(argv,command(1,27,1,insert)+command(2,2)),(27,2)),([],1))
            current=kernel.state(root)
            issued,result=self.products()
            pair=observation()
            self.assertEqual(self.invoke(request(pair,self.pending,issued=issued)),(2,b''))
            self.assertEqual(kernel.state(root),current)
            code,raw=self.invoke(request(pair,self.budget,issued=issued))
            self.assertEqual(code,0)
            stmt=self.check_terminal(raw,1,result)
            query=text_bindings(b'HIAQPA01',(KEY.decode(),))
            change=command(1,27,1,stmt)
            self.assertEqual(kernel.replies(kernel.run_native(argv,change+command(2,3)),(27,3)),([],0))
            self.assertEqual(kernel.state(root),current)
            self.assertEqual(kernel.replies(kernel.run_native(argv,change+command(2,2)),(27,2)),([],1))
            rows,receipts=kernel.replies(kernel.run_native(argv,command(1,27,12,query)+command(2,3)),(27,3))
            self.assertEqual((len(rows),receipts,rows[0][3]),(1,0,'completed'))
            self.assertEqual(rows[0][4].encode(),raw[48:48+struct.unpack_from('<Q',raw,16)[0]])

    def test_normal_aborting_in_final_candidate_does_not_complete_public_rows(self):
        from tests.test_hia_evaluate_paired_batch import PairedMeasurementTests
        from tests.test_hia_program import b,c,f,m,ret
        PairedMeasurementTests.setUpClass()
        self.addCleanup(PairedMeasurementTests.doClassCleanups)
        paired=PairedMeasurementTests()
        baseline=m(f('entry',[],['u32'],[],[b('here',[],[c('answer','u32',7)],ret('answer'))]))
        wrong=m(f('entry',[],['u32'],['trap'],[b('here',[],[],{'op':'trap','code':'user'})]))
        fixture=paired.fixture(baseline,[{'function':'entry','arguments':[]}],other=wrong,double=True)
        summary,rows,events=paired.archived(fixture)
        self.assertEqual((summary[1:4],rows[-1][2:4]),((1,1,2),(0,2**64-6)))
        self.assertEqual(events[-1][0][5],1)
        raw=struct.pack('<8s9Q',*summary)+b''.join(struct.pack('<8Q',*row) for row in rows)
        code,decision=self.invoke(request(raw,self.budget))
        self.assertEqual((code,struct.unpack_from('<8s2Q',decision)),(0,(b'HIAESD01',2,0)))

    def test_original_declared_expectation_refusal(self):
        code,raw=self.invoke(request(observation(5),b''))
        self.assertEqual(code,0)
        self.check_terminal(raw,2,dict(code='E_HIA_WORKLOAD_EXPECTATION',details_artifact=None,
            message='declared case expectation differs from baseline Core at index 0',
            phase='execution',retry_action='correct_input'))
        self.assertEqual(self.invoke(request(observation(5),self.budget)),(2,b''))
