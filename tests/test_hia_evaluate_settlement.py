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

    def test_original_declared_expectation_refusal(self):
        code,raw=self.invoke(request(observation(5),b''))
        self.assertEqual(code,0)
        self.check_terminal(raw,2,dict(code='E_HIA_WORKLOAD_EXPECTATION',details_artifact=None,
            message='declared case expectation differs from baseline Core at index 0',
            phase='execution',retry_action='correct_input'))
        self.assertEqual(self.invoke(request(observation(5),self.budget)),(2,b''))
