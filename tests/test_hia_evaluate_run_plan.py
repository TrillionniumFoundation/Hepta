"""Test request, Store, proof and native image bindings in the run-plan process."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_store import wire
from tools.generate_hia_evaluate_run_plan import PACKER, PACK_MAGIC, SOURCE
from tools.qualify_hia_selfhost import compile_stage

ROOT=Path(__file__).resolve().parents[1]


def sample():
    digest=lambda data: sha256(data).hexdigest()
    def row(i,kind,body,meta=b'{}'):
        ident=f'{i:032x}'
        return {'id':'a-'+ident,'sha256':digest(body),'uri':'hia://artifacts/'+ident},kind,meta,body

    left_core=row(6,0,b'base',b'{"canonical":"left"}')
    right_core=row(7,0,b'candidate',b'{"canonical":"right"}')
    obj=row(8,6,b'object')
    goal=row(9,0,wire({'required_claims':['semantic']}))
    work=row(10,0,b'{ "z": 3.50, "a": [true, false] }')
    ctx=row(0,3,wire({'baseline_program':left_core[0],'objective':goal[0],
                       'workload':work[0],'installation':{'id':'1'},
                       'budget':{'max_native_wall_ms':10,'max_memory_bytes':'8192'}}))
    ctx_ref={'id':'ctx-'+'c'*32,'sha256':ctx[0]['sha256']}
    def arm(i,core,raw):
        return row(i,7,raw,wire({'context':ctx_ref,'installation':{'id':'1'},
                                 'core_sha256':digest(core[2]),'candidate':core[0],
                                 'signatures':{'start':{'params':[],'returns':['u8']}}}))
    left=arm(1,left_core,b'\x7fELF'+65*b'A')
    right=arm(2,right_core,b'\x7fELF'+75*b'B')
    build=row(3,5,wire({'candidate':right_core[0],'native_artifact':right[0],'context':ctx_ref,
                         'object_artifact':obj[0]}))
    vr=row(4,8,b'{"checks":[]}')
    rows=(ctx,left,right,build,vr,left_core,right_core,obj,goal,work)
    arguments={'request_key':'réserve','context':ctx_ref,'baseline_artifact':left[0],
               'candidate_artifact':right[0],'build_receipt':build[0],'verification_receipts':[vr[0]]}
    unsigned={'tool':'hia_evaluate','arguments':arguments,'schema':'hia-agent-worker-request-v1',
              'catalog_sha256':'b'*64,'profile_sha256':'a'*64}
    admission=wire(unsigned)
    request_sha=digest(admission).encode()
    original=json.dumps({**unsigned,'request_sha256':request_sha.decode()},indent=2,ensure_ascii=True).encode()
    call=wire({'arguments':arguments,'tool':'hia_evaluate'})
    owner=digest(wire({'key':arguments['request_key'],'tool':'hia_evaluate'})).encode()
    native_key=digest(call).encode()
    journal=bytearray(512)
    struct.pack_into('<8s5Q',journal,0,b'HIAJRN02',3,9,1,0,1)
    journal[64:128]=native_key
    journal[128:192]=owner
    journal[192:258]=b'r-'+native_key
    mutation=struct.pack('<8s7Q',b'HIAJMO01',2,11,0,48,0,48,512)
    records=b''.join(struct.pack('<4Q',i,kind,len(meta),len(body))+wire(ref)+meta+body
                     for i,(ref,kind,meta,body) in enumerate(rows))
    reference=struct.pack('<8s2Q',b'HIAEBT01',1,0)
    fresh=struct.pack('<8s13Q',b'HIAEFI04',len(rows),20,99,10,8192,len(original),len(records),
                      len(reference),len(reference),50,51,52,53)+original+records+reference*2
    claim=struct.pack('<8s7Q',b'HIAEJC01',len(fresh),3,7,19,512,64,8)+journal+mutation+b'HIASTCP1'+fresh
    half=struct.pack('<8s4Q',b'HIAEFH01',48,len(claim),len(admission),len(call))+claim+admission+call
    schedule=struct.pack('<8s2Q',b'HIAADK02',1,1)+bytes((0,4))
    proof=struct.pack('<8sQ',b'HIAEDP01',len(schedule))+request_sha+schedule
    data=wire([json.loads(left[2])['signatures'],json.loads(work[3])])
    sections=(data,left[3],right[3],reference,reference,left_core[2],right_core[2])
    expected=(struct.pack('<8s11Q',b'HIAEXI01',48,99,10,8192,*map(len,sections))
              +ctx_ref['id'].encode()+owner+b''.join(sections))
    return half,proof,expected


class RunPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_execution_budget_session import BudgetSessionTests
        BudgetSessionTests.setUpClass()
        cls.addClassCleanup(BudgetSessionTests.doClassCleanups)
        folder=BudgetSessionTests.session.parent
        compiler=folder/'B2.image.bin'
        def image(name,path):
            return compile_stage(folder,name,compiler,(ROOT/path).read_bytes())[0]
        payload=image('run-plan',SOURCE).read_bytes()
        canonical=image('canonical-worker','examples/hia_bootstrap/worker_request.hepta').read_bytes()
        packer=image('run-plan-packer',PACKER)
        sections=struct.pack('<3Q',PACK_MAGIC,len(payload),len(canonical))+payload+canonical
        cls.exe=compile_stage(folder,'independent-run-plan',packer,sections,output_extension='.elf')[0]
        cls.exe.chmod(0o500)

    def invoke(self,half,proof):
        request=struct.pack('<8s2Q',b'HIAEXQ01',len(half),len(proof))+half+proof
        r=subprocess.run([self.exe],input=request,capture_output=True,env={'PATH':''},timeout=10)
        self.assertFalse(r.stderr)
        return r.returncode,r.stdout

    def test_public_whitespace_escaped_request_keys_and_canonical_workload(self):
        half,ticket,expected=sample()
        self.assertEqual(self.invoke(half,ticket),(0,expected))

    def test_changed_raw_request_journal_native_images_and_proof_refuse(self):
        half,ticket,_=sample()
        changes=((b'"profile_sha256": "a',b'"profile_sha256": "0'),(b'HIAJRN02',b'HIAJRN01'),
                 (b'HIASTCP1',b'HIASTCP2'),(b'\x7fELFAAAAA',b'\x7fELFBBBBB'),
                 (b'\x7fELFBBBBB',b'\x7fELFAAAAA'),(b'HIAEBT01',b'HIAEBT00'),
                 (b'"canonical":"right"',b'"canonical":"wrong"'),(b'"max_native_wall_ms":10',b'"max_native_wall_ms":99'))
        for old,new in changes:
            with self.subTest(original=old):
                altered=half.replace(old,new,1)
                self.assertNotEqual(altered,half)
                self.assertEqual(self.invoke(altered,ticket),(2,b''))
        for t in (ticket[:-1],ticket[:-1]+b'\0',ticket[:16]+b'0'*64+ticket[80:],
                  ticket[:104]+bytes((255,4)),ticket[:88]+struct.pack('<Q',2)+ticket[96:]):
            self.assertEqual(self.invoke(half,t),(2,b''))
