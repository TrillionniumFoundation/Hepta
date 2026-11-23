"""Compare the installed HIA ledger boundary with the original public record."""
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import subprocess
from types import SimpleNamespace
import unittest

from hepta.hia_agent_service import HIAAgentService, wire
from hepta.hia_agent_store_native import _parameters
from tests.test_hia_agent_store_runtime import command
from tools.generate_hia_evaluate_cost_ledger import PACKER, PACK_MAGIC, SOURCE
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]
CTX_ID = 'ctx-' + '1'*32


def ref(body, key):
    return {'id': 'a-' + key*32, 'sha256': sha256(body).hexdigest(), 'uri': 'hia://artifacts/' + key*32}


def row_payload(table, cells):
    start = 32 + len(cells)*24
    header = bytearray(struct.pack('<8s3Q', b'HIAROW01', 1, table, len(cells)))
    parts = []
    for value in cells:
        if value is None:
            kind, data = 0, b''
        elif isinstance(value, int):
            kind, data = 1, value.to_bytes(8, 'little', signed=True)
        elif isinstance(value, str):
            kind, data = 3, value.encode()
        else:
            kind, data = 4, value
        header.extend(struct.pack('<3Q', kind, start, len(data)))
        start += len(data)
        parts.append(data)
    return bytes(header)+b''.join(parts)


def query_frames(table, rows):
    def frame(kind, row, offset, payload, index):
        return struct.pack('<8s7Q', b'HIAQRF01', kind, table, row, offset, len(payload), index, 0)+payload

    encoded = []
    count = total = 0
    for count, cells in enumerate(rows, 1):
        payload = row_payload(table, cells)
        desc = struct.pack('<8s11Q8s3Q', b'HIAIXLF1', 1, 2, 1, table, 0, len(payload)+128,
                           64, 32, 96, len(payload), 0, b'HIARID01', 1, table, count)
        encoded.append(frame(1,count,0,desc,count))
        for offset in range(0,len(payload),211):
            encoded.append(frame(2,count,offset,payload[offset:offset+211],count))
        encoded.append(frame(3,count,len(payload),b'',count))
        total += len(payload)
    summary = bytes(384)+struct.pack('<4Q',5 if table==5 else 2,127 if table==5 else 63,count,count)
    encoded.append(frame(4,0,total,summary,count))
    return b''.join(encoded)


def ack(ordinal, kind):
    return struct.pack('<8s9Q',b'HIATXR01',1,ordinal,kind,0,0,39,0,0,0)


def case(rows, complete):
    policy = {'schema':'hepta.hia.agent.cost-policy.v1','expected_invocations':'4',
              'external_costs_complete':complete,'external_costs':{'discovery_wall_ns':'0',
              'model_wall_ns':'128','model_tokens':'9'}}
    policy_bytes = wire(policy)
    policy_ref = ref(policy_bytes,'2')
    context = {'budget':{'cost_policy':policy_ref}}
    context_bytes = wire(context)
    context_ref = {'id':CTX_ID,'sha256':sha256(context_bytes).hexdigest()}
    request = wire({'tool':'hia_evaluate','arguments':{'context':context_ref}})
    typed = bytearray()
    for ordinal in range(9):
        row = context_bytes if ordinal==0 else b'{}'
        typed.extend(struct.pack('<4Q',ordinal,3 if ordinal==0 else 7,0,len(row)))
        typed.extend(wire(ref(row,'4')))
        typed.extend(row)
    arm = struct.pack('<8s2Q',b'HIAEBT01',2,0)
    fresh = struct.pack('<8s13Q',b'HIAEFI04',9,1,2,100,100000,len(request),len(typed),
                        len(arm),len(arm),1,2,3,9)+request+typed+2*arm
    decision = struct.pack('<8s8Q',b'HIAESD01',4,1,10,10,0,8,99,2)+b'17'
    artifact = (policy_ref['id'],policy_ref['sha256'],policy_ref['uri'],'input','{}','5'*64)
    replies = b''.join((ack(0,0),query_frames(5,rows),ack(1,27),query_frames(1,[artifact]),ack(2,27),ack(3,3)))
    db = sqlite3.connect(':memory:')
    try:
        db.row_factory = sqlite3.Row
        db.execute('CREATE TABLE costs(sequence INTEGER PRIMARY KEY,context_id TEXT,tool TEXT,'
                   'request_id TEXT,wall_ns TEXT,status TEXT,details BLOB)')
        db.executemany('INSERT INTO costs VALUES(?,?,?,?,?,?,?)',rows)
        context['ref'] = context_ref
        service = SimpleNamespace(store=SimpleNamespace(db=db,get_json=lambda reference:(policy,None)))
        expected = wire(HIAAgentService._cost_ledger_reference(service,context,99,17))
    finally:
        db.close()
    return (fresh,decision,replies,policy_bytes),policy_ref,expected


def render(parts):
    return struct.pack('<8s4Q',b'HIAELR01',*map(len,parts))+b''.join(parts)


class SettledCostLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_execution_budget_session import BudgetSessionTests

        BudgetSessionTests.setUpClass()
        cls.addClassCleanup(BudgetSessionTests.doClassCleanups)
        folder = BudgetSessionTests.session.parent
        compiler = folder/'B2.image.bin'
        app = compile_stage(folder,'ledger',compiler,(ROOT/SOURCE).read_bytes())[0].read_bytes()
        canonical = compile_stage(folder,'canonical-worker',compiler,
                                  (ROOT/'examples/hia_bootstrap/worker_request.hepta').read_bytes())[0].read_bytes()
        packer = compile_stage(folder,'ledger-packer',compiler,(ROOT/PACKER).read_bytes())[0]
        frame = struct.pack('<3Q',PACK_MAGIC,len(app),len(canonical))+app+canonical
        cls.exe = compile_stage(folder,'settled-ledger',packer,frame,output_extension='.elf')[0]
        cls.exe.chmod(0o500)

    def invoke(self,payload):
        result = subprocess.run([self.exe],input=payload,capture_output=True,timeout=15,env={'PATH':''})
        self.assertFalse(result.stderr)
        return result.returncode,result.stdout

    def test_empty_scoped_unscoped_and_signed_imported_costs(self):
        values = [
            (-3,CTX_ID,'quoted "λ"','request\\1','-100000000000000000000000000000000','failed',
             b'  {"z": 1e+02, "a": [3,-0,true]}  '),
            (4,None,'read','\n','+0001_234','ok',b'{"esc":"\\u0061","items":[false,null]}'),
            (9,CTX_ID,'emit','next','100000000000000000000000000000008','ok',b'{}')]
        for rows in ([], values):
            for complete in (False,True):
                with self.subTest(rows=len(rows),complete=complete):
                    parts,policy,expected=case(rows,complete)
                    plan = (command(1,27,8,_parameters((CTX_ID,),5,None))
                            +command(2,27,5,_parameters((policy['id'],),2,None))+command(3,3))
                    self.assertEqual(self.invoke(b'HIAELQ01'+parts[0]),(0,wire(policy)+plan))
                    self.assertEqual(self.invoke(render(parts)),(0,expected))

    def test_refusal_has_no_output(self):
        parts,policy,_ = case([(1,CTX_ID,'read','r','100','ok','{}')],False)
        fresh,decision,replies,body = parts
        changed = lambda raw,old,new: raw.replace(old,new,1)
        for index, replacement in [
            (0,fresh[:-1]),(0,changed(fresh,b'hia_evaluate',b'hia_describe')),
            (0,changed(fresh,policy['id'].encode(),b'a-' + b'3'*32)),
            (1,changed(decision,b'HIAESD01',b'HIAESD00')),(1,decision[:-1]),
            (1,decision[:48]+struct.pack('<Q',7)+decision[56:]),(1,decision[:-2]+b'0x'),
            (2,changed(replies,b'HIATXR01',b'HIATXR00')),(2,replies[:-1]),
            (2,changed(replies,policy['uri'].encode(),b'hia://artifacts/'+b'3'*32)),
            (2,changed(replies,b'HIAQRF01',b'HIAQRF00')),
            (2,changed(replies,b'HIARID01',b'HIARID00')),(3,body+b' ')]:
            with self.subTest(part=index,prefix=replacement[:10]):
                incoming=list(parts)
                incoming[index]=replacement
                self.assertEqual(self.invoke(render(incoming)),(2,b''))
