"""Exercise the native publication projection before invoking real Store/Settlement roles."""
from hashlib import sha256
from pathlib import Path
import os
import struct
import subprocess
import unittest

from hepta.hia_agent_store import AgentStore, wire
import tests.test_hia_evaluate_settlement as settlement_tests
from tools.generate_hia_evaluate_publication import SOURCE, PACKER, PACK_MAGIC
from tools.qualify_hia_selfhost import compile_stage


def frame(mode,parts):
    return struct.pack('<8s9Q',b'HIAEPU01',mode,*map(len,parts))+b''.join(parts)


def extent(value):
    return struct.pack('<Q',len(value))+value


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        settlement_tests.SettlementTests.setUpClass()
        cls.addClassCleanup(settlement_tests.SettlementTests.doClassCleanups)
        cls.settlement=settlement_tests.SettlementTests()
        cls.addClassCleanup(cls.settlement.doCleanups)
        work=settlement_tests.SettlementTests.work
        compiler,=work.glob('B2.image.bin')
        def build(path):
            return compile_stage(work,path.stem,compiler,path.read_bytes())[0]
        app=build(SOURCE).read_bytes()
        cls.exe=compile_stage(work,'publication',build(PACKER),struct.pack('<2Q',PACK_MAGIC,len(app))+app,output_extension='.elf')[0]
        cls.exe.chmod(0o500)
        issued, cls.receipt=cls.settlement.issuer_proof()
        cls.issue_input=issued
        n=struct.unpack_from('<Q',issued,56)[0]
        raw=bytearray(issued[:-n]);raw[:8]=b'HIAEST01';struct.pack_into('<Q',raw,56,0)
        cls.template=bytes(raw)
        code,decision=cls.settlement.invoke(cls.template)
        assert code==0
        refs=issued[-n:-n+880]
        cursor=len(issued)-n+880
        values=[]
        while cursor<len(issued):
            size=struct.unpack_from('<Q',issued,cursor)[0];cursor+=8
            values.append(issued[cursor:cursor+size]);cursor+=size
        cls.ledger,cls.measure,claim,call,unsigned=values
        report_parts=(claim,cls.template,decision,cls.measure)
        report=struct.pack('<8s4Q',b'HIAEMF01',*map(len,report_parts))+b''.join(report_parts)
        store=AgentStore(work/'publication-store')
        try:
            rr=wire(store.put(cls.receipt,'evaluation-receipt'))
        finally:
            store.close()
        cls.parts=[report,call,unsigned,cls.ledger,refs[704:880],refs[528:704],cls.receipt,rr]
        terminal=refs[:352]+rr+refs[528:880]+extent(cls.receipt)+extent(cls.ledger)+extent(cls.measure)
        out=bytearray(cls.template);struct.pack_into('<Q',out,56,len(terminal))
        cls.terminal_input=bytes(out)+terminal

    def invoke(self,raw):
        p=subprocess.run([self.exe],input=raw,capture_output=True,env={'PATH':''},timeout=15)
        self.assertEqual(p.stderr,b'')
        return p.returncode,p.stdout

    def test_all_three_physical_publication_wires(self):
        for mode,kind,body in [(0,20,self.measure),(1,21,self.ledger),(3,22,self.receipt)]:
            with self.subTest(mode=mode):
                expected=struct.pack('<8s3Q',b'HIAEDU01',0,kind,len(body))+sha256(body).hexdigest().encode()+body
                self.assertEqual(self.invoke(frame(mode,self.parts)),(0,expected))

    def test_both_settlement_requests_reproduce_the_original_identity(self):
        for mode,expected in [(2,self.issue_input),(4,self.terminal_input)]:
            with self.subTest(mode=mode):
                rc,wire_bytes=self.invoke(frame(mode,self.parts))
                self.assertEqual((rc,wire_bytes),(0,expected))
                code,result=self.settlement.invoke(wire_bytes)
                self.assertEqual(code,0)
                if mode==2:self.assertEqual(result,self.receipt)
                else:self.assertEqual(result[:8],b'HIAESTR1')

    def test_rejects_mixed_refs_claim_and_truncated_payload(self):
        for index,value in [(0,self.parts[0].replace(b'HIASTCP1',b'HIASTCP0',1)),
                            (0,self.parts[0].replace(b'HIAESD01',b'HIAESD00',1)),
                            (3,self.ledger+b' '),(4,self.parts[5]),(7,self.parts[4])]:
            with self.subTest(index=index):
                parts=self.parts.copy();parts[index]=value
                self.assertEqual(self.invoke(frame(4,parts)),(2,b''))
        self.assertEqual(self.invoke(frame(2,self.parts)[:-1]),(2,b''))
        self.assertEqual(self.invoke(frame(8,self.parts)),(2,b''))

    @unittest.skipUnless(os.environ.get('HIA_TEST_NATIVE_PUBLICATION_STATE'),'physical issued documents required')
    def test_actual_claim_and_issued_store_documents(self):
        out=Path(os.environ['HIA_TEST_NATIVE_PUBLICATION_STATE'])
        issued=(out/'issue-evaluation.input').read_bytes()
        n=struct.unpack_from('<Q',issued,56)[0];cursor=len(issued)-n+880
        blobs=[]
        while cursor<len(issued):
            size=struct.unpack_from('<Q',issued,cursor)[0];cursor+=8
            blobs.append(issued[cursor:cursor+size]);cursor+=size
        ledger,measure,claim,call,unsigned=blobs
        raw=bytearray(issued[:-n]);raw[:8]=b'HIAEST01';struct.pack_into('<Q',raw,56,0)
        rc,decision=self.settlement.invoke(bytes(raw));self.assertEqual(rc,0)
        vals=[claim,bytes(raw),decision,measure]
        report=struct.pack('<8s4Q',b'HIAEMF01',*map(len,vals))+b''.join(vals)
        parts=[report,call,unsigned,ledger,(out/'measurements.ref').read_bytes(),(out/'cost-ledger.ref').read_bytes(),
               (out/'evaluation-receipt.json').read_bytes(),(out/'evaluation-receipt.ref').read_bytes()]
        for mode,name in [(2,'issue-evaluation.input'),(4,'publish-evaluation.input')]:
            self.assertEqual(self.invoke(frame(mode,parts)),(0,(out/name).read_bytes()))
