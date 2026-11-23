"""Exercise the sealed paid Evaluate continuation and its public products."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import time
import unittest

from hepta.hia_agent_store import wire
from tests.test_hia_evaluate_measurements import typed
from tests.test_hia_evaluate_paired_batch import run_pair
from tests.test_hia_program import b,c,f,m,ret
from tools.generate_hia_evaluate_report_flow import ADAPTER, MAGIC, PACKER, PORTS, SOURCE, adapter_source
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import compile_stage

ROOT=Path(__file__).resolve().parents[1]


def envelope(fresh,paid):
    _,request,_,_=typed(fresh)
    request_hash=sha256(wire(dict(arguments=request['arguments'],tool='hia_evaluate'))).hexdigest().encode()
    at=164+struct.unpack_from('<Q',paid,72)[0]
    state=bytearray(512)
    struct.pack_into('<8s7Q',state,0,b'HIAJRN02',3,9,1,0,1,1,0)
    state[64:128]=request_hash
    state[128:192]=paid[at:at+64]
    state[192:258]=b'r-'+request_hash
    return (struct.pack('<8s7Q',b'HIAEJC01',len(fresh),3,135,time.time_ns(),512,64,8)+state+
            struct.pack('<8s7Q',b'HIAJMO01',2,11,0,12288,0,12288,2)+b'HIASTCP1'+fresh)


def unpack(data):
    magic,*sizes=struct.unpack_from('<8s4Q',data)
    if magic != b'HIAEMF01' or sum(sizes)+40 != len(data):
        raise ValueError('incomplete Evaluate documents')
    pos=40;chunks=[]
    for size in sizes:
        chunks.append(data[pos:pos+size]);pos+=size
    return chunks


class ReportFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_evaluate_measurements import MeasurementTests
        MeasurementTests.setUpClass()
        cls.addClassCleanup(MeasurementTests.doClassCleanups)
        cls.measure=MeasurementTests()
        out=cls.measure.pair.reference.owned.parent.parent
        cc=out/'B2.image.bin'
        image,_=compile_stage(out,'paid-plan',cc,(ROOT/SOURCE).read_bytes())
        pack,_=compile_stage(out,'paid-pack',cc,(ROOT/PACKER).read_bytes())
        src=image.read_bytes()
        cls.exe,_=compile_stage(out,'paid-flow',pack,struct.pack('<2Q',MAGIC,len(src))+src,output_extension='.elf')
        cls.exe.chmod(0o500)
        adapter=adapter_source((ROOT/ADAPTER).read_bytes(),(ROOT/PORTS).read_bytes())
        binding=read_adapter_binding((ROOT/PACKER).read_bytes(),adapter,calls=1)
        verify_adapter(cls.exe.read_bytes(),src,binding,entries=(0,))

    def parts(self,claim,archive,paid,direct,owned,start):
        return [claim,archive,paid,owned,direct,self.measure.reference.read_bytes(),
                self.measure.direct.exe.read_bytes(),self.measure.settle.read_bytes(),
                self.measure.measure.read_bytes(),struct.pack('<8sQ',b'HIAEMC01',start)]

    def specimen(self,metric='artifact_bytes'):
        start=time.monotonic_ns()
        doc=m(f('test',[],['u64'],[],[b('entry',[],[c('out','u64',7)],ret('out'))]))
        records=self.measure.specimen(doc,doc,[dict(function='test',arguments=[])],metric)
        self.addCleanup(self.measure.doCleanups)
        fresh,archive,paid,direct,owned=records
        return self.parts(envelope(fresh,paid),archive,paid,direct,owned,start)

    def validate(self,inputs):
        original,archive,paid,owned,direct=inputs[:5]
        admission=struct.unpack_from('<Q',inputs[9],8)[0]
        before=time.monotonic_ns()
        rc,out,err=run_pair(self.exe,inputs)
        after=time.monotonic_ns()
        self.assertEqual((rc,err),(0,b''))
        claim,terms,decision,measurement=unpack(out)
        self.assertEqual(claim,original)
        self.assertEqual(terms[180:244],claim[192:256])
        self.assertEqual(terms[244:310],claim[256:322])
        self.assertEqual(terms[-len(paid):],paid)
        self.assertEqual(decision,self.measure.run_role(self.measure.settle,terms))
        elapsed=struct.unpack_from('<Q',decision,56)[0]
        self.assertLessEqual(before-admission,elapsed)
        self.assertLessEqual(elapsed,after-admission)
        # The oracle rebuilds the same native/VM measurements independently.
        self.assertEqual(measurement,self.measure.issue(claim[648:],archive,paid,direct,owned)[1])
        return out,measurement

    def test_elapsed_through_report_for_both_metrics(self):
        for metric in ('artifact_bytes','latency_ns'):
            with self.subTest(metric=metric):
                _,record=self.validate(self.specimen(metric))
                self.assertEqual(json.loads(record)['metric'],metric)
                self.assertEqual(json.loads(record)['observations'][0]['baseline_native']['values'],[7])

    def test_rejects_crossed_and_incomplete_authorities_before_any_output(self):
        base=self.specimen()
        def edit(slot,at,byte):
            tmp=base.copy()
            item=bytearray(tmp[slot]);item[at]=byte;tmp[slot]=bytes(item)
            return tmp
        for name,items in (('key',edit(0,192,ord('z'))),('public_id',edit(0,258,ord('z'))),
            ('context',edit(2,130,ord('q'))),('phase',edit(2,40,6)),
            ('truncated archive',[base[0],base[1][:-1],*base[2:]]),
            ('clock',[*base[:9],struct.pack('<8sQ',b'HIAEMC01',time.monotonic_ns()+10**10)]),
            ('failed late report role',[*base[:8],b'not an executable',base[9]])):
            with self.subTest(name=name):
                self.assertEqual(run_pair(self.exe,items),(2,b'',b''))
        self.assertEqual(run_pair(self.exe,base,unsealed=0),(2,b'',b''))

    @unittest.skipUnless(os.environ.get('HIA_TEST_CLAIM_WITH_PAID_PAIR'),'ROG original Store claim')
    def test_physical_claim_receipts_and_native_elves(self):
        claim=Path(os.environ['HIA_TEST_CLAIM_WITH_PAID_PAIR']).read_bytes()
        gates=Path(os.environ['HIA_TEST_PAID_GATE_DIR'])
        roles=Path(os.environ['HIA_TEST_ACTUAL_SUPERVISORS'])
        # Earlier genuine fixtures include only the reference window. Newer
        # public admissions provide the preserved original monotonic timestamp.
        start=int(os.environ.get('HIA_TEST_ADMISSION_NS',struct.unpack_from('<Q',claim,728)[0]))
        inputs=self.parts(claim,(gates/'gate-measurements.bin').read_bytes(),
                (gates/'settled.bin').read_bytes(),(roles/'hia-direct-call').read_bytes(),
                (roles/'hia-owned-reference-wire').read_bytes(),start)
        frame,record=self.validate(inputs)
        self.assertEqual(json.loads(record)['observations'][0]['candidate_native']['values'],[7])
        if 'HIA_TEST_PAID_REPORT_OUTPUT' in os.environ:
            Path(os.environ['HIA_TEST_PAID_REPORT_OUTPUT']).write_bytes(frame)
