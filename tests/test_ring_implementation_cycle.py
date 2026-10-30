"""Independent historical behavior, trace extent, and fixture identity checks."""
import json
import unittest
from tools.qualify_ring_implementation_cycle import (verify_upstream, operation_stream,
    encode_operations, oracle, FIXTURE)

class RingImplementationModelTests(unittest.TestCase):
    def test_full_upstream_trees_bind_an_actual_implementation_only_change(self):
        manifest=verify_upstream()
        self.assertTrue(manifest['maintenance_change']['implementation_changed'])
        self.assertEqual(manifest['maintenance_change']['changed_files'],['ringbuffer.c'])
        self.assertEqual(len(manifest['versions']),2)
        self.assertTrue(all(len(v['files'])==8 for v in manifest['versions']))

    def test_zero_length_read_preserves_old_extra_write_and_new_fix(self):
        ops=[('A',[10,20,30]),('R',[0])]
        before,after=oracle(ops,'before')[-1],oracle(ops,'after')[-1]
        self.assertEqual((before['return'],before['tail'],before['count']),(0,1,2))
        self.assertEqual((after['return'],after['tail'],after['count']),(0,0,3))
        self.assertEqual(bytes.fromhex(before['output'])[:2],bytes([10,0xa5]))
        self.assertEqual(bytes.fromhex(after['output']),bytes([0xa5]*256))

    def test_consecutive_short_reads_have_revision_specific_results(self):
        ops=[('A',[10,20,30,40,50]),('R',[1]),('R',[1]),('D',[])]
        before,after=oracle(ops,'before'),oracle(ops,'after')
        self.assertEqual([bytes.fromhex(r['output'])[0] for r in before[1:]],[10,30,50])
        self.assertEqual([bytes.fromhex(r['output'])[0] for r in after[1:]],[10,20,30])
        self.assertEqual(before[1]['return'],after[1]['return'])
        self.assertNotEqual(before[1]['tail'],after[1]['tail'])

    def test_init_does_not_zero_payload_and_full_queue_overwrites_oldest(self):
        ops=[('A',list(range(255))),('I',[])]
        for revision in ['before','after']:
            rows=oracle(ops,revision)
            self.assertEqual((rows[0]['count'],rows[0]['full']),(127,1))
            self.assertEqual(rows[0]['payload'],rows[1]['payload'])
            self.assertEqual((rows[1]['head'],rows[1]['tail'],rows[1]['empty']),(0,0,1))

    def test_declared_old_extent_is_explicit_and_only_one_contract_changes(self):
        before=json.loads((FIXTURE/'contracts-before.json').read_text());after=json.loads((FIXTURE/'contracts-after.json').read_text())
        self.assertEqual(before['functions']['ring_buffer_dequeue_arr']['slice_extra']['data'],1)
        before['functions']['ring_buffer_dequeue_arr']['slice_extra']['data']=0
        self.assertEqual(before,after)

    def test_development_stream_is_deterministic_and_within_real_abi_extents(self):
        operations=operation_stream(123,80)
        self.assertEqual(operations,operation_stream(123,80))
        self.assertEqual(len(encode_operations(operations).splitlines()),98)
        self.assertTrue(all(len(v)<=255 if op=='A' else all(0<=x<=255 for x in v) for op,v in operations))
        self.assertNotEqual(oracle(operations,'before'),oracle(operations,'after'))

if __name__=='__main__':unittest.main()
