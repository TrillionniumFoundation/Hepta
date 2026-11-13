"""Independent Core-VM witnesses, all graph rules, native selected CFG and limits."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from itertools import permutations
import ctypes
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_capability_flow import Capability as C, CapabilityFlowRejected, _reference_rename_capabilities
from hepta.hia_capability_renaming_native import (
    MAGIC, RESULT, NONE, SOURCE, SCHEMA, SELECTOR, MAX_CAPABILITIES,
    NativeCapabilityRenaming, encode_graph, installed_capability_renaming,
)
ROOT = Path(__file__).resolve().parents[1]


def independent_case():
    # No production encoder or resolver participates in these complete bytes.
    wire = struct.pack('<8Q', MAGIC, 3, 3, 10, 0, 0, 0, 0)
    wire += struct.pack('<18Q', 0,3,0,NONE,0,NONE, 1,4,0,0,0,6, 2,5,0,1,0,6)
    wire += struct.pack('<6Q', 0,9, 1,8, 2,7)
    expected = struct.pack('<8Q', RESULT,3,10,0,0,0,0,0)
    expected += struct.pack('<18Q', 9,3,9,NONE,0,NONE, 8,4,9,9,0,6, 7,5,9,8,0,6)
    return wire, expected


def interpreted(wire, capacity):
    # The existing generic observation harness constructs real HIA buffers,
    # invokes f0 in the ordinary resource-checking VM and checks zero leaks.
    from tests import test_hia_core_module_graph_native as observer
    with patch.object(observer, 'SOURCE', SOURCE):
        return observer.vm(wire, capacity)


class CapabilityRenamingSourceTests(unittest.TestCase):
    def test_contract_retains_full_limits_and_does_not_claim_general_admission(self):
        from tools.hia_selfhost_contract import support_contract
        from hepta.hia_program import MAX_NODES
        part=support_contract()['capability_renaming_application']
        self.assertEqual(part['maximum_capabilities'],262144)
        self.assertEqual(MAX_CAPABILITIES,MAX_NODES)
        self.assertEqual(part['maximum_edges'],262144)
        self.assertEqual(part['maximum_symbols'],2097152)
        for key in ('native_general_Core_verifier','selected_reference_fallback',
                    'all_input_refinement_proved','production_activated'):
            self.assertIs(part[key],False)

    def test_complete_independent_VM_witness_and_transactional_refusals(self):
        from tools.generate_hia_capability_renaming import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        wire, expected = independent_case()
        self.assertEqual(interpreted(wire, len(expected)), (len(expected), expected))
        self.assertEqual(interpreted(wire + b'!', 32), (0xffffffff, bytes([90])*32))
        self.assertEqual(interpreted(wire, 32), (0xfffffffe, bytes([90])*32))
        duplicated = bytearray(wire); struct.pack_into('<Q', duplicated, len(wire)-8, 8)
        self.assertEqual(interpreted(bytes(duplicated), len(expected)), (0xfffffffd, bytes([90])*len(expected)))


class CapabilityRenamingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wire, expected = independent_case()
        assert interpreted(wire, len(expected)) == (len(expected), expected)
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-capability-native-')
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        cold = os.environ.get('HEPTA_HIA_CAPABILITY_RENAMING_COLD_REPORT')
        if cold:
            report = json.loads(Path(cold).read_bytes())
            assert report['status'] == 'COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256'] == [sha256(compiler.read_bytes()).hexdigest()]*3
        else:
            seed, _ = build_seed(cls.folder)
            source = (ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert compiler.read_bytes() == first.read_bytes()
        cls.image, cls.receipt = compile_stage(cls.folder, 'capability', compiler, SOURCE.read_bytes())
        image = cls.image.read_bytes()
        cls.native = NativeCapabilityRenaming(image, sha256(image).hexdigest())
        cls.manifest = cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=cls.image.name, image_sha256=sha256(image).hexdigest(),
            compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_native_matches_interpreted_bytes_and_no_foreign_compiler(self):
        wire, expected = independent_case()
        self.assertEqual(self.native.run(wire), expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'], [])

    def test_every_field_arbitrary_symbol_identity_and_all_permutations(self):
        caps = {'owner': C('buffer','owner'), 'mut': C('mutbuf','owner','owner',False,'formal'),
                'read': C('readbuf','owner','mut',False,'formal')}
        for names in permutations(('owner','mut','read')):
            remap = dict(zip(caps,names))
            self.assertEqual(self.native.rename(caps,remap), _reference_rename_capabilities(caps,remap))
        # String transport is identity, not ASCII spelling or a typestate check.
        # Core has already admitted its actual identifier/type profile.
        caps = {'': C('opaque type','',None,True,'原始'), '雪': C('readbuf','','',True,'原始')}
        remap = {'':'雪','雪':''}
        self.assertEqual(self.native.rename(caps,remap), _reference_rename_capabilities(caps,remap))

    def test_random_closed_graphs_renaming_composition_and_external_forgetting(self):
        rng = random.Random(849372)
        for _ in range(400):
            size = rng.randrange(1,35)
            caps = {'n0': C('buffer','n0')}
            for i in range(1,size):
                caps['n'+str(i)] = C(rng.choice(['mutbuf','readbuf']), 'n0', 'n'+str(rng.randrange(i)),
                                    False, rng.choice([None,'formal0','formal1']))
            caps['external'] = C('readbuf','external',None,True,'external')
            names = list(caps); rng.shuffle(names)
            remap = {key: 'new_'+name for key,name in zip(caps,names)}
            if rng.randrange(2): del remap['external']
            actual = self.native.rename(caps,remap)
            self.assertEqual(actual, _reference_rename_capabilities(caps,remap))
            second = {k:'last_'+str(i) for i,k in enumerate(actual)}
            self.assertEqual(self.native.rename(actual,second),
                             self.native.rename(caps,{k:second[v] for k,v in remap.items()}))

    def test_all_refusals_exact_error_precedence_and_output_canaries(self):
        caps = {'a':C('buffer','a'), 'b':C('buffer','b')}
        cases = [(caps,{'a':'x','b':'x'}),(caps,{'a':'x','b':'x','ghost':'z'}),
                 (caps,{'a':'x'}),(caps,{'ghost':'x'}),
                 ({'root':C('readbuf','root',None,True),
                   'parent':C('readbuf','root','root',True),
                   'leaf':C('readbuf','root','parent')},{'leaf':'l'}),
                 ({'root':C('readbuf','root',None,True),
                   'parent':C('readbuf','root','root',True),
                   'leaf':C('readbuf','root','parent')},{'root':'r','leaf':'l'})]
        for caps,remap in cases:
            with self.assertRaises(CapabilityFlowRejected) as ref: _reference_rename_capabilities(caps,remap)
            with self.assertRaises(CapabilityFlowRejected) as new: self.native.rename(caps,remap)
            self.assertEqual((new.exception.code,str(new.exception)),(ref.exception.code,str(ref.exception)))
            wire,_ = encode_graph(caps,remap)
            _,n,m,ns,*_ = struct.unpack_from('<8Q',wire)
            size = 64+m*48
            src=ctypes.create_string_buffer(wire,len(wire));out=ctypes.create_string_buffer(bytes([90])*(size+16))
            scratch=ctypes.create_string_buffer(size+ns*24+16)
            self.assertIn(self.native._entry(src,len(wire),out,size,scratch,len(scratch)-16),range(0xfffffffa,0x100000000))
            self.assertEqual(out.raw[:size+16],bytes([90])*(size+16))

    def test_hostile_internal_types_and_malformed_raw_packets_fail_closed(self):
        class Hostile(dict):
            def items(self): raise AssertionError('hostile iteration')
        for caps,remap in ((Hostile(),{}),({},Hostile()),({'x':object()},{}),({'x':C('buffer','x')},{'x':42})):
            with self.assertRaises(CapabilityFlowRejected): self.native.rename(caps,remap)
        wire,_=independent_case()
        for offset,value in ((0,0),(8,MAX_CAPABILITIES+1),(24,2097153),(32,1),(64,10),(64+32,2)):
            changed=bytearray(wire);struct.pack_into('<Q',changed,offset,value)
            with self.subTest(offset=offset),self.assertRaises(CapabilityFlowRejected):self.native.run(bytes(changed))
        self.assertEqual(self.native.rename({},{}),{})
        self.assertEqual(self.native.rename({'a':C('readbuf','absent',None,True)},{}),{})

    def test_real_selected_CFG_general_safety_checks_and_no_reference_fallback(self):
        from hepta.hia_program import verify_program,HIAProgramRejected
        from hepta.hia_program_runtime import execute_program
        from tests.test_hia_program import joined_loan_program
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}), \
             patch('hepta.hia_capability_flow._reference_rename_capabilities',side_effect=AssertionError('foreign edge policy')):
            for cond in (False,True):
                module=verify_program(joined_loan_program())
                actual=execute_program(module,'join',[cond])
                self.assertEqual(actual['result'],0)
                self.assertEqual(actual['resources']['live_owners'],0)
                self.assertEqual(actual['resources']['live_local_loans'],0)
            bad=joined_loan_program();bad['functions'][0]['blocks'][0]['ops'][0]['op']='not_an_opcode'
            with self.assertRaises(HIAProgramRejected):verify_program(bad)
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)+'.missing'}):
            from hepta.hia_capability_flow import rename_capabilities
            with self.assertRaises(FileNotFoundError):rename_capabilities({}, {})

    def test_private_concurrency_and_cached_source_drift_refusal(self):
        args=[({'o':C('buffer','o')},{'o':'r'+str(i)}) for i in range(64)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            actual=list(pool.map(lambda x:self.native.rename(*x),args))
        self.assertEqual(actual,[_reference_rename_capabilities(*x) for x in args])
        self.assertIsNotNone(installed_capability_renaming(str(self.manifest)))
        with patch('hepta.hia_capability_renaming_native.SOURCE',self.folder/'missing-source'):
            with self.assertRaises(FileNotFoundError):installed_capability_renaming(str(self.manifest))

    def test_complete_Core_node_ceiling_and_one_past_without_smaller_demo_limit(self):
        # Full 262,144-state policy, not a 1024-name sampled substitute. IDs are
        # distinct graph input symbols, not host-computed relation results.
        n=MAX_CAPABILITIES
        wire=bytearray(struct.pack('<8Q',MAGIC,n,n,n+1,0,0,0,0))
        for i in range(n):wire.extend(struct.pack('<6Q',i,n,i,NONE,0,NONE))
        for i in range(n):wire.extend(struct.pack('<2Q',i,n-1-i))
        actual=self.native.run(bytes(wire))
        self.assertEqual(struct.unpack_from('<8Q',actual),(RESULT,n,n+1,0,0,0,0,0))
        for i,row in enumerate(struct.iter_unpack('<6Q',actual[64:])):
            self.assertEqual(row,(n-1-i,n,n-1-i,NONE,0,NONE))
        struct.pack_into('<Q',wire,8,n+1)
        with self.assertRaises(CapabilityFlowRejected):self.native.run(bytes(wire))


if __name__ == '__main__':unittest.main()
