"""Independent native decisions and the complete 50-instruction host oracle."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_instruction_policy_native import (
    SOURCE,SCHEMA,SELECTOR,ERROR_CODES,NativeInstructionPolicy,packet,transport)
from hepta.hia_opcodes import OPCODES,OpcodeRejected,opcode_spec,check_instruction,_GROUPS,WIDTHS


def interpreted(raw):
    from tests import test_hia_function_shape_native as observer
    with patch.object(observer,'SOURCE',SOURCE):return observer.interpreted(raw)


def example(spec):
    args=[]
    for rule in spec.operands or ():
        if rule.startswith('='):typ=args[int(rule[1:])]
        else:
            rule=rule.removeprefix('declared:')
            typ=next((v for v in ('u32','bool','buffer','readbuf','mutbuf','chain') if v in _GROUPS.get(rule,())),rule)
        args.append(typ)
    out=[]
    for rule in spec.results or ():
        if rule.startswith('='):typ=args[int(rule[1:])]
        else:
            rule=rule.removeprefix('declared:')
            typ='u32' if rule in {'scalar','integer'} else rule
        out.append(typ)
    attrs={'value':0} if spec.name=='const' else {'mode':'checked'} if spec.name=='int.cast' else {'function':'callee'} if spec.name=='call' else {}
    return args,out,attrs


class InstructionPolicySourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM_before_native(self):
        from tools.generate_hia_instruction_policy import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        self.assertEqual(interpreted(packet('int.add.checked','hepta.hia.program.v1',['u64','u64'],['u64'],{})),8)
        self.assertEqual(interpreted(packet('const','hepta.hia.program.v8',[],['u8'],{'value':256})),0xfffffff9)
        self.assertEqual(interpreted(packet('borrow.mut','hepta.hia.program.v8',['readbuf'],['mutbuf'],{})),0xfffffff8)
        self.assertEqual(interpreted(packet('chain.empty','hepta.hia.program.v6',[],['chain'],{})),0xfffffff0)

    def test_full_catalog_schema_and_groups_not_compiler_opcode_subset(self):
        from tools.generate_hia_instruction_policy import GROUPS,TYPES,source_program
        from hepta.hia_opcodes import TYPES as ACTUAL_TYPES
        self.assertEqual(len(OPCODES),50);self.assertEqual(set(TYPES),ACTUAL_TYPES)
        self.assertEqual(set(GROUPS),set(_GROUPS));self.assertIn('return local_check',source_program())


class InstructionPolicyNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert interpreted(packet('const','hepta.hia.program.v8',[],['u64'],{'value':(1<<64)-1}))==0
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-instruction-policy-');cls.folder=Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cold=os.environ.get('HEPTA_HIA_INSTRUCTION_POLICY_COLD_REPORT')
        if cold:
            report=json.loads(Path(cold).read_bytes());assert report['status']=='COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested=json.loads(Path(report['nested_report']).read_bytes());compiler=Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256']==[sha256(compiler.read_bytes()).hexdigest()]*3
        else:
            seed,_=build_seed(cls.folder);source=SOURCE.with_name('selfhost.hepta').read_bytes()
            first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
            compiler,_=compile_stage(cls.folder,'B2',first,source);assert first.read_bytes()==compiler.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'instruction-policy',compiler,SOURCE.read_bytes())
        cls.compiler=compiler;raw=image.read_bytes();cls.native=NativeInstructionPolicy(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json';cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,
            source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),image_path=image.name,
            image_sha256=sha256(raw).hexdigest(),compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def compare(self,name,args,out,attrs,version=8):
        schema='hepta.hia.program.v'+str(version)
        try:expected=check_instruction(opcode_spec(name,schema),args,out,attrs)
        except OpcodeRejected as exc:expected=exc.code
        result=self.native.status(packet(name,schema,args,out,attrs))
        actual=ERROR_CODES[result] if result in ERROR_CODES else frozenset(v for i,v in enumerate(('alloc','read','write','trap')) if result&(1<<i))
        self.assertNotEqual(result,0xfffffffd);self.assertEqual(actual,expected,(name,args,out,attrs,version,result))

    def test_every_opcode_every_version_all_arity_and_type_mutations(self):
        for spec in OPCODES.values():
            args,out,attrs=example(spec)
            for version in range(1,10):self.compare(spec.name,args,out,attrs,version)
            for group in ('args','out'):
                for replacement in ([],['u32']*8):
                    self.compare(spec.name,replacement if group=='args' else args,replacement if group=='out' else out,attrs)
                values=args if group=='args' else out
                for index in range(len(values)):
                    for typ in ('i8','u64','bool','unit','buffer','readbuf','mutbuf','chain','unknown'):
                        changed=values[:];changed[index]=typ
                        self.compare(spec.name,changed if group=='args' else args,changed if group=='out' else out,attrs)

    def test_all_exact_integer_boundaries_and_scalar_kind_distinctions(self):
        for typ,bits in WIDTHS.items():
            low,high=(-(1<<(bits-1)),(1<<(bits-1))-1) if typ.startswith('i') else (0,(1<<bits)-1)
            for value in (low-1,low,low+1,high-1,high,high+1,True,False,None,1.0,-0.0,1e50,[],{},'1'):
                self.compare('const',[],[typ],{'value':value})
        for typ in ('unit','bool'):
            for value in (None,True,False,0,1,-1,1.0,[],{},'null'):self.compare('const',[],[typ],{'value':value})
        for value in (1<<300,-(1<<300)):self.compare('const',[],['u64'],{'value':value})
        class IntSubclass(int):pass
        self.compare('const',[],['u64'],{'value':IntSubclass(1)})

    def test_exact_attributes_cast_modes_and_error_precedence(self):
        for spec in OPCODES.values():
            args,out,attrs=example(spec)
            for changed in (None,False,[],dict(attrs,unknown=0),{'bad':0},{1:0}):self.compare(spec.name,args,out,changed)
            self.compare(spec.name,args+['unknown'],out,{'bad':0})
        for mode in ('checked','wrap','other',None,False,1,1.0,[],{}):self.compare('int.cast',['i64'],['u8'],{'mode':mode})
        for name in ('unknown','',None,42):self.compare(name,[],[],{'bad':0})
        for version in (0,9):self.compare('const',[],['u32'],{'extra':None},version)

    def test_full_call_transport_not_compiler_16_argument_or_128_export_subset(self):
        self.compare('call',['u64']*16384,['u64']*1024,{'function':'callee'})
        self.compare('call',[],[],{'function':'x'*8388608})
        self.compare('call',[],[],{'function':[None]*262144})
        nested=None
        for _ in range(64):nested=[nested]
        self.compare('call',[],[],{'function':nested})

    def test_typed_wire_custody_refuses_truncation_overflow_and_extra_nodes(self):
        raw=packet('const','hepta.hia.program.v8',[],['u32'],{'value':1})
        for n in range(len(raw)):self.assertEqual(self.native.status(raw[:n]),0xfffffffb)
        for value in (raw+b'x',struct.pack('<QQ',5,(1<<64)-1),struct.pack('<QQQ',5,8,1),transport(None)):
            self.assertEqual(self.native.status(value),0xfffffffb)
        for i in (0,8,16):
            corrupt=bytearray(raw);struct.pack_into('<Q',corrupt,i,(1<<64)-1)
            self.assertEqual(self.native.status(bytes(corrupt)),0xfffffffb)

    def test_selected_production_core_keeps_body_ownership_and_effect_checks(self):
        from hepta import hia_program as core
        from tests.test_hia_program import joined_loan_program
        with (patch.dict(os.environ,{SELECTOR:str(self.manifest)}),
              patch.object(core,'opcode_spec',side_effect=AssertionError('foreign opcode')),
              patch.object(core,'check_instruction',side_effect=AssertionError('foreign local check'))):
            checked=core.verify_program(joined_loan_program())
            self.assertEqual(core.execute_program(checked,'join',[True])['result'],0)
            bad=joined_loan_program();bad['functions'][0]['blocks'][0]['ops'][0]['op']='unknown'
            with self.assertRaises(core.HIAProgramRejected):core.verify_program(bad)
            bad=joined_loan_program();bad['functions'][0]['effects']=[]
            with self.assertRaises(core.HIAProgramRejected):core.verify_program(bad)
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)+'.missing'}):
            with self.assertRaises(FileNotFoundError):core.verify_program(joined_loan_program())

    def test_no_runtime_foreign_policy_or_JSON_decoder(self):
        with (patch('json.loads',side_effect=AssertionError('foreign JSON decoder')),
              patch('hepta.hia_opcodes.opcode_spec',side_effect=AssertionError('foreign opcode')),
              patch('hepta.hia_opcodes.check_instruction',side_effect=AssertionError('foreign checker'))):
            self.assertEqual(self.native.check('int.cast','hepta.hia.program.v8',['u64'],['u8'],{'mode':'checked'}),{'trap'})
            self.assertEqual(self.native.check('buffer.copy','hepta.hia.program.v8',['mutbuf','readbuf','usize'],[],{}),{'read','write','trap'})
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_strict_build_wrong_source_before_output_and_matching_current_cold(self):
        from tools.build_hia_instruction_policy import build
        wrong=self.folder/'wrong.json';wrong.write_text(json.dumps({'profile':'wrong','source_manifest':{}}));output=self.folder/'wrong-output'
        with self.assertRaisesRegex(ValueError,'source identity'):build(output,self.compiler,wrong)
        self.assertFalse(output.exists())
        cold=os.environ.get('HEPTA_HIA_INSTRUCTION_POLICY_COLD_REPORT')
        if cold:
            from hepta.hia_instruction_policy_native import installed_instruction_policy
            manifest=build(self.folder/'matching-output',self.compiler,Path(cold))
            self.assertEqual(installed_instruction_policy(str(manifest)).status(packet('const','hepta.hia.program.v8',[],['u32'],{'value':7})),0)


if __name__=='__main__':unittest.main()
