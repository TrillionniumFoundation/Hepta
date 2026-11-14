"""Permanent source admission controls for the separate Linux file profile.

No test in this class executes a native image or grants matching-cold authority.
The independent finite kernel/fault panels retain their complete original raw.
"""
from pathlib import Path
import copy
import json
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program, HIAProgramRejected
from hepta.hia_linux_file import (
    PROFILE, MODULE, FILE_OPCODES, FILE_FLAGS, PROFILE_SOURCE_FILES,
    SOURCE_LIMIT, OUTPUT_LIMIT, WORKSPACE_LIMIT, FUNCTION_LIMIT, BLOCK_LIMIT,
    INSTRUCTION_LIMIT, LinuxStartupSnapshot, VerifiedLinuxFileProgram,
)
from hepta.hia_program_runtime import execute_program

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/native_file_read.hepta'


class LinuxFileSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=SOURCE.read_bytes()
        cls.checked=assemble_program(cls.raw,profile=PROFILE)
        cls.doc=cls.checked.as_dict()

    def test_explicit_public_parse_verify_render_roundtrip(self):
        self.assertIs(type(self.checked),VerifiedLinuxFileProgram)
        self.assertEqual(verify_program(self.doc,profile=PROFILE).canonical_bytes,self.checked.canonical_bytes)
        self.assertEqual(assemble_program(render_assembly(self.doc,profile=PROFILE),profile=PROFILE).canonical_bytes,
                         self.checked.canonical_bytes)

    def test_default_and_three_old_profiles_reject_the_same_bytes(self):
        for profile in (None,'hepta.hia.linux-stdio.v1','hepta.hia.linux-process.v1','hepta.hia.linux-cli-process.v1','unknown'):
            with self.subTest(profile=profile),self.assertRaises(HIAProgramRejected):
                assemble_program(self.raw,profile=profile)
            with self.subTest(document=profile),self.assertRaises(HIAProgramRejected):
                verify_program(self.doc,profile=profile)

    def test_old_global_opcode_and_effect_vocabularies_are_unchanged(self):
        from hepta.hia_opcodes import EFFECTS, OPCODES
        self.assertNotIn('linux_file',EFFECTS)
        self.assertFalse(set(FILE_OPCODES)&set(OPCODES))
        self.assertEqual(set(FILE_OPCODES),{'linux.file.open','linux.file.stat','linux.file.read',
                        'linux.file.close','linux.file.fdflags','linux.file.statusflags'})
        self.assertEqual(FILE_FLAGS,0xa0800)

    def test_file_extent_does_not_expand_source_image_or_vm_limits(self):
        self.assertEqual((SOURCE_LIMIT,OUTPUT_LIMIT,WORKSPACE_LIMIT),(1048576,8388609,1048576))
        self.assertEqual((FUNCTION_LIMIT,BLOCK_LIMIT,INSTRUCTION_LIMIT),(128,1536,8192))
        touched=[]
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.checked,'f0',(b'',b'',b''),profile=PROFILE,
                linux_file_provider=lambda q:touched.append(q),linux_process_startup=LinuxStartupSnapshot((),()),max_steps=10000001)
        self.assertEqual(touched,[])

    def test_verified_bytes_are_rechecked_and_not_core_authority(self):
        bad=copy.deepcopy(self.doc);bad['module']='not_'+MODULE
        forged=VerifiedLinuxFileProgram(json.dumps(bad).encode())
        with self.assertRaises(HIAProgramRejected):verify_program(forged,profile=PROFILE)
        with self.assertRaises(HIAProgramRejected):verify_program(self.checked)
        with self.assertRaises(HIAProgramRejected):VerifiedLinuxFileProgram(bytearray(self.checked.canonical_bytes)).as_dict()

    def test_file_effect_cannot_be_omitted(self):
        doc=copy.deepcopy(self.doc)
        for fn in doc['functions']:fn['effects']=[x for x in fn['effects'] if x!='linux_file']
        with self.assertRaises(HIAProgramRejected):verify_program(doc,profile=PROFILE)

    def test_wrong_return_type_and_extra_descriptor_operand_refuse(self):
        for mutation in ('result','descriptor'):
            doc=copy.deepcopy(self.doc)
            op=next(op for f in doc['functions'] for b in f['blocks'] for op in b['ops'] if op['op']=='linux.file.read')
            if mutation=='result':op['out'][0]['type']='u64'
            else:op['args'].append(op['args'][1])
            with self.subTest(mutation=mutation),self.assertRaises(HIAProgramRejected):verify_program(doc,profile=PROFILE)

    def test_mutating_file_effect_requires_mutable_borrow(self):
        # A one-block public input isolates the typed borrow. The full reader's
        # loop carries its borrow through SSA block parameters, so its current
        # operand name need not equal the function's entry parameter name.
        source='''hia-asm.v1 hepta.hia.program.v8 selfhost_linux_file
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(write,trap,linux_file) entry(b0)
block b0(s:readbuf,o:mutbuf,w:mutbuf)
  z:usize = const() {"value":0}
  r:i64 = linux.file.read(o,z,z)
  x:u32 = const() {"value":0}
  ret(x)
end
'''
        assemble_program(source,profile=PROFILE)
        with self.assertRaises(HIAProgramRejected):
            assemble_program(source.replace('linux.file.read(o,','linux.file.read(s,'),profile=PROFILE)

    def test_default_or_old_provider_is_not_file_authority(self):
        touched=[]
        provider=lambda q:touched.append(q)
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.checked,'f0',(b'',b'',b''),linux_file_provider=provider)
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.checked,'f0',(b'',b'',b''),profile=PROFILE,
                linux_process_provider=provider,linux_process_startup=LinuxStartupSnapshot((),()))
        self.assertEqual(touched,[])

    def test_finite_file_effects_do_not_import_an_os_provider(self):
        import ast
        text=(ROOT/'hepta/hia_linux_file.py').read_text();tree=ast.parse(text)
        imports=[n for n in ast.walk(tree) if isinstance(n,(ast.Import,ast.ImportFrom))]
        for n in imports:
            names=[a.name for a in n.names]+[getattr(n,'module','') or '']
            self.assertFalse({'os','subprocess','ctypes','fcntl'}&set(names))
        self.assertIn('explicit_effect_provider',text)
        self.assertIn('self.file_fd = None',text)

    def test_exact_three_resources_exist_and_unknown_resource_refuses(self):
        from hepta.hia_linux_file import profile_resource_path
        self.assertEqual(PROFILE_SOURCE_FILES,(
            'examples/hia_bootstrap/selfhost_linux_file.hepta',
            'examples/hia_bootstrap/linux_file_entry_packer.hepta',
            'examples/hia_bootstrap/native_file_read.hepta'))
        for path in PROFILE_SOURCE_FILES:
            self.assertEqual(profile_resource_path(path).read_bytes(),(ROOT/path).read_bytes())
        with self.assertRaises(ValueError):profile_resource_path('examples/hia_bootstrap/selfhost.hepta')

    def test_three_generated_sources_keep_original_compiler_budgets(self):
        from tools.generate_hia_selfhost_linux_file import extension_source,build
        from tools.generate_hia_linux_file_entry import generated as packer
        from tools.generate_hia_native_file_read import generated as reader
        text,proof=extension_source();compiler,_,report=build(text,True)
        self.assertEqual((ROOT/PROFILE_SOURCE_FILES[0]).read_text(),compiler)
        self.assertEqual((ROOT/PROFILE_SOURCE_FILES[1]).read_text(),packer())
        self.assertEqual((ROOT/PROFILE_SOURCE_FILES[2]).read_text(),reader())
        self.assertEqual(proof['new_profile_values'],[0,4,6])
        self.assertLessEqual(report['counts']['functions'],128)
        self.assertLessEqual(report['counts']['blocks'],1536)
        self.assertLessEqual(report['counts']['operations'],8192)


if __name__=='__main__':unittest.main()
