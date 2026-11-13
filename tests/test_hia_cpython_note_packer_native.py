"""Permanent independent controls for the HIA-produced hosted CPython mechanism.

GNU assembly/C are independent test references only. Production code bytes
come from the admitted HIA packer. These controls do not qualify physical
recursion, complete normalization, or a standalone HIA runtime.
"""
from __future__ import annotations
import ast
import ctypes
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import patch
import weakref

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program_normalization_notes import NativeCPythonNotes
# Load the source-owned sibling under its normal unittest module name.
# This also works when tests/ is not an installed Python package.
_support_name = 'test_hia_program_normalization_native'
_support_path = Path(__file__).with_name(_support_name + '.py').resolve()
if _support_name in sys.modules:
    _support = sys.modules[_support_name]
    if Path(_support.__file__).resolve() != _support_path:
        raise RuntimeError('normalization test-support module identity differs')
else:
    _spec = importlib.util.spec_from_file_location(_support_name, _support_path)
    _support = importlib.util.module_from_spec(_spec)
    sys.modules[_support_name] = _support
    _spec.loader.exec_module(_support)
ROOT = _support.ROOT
_native_fixture, _native_teardown = _support._native_fixture, _support._native_teardown
digest, encoded, put, retained_fixture = _support.digest, _support.encoded, _support.put, _support.retained_fixture

SOURCE = ROOT / 'examples/hia_bootstrap/cpython_note_packer.hepta'
REFERENCE_ASSEMBLY = ROOT / 'tools/hia_cpython_note_packer_reference.S'
REFERENCE_LINKER = ROOT / 'tools/hia_cpython_note_packer_reference.ld'
EXPECTED_SHA256 = 'd1ed5ac60b3d84952157262d6ea4252cbe4346c38417281945af636f5deacf23'
EXPECTED_BYTES = 298


def _definitions(source, wanted=None, namespace=None, exclude=()):
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))
             and (wanted is None or node.name in wanted) and node.name not in exclude]
    if wanted is not None and {node.name for node in nodes} != set(wanted):
        raise AssertionError('retained note control inventory differs')
    result = {'__name__':'__main__','sys':sys,'json':json,'weakref':weakref,
              'Path':Path,'digest':digest,'struct':struct}
    if namespace:
        result.update(namespace)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'retained-note-controls','exec'),result)
    return result


def elf_image(raw):
    # The original independent section parser is retained byte-for-byte.
    fixture = retained_fixture()
    helper = _definitions(fixture['sources']['flat_cpython_notes_r7.py']['text'],
                          {'elf_sections'})
    if struct.unpack_from('<H',raw,16)[0] != 2 or struct.unpack_from('<Q',raw,24)[0] != 0:
        raise AssertionError('reference is not an entry-zero linked ELF')
    sections = helper['elf_sections'](raw)
    allocated = [row for row in sections if row['flags']&2 and row['bytes']]
    if (len(allocated)!=1 or allocated[0]['name']!='.text'
            or allocated[0]['address']!=0):
        raise AssertionError('reference flat section layout differs')
    return allocated[0]['data']


def vm_emit(source, capacity):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    # Directly observe the retained Core interpreter's three-buffer ABI. A
    # synthetic assembly wrapper returning every byte would exceed its
    # unchanged 256-item assembly-list admission limit for this 298-byte
    # output; it is neither necessary nor a reason to raise that limit.
    with patch.dict(os.environ,{key:'' for key in os.environ if key.startswith('HEPTA_HIA_')}):
        program=assemble_program(SOURCE.read_bytes())
    machine=_Machine(program,3_000_000,1<<20,None,256)
    input_owner=_Owner(1,bytearray(source))
    output_owner=_Owner(2,bytearray([0xa5])*capacity)
    workspace_owner=_Owner(3,bytearray([0xa5])*16)
    returned=machine.invoke(machine.functions['f0'],
        [_View(input_owner,False),_View(output_owner,True),_View(workspace_owner,True)])
    if len(returned)!=1 or bytes(input_owner.data)!=source or workspace_owner.data!=bytearray([0xa5])*16:
        raise AssertionError('independent Core note emitter changed its fixed ABI')
    return returned[0],bytes(output_owner.data)


def actual_emit(image, source, capacity):
    initial=bytes([0xa5])*(capacity+16)
    wire=ctypes.create_string_buffer(b'\x6b'*8+source+b'\x6b'*8)
    output=ctypes.create_string_buffer(initial,len(initial))
    work=ctypes.create_string_buffer(b'\x6b'*32,32)
    source_before=bytes(wire);work_before=bytes(work)
    result=image._entry(ctypes.addressof(wire)+8,len(source),
                        ctypes.addressof(output)+8,capacity,
                        ctypes.addressof(work)+8,16)
    if bytes(wire)!=source_before or bytes(work)!=work_before:
        raise AssertionError('native note packer changed source/workspace')
    observed=bytes(output)
    if observed[:8]!=initial[:8] or observed[-8:]!=initial[-8:]:
        raise AssertionError('native note packer crossed declared output')
    return result,observed[8:8+capacity]


class CPythonNotePackerSourceTests(unittest.TestCase):
    def test_HIA_source_regenerates_and_has_no_runtime_import(self):
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from tools.generate_hia_cpython_note_packer import document,reference_image
        document_=document()
        self.assertEqual(render_assembly(document_).encode('utf-8'),SOURCE.read_bytes())
        self.assertEqual(len(reference_image()),EXPECTED_BYTES)
        self.assertEqual(digest(reference_image()),EXPECTED_SHA256)
        self.assertEqual(len(document_['functions']),2)
        assembled=assemble_program(SOURCE.read_bytes()).as_dict()
        self.assertEqual(assembled['module'],'cpython_note_packer')
        for function in assembled['functions']:
            self.assertLessEqual(len(function['blocks']),256)
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']),16)

    def test_independent_Core_VM_complete_emission_and_refusal_precedence(self):
        from tools.generate_hia_cpython_note_packer import reference_image
        image=reference_image()
        for name,raw,capacity,status in (
                ('exact',b'',298,298),('short',b'',297,0xfffffffe),
                ('nonempty',b'x',298,0xffffffff),('precedence',b'x',0,0xffffffff),
                ('zero-output',b'',0,0xfffffffe),('tail',b'',306,298)):
            with self.subTest(case=name):
                result,output=vm_emit(raw,capacity)
                self.assertEqual(result,status)
                expected=image+bytes([0xa5])*(capacity-len(image)) if status==298 else bytes([0xa5])*capacity
                self.assertEqual(output,expected)


class CPythonNotePackerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _native_fixture(cls)

    @classmethod
    def tearDownClass(cls):
        _native_teardown(cls)

    def _command(self,name,command):
        result=subprocess.run(command,capture_output=True,timeout=30)
        put(self.folder/(name+'.stdout'),result.stdout)
        put(self.folder/(name+'.stderr'),result.stderr)
        self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))

    def test_independent_assembler_VM_and_actual_HIA_packer_complete_bytes(self):
        assembler,linker=shutil.which('as'),shutil.which('ld')
        self.assertIsNotNone(assembler,'independent GNU assembler is required')
        self.assertIsNotNone(linker,'independent GNU linker is required')
        assembler,linker=Path(assembler).resolve(strict=True),Path(linker).resolve(strict=True)
        inputs={path:path.read_bytes() for path in (assembler,linker,REFERENCE_ASSEMBLY,REFERENCE_LINKER,SOURCE)}
        obj,elf=self.folder/'note-reference.o',self.folder/'note-reference.elf'
        self._command('reference-assemble',[str(assembler),'--64',str(REFERENCE_ASSEMBLY),'-o',str(obj)])
        self._command('reference-link',[str(linker),'-nostdlib','-T',str(REFERENCE_LINKER),'-o',str(elf),str(obj)])
        reference=elf_image(elf.read_bytes())
        self.assertEqual(len(reference),EXPECTED_BYTES)
        self.assertEqual(digest(reference),EXPECTED_SHA256)
        note=self.metadata['hosted_mechanisms']['cpython_notes']
        actual_note=(self.manifest.parent/note['image_path']).read_bytes()
        self.assertEqual(actual_note,reference)
        declaration=note['production']
        packer=(self.manifest.parent/declaration['packer_image_path']).read_bytes()
        machine=NativeHiaJsonImage(packer,declaration['packer_image_sha256'])
        try:
            for name,raw,capacity,status in (
                    ('exact',b'',298,298),('short',b'',297,0xfffffffe),
                    ('nonempty',b'x',298,0xffffffff),('precedence',b'x',0,0xffffffff),
                    ('zero-output',b'',0,0xfffffffe),('tail',b'',306,298)):
                with self.subTest(case=name):
                    vm=vm_emit(raw,capacity)
                    actual=actual_emit(machine,raw,capacity)
                    expected=reference+bytes([0xa5])*(capacity-298) if status==298 else bytes([0xa5])*capacity
                    self.assertEqual(vm,(status,expected))
                    self.assertEqual(actual,(status,expected))
                    self.observations.append({'case':'independent-packer-'+name,
                        'actual_return':actual[0],'output_sha256':digest(actual[1]),
                        'VM_equal':True,'assembler_equal':True,'guards_unchanged':True})
        finally:
            machine._entry=None
            machine._mapping.close()
        for path,raw in inputs.items():self.assertEqual(path.read_bytes(),raw,str(path))

    def test_original_35_hosted_mechanism_controls_on_HIA_produced_bytes(self):
        fixture=retained_fixture()
        files=self.folder/'retained-references';files.mkdir(mode=0o700)
        for name in ('probe_cpython314_notes_r1.py','probe_cpython314_note_context_r2.py'):
            put(files/'helpers'/name,fixture['sources'][name]['text'].encode('utf-8'))
        # The old reference bridge and fixed C implementation remain a
        # sensitive lifetime negative control, never a production dependency.
        original=files/'evidence/flat-cpython-notes-r1'
        old_bridge=original/'source/hepta/hia_program_normalization_notes.py'
        put(old_bridge,fixture['sources']['original_flat_note_bridge_r1.py']['text'].encode('utf-8'))
        old_c=original/'note.c';old_ld=original/'note.ld'
        put(old_c,fixture['sources']['original_flat_note_r1.c']['text'].encode('utf-8'))
        put(old_ld,fixture['sources']['original_flat_note_r1.ld']['text'].encode('utf-8'))
        cc,ld=shutil.which('cc'),shutil.which('ld')
        self.assertIsNotNone(cc,'independent historical C negative-control compiler required')
        self.assertIsNotNone(ld,'independent historical negative-control linker required')
        cc,ld=Path(cc).resolve(strict=True),Path(ld).resolve(strict=True)
        tools_before={path:path.read_bytes() for path in (cc,ld)}
        obj,elf=original/'note.o',original/'note.elf'
        self._command('old-reference-compile',[str(cc),'-std=c11','-c','-Os','-fPIC','-ffreestanding',
            '-fno-builtin','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables',
            '-fno-ident','-fcf-protection=none','-march=x86-64','-mtune=generic','-Wall','-Wextra',
            str(old_c),'-o',str(obj)])
        self._command('old-reference-link',[str(ld),'-nostdlib','-T',str(old_ld),'-o',str(elf),str(obj)])
        old_image=elf_image(elf.read_bytes())
        self.assertEqual(digest(old_image),'e82fd51964ce25990f24e723fb0b3270b2e8b69c7fdc2e1b3999648df070db61')
        put(original/'note.image.bin',old_image)
        note=self.metadata['hosted_mechanisms']['cpython_notes']
        image=self.manifest.parent/note['image_path'];raw_image=image.read_bytes()
        self.assertEqual(digest(raw_image),EXPECTED_SHA256)
        module=NativeCPythonNotes(raw_image,digest(raw_image))
        report={'observations':[]}
        source=fixture['sources']['flat_cpython_notes_r7.py']['text']
        wanted={'load_definitions','mapping','deliver_observation','invalid_delivery_control',
                'invalid_c_delivery_fields','delivery_negative','replacement_lifetime',
                'replacement_lifetime_control'}
        namespace=_definitions(source,wanted,{
            'ROOT':files,'BASE':ROOT,'CASE':self.folder,'Path':Path,'ctypes':ctypes,
            'importlib':importlib,'subprocess':subprocess,'os':os,
            'inputs':{},'module':module,'image':image,'raw_image':raw_image,
            'bridge':ROOT/'hepta/hia_program_normalization_notes.py',
            'put':put,'report':report})
        begin=source.index('    code_map=mapping(module._code_address)')
        end=source.index('    report["status"]="PASS_FLAT_HOSTED_NOTE_AND_DELIVERY_MECHANISM_ONLY"',begin)
        block='if True:\n'+source[begin:end]
        try:
            exec(compile(block,'retained-note-35','exec'),namespace)
        finally:
            self.observations.extend(report['observations'])
            if not module.closed:module.close()
        self.assertEqual(len(report['observations']),35)
        for path,raw in tools_before.items():self.assertEqual(path.read_bytes(),raw,str(path))


if __name__=='__main__':
    unittest.main()
