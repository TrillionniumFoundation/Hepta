"""Clang-compiled ELF64 positive, negative, mutation, and bounded parser tests."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from hepta.elf_shared_abi import inspect_owned_shared_elf, ELFSharedABIRejected


def _u(buf: bytes, pos: int, size: int) -> int:
    return int.from_bytes(buf[pos:pos + size], 'little')


def _set(buf: bytes, pos: int, size: int, value: int) -> bytes:
    result = bytearray(buf)
    result[pos:pos + size] = value.to_bytes(size, 'little')
    return bytes(result)


def _sections(buf: bytes):
    at, count = _u(buf, 40, 8), _u(buf, 60, 2)
    return [at + 64*i for i in range(count)]


def _symtab(buf: bytes):
    sections = _sections(buf)
    for sec in sections:
        if _u(buf, sec + 4, 4) == 11:
            linked = _u(buf, sec + 40, 4)
            return _u(buf, sec + 24, 8), _u(buf, sec + 32, 8), sections[linked]
    raise AssertionError('no dynsym')


def _symbol(buf: bytes, target: str) -> tuple[int, int]:
    start, size, string_section = _symtab(buf)
    strings = _u(buf, string_section + 24, 8)
    for pos in range(start, start + size, 24):
        name_at = strings + _u(buf, pos, 4)
        if buf[name_at:buf.find(b'\0',name_at)].decode('ascii') == target:
            return pos, strings
    raise AssertionError('symbol not found: '+target)


@unittest.skipUnless(shutil.which('clang'), 'native Clang is required')
class SharedELFTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)

    def compile(self, text: str, name='lib.so') -> bytes:
        source, binary = self.root / (name+'.c'), self.root / name
        source.write_text(text)
        p = subprocess.run(['clang', '-fPIC','-shared','-O2',str(source),'-o',str(binary)],
                           capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        return binary.read_bytes()

    def assert_reject(self, data: bytes, exports=('foo',)):
        with self.assertRaises(ELFSharedABIRejected):
            inspect_owned_shared_elf(data, exports)

    def test_correct_abi_with_malloc_and_crt_imports(self):
        code = '#include <stdlib.h>\n__attribute__((visibility("default"))) int foo(int x) {void *p=malloc((size_t)x+1); if(!p) abort(); free(p); return x+7;}\n'
        data = self.compile(code)
        ok = inspect_owned_shared_elf(data, ('foo',))
        self.assertEqual(ok['dynamic_exports'], ['foo'])
        self.assertTrue(set(ok['unresolved_imports']) <= {'malloc','free','abort','memset','calloc','__cxa_finalize', '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', '__gmon_start__'})
        self.assertFalse(ok['claims']['backend_refinement_proven'])
        self.assert_reject(data,('bar',))

    def test_extra_function_and_extra_external_call_rejected(self):
        good = self.compile('int foo(int x) {return x+7;}\nint extra(int x) {return x+8;}\n','extra.so')
        self.assert_reject(good)
        foreign = self.compile('#include <stdio.h>\nint foo(int x) {puts("foreign");return x;}\n','foreign.so')
        self.assert_reject(foreign)

    def test_self_consistent_hostile_symbol_mutations_fail(self):
        data = self.compile('int foo(int x) {return x+7;}\n')
        pos, _ = _symbol(data, 'foo')
        sec = _sections(data)[_u(data, pos + 6, 2)]
        symbol_value = _u(data,pos+8,8)
        section_size = _u(data,sec+32,8)
        section_addr = _u(data,sec+16,8)
        tests = {
            'wrong symbol type': _set(data,pos+4,1,(_u(data,pos+4,1)&0xf0)|1),
            'beyond executable section': _set(data,pos+8,8,section_addr+section_size),
            'zero function length': _set(data,pos+16,8,0),
            'hidden function visibility': _set(data,pos+5,1,2),
            'non-executable section': _set(data,sec+8,8,_u(data,sec+8,8)&~4),
            'invalid dynamic symbol string': _set(data,pos,4,2**32-1),
        }
        self.assertGreaterEqual(symbol_value,section_addr)
        self.assertGreater(section_size,0)
        for reason, mutated in tests.items():
            with self.subTest(reason=reason):
                self.assert_reject(mutated)

    def test_executable_segment_is_mandatory(self):
        data=self.compile('int foo(int x) {return x+7;}\n')
        phoff, nph = _u(data,32,8), _u(data,56,2)
        found=False
        for i in range(nph):
            pos=phoff+56*i
            if _u(data,pos,4)==1 and _u(data,pos+4,4)&1:
                self.assert_reject(_set(data,pos+4,4,_u(data,pos+4,4)&~1))
                found=True
        self.assertTrue(found)

    def test_truncation_and_bad_tables_rejected(self):
        data=self.compile('int foo(int x) {return x+7;}\n')
        cases=[data[:30], _set(data,40,8,len(data)+800), _set(data,58,2,0),
               _set(data,16,2,1),_set(data,18,2,183),_set(data,54,2,0)]
        for mutated in cases:
            with self.subTest(length=len(mutated)):
                self.assert_reject(mutated)

    def test_loader_dynamic_metadata_and_dependency_are_binding(self):
        data=self.compile('int foo(int x){return x+7;}\n')
        phoff, nph = _u(data,32,8), _u(data,56,2)
        dynamic=None
        for i in range(nph):
            p=phoff+56*i
            if _u(data,p,4)==2:
                dynamic=(_u(data,p+8,8),_u(data,p+32,8))
        self.assertIsNotNone(dynamic)
        at, size=dynamic
        tags={}
        for i in range(at,at+size,16):
            tag=_u(data,i,8)
            if tag==0:break
            tags.setdefault(tag,i)
        self.assertIn(5,tags)
        self.assertIn(6,tags)
        self.assertIn(10,tags)
        self.assertIn(11,tags)
        for tag in (5,6,10,11):
            mutant=_set(data,tags[tag]+8,8,_u(data,tags[tag]+8,8)+1)
            with self.subTest(tag=tag):
                self.assert_reject(mutant)
        if 1 in tags:  # DT_NEEDED must refer only to reviewed libc runtime
            symoff,symsize,strsec = _symtab(data)
            stroff=_u(data,strsec+24,8)
            offset=_u(data,tags[1]+8,8)
            modified=bytearray(data)
            modified[stroff+offset:stroff+offset+4]=b'evil'
            self.assert_reject(bytes(modified))

    def test_duplicate_export_hidden_by_name_set_rejected(self):
        data=self.compile('int foo(int x){return x+7;}\nint bar(int x){return x+8;}\n','both.so')
        self.assertEqual(set(inspect_owned_shared_elf(data,('bar','foo'))['dynamic_exports']),{'bar','foo'})
        pos,strings=_symbol(data,'bar')
        name_offset=strings+_u(data,pos,4)
        forged=bytearray(data)
        forged[name_offset:name_offset+3]=b'foo'
        self.assert_reject(bytes(forged),('foo',))

    def test_empty_public_export_profile(self):
        data=self.compile('static int hidden(int x){return x+7;}\n','empty.so')
        result=inspect_owned_shared_elf(data,())
        self.assertEqual(result['dynamic_exports'],[])

if __name__=='__main__':unittest.main()
