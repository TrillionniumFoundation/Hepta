"""Unsigned scalar calls require fresh proof and the shared sealed-image loader."""
from __future__ import annotations

from copy import deepcopy
import ctypes
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_verified_kernel_load as loader
from hepta.elf_shared_abi import ELFSharedABIRejected
from hepta.hia_safe_core import SafeCoreRejected
from hepta.hia_safe_core_elf import _ELF
from hepta.hia_verified_scalar import build_verified_scalar, emit_verified_scalar
from tests.test_hia_program import arithmetic, b, c, f, ret
from tests.test_hia_verified_scalar import AVAILABLE


ROOT = Path(__file__).resolve().parents[1]
WIDTHS = {'bool': 1, 'u8': 8, 'u16': 16, 'u32': 32, 'u64': 64, 'usize': 64}


def identity_core(typ, count=1):
    params = [(f'value{index}', typ) for index in range(count)]
    return {'schema': 'hepta.hia.program.v8', 'module': 'scalar_identity', 'functions': [
        f('calculate', params, [typ], [], [b('entry', params, [], ret('value0'))])]}


def constant_core(count=0):
    params = [(f'ignored{index}', 'u64') for index in range(count)]
    return {'schema': 'hepta.hia.program.v8', 'module': 'scalar_constant', 'functions': [
        f('calculate', params, ['u64'], [], [b('entry', params, [c('answer', 'u64', 7)], ret('answer'))])]}


@unittest.skipUnless(AVAILABLE and hasattr(os, 'memfd_create') and hasattr(os, 'MFD_ALLOW_SEALING'),
                     'Linux x86-64, GNU ld, pinned Z3 and sealed memfds are required')
class VerifiedScalarLoadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='hia-scalar-load-')
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.cases = {}
        for name, core in ([(typ, identity_core(typ)) for typ in WIDTHS] +
                           [('constant', constant_core()),
                            ('checked', arithmetic('int.add.checked', 'u8'))]):
            image = emit_verified_scalar(core)
            final = cls.root / (name + '.so')
            build_verified_scalar(core, final, image=image)
            obj = cls.root / (name + '.o')
            obj.write_bytes(image.object_bytes)
            document = cls.root / (name + '.json')
            document.write_text(json.dumps(core))
            cls.cases[name] = (core, image.object_bytes, final.read_bytes(), document, obj, final)

    def load(self, name='u64'):
        return loader.load_verified_scalar_kernel(*self.cases[name][:3])

    @staticmethod
    def key(loaded):
        return (loaded.image_sha256, 'calculate',
                ('scalar-safe-core-v2', loaded.parameter_types, loaded.return_type))

    def child(self, script, *args, timeout=45):
        return subprocess.run([sys.executable, '-B', '-c', script, *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=timeout)

    def test_actual_mapped_unsigned_calls_normalize_dirty_argument_high_bits(self):
        for typ, width in WIDTHS.items():
            with self.subTest(type=typ):
                loaded = self.load(typ)
                self.assertEqual(loaded.parameter_types, (typ,))
                self.assertEqual(loaded.return_type, typ)
                self.assertEqual(loaded.function.argtypes, [ctypes.c_uint64])
                self.assertIs(loaded.function.restype, ctypes.c_uint64)
                self.assertFalse(loaded.validation['checker']['producer_reemission_used'])
                self.assertEqual(loaded.validation['image_binding']['function_shape'], 'direct_entry')
                self.assertTrue(loaded.mapping_admission['sealed_image_and_loaded_symbol_bound'])
                self.assertEqual(loaded.mapping_admission['permissions'], 'r-xp')
                self.assertEqual(loaded.mapping_admission['mapped_text_sha256'],
                                 loaded.validation['image_binding']['linked_text_sha256'])
                for word in (0, 1, 2, 255, 0xFEDCBA9876543210, (1 << 64) - 1):
                    self.assertEqual(loaded.function(word), word & ((1 << width) - 1))

    def test_same_image_zero_and_six_word_abis_have_separate_cache_entries(self):
        first = self.load('constant')
        _, obj, final, _, _, _ = self.cases['constant']
        second = loader.load_verified_scalar_kernel(constant_core(6), obj, final)
        self.assertEqual(first.image_sha256, second.image_sha256)
        self.assertEqual(first.function.argtypes, [])
        self.assertEqual(second.function.argtypes, [ctypes.c_uint64] * 6)
        self.assertEqual(first.function(), 7)
        self.assertEqual(second.function(1, 2, 3, 4, 5, 6), 7)
        self.assertNotEqual(self.key(first), self.key(second))
        self.assertIn(self.key(first), loader._IMAGES)
        self.assertIn(self.key(second), loader._IMAGES)
        self.assertNotEqual(loader._IMAGES[self.key(first)]['fd'], loader._IMAGES[self.key(second)]['fd'])

    def test_cached_image_gets_a_fresh_callable_after_caller_abi_pollution(self):
        first = self.load()
        first.function.argtypes = [ctypes.c_void_p] * 6
        first.function.restype = ctypes.c_uint8
        second = self.load()
        self.assertIsNot(first.function, second.function)
        self.assertEqual(second.function.argtypes, [ctypes.c_uint64])
        self.assertIs(second.function.restype, ctypes.c_uint64)
        self.assertEqual(second.function(0x123456789ABCDEF0), 0x123456789ABCDEF0)
        self.assertEqual(first.function.argtypes, [ctypes.c_void_p] * 6)
        self.assertIs(first.function.restype, ctypes.c_uint8)

    def test_cached_image_is_reproved_and_hot_calls_have_no_solver_or_probe(self):
        old = self.load()
        old.validation['profile'] = 'caller-edited-receipt'
        old.validation['claims'].clear()
        old.cpu_admission['common_features'] = []
        proof = loader.validate_safe_core_artifact
        admit = loader.require_host_isa
        with patch.object(loader, 'validate_safe_core_artifact', wraps=proof) as proved, \
                patch.object(loader, 'require_host_isa', wraps=admit) as probed:
            loaded = self.load()
            proved.assert_called_once()
            self.assertEqual(proved.call_args.kwargs['profile_version'], 2)
            probed.assert_called_once_with([], 0)
            for value in (0, 65536, (1 << 64) - 1):
                self.assertEqual(loaded.function(value), value)
            proved.assert_called_once()
            probed.assert_called_once()
        core, obj, final, _, _, _ = self.cases['u64']
        for receipt in (old.validation, old.cpu_admission):
            with self.assertRaises(loader.VerifiedKernelLoadRejected):
                loader.load_verified_scalar_kernel(core, receipt, final)
        with self.assertRaises(ValueError):
            loader.load_verified_scalar_kernel(old.validation, obj, final)

    def test_scalar_mapping_is_sealed_against_content_and_length_changes(self):
        loaded = self.load()
        entry = loader._IMAGES[self.key(loaded)]
        descriptor = entry['fd']
        self.assertEqual(fcntl.fcntl(descriptor, loader.F_GET_SEALS) & loader.IMAGE_SEALS,
                         loader.IMAGE_SEALS)
        for action in (lambda: os.pwrite(descriptor, b'X', 0),
                       lambda: os.ftruncate(descriptor, entry['bytes'] - 1),
                       lambda: os.ftruncate(descriptor, entry['bytes'] + 1)):
            with self.assertRaises(OSError) as caught:
                action()
            self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assertEqual(sha256(os.pread(descriptor, entry['bytes'], 0)).hexdigest(),
                         loaded.image_sha256)
        self.assertEqual(loaded.function(1234), 1234)

    def test_borrowed_signed_many_word_and_multifunction_scopes_are_refused_before_proof(self):
        from tests.test_hia_safe_core import read_byte
        multiple = identity_core('u64')
        other = deepcopy(multiple['functions'][0])
        other['name'] = 'other'
        multiple['functions'].append(other)
        _, obj, final, _, _, _ = self.cases['u64']
        cases = (read_byte(), identity_core('i64'), identity_core('u64', 7), multiple)
        for document in cases:
            with self.subTest(document=document['module']), \
                    patch.object(loader, 'validate_safe_core_artifact',
                                 side_effect=AssertionError('unadmitted ABI reached proof')), \
                    self.assertRaises(loader.VerifiedKernelLoadRejected):
                loader.load_verified_scalar_kernel(document, obj, final)

    def test_ordinary_safe_core_wrapper_is_not_loaded_as_a_direct_scalar_entry(self):
        from hepta.hia_program import verify_program
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        core = verify_program(identity_core('u64'))
        image = emit_program_machine(core)
        path = self.root / 'ordinary-wrapper.so'
        compile_program_machine(image, program=core, output=path, linker='ld')
        with patch.object(loader.os, 'memfd_create', side_effect=AssertionError('wrapper reached mapping')):
            with self.assertRaisesRegex(loader.VerifiedKernelLoadRejected, 'direct scalar entry'):
                loader.load_verified_scalar_kernel(core, image.object_bytes, path.read_bytes())

    def test_failed_or_incomplete_proof_never_switches_profile_or_maps(self):
        for ok, complete in ((False, True), (True, False), (1, True), (True, 1)):
            with self.subTest(ok=ok, complete=complete), \
                    patch.object(loader, 'validate_safe_core_artifact',
                                 return_value={'ok': ok, 'complete': complete,
                                               'profile': loader.ARTIFACT_PROFILE_V2}), \
                    patch.object(loader, 'validate_verified_simd_artifact',
                                 side_effect=AssertionError('scalar failure switched profile')), \
                    patch.object(loader.os, 'memfd_create', side_effect=AssertionError('failed proof mapped')):
                with self.assertRaisesRegex(loader.VerifiedKernelLoadRejected, 'did not complete'):
                    self.load()

    def test_semantically_wrong_matching_object_and_final_bytes_are_refuted_before_mapping(self):
        core, obj, final, _, _, _ = self.cases['u64']
        wrong = []
        for data, kind in ((obj, 1), (final, 3)):
            text = _ELF(data, kind).section('.text', 1)
            self.assertEqual(text['data'][:3], b'\x48\x89\xf8')
            changed = bytearray(data)
            changed[text['offset'] + 2] = 0xF0  # mov rax,rsi instead of the input rdi
            wrong.append(bytes(changed))
        with patch.object(loader.os, 'memfd_create', side_effect=AssertionError('wrong machine mapped')), \
                patch.object(loader, 'validate_verified_simd_artifact',
                             side_effect=AssertionError('failed proof switched profile')):
            with self.assertRaises(SafeCoreRejected) as caught:
                loader.load_verified_scalar_kernel(core, *wrong)
        self.assertEqual(caught.exception.counterexample['obligation'],
                         'core_to_final_image_return_abort_and_caller_bytes')

    def test_ifunc_export_is_refused_before_any_mapping(self):
        core, obj, final, _, _, _ = self.cases['u64']
        wrong = bytearray(final)
        parsed = _ELF(final, 3)
        for name in ('.symtab', '.dynsym'):
            table = parsed.section(name)
            for index, symbol in enumerate(parsed.symbols(name)):
                if symbol['name'] == 'calculate':
                    wrong[table['offset'] + index * 24 + 4] = (symbol['info'] & 0xF0) | 10
        with patch.object(loader.os, 'memfd_create', side_effect=AssertionError('IFUNC reached mapping')):
            with self.assertRaises(ELFSharedABIRejected):
                loader.load_verified_scalar_kernel(core, obj, bytes(wrong))

    def test_loading_in_a_fresh_process_never_imports_a_producer(self):
        script = r'''
import importlib.abc, json, sys
from pathlib import Path
blocked = {'hepta.hia_verified_scalar', 'hepta.hia_verified_simd', 'hepta.hia_verified_simd_wide',
           'hepta.hia_program_native', 'hepta.hia_machine_x64', 'hepta.hia_machine_elf'}
class RejectProducer(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError('producer import during fresh scalar admission: ' + fullname)
sys.meta_path.insert(0, RejectProducer())
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
core = json.loads(Path(sys.argv[1]).read_text())
loaded = load_verified_scalar_kernel(core, Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes())
assert loaded.function(0x123456789abcdef0) == 0x123456789abcdef0
assert not blocked.intersection(sys.modules)
print(json.dumps({'fresh_independent_load': True, 'producer_imported': False}))
'''
        result = self.child(script, *self.cases['u64'][3:])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'fresh_independent_load': True, 'producer_imported': False})

    def test_checked_overflow_preserves_actual_nonreturning_abort(self):
        loaded = self.load('checked')
        self.assertEqual(loaded.function(0xFFFFFFFFFFFFFF00, 1), 1)
        self.assertEqual(loaded.function(254, 1), 255)
        script = r'''
import json, resource, sys
from pathlib import Path
from hepta.hia_verified_kernel_load import load_verified_scalar_kernel
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
loaded = load_verified_scalar_kernel(json.loads(Path(sys.argv[1]).read_text()),
                                     Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes())
assert loaded.function(254, 1) == 255
loaded.function(255, 1)
raise AssertionError('checked overflow returned')
'''
        result = self.child(script, *self.cases['checked'][3:])
        self.assertEqual(result.returncode, -signal.SIGABRT, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required for the isolated GNU IFUNC control')
    def test_cached_ifunc_resolver_is_never_executed_by_scalar_admission(self):
        marker = self.root / 'scalar-ifunc-resolver-executed'
        source = self.root / 'scalar-ifunc-cache.c'
        library = source.with_suffix('.so')
        source.write_text(r'''
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
typedef uint64_t (*kernel_t)(uint64_t);
static uint64_t implementation(uint64_t value) { return value; }
static kernel_t resolve(void) {
  int fd = open(MARKER, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd >= 0) { (void)write(fd, "resolver", 8); close(fd); }
  return implementation;
}
uint64_t calculate(uint64_t) __attribute__((ifunc("resolve")));
uint64_t forward_to_calculate(uint64_t value) { return calculate(value); }
'''.replace('MARKER', json.dumps(str(marker))))
        built = subprocess.run(['cc', '-shared', '-fPIC', '-Wl,-z,lazy', str(source), '-o', str(library)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        script = r'''
import ctypes, json, os, sys
from pathlib import Path
from unittest.mock import patch
from hepta import hia_verified_kernel_load as loader
old_bytes = Path(sys.argv[1]).read_bytes()
core = json.loads(Path(sys.argv[2]).read_text())
object_bytes, final_bytes = (Path(p).read_bytes() for p in sys.argv[3:5])
marker = Path(sys.argv[5]); assert not marker.exists()
system = ctypes.CDLL(None)
opening = system['dlopen']; opening.argtypes = (ctypes.c_char_p, ctypes.c_int); opening.restype = ctypes.c_void_p
closing = system['dlclose']; closing.argtypes = (ctypes.c_void_p,); closing.restype = ctypes.c_int
created, old_handles = [], []
original_create = os.memfd_create
def create(*args, **kwargs):
    old_fd = original_create('unrelated-scalar-lazy-ifunc')
    os.write(old_fd, old_bytes)
    path = '/proc/' + str(os.getpid()) + '/fd/' + str(old_fd)
    handle = opening(os.fsencode(path), os.RTLD_LOCAL | os.RTLD_LAZY)
    assert handle and not marker.exists()
    old_handles.append(handle)
    os.close(old_fd)
    next_fd = original_create(*args, **kwargs)
    assert next_fd == old_fd, (old_fd, next_fd)
    created.append(next_fd)
    return next_fd
try:
    with patch.object(loader.os, 'memfd_create', side_effect=create):
        loader.load_verified_scalar_kernel(core, object_bytes, final_bytes)
except loader.VerifiedKernelLoadRejected as error:
    assert 'cached object' in str(error), str(error)
else:
    raise AssertionError('cached IFUNC object escaped scalar admission')
assert len(created) == len(old_handles) == 1
assert not marker.exists(), 'unverified IFUNC resolver ran before rejection'
assert not loader._IMAGES and loader._TOTAL_BYTES == 0
try:
    os.fstat(created[0])
except OSError:
    pass
else:
    raise AssertionError('failed IFUNC admission leaked its descriptor')
assert closing(old_handles[0]) == 0 and not marker.exists()
print(json.dumps({'cached_ifunc_rejected': True, 'resolver_executed': False}))
'''
        result = self.child(script, library, *self.cases['u64'][3:], marker)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'cached_ifunc_rejected': True, 'resolver_executed': False})
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
