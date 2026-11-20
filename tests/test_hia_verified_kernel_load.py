"""Fresh proof/CPU admission and exact sealed-image callable binding controls."""
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
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_verified_cpu import VerifiedCPURejected
from hepta.hia_verified_kernel import build_verified_kernel
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta import hia_verified_kernel_load as loader
from tests.test_hia_verified_simd import AVAILABLE


@unittest.skipUnless(AVAILABLE and hasattr(os, 'memfd_create') and hasattr(os, 'MFD_ALLOW_SEALING'),
                     'Linux x86-64, GNU ld, pinned Z3 and sealed memfds are required')
class VerifiedKernelLoadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-verified-load-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cases = {}
        for kind, export in (('sum_u8', 'calculate'), ('all_zero_u8', 'calculate'),
                             ('sum_u8', '_FuncPtr'), ('sum_u8', '__class__')):
            core = simd_kernel_program(kind, export)
            stem = kind + '-' + export
            final = cls.root / (stem + '.so')
            # Native functions used here have first passed the production
            # build's independent final-ELF checker and fresh CPU gate.
            build = build_verified_kernel(core, final, strategy='simd', simd_isa='sse2')
            image = emit_verified_simd(core, isa='sse2')
            obj = cls.root / (stem + '.o')
            obj.write_bytes(image.object_bytes)
            cls.cases[(kind, export)] = (core, image.object_bytes, final.read_bytes(), build, obj, final)

    def load(self, kind='sum_u8', export='calculate'):
        core, obj, final, _, _, _ = self.cases[(kind, export)]
        return loader.load_verified_simd_kernel(core, obj, final)

    def assert_sum(self, loaded):
        data = (ctypes.c_uint8 * 3)(255, 255, 7)
        self.assertEqual(loaded.function(data, 3, 3), 517)

    def test_python_member_export_names_resolve_the_checked_native_symbol(self):
        for export in ('_FuncPtr', '__class__'):
            with self.subTest(export=export):
                loaded = self.load(export=export)
                self.assertIsInstance(loaded.function, ctypes._CFuncPtr)
                self.assert_sum(loaded)
                mapping = loaded.mapping_admission
                self.assertTrue(mapping['sealed_image_and_loaded_symbol_bound'])
                self.assertEqual(mapping['permissions'], 'r-xp')
                self.assertEqual(mapping['mapped_text_sha256'],
                                 loaded.validation['image_binding']['linked_text_sha256'])

    def test_reused_image_receives_a_new_function_with_an_independent_abi(self):
        first = self.load()
        first.function.restype = ctypes.c_uint8
        first.function.argtypes = [ctypes.c_uint64]
        second = self.load()
        self.assertIsNot(first.function, second.function)
        self.assertIs(second.function.restype, ctypes.c_uint64)
        self.assertEqual(second.function.argtypes,
                         [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64])
        self.assert_sum(second)
        # A fresh load does not mutate the earlier caller's Python object.
        self.assertIs(first.function.restype, ctypes.c_uint8)
        self.assertEqual(first.function.argtypes, [ctypes.c_uint64])

    def test_sealed_mapping_rejects_byte_changes_and_size_changes(self):
        loaded = self.load()
        key = (loaded.image_sha256, 'calculate', 'sum_u8')
        entry = loader._IMAGES[key]
        fd = entry['fd']
        # Linux UAPI F_GET_SEALS=1024+10 and seals=1|2|4|8. Some Python
        # builds omit these names despite a kernel that implements them.
        required = 1 | 2 | 4 | 8
        self.assertEqual(fcntl.fcntl(fd, 1034) & required, required)
        for action in (lambda: os.pwrite(fd, b'X', 0),
                       lambda: os.ftruncate(fd, entry['bytes'] - 1),
                       lambda: os.ftruncate(fd, entry['bytes'] + 1)):
            with self.assertRaises(OSError) as caught:
                action()
            self.assertEqual(caught.exception.errno, errno.EPERM)
        self.assertEqual(sha256(os.pread(fd, entry['bytes'], 0)).hexdigest(), loaded.image_sha256)
        self.assert_sum(loaded)

    def test_cached_image_still_requires_a_fresh_cpu_probe(self):
        loaded = self.load()
        # Deliberately change old mutable receipt fields. They must never
        # supply requirements or authorize the next cached-image load.
        loaded.validation['required_cpu_features'] = []
        loaded.validation['required_xcr0_mask'] = 0
        loaded.cpu_admission['common_features'] = ['sse2', 'avx', 'avx2', 'avx512f', 'avx512bw']
        unsupported = deepcopy(loaded.cpu_admission)
        unsupported['common_features'] = []
        unsupported['common_xcr0'] = 0
        with patch('hepta.hia_verified_cpu.probe_host_isa', return_value=unsupported) as fresh:
            with self.assertRaisesRegex(VerifiedCPURejected, 'does not enable'):
                self.load()
            fresh.assert_called_once_with()
            # CPU admission has no hot-path probe, and a later failed load
            # must not invalidate an already admitted mapping.
            self.assert_sum(loaded)
            fresh.assert_called_once_with()
        self.assert_sum(self.load())

    def test_cached_image_is_proved_again_and_receipts_are_not_proof_inputs(self):
        loaded = self.load()
        original = loader.validate_verified_simd_artifact
        with patch.object(loader, 'validate_verified_simd_artifact', wraps=original) as prove:
            self.assert_sum(self.load())
            prove.assert_called_once()
        core, obj, final, build, _, _ = self.cases[('sum_u8', 'calculate')]
        for old_receipt in (loaded.validation, loaded.cpu_admission, build):
            with self.subTest(receipt=old_receipt.get('schema')):
                with self.assertRaises(loader.VerifiedKernelLoadRejected):
                    loader.load_verified_simd_kernel(core, old_receipt, final)
                with self.assertRaises(ValueError):
                    loader.load_verified_simd_kernel(old_receipt, obj, final)

    def test_wrong_loader_handle_is_rejected_by_actual_mapping_identity(self):
        correct = self.load()
        wrong = self.load(kind='all_zero_u8')
        correct_entry = loader._IMAGES[(correct.image_sha256, 'calculate', 'sum_u8')]
        wrong_entry = loader._IMAGES[(wrong.image_sha256, 'calculate', 'all_zero_u8')]
        _, obj, final, _, _, _ = self.cases[('sum_u8', 'calculate')]
        binding = loader.bind_final_artifact(obj, final, 'calculate')
        with self.assertRaisesRegex(loader.VerifiedKernelLoadRejected, 'exact sealed ELF mapping'):
            loader._checked_function(wrong_entry['library'], correct_entry['fd'],
                                     correct.validation, binding)
        self.assert_sum(correct)

    def test_prior_dlopen_fd_name_collision_is_rejected_before_target_resolution(self):
        # This process-global dlopen name cache must be constructed in a
        # child so its stale handle cannot affect another test or caller.
        source = r'''
import ctypes, json, os, sys
from pathlib import Path
from unittest.mock import patch
from hepta.hia_verified_simd import simd_kernel_program
from hepta import hia_verified_kernel_load as loader
old_bytes, object_bytes, final_bytes = (Path(p).read_bytes() for p in sys.argv[1:])
created, old_libraries = [], []
original_create = os.memfd_create
def create(*args, **kwargs):
    # Populate the unrelated name cache immediately before allocation,
    # after Z3/probe initialization has settled its own descriptors.
    old_fd = original_create('unrelated-earlier-library')
    os.write(old_fd, old_bytes)
    path = '/proc/' + str(os.getpid()) + '/fd/' + str(old_fd)
    old_libraries.append(ctypes.CDLL(path, mode=os.RTLD_LOCAL | os.RTLD_NOW))
    os.close(old_fd)
    next_fd = original_create(*args, **kwargs)
    created.append(next_fd)
    assert next_fd == old_fd, (old_fd, next_fd)
    return next_fd
try:
    with patch.object(loader.os, 'memfd_create', side_effect=create):
        loader.load_verified_simd_kernel(simd_kernel_program('sum_u8'), object_bytes, final_bytes)
except loader.VerifiedKernelLoadRejected as error:
    assert 'cached object' in str(error), str(error)
else:
    raise AssertionError('stale dlopen name escaped admission')
assert len(created) == 1 and len(old_libraries) == 1
fd = created[0]
assert not loader._IMAGES and loader._TOTAL_BYTES == 0
try:
    os.fstat(fd)
except OSError:
    pass
else:
    raise AssertionError('failed mapping leaked its descriptor')
print(json.dumps({'stale_mapping_rejected': True, 'failed_mapping_fd_closed': True}))
'''
        old = self.cases[('all_zero_u8', 'calculate')][-1]
        obj, final = self.cases[('sum_u8', 'calculate')][-2:]
        result = subprocess.run([sys.executable, '-B', '-c', source, str(old), str(obj), str(final)],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'stale_mapping_rejected': True, 'failed_mapping_fd_closed': True})

    @unittest.skipUnless(shutil.which('cc'), 'C compiler required for the isolated GNU IFUNC control')
    def test_cached_ifunc_resolver_is_never_executed_during_failed_admission(self):
        marker = self.root / 'ifunc-resolver-executed'
        fixture_source = self.root / 'ifunc-cache-control.c'
        fixture_library = fixture_source.with_suffix('.so')
        fixture_source.write_text(r'''
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
typedef uint64_t (*kernel_t)(const uint8_t*, uint64_t, uint64_t);
static uint64_t implementation(const uint8_t* p, uint64_t extent, uint64_t count) {
  (void)p; (void)extent; (void)count; return 123;
}
static kernel_t resolve(void) {
  int fd = open(MARKER, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd >= 0) { (void)write(fd, "resolver", 8); close(fd); }
  return implementation;
}
uint64_t calculate(const uint8_t*, uint64_t, uint64_t) __attribute__((ifunc("resolve")));
/* This unapplied PLT binding also detects an unsafe RTLD_LAZY -> NOW upgrade. */
uint64_t forward_to_calculate(const uint8_t* p, uint64_t extent, uint64_t count) {
  return calculate(p, extent, count);
}
'''.replace('MARKER', json.dumps(str(marker))))
        built = subprocess.run(['cc', '-shared', '-fPIC', '-Wl,-z,lazy', str(fixture_source),
                                '-o', str(fixture_library)], capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        source = r'''
import ctypes, json, os, sys
from pathlib import Path
from unittest.mock import patch
from hepta.hia_verified_simd import simd_kernel_program
from hepta import hia_verified_kernel_load as loader
old_bytes, object_bytes, final_bytes = (Path(p).read_bytes() for p in sys.argv[1:4])
marker = Path(sys.argv[4])
assert not marker.exists()
system = ctypes.CDLL(None)
opening = system['dlopen']; opening.argtypes = (ctypes.c_char_p, ctypes.c_int); opening.restype = ctypes.c_void_p
closing = system['dlclose']; closing.argtypes = (ctypes.c_void_p,); closing.restype = ctypes.c_int
created, old_handles = [], []
original_create = os.memfd_create
def create(*args, **kwargs):
    old_fd = original_create('unrelated-lazy-ifunc')
    os.write(old_fd, old_bytes)
    path = '/proc/' + str(os.getpid()) + '/fd/' + str(old_fd)
    # CDLL would force NOW; direct dlopen is necessary to preserve this
    # unrelated object's genuinely lazy unresolved IFUNC PLT binding.
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
        loader.load_verified_simd_kernel(simd_kernel_program('sum_u8'), object_bytes, final_bytes)
except loader.VerifiedKernelLoadRejected as error:
    assert 'cached object' in str(error), str(error)
else:
    raise AssertionError('cached IFUNC object escaped admission')
assert len(created) == len(old_handles) == 1
assert not marker.exists(), 'unverified IFUNC resolver ran before rejection'
assert not loader._IMAGES and loader._TOTAL_BYTES == 0
try:
    os.fstat(created[0])
except OSError:
    pass
else:
    raise AssertionError('failed IFUNC admission leaked its descriptor')
assert closing(old_handles[0]) == 0
assert not marker.exists()
print(json.dumps({'cached_ifunc_rejected': True, 'resolver_executed': False}))
'''
        obj, final = self.cases[('sum_u8', 'calculate')][-2:]
        result = subprocess.run([sys.executable, '-B', '-c', source, str(fixture_library),
                                 str(obj), str(final), str(marker)],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {'cached_ifunc_rejected': True, 'resolver_executed': False})
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
