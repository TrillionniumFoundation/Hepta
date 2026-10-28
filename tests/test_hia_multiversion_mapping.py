"""Actual loader fd reuse must refuse before the first multiversion probe."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from tests.test_hia_multiversion import _CLANG, _NATIVE

ROOT = Path(__file__).resolve().parents[1]


_RETAINED_MAPPING = r'''
import _ctypes, ctypes, errno, json, os, tempfile
from pathlib import Path
from unittest.mock import patch
import hepta.hia_multiversion as mv
from tests.test_hia_multiversion import scalar_program

real_close, real_unload = os.close, _ctypes.dlclose
old = None
reserved = None
handle = None
with tempfile.TemporaryDirectory(prefix='hia-real-loader-reuse-') as temporary:
    root = Path(temporary)
    old = mv.ScalarMultiversionRuntime(scalar_program(), root, clang=CLANG)
    state = old._states[0]
    descriptor, handle, library = state.fd, state.library._handle, state.library
    first_mapping = state.info.as_dict()['loaded_mapping']
    assert first_mapping['inode'] == os.fstat(descriptor).st_ino
    assert old.call('calculate', [13]) == 13
    def keep_original_reference(value):
        if value == handle:
            raise OSError(errno.EIO, 'controlled loader release refusal before real dlclose')
        return real_unload(value)
    with patch('_ctypes.dlclose', keep_original_reference):
        old.close()
    assert old.snapshot()['cleanup']['pending'][0]['native']['library']['status'] == 'unknown'
    try:
        os.fstat(descriptor)
    except OSError:
        pass
    else:
        raise AssertionError('independently owned fd was not closed')
    # Keep the old numeric slot reserved while B acquires directory/artifact
    # pins. Only the test-owned reservation is replaced with B's real memfd.
    reserved = os.open('/dev/null', os.O_RDONLY)
    if reserved != descriptor:
        os.dup2(reserved, descriptor, inheritable=False)
        real_close(reserved)
        reserved = descriptor
    sealed = mv._sealed_fd
    new_inodes = []
    def reuse_number(data):
        global reserved
        fresh = sealed(data)
        new_inodes.append(os.fstat(fresh).st_ino)
        real_close(reserved)
        reserved = None
        os.dup2(fresh, descriptor, inheritable=False)
        real_close(fresh)
        return descriptor
    rejected = None
    try:
        with patch.object(mv, '_sealed_fd', reuse_number), \
             patch.object(mv, '_probe_vectors', side_effect=AssertionError('native probe must not start')) as probes:
            try:
                unexpected = mv.ScalarMultiversionRuntime(scalar_program(value=1), root, clang=CLANG)
            except mv.MultiversionRejected as error:
                assert 'loaded native mapping' in str(error), str(error)
                rejected = error.hia_cleanup
            else:
                unexpected.close()
                raise AssertionError('stale loader mapping was accepted')
            assert probes.call_count == 0
        assert len(new_inodes) == 1 and new_inodes[0] != first_mapping['inode']
        assert rejected['owned_native_release_complete']
        assert rejected['owned_identity_release_complete']
        assert rejected['pending_resource_count'] == 0
        assert rejected['observed_closed_and_directory_absent']
        try:
            os.fstat(descriptor)
        except OSError:
            pass
        else:
            raise AssertionError('refused new mapping leaked its own memfd')
        # B's refusal cleanup released only B's dlopen reference. The test's
        # deliberately retained A still identifies and executes A's code.
        function = library.calculate
        function.argtypes = [ctypes.c_uint64]
        function.restype = ctypes.c_uint64
        assert function(13) == 13
    finally:
        if reserved is not None:
            real_close(reserved)
        real_unload(handle)
        handle = None
# File removal above is test-owned; production may only release now-absent pins.
old.retry_cleanup()
print(json.dumps({'actual_different_inodes': True, 'old_loader_reference_retained': True,
                  'native_probes_before_refusal': 0, 'new_cleanup': rejected}))
'''


_UNKNOWN_MAPPING = r'''
import copy, json, os, tempfile
from pathlib import Path
from unittest.mock import patch
import hepta.hia_multiversion as mv
from tests.test_hia_multiversion import scalar_program

with tempfile.TemporaryDirectory(prefix='hia-map-evidence-') as temporary:
    root = Path(temporary)
    program = scalar_program()
    other = copy.deepcopy(program['functions'][0])
    other['name'] = 'another'
    program['functions'].append(other)
    with mv.ScalarMultiversionRuntime(program, root, clang=CLANG) as runtime:
        info = runtime._states[0].info.as_dict()
        mapping = info['loaded_mapping']
        assert set(mapping['symbols']) == {'calculate', 'another'}
        assert mapping['inode'] == os.fstat(runtime._states[0].fd).st_ino
        assert len(mapping['checker_sha256']) == 64
        mapping['inode'] = -1
        assert runtime._states[0].info.as_dict()['loaded_mapping']['inode'] >= 0
        assert runtime.call('another', [23]) == 23
    real_open = open
    def no_mapping(path, *args, **kwargs):
        if path == '/proc/self/maps':
            raise PermissionError('controlled missing kernel mapping evidence')
        return real_open(path, *args, **kwargs)
    with patch('builtins.open', no_mapping), \
         patch.object(mv, '_probe_vectors', side_effect=AssertionError('probe before mapping evidence')) as probes:
        try:
            mv.ScalarMultiversionRuntime(program, root, clang=CLANG)
        except mv.MultiversionRejected as error:
            assert 'loaded native mapping' in str(error)
            cleanup = error.hia_cleanup
            assert cleanup['owned_native_release_complete']
            assert cleanup['owned_identity_release_complete']
            assert cleanup['pending_resource_count'] == 0
        else:
            raise AssertionError('unknown mapping became admission authority')
        assert probes.call_count == 0
print(json.dumps({'all_exports_bound': 2, 'unknown_refused_before_probes': True, 'cleanup': cleanup}))
'''


@unittest.skipUnless(_NATIVE, "qualified Linux sealing, Clang and Z3 required")
class MultiversionMappingTests(unittest.TestCase):
    def isolated(self, script):
        result = subprocess.run([sys.executable, '-B', '-c', 'CLANG = ' + repr(_CLANG) + '\n' + script],
                                cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_real_retained_loader_mapping_and_reused_fd_refuse_before_probe(self):
        result = self.isolated(_RETAINED_MAPPING)
        self.assertTrue(result['actual_different_inodes'])
        self.assertEqual(result['native_probes_before_refusal'], 0)

    def test_all_exports_bind_and_unknown_mapping_refuses_before_probe(self):
        result = self.isolated(_UNKNOWN_MAPPING)
        self.assertEqual(result['all_exports_bound'], 2)
        self.assertTrue(result['unknown_refused_before_probes'])


if __name__ == '__main__':
    unittest.main()
