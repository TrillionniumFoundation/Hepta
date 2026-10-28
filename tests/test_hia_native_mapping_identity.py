"""Actual sealed-file/loaded-entry identity, including retained ld.so mappings.

The fd-reuse counterexample runs in an isolated interpreter so its deliberately
retained old dlopen reference cannot contaminate unrelated compiler tests.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from hepta.native_mapping_identity import NativeMappingRejected, verify_loaded_symbols

CLANG = os.environ.get("CLANG") or os.environ.get("HEPTA_CLANG") or shutil.which("clang-20") or shutil.which("clang")
NATIVE = (sys.platform == "linux" and CLANG and importlib.util.find_spec("z3") is not None
          and importlib.util.find_spec("fcntl") is not None)
ROOT = Path(__file__).resolve().parents[1]


class LoadedMappingInputTests(unittest.TestCase):
    def test_missing_descriptor_or_symbol_evidence_rejects(self):
        for descriptor, symbols in ((-1, {}), (True, {}), (0, {}), (0, {"calculate": object()})):
            with self.subTest(descriptor=descriptor, symbols=symbols), self.assertRaises(NativeMappingRejected):
                verify_loaded_symbols(descriptor, symbols)


_SCALAR_REUSE = r'''
import _ctypes, copy, ctypes, json, os, sys, tempfile, time
from pathlib import Path
from unittest.mock import patch
import hepta.hia_adaptive as adaptive
from hepta.hia_optimization import build_optimized_native
from hepta.hia_native_differential import _pin_native_artifact
from hepta.native_mapping_identity import NativeMappingRejected, verify_loaded_symbols
from tools.qualify_hia_adaptive import programs

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    first, _ = programs()
    second = copy.deepcopy(first)
    second['functions'][0]['blocks'][0]['ops'][-1]['op'] = 'int.sub.wrap'
    a, state = adaptive._profile(first)
    b, other_state = adaptive._profile(second)
    ra = build_optimized_native(a, a, root/'a.so', clang=sys.argv[1])
    rb = build_optimized_native(b, b, root/'b.so', clang=sys.argv[1])
    assert ra['native']['artifact_sha256'] != rb['native']['artifact_sha256']
    original, _, old_fd = _pin_native_artifact(root/'a.so')
    old_library = ctypes.CDLL('/proc/self/fd/'+str(old_fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    old_function = old_library.calculate
    old_function.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    old_function.restype = ctypes.c_uint64
    old_mapping = verify_loaded_symbols(old_fd, {'calculate': old_function})
    assert old_mapping['inode'] == os.fstat(old_fd).st_ino
    assert old_function(7, 2) == 9
    # Reproduce the actual former cleanup bug: close fd, keep dlopen reference.
    os.close(old_fd)
    captured = []
    real_pin = adaptive._pin_native_artifact
    def capture(path):
        result = real_pin(path)
        captured.append(result[2])
        assert result[2] == old_fd, 'qualified isolated reproduction must reuse the numeric fd'
        # The still-live old function has the same export name but belongs to a
        # different file object. This independent guard must reject it too.
        try:
            verify_loaded_symbols(result[2], {'calculate': old_function})
        except NativeMappingRejected:
            pass
        else:
            raise AssertionError('old function was bound to the new descriptor')
        return result
    try:
        with patch.object(adaptive, '_pin_native_artifact', side_effect=capture):
            try:
                unexpected = adaptive._load_image(b, other_state, root/'b.so', rb, time.monotonic_ns())
            except adaptive.AdaptiveRejected as error:
                assert 'E_ADAPT_MAPPING' in str(error), str(error)
            else:
                adaptive.AdaptiveRuntime._dispose(unexpected)
                raise AssertionError('cached same-export old mapping reached native admission')
        assert captured == [old_fd]
        try:
            os.fstat(captured[0])
        except OSError:
            pass
        else:
            raise AssertionError('rejected admission leaked its new sealed descriptor')
        assert old_function(7, 2) == 9, 'reject cleanup consumed someone else\'s dlopen reference'
    finally:
        _ctypes.dlclose(old_library._handle)
    # Once the old reference is correctly released, a normal load binds B and
    # executes subtraction. No mutable pathname is introduced as a workaround.
    image = adaptive._load_image(b, other_state, root/'b.so', rb, time.monotonic_ns())
    try:
        assert image.loaded_mapping['inode'] == os.fstat(image.fd).st_ino
        assert image.function(7, 2) == 5
        positive = image.loaded_mapping
    finally:
        adaptive.AdaptiveRuntime._dispose(image)
    print(json.dumps({'same_export_reuse_rejected': True, 'rejected_fd_closed': True,
                      'normal_subtraction': 5, 'normal_loaded_mapping': positive}))
'''


_UNKNOWN_AND_DRIVER = r'''
import _ctypes, ctypes, json, os, sys, tempfile, time
from pathlib import Path
from unittest.mock import patch
import hepta.hia_adaptive as adaptive
import hepta.hia_stateful as stateful
from hepta.hia_optimization import build_optimized_native
from hepta.native_mapping_identity import verify_loaded_symbols
from tools.qualify_hia_adaptive import programs

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    base, _ = programs()
    checked, state = adaptive._profile(base)
    receipt = build_optimized_native(checked, checked, root/'base.so', clang=sys.argv[1])
    real_pin, captured = adaptive._pin_native_artifact, []
    def capture(path):
        result = real_pin(path);captured.append(result[2]);return result
    real_open = open
    def unavailable(path, *args, **kwargs):
        if path == '/proc/self/maps':
            raise PermissionError('controlled unavailable mapping evidence')
        return real_open(path, *args, **kwargs)
    with patch.object(adaptive, '_pin_native_artifact', side_effect=capture), patch('builtins.open', side_effect=unavailable):
        try:
            adaptive._load_image(checked, state, root/'base.so', receipt, time.monotonic_ns())
        except adaptive.AdaptiveRejected as error:
            assert 'E_ADAPT_MAPPING' in str(error)
        else:
            raise AssertionError('missing kernel mapping evidence was accepted')
    try:
        os.fstat(captured[0])
    except OSError:
        pass
    else:
        raise AssertionError('unknown mapping refusal leaked descriptor')
    driver_dir = root/'driver';driver_dir.mkdir()
    library, descriptor, metadata = stateful._driver(driver_dir, sys.argv[1])
    try:
        assert set(metadata['loaded_mapping']['symbols']) == set(stateful._EXPORTS)
        assert metadata['loaded_mapping']['inode'] == os.fstat(descriptor).st_ino
        assert library.hs_live() == 0
        owner = library.hs_new(2, 0)
        assert owner
        try:
            library.hs_write(owner, 1, 17)
            assert library.hs_read(owner, 1) == 17
        finally:
            library.hs_free(owner)
        assert library.hs_live() == 0
        # Driver entrypoints require the same mapping gate, even if the old
        # cached driver happened to have identical bytes and export spellings.
        old_number = descriptor
        os.close(descriptor);descriptor = None
        new_dir = root/'another-driver';new_dir.mkdir()
        real_state_pin, state_fds = stateful._pin_native_artifact, []
        def capture_state(path):
            result = real_state_pin(path);state_fds.append(result[2]);return result
        with patch.object(stateful, '_pin_native_artifact', side_effect=capture_state):
            try:
                unexpected, new_fd, _ = stateful._driver(new_dir, sys.argv[1])
            except adaptive.AdaptiveRejected as error:
                assert 'E_STATE_DRIVER_MAPPING' in str(error), str(error)
            else:
                _ctypes.dlclose(unexpected._handle);os.close(new_fd)
                raise AssertionError('cached driver mapping reached native admission')
        assert state_fds == [old_number]
        try:
            os.fstat(old_number)
        except OSError:
            pass
        else:
            raise AssertionError('driver refusal leaked descriptor')
        assert library.hs_live() == 0
    finally:
        _ctypes.dlclose(library._handle)
        if descriptor is not None:os.close(descriptor)
    print(json.dumps({'unknown_mapping_rejected': True, 'driver_exports_bound': len(stateful._EXPORTS),
                      'cached_driver_rejected': True, 'final_live': 0}))
'''


@unittest.skipUnless(NATIVE, "requires qualified Linux, pinned Z3 and Clang for actual loaded mapping")
class ActualLoadedMappingTests(unittest.TestCase):
    def run_isolated(self, script):
        result = subprocess.run([sys.executable, '-c', script, CLANG], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_same_export_fd_reuse_rejects_old_mapping_and_normal_load_runs_new_code(self):
        result = self.run_isolated(_SCALAR_REUSE)
        self.assertTrue(result['same_export_reuse_rejected'])
        self.assertTrue(result['rejected_fd_closed'])
        self.assertEqual(result['normal_subtraction'], 5)

    def test_missing_mapping_and_cached_driver_fail_closed_with_cleanup(self):
        result = self.run_isolated(_UNKNOWN_AND_DRIVER)
        self.assertTrue(result['unknown_mapping_rejected'])
        self.assertTrue(result['cached_driver_rejected'])
        self.assertEqual(result['driver_exports_bound'], 14)
        self.assertEqual(result['final_live'], 0)


if __name__ == '__main__':
    unittest.main()
