"""P4 C++ contract native compiler entry uses file-backed bounded capture."""
from __future__ import annotations

from pathlib import Path
import base64
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, CaptureResult
from hepta.cpp_contracts import _command
from hepta.cpp_contracts import bridge_cpp_contracts
from hepta.c_migrate import MigrationRejected


class CppContractCompilerCaptureTests(unittest.TestCase):
    def test_compiler_capture_has_explicit_time_and_byte_budgets(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   return_value=CaptureResult(0, "ok", "")) as run:
            result = _command(["c++", "--version"], timeout=11)
            self.assertEqual(result.stdout, "ok")
            run.assert_called_once_with(
                ["c++", "--version"], timeout=11, stdin_limit=0,
                stdout_limit=64000, stderr_limit=256000)

    def test_output_overrun_never_counts_as_native_success(self):
        for reason in ("E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_ENCODING"):
            with self.subTest(reason=reason):
                with patch("hepta.cpp_contracts.run_bounded",
                           side_effect=CaptureRejected(reason, "rejected")):
                    with self.assertRaises(MigrationRejected) as error:
                        _command(["c++", "-c", "bridge.cpp"])
                self.assertEqual(error.exception.code, "E_CPP_CAPTURE")

    def test_timeout_maps_to_environment_error(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   side_effect=CaptureRejected("E_CAPTURE_TIMEOUT", "timeout")):
            with self.assertRaises(MigrationRejected) as error:
                _command(["c++", "--version"])
        self.assertEqual(error.exception.code, "E_CPP_ENV")

    def test_nonzero_status_remains_native_rejection(self):
        with patch("hepta.cpp_contracts.run_bounded",
                   return_value=CaptureResult(7, "", "invalid C++")):
            with self.assertRaises(MigrationRejected) as error:
                _command(["c++", "-c", "bridge.cpp"])
        self.assertEqual(error.exception.code, "E_CPP_NATIVE")

    def test_real_nonzero_exit_preserves_raw_crlf_separately_from_normalized_text(self):
        argv = [sys.executable, '-c',
                'import sys;sys.stdout.buffer.write(b"out\\r\\n");sys.stderr.buffer.write(b"err\\r\\n");sys.exit(7)']
        with self.assertRaises(MigrationRejected) as error:
            _command(argv)
        receipt = error.exception.native_process
        self.assertEqual(error.exception.code, 'E_CPP_NATIVE')
        self.assertEqual(receipt['status'], 'exited')
        self.assertEqual(receipt['exit_code'], 7)
        self.assertEqual(receipt['argv'], argv)
        self.assertEqual(receipt['stdout'], 'out\n')
        self.assertEqual(receipt['stderr'], 'err\n')
        self.assertEqual(base64.b64decode(receipt['stdout_raw_base64']), b'out\r\n')
        self.assertEqual(base64.b64decode(receipt['stderr_raw_base64']), b'err\r\n')
        self.assertTrue(receipt['raw_streams_available'])
        self.assertTrue(receipt['executable_unchanged'])

    def test_launch_failure_cannot_masquerade_as_native_compile_exit(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(MigrationRejected) as error:
                _command([str(Path(td) / 'missing-cxx'), '-c', 'bridge.cpp'])
        self.assertEqual(error.exception.code, 'E_CPP_ENV')
        self.assertEqual(error.exception.native_process['status'], 'capture_rejected')
        self.assertEqual(error.exception.native_process['capture_error'], 'E_CAPTURE_EXEC')
        self.assertIsNone(error.exception.native_process['exit_code'])

    def test_failed_identity_probe_is_not_reported_as_generated_cpp_compile(self):
        contract = {'schema': 'hepta.cpp-contract.v1', 'module': 'probe_failure',
                    'pod_types': [], 'handles': [], 'functions': [{'name': 'value', 'cpp_name': 'value',
                    'template_args': [], 'params': [], 'returns': 'u64', 'exception': 'noexcept',
                    'threading': 'any_thread', 'reentrancy': 'allowed', 'allocation': 'none_declared'}]}
        with tempfile.TemporaryDirectory() as td:
            header = Path(td) / 'foreign.hpp'
            header.write_text('#include <cstdint>\ninline std::uint64_t value() noexcept { return 7; }\n')
            def failed_identity(cxx, run, **kwargs):
                return run([sys.executable, '-c', 'import sys;sys.stderr.write("probe failure\\n");sys.exit(5)'])
            with patch('hepta.cpp_host_toolchain.compiler_identity', side_effect=failed_identity):
                report = bridge_cpp_contracts(header, contract, Path(td) / 'unpublished')
            self.assertFalse(report['ok'])
            self.assertEqual(report['diagnostics'][0]['code'], 'E_CPP_NATIVE')
            self.assertEqual(report['failure']['phase'], 'compiler_identity')
            self.assertEqual(report['failure']['process']['exit_code'], 5)
            self.assertNotIn('generated_inputs', report['failure'])
            self.assertFalse((Path(td) / 'unpublished').exists())

    def test_real_bad_signature_retains_generated_source_and_failed_compile(self):
        compiler = shutil.which('clang++') or shutil.which('g++') or shutil.which('cl.exe')
        self.assertIsNotNone(compiler, 'A real C++20 compiler is mandatory')
        contract = {'schema': 'hepta.cpp-contract.v1', 'module': 'bad_signature', 'pod_types': [], 'functions': [],
                    'handles': [{'name': 'Object', 'cpp_type': 'Object', 'template_args': [],
                    'threading': 'serialized', 'reentrancy': 'reject', 'allocator': 'cpp_shared_owner',
                    'destruction': 'nothrow_defer_inflight', 'methods': [{'name': 'value', 'cpp_method': 'value',
                    'const': True, 'params': [], 'returns': 'u64', 'return_mode': 'value', 'exception': 'noexcept'}]}]}
        with tempfile.TemporaryDirectory() as td:
            header = Path(td) / 'foreign.hpp'
            header.write_text('#include <cstdint>\nstruct Object { std::uint32_t value() const noexcept { return 7; } };\n')
            dest = Path(td) / 'unpublished'
            report = bridge_cpp_contracts(header, contract, dest, cxx=compiler, rustc='missing-rustc-must-not-run')
            self.assertFalse(report['ok'])
            self.assertFalse(dest.exists())
            failure = report['failure']
            self.assertEqual(failure['phase'], 'cpp_compile')
            self.assertEqual(failure['generated_inputs']['contract'], contract)
            self.assertEqual(failure['process']['status'], 'exited')
            self.assertGreater(failure['process']['exit_code'], 0)
            self.assertTrue(failure['process']['raw_streams_available'])
            self.assertIn('HEPTA_CPP_METHOD_RESULT:hepta_cpp_bad_signature_Object_value',
                          failure['process']['stdout'] + failure['process']['stderr'])
            self.assertIn('bridge.cpp', failure['generated_inputs']['files'])

    @unittest.skipUnless(shutil.which("clang++"), "Real Clang++ required")
    def test_native_cxx20_standard_library_object_compiled(self):
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-capture-") as tmp:
            src, target = Path(tmp)/"bridge.cpp", Path(tmp)/"bridge.o"
            src.write_text(
                '#include <vector>\n'
                'extern "C" int vector_size() { std::vector<int> v{1,2,3};'
                'return static_cast<int>(v.size()); }\n',
                encoding="utf-8")
            result = _command([shutil.which("clang++"), "-std=c++20", "-O2",
                               "-fPIC", "-pthread", "-Werror", "-c",
                               str(src), "-o", str(target)])
            self.assertEqual(result.returncode, 0)
            self.assertGreater(target.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
