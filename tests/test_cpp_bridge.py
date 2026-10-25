"""C++ bridge qualifies only a small, explicitly unsafe external ABI subset."""
import ctypes
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

from hepta.cpp_bridge import bridge_cpp


HEADER = """
#pragma once
#include <stdint.h>
class Counter {
 public:
  Counter() : value_(0) {}
  ~Counter() = default;
  int32_t add(int32_t delta) { value_ += delta; return value_; }
  int32_t value() const { return value_; }
 private:
  int32_t value_;
};
"""


class CppBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.header = self.root / "lib.hpp"
        self.cpp = self.root / "bridge.cpp"
        self.hepta = self.root / "bridge.hepta"
        self.header.write_text(HEADER)
        self.assertIsNotNone(shutil.which("clang++"), "Clang++ is mandatory for P4 bridge tests")

    def bridge(self, name="Counter"):
        return bridge_cpp(self.header, name, self.cpp, self.hepta)

    def test_bindings_are_frontend_checked_but_not_declared_safe(self):
        report = self.bridge()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "clang_and_hepta_frontend_checked")
        self.assertFalse(report["foreign_library_soundness_proved"])
        self.assertFalse(report["thread_safety_of_foreign_internals_proved"])
        self.assertFalse(report["native_link_qualified"])
        self.assertEqual(report["methods"], ["add", "value"])
        self.assertIn("raw mut u64", self.hepta.read_text())
        self.assertIn("effects {ffi, unsafe", self.hepta.read_text())

    def test_native_opaque_handle_stale_and_concurrent_calls(self):
        report = self.bridge()
        self.assertTrue(report["ok"], report)
        output = self.root / "bridge.so"
        p = subprocess.run(["clang++", "-std=c++20", "-O2", "-fPIC", "-shared", "-pthread",
                            str(self.cpp), "-o", str(output)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        lib = ctypes.CDLL(str(output))
        signatures = {
            "new": [ctypes.POINTER(ctypes.c_uint64)],
            "destroy": [ctypes.c_uint64],
            "add": [ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)],
            "value": [ctypes.c_uint64, ctypes.POINTER(ctypes.c_int32)],
        }
        fn = {}
        for name, arguments in signatures.items():
            f = getattr(lib, "hepta_cpp_Counter_" + name)
            f.argtypes = arguments
            f.restype = ctypes.c_int32
            fn[name] = f
        handle = ctypes.c_uint64(0)
        result = ctypes.c_int32(-99)
        self.assertEqual(fn["new"](ctypes.byref(handle)), 0)
        self.assertNotEqual(handle.value, 0)
        self.assertEqual(fn["add"](handle.value, 3, ctypes.byref(result)), 0)
        self.assertEqual(result.value, 3)
        failures = []
        def worker():
            scratch = ctypes.c_int32()
            for _ in range(30):
                status = fn["add"](handle.value, 1, ctypes.byref(scratch))
                if status:
                    failures.append(status)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(fn["value"](handle.value, ctypes.byref(result)), 0)
        self.assertEqual(result.value, 123)
        self.assertEqual(fn["destroy"](handle.value), 0)
        self.assertEqual(fn["destroy"](handle.value), 2)
        self.assertEqual(fn["value"](handle.value, ctypes.byref(result)), 2)

    def test_cpp_exceptions_become_nonzero_status_without_writing_output(self):
        self.header.write_text("""
            #include <stdint.h>
            class Failer {
              public: Failer() {} ~Failer() = default;
              int32_t run(int32_t value) { if (value) throw 3; return 7; }
            };
        """)
        report = self.bridge("Failer")
        self.assertTrue(report["ok"], report)
        output = self.root / "failer.so"
        p = subprocess.run(["clang++", "-std=c++20", "-fPIC", "-shared", "-pthread",
                            str(self.cpp), "-o", str(output)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        lib = ctypes.CDLL(str(output))
        new = lib.hepta_cpp_Failer_new
        new.argtypes = [ctypes.POINTER(ctypes.c_uint64)]
        new.restype = ctypes.c_int32
        run = lib.hepta_cpp_Failer_run
        run.argtypes = [ctypes.c_uint64, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32)]
        run.restype = ctypes.c_int32
        delete = lib.hepta_cpp_Failer_destroy
        delete.argtypes = [ctypes.c_uint64]
        delete.restype = ctypes.c_int32
        handle = ctypes.c_uint64()
        out = ctypes.c_int32(44)
        self.assertEqual(new(ctypes.byref(handle)), 0)
        self.assertEqual(run(handle.value, 0, ctypes.byref(out)), 0)
        self.assertEqual(out.value, 7)
        self.assertEqual(run(handle.value, 1, ctypes.byref(out)), 3)
        self.assertEqual(out.value, 7)
        self.assertEqual(delete(handle.value), 0)

    def test_private_constructor_or_template_refused(self):
        self.header.write_text("""
            #include <stdint.h>
            class Hidden {
              Hidden() {}
              public: ~Hidden() = default; int32_t get() { return 1; }
            };
        """)
        report = self.bridge("Hidden")
        self.assertFalse(report["ok"])
        self.assertFalse(self.cpp.exists())
        self.header.write_text("""
            #include <stdint.h>
            template <typename T> class Box {
              public: Box() {} ~Box() = default; int32_t get() { return 1; }
            };
        """)
        report = self.bridge("Box")
        self.assertFalse(report["ok"])
        self.assertFalse(self.cpp.exists())

    def test_inherited_class_is_rejected_as_out_of_subset(self):
        self.header.write_text("""
            #include <stdint.h>
            class Base { public: virtual ~Base() = default; };
            class Derived : public Base {
              public: Derived() {} ~Derived() = default;
              int32_t get() { return 1; }
            };
        """)
        report = self.bridge("Derived")
        self.assertFalse(report["ok"], report)
        self.assertIn("E_CPP_HIERARCHY", [d["code"] for d in report["diagnostics"]])
        self.assertFalse(self.cpp.exists())

    def test_no_overwrite_or_partial_outputs(self):
        self.hepta.write_text("do not change")
        report = self.bridge()
        self.assertFalse(report["ok"])
        self.assertEqual(self.hepta.read_text(), "do not change")
        self.assertFalse(self.cpp.exists())


if __name__ == "__main__":
    unittest.main()
