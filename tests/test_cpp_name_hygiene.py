"""Runtime regressions for accepted public names capturing generated locals."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.cpp_contracts import bridge_cpp_contracts


def parameter(name, mode="value"):
    p = {"name": name, "type": "i32", "mode": mode}
    if mode != "value":
        p["retention"] = "call_only"
    return p


def method(name, params, const=False):
    return {"name": name, "cpp_method": name, "const": const, "params": params,
            "returns": "i32", "return_mode": "value", "exception": "noexcept"}


def contract(methods):
    return {"schema": "hepta.cpp-contract.v1", "module": "hygiene", "pod_types": [],
            "functions": [], "handles": [{"name": "Box", "cpp_type": "Box", "template_args": [],
                "threading": "serialized", "reentrancy": "reject", "allocator": "cpp_shared_owner",
                "destruction": "nothrow_defer_inflight", "methods": methods}]}


@unittest.skipUnless(shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc")),
                     "name hygiene regression requires g++ and pinned rustc")
class CppNameHygieneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cpp-names-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def execute(self, directory, source, main, *, compiler="g++", label="fixed"):
        wrapper = self.root / (label + "-bridge.cpp")
        wrapper.write_text(source)
        caller = self.root / (label + "-main.cpp")
        caller.write_text('#include "bridge.h"\n#include <cstdio>\n' + main)
        binary = self.root / (label + "-native")
        built = subprocess.run([compiler, "-std=c++20", "-O2", "-pthread", "-Werror",
                                "-I" + str(directory), str(wrapper), str(caller), "-o", str(binary)],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(built.returncode, 0, built.stderr)
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        return ran.stdout.strip()

    def test_receiver_conversion_silent_miscompile_and_runtime_negative_control(self):
        header = self.root / "box.hpp"
        header.write_text("""
            #pragma once
            #include <cstdint>
            struct Box {
                Box() noexcept = default;
                ~Box() noexcept = default;
                operator std::int32_t() const noexcept { return 99; }
                std::int32_t echo(std::int32_t value) noexcept { return value; }
            };
        """)
        candidate = contract([method("echo", [parameter("receiver")])])
        compilers = ["g++"]
        if shutil.which("clang++"):
            compilers.append("clang++")
        main = """
            int main() {
                uint64_t handle = 0;
                int32_t output = -1;
                if (hepta_cpp_hygiene_Box_new(&handle)) return 1;
                if (hepta_cpp_hygiene_Box_echo(handle, 7, &output)) return 2;
                if (hepta_cpp_hygiene_Box_destroy(handle)) return 3;
                std::printf("%d\\n", output);
            }
        """
        for index, compiler in enumerate(compilers):
            with self.subTest(compiler=compiler):
                directory = self.root / ("generated" + str(index))
                report = bridge_cpp_contracts(header, candidate, directory, cxx=compiler)
                self.assertTrue(report["ok"], report)
                source = (directory / "bridge.cpp").read_text()
                self.assertEqual(self.execute(directory, source, main, compiler=compiler,
                                              label="fixed" + str(index)), "7")
                # Deliberately restore the old implementation binding. The
                # type/compile gates still pass; execution must expose 99.
                captured = source.replace("std::int32_t hepta_arg0", "std::int32_t receiver")
                captured = captured.replace("static_cast<std::int32_t>(hepta_arg0)",
                                            "static_cast<std::int32_t>(receiver)")
                self.assertNotEqual(captured, source)
                self.assertEqual(self.execute(directory, captured, main, compiler=compiler,
                                              label="captured" + str(index)), "99")

    def test_free_constructor_method_span_and_scope_inputs_use_position_bindings(self):
        header = self.root / "all.hpp"
        header.write_text("""
            #pragma once
            #include <cstdint>
            #include <span>
            inline std::int32_t identity(std::int32_t value) noexcept { return value; }
            struct Box {
                std::int32_t seed;
                explicit Box(std::int32_t value) noexcept: seed(value) {}
                operator std::int32_t() const noexcept { return 99; }
                std::int32_t echo(std::int32_t value) noexcept { return value; }
                std::int32_t sum(std::int32_t a, std::int32_t b, std::int32_t c,
                    std::int32_t d, std::int32_t e, std::int32_t f, std::int32_t g,
                    std::int32_t h, std::int32_t i) noexcept {
                    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g + 8*h + 9*i;
                }
                std::int32_t borrowed(std::span<const std::int32_t> values) const noexcept {
                    return values.empty() ? seed : seed + values[0];
                }
            };
        """)
        names = ("entry", "registry", "lock", "object", "receiver", "active", "result", "registry_lock", "it")
        candidate = contract([method("echo", [parameter("receiver")]),
                              method("sum", [parameter(n) for n in names]),
                              method("borrowed", [parameter("object", "borrow_const")], True)])
        candidate["schema"] = "hepta.cpp-contract.v3"
        candidate["handles"][0]["constructors"] = [{"name": "new", "params": [parameter("result")],
                                                       "exception": "noexcept"}]
        candidate["functions"] = [{"name": "identity", "cpp_name": "identity", "template_args": [],
            "params": [parameter("result")], "returns": "i32", "exception": "noexcept",
            "threading": "any_thread", "reentrancy": "allowed", "allocation": "none_declared"}]
        candidate["scopes"] = [{"name": "scoped", "handle": "Box", "constructor": "new",
            "params": [parameter("result"), parameter("object", "borrow_const")],
            "constructor_args": ["result"], "calls": [{"method": "borrowed", "args": ["object"]}],
            "lifetime": "call_scoped_cpp_raii"}]
        directory = self.root / "generated"
        report = bridge_cpp_contracts(header, candidate, directory, cxx="g++")
        self.assertTrue(report["ok"], report)
        # Public source names and ABI argument order remain unchanged.
        public_header = (directory / "bridge.h").read_text()
        self.assertIn("int32_t receiver, int32_t* out", public_header)
        self.assertIn("const int32_t* object, size_t object_len", public_header)
        main = """
            int main() {
                uint64_t handle = 0;
                int32_t output = -1, input = 5;
                if (hepta_cpp_hygiene_identity(13) != 13) return 1;
                if (hepta_cpp_hygiene_Box_new(11, &handle)) return 2;
                if (hepta_cpp_hygiene_Box_echo(handle, 7, &output) || output != 7) return 3;
                if (hepta_cpp_hygiene_Box_sum(handle,1,2,3,4,5,6,7,8,9,&output) || output != 285) return 4;
                if (hepta_cpp_hygiene_Box_borrowed(handle,&input,1,&output) || output != 16) return 5;
                if (hepta_cpp_hygiene_Box_borrowed(handle,nullptr,0,&output) || output != 11) return 6;
                output = -1;
                if (hepta_cpp_hygiene_Box_borrowed(handle,nullptr,1,&output) != 1 || output != -1) return 7;
                if (hepta_cpp_hygiene_scoped(20,&input,1,&output) || output != 25) return 8;
                if (hepta_cpp_hygiene_Box_destroy(handle)) return 9;
                std::puts("all routes correct");
            }
        """
        self.assertEqual(self.execute(directory, (directory / "bridge.cpp").read_text(), main),
                         "all routes correct")


if __name__ == "__main__":
    unittest.main()
