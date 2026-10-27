"""Actual C++/Hepta ABI execution and deliberate contract violations."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.cpp_bridge import bridge_cpp_contracts
from tools.validate_cpp import EXAMPLE, qualify_cpp


NATIVE = shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc"))


def function(name, cpp_name, *, returns="u64", params=None, exception="noexcept"):
    return {"name": name, "cpp_name": cpp_name, "template_args": [],
            "params": params or [], "returns": returns, "exception": exception,
            "threading": "any_thread", "reentrancy": "allowed", "allocation": "none_declared"}


def method(name, *, params=None, returns="u64", const=True, exception="noexcept"):
    return {"name": name, "cpp_method": name, "const": const, "params": params or [],
            "returns": returns, "return_mode": "value", "exception": exception}


@unittest.skipUnless(NATIVE, "C++ contract qualification requires g++ and pinned rustc")
class CppContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-cpp-contract-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.contract = json.loads((EXAMPLE / "contract.json").read_text())

    def generate(self, contract=None, header=None):
        return bridge_cpp_contracts(header or EXAMPLE / "foreign.hpp", contract or self.contract,
                                    self.root / "generated", cxx="g++")

    def test_bidirectional_real_std_library_and_negative_boundaries(self):
        report = qualify_cpp(self.root, benchmark=False)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["native_link_qualified"])
        for key in ("bidirectional_native", "pod", "borrowed", "negative_boundaries", "cpp_templates", "std_string", "std_vector"):
            self.assertTrue(report["execution"][key])
        self.assertEqual(report["execution"]["serialized_calls"], 400)
        self.assertFalse(report["foreign_cpp_library_rewritten"])
        self.assertEqual(report["performance"]["status"], "not_run")

    def test_route_costs_and_unproved_claims_are_separate_from_checks(self):
        report = self.generate()
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "cpp_object_and_hepta_native_checked")
        self.assertFalse(report["native_link_qualified"])
        self.assertFalse(report["borrow_retention_proved"])
        self.assertFalse(report["foreign_library_soundness_proved"])
        costs = {row["symbol"]: row for row in report["cost_accounting"]}
        self.assertEqual(costs["hepta_cpp_stdlib_mix"]["wrapper_mutex_acquisitions"], 0)
        self.assertEqual(costs["hepta_cpp_stdlib_sum"]["input_buffer_copy_bytes"], 0)
        self.assertEqual(costs["hepta_cpp_stdlib_IntVector_at"]["wrapper_mutex_acquisitions"], 2)
        self.assertEqual(costs["hepta_cpp_stdlib_IntVector_at"]["accounting_scope"], "successful_call_after_registry_initialization")
        self.assertGreater(report["object_bytes"], 0)

    def test_compiler_rejects_false_noexcept_promise_without_publishing(self):
        self.contract["functions"][4]["exception"] = "noexcept"
        report = self.generate()
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_NATIVE")
        self.assertFalse((self.root / "generated").exists())

    def test_compiler_rejects_wrong_function_signature_without_publishing(self):
        self.contract["functions"][0]["params"][0]["type"] = "i64"
        report = self.generate()
        self.assertFalse(report["ok"], report)
        self.assertFalse((self.root / "generated").exists())

    def test_compiler_rejects_wrong_pod_layout(self):
        self.contract["pod_types"][0]["fields"].reverse()
        report = self.generate()
        self.assertFalse(report["ok"], report)
        self.assertIn("static assertion", report["diagnostics"][0]["message"])

    def test_nontrivial_pod_is_rejected_by_native_traits(self):
        header = self.root / "bad.hpp"
        header.write_text("#include <cstdint>\nnamespace bad { struct Pair { std::int64_t first, second; ~Pair() {} }; }\n")
        self.contract["pod_types"][0]["cpp_type"] = "bad::Pair"
        self.contract["functions"] = []
        self.contract["handles"] = [{"name": "Object", "cpp_type": "bad::Pair", "template_args": [],
            "threading": "serialized", "reentrancy": "reject", "allocator": "cpp_shared_owner",
            "destruction": "nothrow_defer_inflight", "methods": [method("missing")]}]
        report = self.generate(header=header)
        self.assertFalse(report["ok"], report)
        self.assertIn("static assertion", report["diagnostics"][0]["message"])

    def test_omitted_field_cannot_hide_inside_pod_padding(self):
        header = self.root / "omitted.hpp"
        header.write_text("#include <cstdint>\nnamespace bad { struct P { std::uint32_t first; std::uint8_t second; std::uint8_t hidden; }; inline P echo(P v) noexcept { return v; } }\n")
        contract = {"schema": "hepta.cpp-contract.v1", "module": "omitted", "handles": [],
                    "pod_types": [{"name": "P", "cpp_type": "bad::P", "fields": [
                        {"name": "first", "type": "u32"}, {"name": "second", "type": "u8"}]}],
                    "functions": [function("echo", "bad::echo", returns="P", params=[{"name": "v", "type": "P", "mode": "value"}])]}
        report = self.generate(contract, header)
        self.assertFalse(report["ok"], report)
        self.assertIn("structured binding", report["diagnostics"][0]["message"])

    def test_reference_results_need_explicit_copy_policy(self):
        self.contract["handles"][0]["methods"][2]["return_mode"] = "value"
        report = self.generate()
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_NATIVE")

    def test_unknown_fields_unsafe_type_injection_and_retention_rejected(self):
        variants = []
        changed = copy.deepcopy(self.contract)
        changed["skip_native"] = True
        variants.append(changed)
        changed = copy.deepcopy(self.contract)
        changed["functions"][3]["params"][0]["retention"] = "forever"
        variants.append(changed)
        changed = copy.deepcopy(self.contract)
        changed["handles"][0]["cpp_type"] = "std::vector<int>; void attack()"
        variants.append(changed)
        changed = copy.deepcopy(self.contract)
        changed["handles"][0]["allocator"] = "free_from_hepta"
        variants.append(changed)
        for candidate in variants:
            with self.subTest(candidate=candidate):
                report = self.generate(candidate)
                self.assertFalse(report["ok"], report)
                self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_CONTRACT")
                self.assertFalse((self.root / "generated").exists())

    def test_missing_native_compiler_does_not_become_frontend_success(self):
        report = bridge_cpp_contracts(EXAMPLE / "foreign.hpp", self.contract, self.root / "generated",
                                      cxx="/no/such/cpp/compiler")
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_ENV")
        self.assertFalse((self.root / "generated").exists())

    def test_existing_directory_is_preserved(self):
        dest = self.root / "generated"
        dest.mkdir()
        (dest / "keep").write_text("original")
        report = self.generate()
        self.assertFalse(report["ok"], report)
        self.assertEqual(list(dest.iterdir()), [dest / "keep"])
        self.assertEqual((dest / "keep").read_text(), "original")

    def test_native_affinity_reentrancy_deferred_destructor_and_ctor_exception(self):
        header = self.root / "probes.hpp"
        header.write_text(r'''
            #pragma once
            #include <cstdint>
            #include <stdexcept>
            extern "C" std::int32_t hepta_cpp_probes_Allowed_value(std::uint64_t, std::uint64_t*) noexcept;
            extern "C" std::int32_t hepta_cpp_probes_Allowed_destroy(std::uint64_t) noexcept;
            extern "C" std::int32_t hepta_cpp_probes_Rejected_value(std::uint64_t, std::uint64_t*) noexcept;
            namespace probe {
            inline std::uint64_t drops = 0;
            inline std::uint64_t destructions() noexcept { return drops; }
            struct Allowed {
                std::uint64_t* resource = new std::uint64_t(91);
                ~Allowed() noexcept { delete resource; ++drops; }
                std::uint64_t value() const noexcept { return *resource; }
                std::uint64_t bounce(std::uint64_t h) {
                    std::uint64_t out = 0;
                    auto code = hepta_cpp_probes_Allowed_value(h, &out);
                    return code ? 1000 + code : out;
                }
                std::uint64_t retire(std::uint64_t h) {
                    auto code = hepta_cpp_probes_Allowed_destroy(h);
                    if (code) return 1000 + code;
                    return *resource; // must stay alive after reentrant destroy
                }
            };
            struct Rejected {
                std::uint64_t value() const noexcept { return 92; }
                std::uint64_t bounce(std::uint64_t h) {
                    std::uint64_t out = 0;
                    return hepta_cpp_probes_Rejected_value(h, &out);
                }
            };
            struct Affine {
                std::uint64_t value() const noexcept { return 93; }
            };
            struct Failing {
                Failing() { throw std::runtime_error("construction failed"); }
                std::uint64_t value() const noexcept { return 94; }
            };
            }
        ''')
        value = method("value")
        p = [{"name": "h", "type": "u64", "mode": "value"}]
        handles = []
        for name in ("Allowed", "Rejected", "Affine", "Failing"):
            methods = [copy.deepcopy(value)]
            if name in {"Allowed", "Rejected"}:
                methods.append(method("bounce", params=p, const=False, exception="catch_status"))
            if name == "Allowed":
                methods.append(method("retire", params=p, const=False, exception="catch_status"))
            handles.append({"name": name, "cpp_type": "probe::" + name, "template_args": [],
                            "threading": "creator_thread" if name == "Affine" else "serialized",
                            "reentrancy": "allow" if name == "Allowed" else "reject",
                            "allocator": "cpp_shared_owner", "destruction": "nothrow_defer_inflight", "methods": methods})
        contract = {"schema": "hepta.cpp-contract.v1", "module": "probes", "pod_types": [],
                    "functions": [function("drops", "probe::destructions")], "handles": handles}
        report = self.generate(contract, header)
        self.assertTrue(report["ok"], report)
        generated = self.root / "generated"
        main = self.root / "main.cpp"
        main.write_text(r'''
            #include "bridge.h"
            #include <thread>
            #include <cstdlib>
            static void check(bool value) { if (!value) std::abort(); }
            int main() {
                uint64_t a=0, r=0, t=0, out=0, failed=777;
                check(hepta_cpp_probes_Allowed_new(&a)==0);
                check(hepta_cpp_probes_Rejected_new(&r)==0 && r!=a);
                check(hepta_cpp_probes_Affine_new(&t)==0 && t!=r && t!=a);
                check(hepta_cpp_probes_Allowed_bounce(a,a,&out)==0 && out==91);
                check(hepta_cpp_probes_Rejected_bounce(r,r,&out)==0 && out==6);
                check(hepta_cpp_probes_Allowed_value(r,&out)==2); // module-local type confusion rejected
                int call=0, destroy=0;
                std::thread worker([&] {
                    uint64_t sentinel=444;
                    call=hepta_cpp_probes_Affine_value(t,&sentinel);
                    destroy=hepta_cpp_probes_Affine_destroy(t);
                    check(sentinel==444);
                });
                worker.join();
                check(call==5 && destroy==5);
                check(hepta_cpp_probes_Affine_value(t,&out)==0 && out==93);
                check(hepta_cpp_probes_drops()==0);
                check(hepta_cpp_probes_Allowed_retire(a,a,&out)==0 && out==91);
                check(hepta_cpp_probes_drops()==1);
                check(hepta_cpp_probes_Allowed_value(a,&out)==2);
                check(hepta_cpp_probes_Allowed_destroy(a)==2);
                check(hepta_cpp_probes_Rejected_destroy(r)==0);
                check(hepta_cpp_probes_Affine_destroy(t)==0);
                check(hepta_cpp_probes_Failing_new(&failed)==3 && failed==777);
                // Thread identity must not become valid again when a native
                // thread ID is recycled after its original owner exits.
                uint64_t orphan=0;
                std::thread creator([&] { check(hepta_cpp_probes_Affine_new(&orphan)==0); });
                creator.join();
                std::thread replacement([&] {
                    uint64_t sentinel=999;
                    check(hepta_cpp_probes_Affine_value(orphan,&sentinel)==5 && sentinel==999);
                    check(hepta_cpp_probes_Affine_destroy(orphan)==5);
                });
                replacement.join(); // orphan is intentionally unreclaimed, as documented
            }
        ''')
        exe = self.root / "probes"
        p = subprocess.run(["g++", "-std=c++20", "-O2", "-pthread", "-I" + str(generated),
                            str(generated / "bridge.cpp"), str(main), "-o", str(exe)],
                           text=True, capture_output=True, timeout=90)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = subprocess.run([str(exe)], text=True, capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
