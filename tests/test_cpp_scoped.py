"""C++ scoped RAII: finite contracts, actual Hepta calls, and failure cleanup."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.backend import compile_rust, emit_header
from hepta.cpp_contracts import _command, _validate, bridge_cpp_contracts
from hepta.cpp_scoped import EXAMPLE, TIMING_CASES, qualify_scoped_cpp
from hepta.pipeline import analyze_project

NATIVE = shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc"))


def contract() -> dict:
    return json.loads((EXAMPLE / "contract.json").read_text())


class ScopedContractTests(unittest.TestCase):
    def test_explicit_finite_scopes_and_unchanged_older_contract_shapes(self):
        self.assertEqual(len(_validate(contract())["scopes"]), 4)
        for directory in ("stdlib", "constructors"):
            with self.subTest(version=directory):
                old = json.loads((EXAMPLE.parent / directory / "contract.json").read_text())
                self.assertNotIn("scopes", _validate(old))

    def test_unknown_or_escaping_scoped_contracts_fail_closed(self):
        mutations = {
            "missing_scopes": lambda c: c.pop("scopes"),
            "unknown_schema_shape": lambda c: c.update(schema=[]),
            "empty_calls": lambda c: c["scopes"][0].update(calls=[]),
            "too_many_calls": lambda c: c["scopes"][0].update(calls=c["scopes"][0]["calls"] * 9),
            "unknown_handle": lambda c: c["scopes"][0].update(handle="Other"),
            "unknown_constructor": lambda c: c["scopes"][0].update(constructor="missing"),
            "unknown_method": lambda c: c["scopes"][0]["calls"][0].update(method="missing"),
            "code_injection": lambda c: c["scopes"][0]["calls"][0].update(args=["fn()"]),
            "unknown_input": lambda c: c["scopes"][0]["calls"][0].update(args=["missing"]),
            "wrong_arity": lambda c: c["scopes"][0].update(constructor_args=["count"]),
            "wrong_type": lambda c: c["scopes"][0]["params"][0].update(type="u32"),
            "wrong_mode": lambda c: c["scopes"][0]["params"][0].update(mode="const_ref", retention="call_only"),
            "retained_borrow": lambda c: c["scopes"][0]["params"][2].update(retention="object_lifetime"),
            "raw_result": lambda c: c["handles"][0]["methods"][-1].update(returns="raw const i64"),
            "borrowed_result": lambda c: c["handles"][0]["methods"][-1].update(return_mode="reference"),
            "handle_escape": lambda c: c["scopes"][0].update(return_handle=True),
            "escaping_lifetime": lambda c: c["scopes"][0].update(lifetime="return_to_caller"),
            "duplicate_export": lambda c: c["scopes"][0].update(name="Vector_destroy"),
            "unused_input": lambda c: c["scopes"][0]["params"].append({"name": "extra", "type": "i64", "mode": "value"}),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                candidate = contract()
                mutation(candidate)
                with self.assertRaises(MigrationRejected):
                    _validate(candidate)

    def test_scope_does_not_implicitly_change_argument_categories(self):
        candidate = contract()
        # A call-only const reference cannot be silently replaced with a value
        # input, even if C++ overload resolution would happen to accept it.
        candidate["scopes"][0]["params"][2] = {"name": "appended", "type": "i64", "mode": "value"}
        with self.assertRaisesRegex(MigrationRejected, "mode and retention"):
            _validate(candidate)


@unittest.skipUnless(NATIVE, "native C++ and the locked Rust toolchain required")
class ScopedNativeTests(unittest.TestCase):
    def test_mutable_span_failure_preserves_output_but_not_foreign_input_writes(self):
        with tempfile.TemporaryDirectory(prefix="hepta-scoped-span-") as directory:
            root = Path(directory)
            header = root / "foreign.hpp"
            header.write_text('''#pragma once
                #include <span>
                #include <cstdint>
                #include <stdexcept>
                struct Member {
                    static inline unsigned live = 0;
                    Member() { ++live; }
                    ~Member() noexcept { --live; }
                };
                struct SpanOperation {
                    Member member;
                    std::int64_t copied = 0;
                    SpanOperation(std::span<std::int64_t> values, std::uint64_t fail) {
                        if (!values.empty()) copied = ++values[0];
                        if (fail) throw std::runtime_error("after input mutation");
                    }
                    std::int64_t get() const noexcept { return copied; }
                };
            ''')
            values = {"name": "values", "type": "i64", "mode": "borrow_mut", "retention": "call_only"}
            failure = {"name": "failure", "type": "u64", "mode": "value"}
            candidate = {"schema": "hepta.cpp-contract.v3", "module": "spans", "pod_types": [], "functions": [],
                         "handles": [{"name": "Object", "cpp_type": "SpanOperation", "template_args": [],
                                      "threading": "serialized", "reentrancy": "reject", "allocator": "cpp_shared_owner",
                                      "destruction": "nothrow_defer_inflight",
                                      "constructors": [{"name": "new", "params": [values, failure], "exception": "catch_status"}],
                                      "methods": [{"name": "get", "cpp_method": "get", "const": True, "params": [],
                                                   "returns": "i64", "return_mode": "value", "exception": "noexcept"}]}],
                         "scopes": [{"name": "run", "handle": "Object", "constructor": "new", "params": [values, failure],
                                     "constructor_args": ["values", "failure"], "calls": [{"method": "get", "args": []}],
                                     "lifetime": "call_scoped_cpp_raii"}]}
            generated = root / "bridge"
            report = bridge_cpp_contracts(header, candidate, generated, cxx="g++")
            self.assertTrue(report["ok"], report)
            self.assertFalse(report["scoped_lifetime_checks"][0]["foreign_nonretention_proved"])
            consumer = generated / "consumer.hepta"
            consumer.write_text('''module consumer;
                import bridge;
                export "C" fn hepta_span(values: raw mut i64, count: usize,
                                         failure: u64, out: raw mut i64) -> i32
                effects {ffi, unsafe, write, alloc, block} {
                    unsafe { return bridge::hepta_cpp_spans_run(values, count, failure, out); }
                }
            ''')
            checked = analyze_project(consumer, crate_type="staticlib")
            self.assertTrue(checked.report["ok"], checked.report)
            exports = replace(checked.program, functions=[f for f in checked.program.functions if f.export_c])
            (generated / "hepta.h").write_text(emit_header(exports))
            library = root / "consumer.a"
            compiled = compile_rust(checked.rust, crate_type="staticlib", output=library)
            self.assertTrue(compiled["ok"], compiled)
            harness = root / "main.cpp"
            harness.write_text('''#include "hepta.h"
                #include "foreign.hpp"
                #include <limits>
                int main() {
                    std::int64_t input = 7, output = -90;
                    if (hepta_span(&input, 1, 1, &output) != 3 || input != 8 || output != -90 || Member::live) return 1;
                    if (hepta_span(&input, 1, 0, &output) != 0 || input != 9 || output != 9 || Member::live) return 2;
                    output = -90;
                    if (hepta_span(nullptr, 1, 0, &output) != 1 || output != -90 || Member::live) return 3;
                    auto excessive = static_cast<std::size_t>((std::numeric_limits<std::ptrdiff_t>::max)()) / sizeof(input) + 1;
                    if (hepta_span(&input, excessive, 0, &output) != 7 || input != 9 || output != -90 || Member::live) return 4;
                    alignas(std::int64_t) unsigned char data[sizeof(input)+1]{};
                    if (hepta_span(reinterpret_cast<std::int64_t*>(data+1), 1, 0, &output) != 8 || output != -90 || Member::live) return 5;
                    if (hepta_span(nullptr, 0, 0, &output) != 0 || output != 0 || Member::live) return 6;
                }
            ''')
            executable = root / "span-native"
            _command(["g++", "-std=c++20", "-O2", "-pthread", "-Werror", "-I" + str(generated), "-I" + str(root),
                      str(generated / "bridge.cpp"), str(harness), str(library), "-ldl", "-lm", "-o", str(executable)])
            self.assertEqual(_command([str(executable)], timeout=15).returncode, 0)

    def test_real_cpp_hepta_lifecycle_errors_allocation_refusal_and_costs(self):
        with tempfile.TemporaryDirectory(prefix="hepta-scoped-test-") as directory:
            report = qualify_scoped_cpp(directory, iterations=2000)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["native_link_qualified"])
        self.assertEqual(report["execution_process"]["returncode"], 0)
        execution = report["execution"]
        self.assertEqual(execution["vector_differential_cases"], 16)
        self.assertEqual(execution["probe_lifecycle_paths"], 4)
        self.assertEqual(execution["unit_cleanup_paths"], 2)
        self.assertEqual(execution["output_guard_cases"], 2)
        self.assertTrue(execution["pod_reference_copy"])
        self.assertTrue(execution["output_after_destructor"])
        self.assertEqual(execution["live_cpp_allocation_delta"], 0)
        self.assertEqual(execution["scoped_wrapper_allocation_delta"], 0)
        self.assertGreaterEqual(execution["allocation_refusal_sites"], 2)
        self.assertEqual(execution["allocation_refusal_sites"], execution["allocation_recoveries"])
        self.assertEqual(execution["direct_cpp_new_calls"], execution["scoped_cpp_new_calls"])
        self.assertGreater(execution["handle_cpp_new_calls"], execution["scoped_cpp_new_calls"])
        self.assertFalse(report["foreign_cpp_library_rewritten"])
        self.assertFalse(report["whole_library_memory_safety_proved"])
        self.assertFalse(report["arbitrary_hepta_raii_supported"])
        scopes = report["bridge_generation"]["scoped_lifetime_checks"]
        self.assertEqual(len(scopes), 4)
        for scope in scopes:
            self.assertFalse(scope["object_handle_exported"])
            self.assertFalse(scope["foreign_nonretention_proved"])
            self.assertTrue(scope["destructor_nothrow_native_checked"])
        costs = [c for c in report["bridge_generation"]["cost_accounting"] if c["route"] == "call_scoped_cpp_raii"]
        self.assertEqual(len(costs), 4)
        for cost in costs:
            for field in ("wrapper_heap_allocations", "wrapper_registry_lookups",
                          "wrapper_mutex_acquisitions", "wrapper_shared_owner_copies"):
                self.assertEqual(cost[field], 0)
        rows = report["performance"]["measurements"]
        self.assertEqual({r["case"] for r in rows}, TIMING_CASES)
        self.assertTrue(all(len(r["samples_ns"]) == 7 for r in rows))
        self.assertEqual(len({r["checksum"] for r in rows}), 1)

    def test_throwing_destructor_native_rejection_publishes_nothing(self):
        with tempfile.TemporaryDirectory(prefix="hepta-scoped-reject-") as directory:
            root = Path(directory)
            header = root / "foreign.hpp"
            header.write_text((EXAMPLE / "foreign.hpp").read_text().replace("~Probe() noexcept;", "~Probe() noexcept(false);"))
            output = root / "generated"
            report = bridge_cpp_contracts(header, contract(), output, cxx="g++")
            self.assertFalse(report["ok"])
            self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_NATIVE")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
