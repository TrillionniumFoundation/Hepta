"""Real opt-in Rust admission with Python used only as a differential oracle.

Positive observations invoke the actual pinned Rust binary. Explicit tampering
controls replace only a captured response and are refusal tests, not qualifying
observations. A clean child blocks all Python semantic-module imports entirely.
"""
from copy import deepcopy
from hashlib import sha256
import json
import platform
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta import hia_rust_byte_dag as raw_mode
from hepta import hia_rust_crosscheck as transport
from hepta.hia_static_budget import analyze_static_budget
from tests import test_hia_rust_bound_depth as native
from tests.test_hia_rust_crosscheck import owned_program, scalar_program
from tests.test_hia_rust_static_budget import metric_diamond, multiple_return_loan, expanding_calls
from tests.test_hia_static_budget import acyclic_calls, cyclic_control_flow, cyclic_calls
from tests.test_hia_program import b, c, f, i, m, ret
from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_overlap_move import move_program
from tests.test_hia_swap_v4 import swap_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_range_fill_v6 import fill_program
from tests.test_hia_composite_abi import nominal_identity_program
from tests.test_hia_execution_contract import held_program
from tests.test_hia_optimization_contract import cleanup_module

wire = native.wire
METRICS = ("max_allocator_interactions", "max_vm_ticks", "max_call_depth")
OWNED_LIMITS = dict(zip(METRICS, (2, 4, 1)))
SCALAR_LIMITS = dict(zip(METRICS, (0, 2, 1)))


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual raw byte-DAG admission requires Linux/Cargo; NOT qualified")
class RustByteDagAdmission(unittest.TestCase):
    setUpClass = classmethod(native.RustBoundDepthParity.setUpClass.__func__)

    def invoke(self, raw, entry, arguments, static_policy, **policy):
        return raw_mode.execute_rust_byte_dag(raw, entry, arguments, self.executable,
            executable_sha256=self.digest, static_policy=static_policy, **policy)

    def compare(self, source, entry, arguments, *, raw=None, **policy):
        # These are test-only oracles. Neither is called by the raw Rust route.
        python_bounds = analyze_static_budget(source)
        limits = {metric: max(row[metric] for row in python_bounds["functions"]) for metric in METRICS}
        actual_transport = transport._run_pinned_shadow
        captured = []

        def record(binary, argv, payload, timeout, **kwargs):
            response = actual_transport(binary, argv, payload, timeout, **kwargs)
            captured.append({"argv": argv, "stdin_sha256": sha256(payload).hexdigest(),
                "executable_sha256": sha256(binary).hexdigest(), "stdout": response[0].decode(),
                "stderr": response[1].decode(), "returncode": response[2]})
            return response

        payload = wire(source) if raw is None else raw
        with patch.object(transport, "_run_pinned_shadow", record):
            result = self.invoke(payload, entry, arguments, limits, **policy)
        oracle = transport.crosscheck_rust_execution_v4(source, entry, arguments, self.executable,
            executable_sha256=self.digest, **policy)
        report = result["rust_report"]
        self.assertEqual(report["runtime"]["execution"], oracle["rust_report"])
        self.assertEqual(report["static_budget"]["functions"], python_bounds["functions"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["stdin_sha256"], sha256(payload).hexdigest())
        self.assertEqual(captured[0]["executable_sha256"], self.digest)
        self.assertIs(report["claims"]["rust_interpreter_admission_authority_for_this_profile"], True)
        self.assertIs(report["claims"]["default_production_admission_changed"], False)
        self.assertIs(report["claims"]["native_execution_authorized"], False)
        self.assertIs(report["runtime"]["execution"]["claims"]["production_admission_authorized"], False)
        type(self).observations.append({"test": self.id(), "request": report["request"],
            "rust_report": report, "python_report": oracle["python_report"],
            "python_bounds": python_bounds, "process": captured[0], "matched": True})
        return report

    def raw(self, source, entry, arguments, static_policy, runtime_policy):
        return subprocess.run([str(self.executable), "--byte-dag-admit-run", entry, arguments,
            static_policy, runtime_policy], input=source, capture_output=True, timeout=15)

    def test_all_primitive_versions_preserve_full_v4_results_and_exact_failure_indices(self):
        for version in range(1, 9):
            source = owned_program()
            source["schema"] = f"hepta.hia.program.v{version}"
            for failure in (None, 1, (1 << 64) + 1):
                for size in (0, 3):
                    with self.subTest(version=version, fail=failure, size=size):
                        report = self.compare(source, "allocate_release", (size,), max_steps=4,
                            max_heap_bytes=3, max_call_depth=1, allocation_fail_at=failure)
                        encoded = None if failure is None else hex(failure)
                        self.assertEqual(report["request"]["execution_policy"]["allocation_fail_at"], encoded)

    def test_raw_entry_works_when_all_python_semantic_imports_are_unavailable(self):
        code = """
import sys, json
for name in ('hia_program', 'hia_program_composite', 'hia_program_runtime',
             'hia_static_budget', 'hia_source_bridge', 'hia_program_llvm'):
    sys.modules['hepta.' + name] = None
from hepta.hia_rust_byte_dag import execute_rust_byte_dag
result = execute_rust_byte_dag(sys.stdin.buffer.read(), 'identity', [37], sys.argv[1],
    executable_sha256=sys.argv[2], static_policy={
        'max_allocator_interactions': 0, 'max_vm_ticks': 2, 'max_call_depth': 1},
    max_steps=2, max_heap_bytes=0, max_call_depth=1)
print(json.dumps(result, sort_keys=True))
"""
        result = subprocess.run([sys.executable, "-c", code, str(self.executable), self.digest],
            cwd=native.ROOT, input=wire(scalar_program()), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)["rust_report"]
        self.assertEqual(report["runtime"]["execution"]["values"], [37])
        self.assertIs(report["claims"]["python_verifier_required_for_this_mode"], False)
        with patch("hepta.hia_program.verify_program", side_effect=AssertionError("Python verifier forbidden")), \
             patch("hepta.hia_static_budget.analyze_static_budget", side_effect=AssertionError("Python analyzer forbidden")), \
             patch("hepta.hia_program_runtime.execute_program", side_effect=AssertionError("Python VM forbidden")):
            self.invoke(wire(owned_program()), "allocate_release", [3], OWNED_LIMITS)
            invalid = owned_program()
            invalid["functions"][0]["blocks"][0]["ops"].pop()
            with self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "Rust rejected"):
                self.invoke(wire(invalid), "allocate_release", [3], OWNED_LIMITS)

    def test_raw_format_and_negative_zero_bind_the_original_snapshot(self):
        source = m(f("zero", [], ["u8"], [], [b("entry", [], [c("zero", "u8", 0)], ret("zero"))]))
        variants = (wire(source), json.dumps(source, indent=2).encode(),
                    wire(source).replace(b'"value":0', b'"value":-0'),
                    wire(source).replace(b'"zero"', b'"\\u007aero"'))
        reports = [self.compare(source, "zero", [], raw=raw) for raw in variants]
        self.assertEqual(len({r["request_sha256"] for r in reports}), len(variants))
        self.assertEqual(len({r["request"]["program_sha256"] for r in reports}), 1)
        for raw, report in zip(variants, reports):
            self.assertEqual(report["request"]["input_sha256"], sha256(raw).hexdigest())
            self.assertEqual(report["runtime"], reports[0]["runtime"])

    def test_complete_differential_covers_branches_calls_multi_returns_and_stops(self):
        cases = [(metric_diamond(), "choose", [choice, 3]) for choice in (True, False)]
        cases += [(acyclic_calls(), "outer", [3]), (multiple_return_loan(), "run", [3, 37])]
        policies = ({}, {"max_steps": 1}, {"max_steps": 2}, {"max_call_depth": 1},
                    {"max_heap_bytes": 1}, {"allocation_fail_at": 1})
        for source, entry, args in cases:
            for policy in policies:
                with self.subTest(entry=entry, policy=policy):
                    self.compare(source, entry, args, **policy)
        stopped = self.compare(multiple_return_loan(), "run", [3, 37], max_steps=4)
        self.assertEqual(stopped["runtime"]["execution"]["status"], "budget_exceeded")
        self.assertGreater(stopped["runtime"]["execution"]["resources"]["live_bytes"], 0)
        self.assertIs(stopped["claims"]["successful_return_or_cleanup_guaranteed"], False)

    def test_actual_error_values_cancellation_and_allocation_traps_keep_outcome_distinctions(self):
        for args, failure, expected in (([False, 3], None, 4), ([True, 0], None, 2),
                                        ([False, 0], 1, 1)):
            result = self.compare(cleanup_module(), "run", args,
                                  allocation_fail_at=failure)["runtime"]["execution"]
            self.assertEqual((result["status"], result["values"]), ("returned", [expected]))
        result = self.compare(held_program(), "held", [4, 0],
                              allocation_fail_at=1)["runtime"]["execution"]
        self.assertEqual((result["status"], result["error"]["code"]), ("trapped", "allocation"))

    def test_captured_trap_and_quota_response_cannot_erase_retained_loans_or_payloads(self):
        source = held_program()
        limits = dict(zip(METRICS, (2, 7, 1)))
        for args, policy in (([4, 4], {}), ([4, 0], {"max_steps": 3})):
            actual = self.compare(source, "held", args, **policy)
            ledger = actual["runtime"]["execution"]["resources"]
            self.assertEqual((ledger["live_owners"], ledger["live_local_loans"], ledger["live_bytes"]), (1, 1, 4))
            for change in ({"live_local_loans": 0}, {"loans_ended": 2}, {"live_bytes": 0},
                           {"owners_dropped": 1, "live_owners": 0}, {"allocations": 0}):
                malformed = deepcopy(actual)
                malformed["runtime"]["execution"]["resources"].update(change)
                with self.subTest(policy=policy, change=change), patch.object(transport,
                        "_run_pinned_shadow", return_value=(wire(malformed) + b"\n", b"", 0)):
                    with self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "E_HIA_EXECUTION_CONTRACT"):
                        self.invoke(wire(source), "held", args, limits, **policy)

    def test_bulk_byte_operations_and_scalar_result_boundaries_use_the_same_machine(self):
        cases = ((bulk_program(), "bulk", [8, 8, 37]),
                 (move_program(), "move_bytes", [5, 1, 0, 4, 2]),
                 (swap_program(), "swap_bytes", [5, 0, 4, 0]),
                 (copy_program(), "copy_offset", [5, 1, 2, 2, 1]),
                 (fill_program(), "fill_range", [8, 2, 3, 37, 2]))
        for source, entry, args in cases:
            for policy in ({}, {"max_steps": 5}, {"allocation_fail_at": 1}):
                with self.subTest(entry=entry, policy=policy):
                    self.compare(source, entry, args, **policy)
        for typ, values in (("bool", [False, True]), ("unit", [None]),
                ("i8", [-128, 127]), ("u8", [0, 255]), ("i64", [-(1 << 63), (1 << 63) - 1]),
                ("u64", [0, (1 << 64) - 1]), ("isize", [-(1 << 63)]), ("usize", [(1 << 64) - 1])):
            source = m(f("identity", [("x", typ)], [typ], [], [b("entry", [("x", typ)], [], ret("x"))]))
            for value in values:
                with self.subTest(typ=typ, value=value):
                    self.compare(source, "identity", [value])

    def test_static_limit_boundary_applies_to_hidden_functions_before_execution(self):
        for metric in METRICS:
            wrong = dict(OWNED_LIMITS)
            wrong[metric] -= 1
            with self.subTest(metric=metric), self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "Rust rejected"):
                self.invoke(wire(owned_program()), "allocate_release", [0], wrong, max_steps=1)
        source = scalar_program()
        source["exports"] = ["identity"]
        source["functions"].extend(owned_program()["functions"])
        with self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "Rust rejected"):
            self.invoke(wire(source), "identity", [7], SCALAR_LIMITS)
        report = self.invoke(wire(source), "identity", [7], OWNED_LIMITS)["rust_report"]
        self.assertEqual(len(report["static_budget"]["functions"]), 2)
        self.assertEqual(report["runtime"]["execution"]["values"], [7])

    def test_unknown_scope_and_invalid_hidden_resources_refuse_with_actual_rust(self):
        chain = scalar_program()
        chain["schema"] = "hepta.hia.program.v8"
        chain["functions"].append(f("destroy", [("root", "chain")], [], ["alloc"], [
            b("entry", [("root", "chain")], [i("owner.drop", ["root"])], ret())]))
        invalid = scalar_program()
        hidden = owned_program()["functions"][0]
        hidden["blocks"][0]["ops"].pop()
        invalid["functions"].append(hidden)
        unknown = scalar_program()
        unknown["functions"].append(f("hidden", [], [], [], [
            b("entry", [], [i("future.unsafe")], ret())]))
        cases = [chain, invalid, unknown, nominal_identity_program(), expanding_calls(63)]
        for hidden_module in (cyclic_control_flow(), cyclic_calls()):
            source = scalar_program()
            source["functions"].extend(hidden_module["functions"])
            cases.append(source)
        largest = {metric: (1 << 64) - 1 for metric in METRICS}
        for source in cases:
            with self.subTest(schema=source["schema"], functions=len(source["functions"])):
                raw = self.raw(wire(source), "identity", "[7]", wire(largest).decode(), wire({
                    "max_steps": 1, "max_heap_bytes": 0, "max_call_depth": 1,
                    "allocation_fail_at": "0x1"}).decode())
                self.assertEqual(raw.returncode, 1)
                self.assertEqual(raw.stdout, b"")
                self.assertTrue(raw.stderr.startswith(b"E_HIA_"), raw.stderr)
                self.assertNotIn(b"panicked", raw.stderr)
                with self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "Rust rejected"):
                    self.invoke(wire(source), "identity", [7], largest, max_steps=1,
                                max_heap_bytes=0, max_call_depth=1, allocation_fail_at=1)

    def test_native_and_transport_policies_keep_exact_types_and_public_boundary(self):
        runtime = wire({"max_steps": 4, "max_heap_bytes": 8, "max_call_depth": 1,
                        "allocation_fail_at": None}).decode()
        static = wire(OWNED_LIMITS).decode()
        raw_static = [static + "{}", static[:-1] + ',"max_vm_ticks":4}',
                      static.replace('"max_vm_ticks":4', '"max_vm_ticks":4.0'),
                      " " * (1025 - len(static)) + static]
        for malformed in raw_static:
            observed = self.raw(wire(owned_program()), "allocate_release", "[3]", malformed, runtime)
            self.assertEqual(observed.returncode, 1)
            self.assertEqual(observed.stdout, b"")
        for bad in (True, -1, 1.0, "4", None, 1 << 64):
            with patch.object(transport, "_verified_executable_bytes") as launch:
                with self.assertRaises(raw_mode.HIARustByteDagRejected):
                    self.invoke(wire(owned_program()), "allocate_release", [3], {**OWNED_LIMITS, "max_vm_ticks": bad})
                launch.assert_not_called()
        source = scalar_program()
        source["exports"] = []
        for module, args in ((source, [7]), (scalar_program(), [True]), (scalar_program(), [-1])):
            with self.assertRaisesRegex(raw_mode.HIARustByteDagRejected, "Rust rejected"):
                self.invoke(wire(module), "identity", args, SCALAR_LIMITS)
        for mutable_or_normalized in (bytearray(wire(source)), source, wire(source).decode()):
            with self.assertRaises(raw_mode.HIARustByteDagRejected):
                self.invoke(mutable_or_normalized, "identity", [7], SCALAR_LIMITS)

    def test_wide_policy_wire_limit_and_pin_are_enforced_before_process_start(self):
        selected = {"max_steps": 2, "max_heap_bytes": 0, "max_call_depth": 1, "allocation_fail_at": None}
        digits = 1024 - len(wire(selected))
        index = 1 << (4 * (digits - 1))
        report = self.invoke(wire(scalar_program()), "identity", [7], SCALAR_LIMITS,
            max_steps=2, max_heap_bytes=0, max_call_depth=1, allocation_fail_at=index)["rust_report"]
        self.assertEqual(len(wire(report["request"]["execution_policy"])), 1024)
        self.assertEqual(int(report["request"]["execution_policy"]["allocation_fail_at"], 16), index)
        with patch.object(transport, "_run_pinned_shadow") as launch:
            with self.assertRaises(raw_mode.HIARustByteDagRejected):
                self.invoke(wire(scalar_program()), "identity", [7], SCALAR_LIMITS,
                    max_steps=2, max_heap_bytes=0, max_call_depth=1, allocation_fail_at=index << 4)
            with self.assertRaises(raw_mode.HIARustByteDagRejected):
                raw_mode.execute_rust_byte_dag(wire(scalar_program()), "identity", [7], self.executable,
                    executable_sha256="0" * 64, static_policy=SCALAR_LIMITS)
            launch.assert_not_called()

    def test_rehashed_request_replay_protocol_changes_and_claim_promotions_reject(self):
        source = scalar_program()
        raw = json.dumps(source, indent=2).encode()
        actual = self.invoke(raw, "identity", [7], SCALAR_LIMITS)["rust_report"]
        variants = []
        for field, wrong in (("input_sha256", actual["request"]["program_sha256"]),
                ("program_sha256", "0" * 64), ("function", "private"), ("arguments", [8]),
                ("static_policy", {**SCALAR_LIMITS, "max_vm_ticks": 3}),
                ("execution_policy", {**actual["request"]["execution_policy"], "max_steps": 1_000_001})):
            changed = deepcopy(actual)
            changed["request"][field] = wrong
            changed["request_sha256"] = sha256(wire(changed["request"])).hexdigest()
            variants.append(changed)
        for section, field, value in (("claims", "native_execution_authorized", True),
                ("claims", "default_production_admission_changed", True),
                ("claims", "rust_interpreter_admission_authority_for_this_profile", 1)):
            changed = deepcopy(actual)
            changed[section][field] = value
            variants.append(changed)
        for field, value in (("profile", "future-profile"), ("core_schema", "hepta.hia.program.v8")):
            changed = deepcopy(actual)
            changed["static_budget"][field] = value
            variants.append(changed)
        for field, value in (("function", "other"), ("max_vm_ticks", True), ("max_call_depth", 1 << 64)):
            changed = deepcopy(actual)
            changed["static_budget"]["functions"][0][field] = value
            variants.append(changed)
        changed = deepcopy(actual)
        changed["static_budget"]["functions"] = []
        variants.append(changed)
        changed = deepcopy(actual)
        changed["runtime"]["request"]["policy"]["allocation_fail_at"] = "0x1"
        changed["runtime"]["request_sha256"] = sha256(wire(changed["runtime"]["request"])).hexdigest()
        variants.append(changed)
        changed = deepcopy(actual)
        changed["runtime"]["schema"] = "hepta.hia.rust-bound-execution.v3"
        variants.append(changed)
        changed = deepcopy(actual)
        changed["runtime"]["execution"]["claims"]["production_admission_authorized"] = True
        variants.append(changed)
        changed = deepcopy(actual)
        changed["runtime"]["execution"]["resources"]["live_bytes"] = 1
        variants.append(changed)
        changed = deepcopy(actual)
        changed["runtime"]["execution"]["steps"] = 3
        variants.append(changed)
        raw_variants = [wire(item) + b"\n" for item in variants]
        raw_variants += [wire(actual) + b"\n{}\n", wire(actual)[:-1] + b',"claims":{}}\n']
        for index, response in enumerate(raw_variants):
            with self.subTest(index=index), patch.object(transport, "_run_pinned_shadow", return_value=(response, b"", 0)):
                with self.assertRaises(raw_mode.HIARustByteDagRejected):
                    self.invoke(raw, "identity", [7], SCALAR_LIMITS)

    def test_caller_mutation_and_complete_large_inventory_do_not_rebind_snapshot(self):
        source = scalar_program()
        static, arguments = dict(SCALAR_LIMITS), [7]
        actual_transport = transport._run_pinned_shadow

        def mutate_caller(*args, **kwargs):
            static["max_vm_ticks"] = 999
            arguments[0] = 999
            return actual_transport(*args, **kwargs)

        with patch.object(transport, "_run_pinned_shadow", mutate_caller):
            report = self.invoke(wire(source), "identity", arguments, static)["rust_report"]
        self.assertEqual(report["request"]["arguments"], [7])
        self.assertEqual(report["request"]["static_policy"], SCALAR_LIMITS)
        large = m(*(f("f" + str(index) + "x" * 110, [], [], [], [b("entry", [], [], ret())])
                    for index in range(400)))
        report = self.compare(large, large["functions"][0]["name"], [])
        self.assertEqual(len(report["static_budget"]["functions"]), 400)
        self.assertGreater(len(wire(report)), transport.MAX_OUTPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
