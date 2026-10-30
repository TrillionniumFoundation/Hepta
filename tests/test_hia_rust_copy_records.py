"""Actual raw Rust nominal admission, erasure, and same-Machine execution."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program, hia_program_composite, hia_program_runtime
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, HIAProgramBudgetExceeded, execute_program
from hepta.hia_rust_crosscheck import _execution_claims
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_program_composite import module, record, ref
from tests.test_hia_composite_abi import nominal_identity_program
from tests import test_hia_rust_bound_depth as depth_v2

PROFILE = "monomorphic-copy-records-over-primitive-v6-v1"
CLAIMS = {"raw_monomorphic_copy_records_checked": True, "same_primitive_core_reverified": True,
          "python_normalizer_or_runtime_used": False, "general_composite_input_supported": False,
          "rust_is_production_admission_authority": False, "whole_language_soundness_proved": False,
          "native_backend_refinement_proved": False}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def policy(*, steps=100_000, heap=1024 * 1024, depth=32, fail=None):
    return {"max_steps": steps, "max_heap_bytes": heap, "max_call_depth": depth,
            "allocation_fail_at": None if fail is None else hex(fail)}


def empty_entry():
    return f("entry", [], [], [], [b("entry", [], [], ret())])


def nested_values():
    args = [("wide", "u64"), ("negative", "i64"), ("flag", "bool"), ("nothing", "unit")]
    types = [record("Empty", []), record("Inside", args),
             record("Outside", [("inside", ref("Inside")), ("empty", "Empty")])]
    zero = f("zero", [("z", "Empty")], [ref("Empty")], [], [b("entry", [("z", "Empty")], [], ret("z"))])
    relay = f("relay", [("p", "Outside")], ["Outside"], [], [b("entry", [("p", "Outside")], [], ret("p"))])
    public = f("entry", args, [t for _, t in args], [], [b("entry", args, [
        i("record.make", [], [("empty", "Empty")]),
        i("call", ["empty"], [("again", "Empty")], function="zero"),
        i("record.make", [n for n, _ in args], [("inside", "Inside")]),
        i("record.make", ["inside", "again"], [("outside", "Outside")]),
        i("call", ["outside"], [("returned", "Outside")], function="relay"),
        i("record.unpack", ["returned"], [("unpacked", "Inside"), ("unused", "Empty")]),
        *[i("record.get", ["unpacked"], [("out_" + n, t)], field=n) for n, t in args],
    ], ret(*("out_" + n for n, _ in args)))])
    return module(types, zero, relay, public)


def record_loop():
    fields = [("limit", "usize"), ("index", "usize"), ("sum", "usize")]
    return module([record("State", fields)], f("entry", [("n", "usize")], ["usize"], ["trap"], [
        b("entry", [("n", "usize")], [c("zero", "usize", 0),
            i("record.make", ["n", "zero", "zero"], [("initial", "State")])], jump("loop", "initial")),
        b("loop", [("state", "State")], [
            *[i("record.get", ["state"], [(name, typ)], field=name) for name, typ in fields],
            i("compare.lt", ["index", "limit"], [("more", "bool")]),
        ], branch("more", ("body", "state"), ("done", "sum"))),
        b("body", [("carried", "State")], [
            i("record.unpack", ["carried"], [("bound", "usize"), ("current", "usize"), ("acc", "usize")]),
            c("one", "usize", 1), i("int.add.checked", ["current", "one"], [("next", "usize")]),
            i("int.add.checked", ["acc", "current"], [("total", "usize")]),
            i("record.make", ["bound", "next", "total"], [("updated", "State")]),
        ], jump("loop", "updated")),
        b("done", [("result", "usize")], [], ret("result")),
    ]))


def record_resources(*, trap=False, fallible=False):
    params = [("frame", "Frame")]
    operations = [i("record.get", ["frame"], [("size", "usize")], field="size"),
        i("buffer.try_new" if fallible else "buffer.new", ["size"],
          [("owner", "buffer"), ("ok", "bool")] if fallible else [("owner", "buffer")])]
    if not trap:
        operations += [i("borrow.mut", ["owner"], [("view", "mutbuf")]),
                       i("buffer.len", ["view"], [("length", "usize")]),
                       i("loan.end", ["view"]), i("owner.drop", ["owner"])]
    helper = f("internal", params, ["Frame"], ["alloc", "read", "trap"], [
        b("entry", params, operations, {"op": "trap", "code": "user"} if trap else ret("frame"))])
    entry = f("entry", [("n", "usize")], ["usize"], ["alloc", "read", "trap"], [
        b("entry", [("n", "usize")], [i("record.make", ["n"], [("frame", "Frame")]),
            i("call", ["frame"], [("back", "Frame")], function="internal"),
            i("record.get", ["back"], [("result", "usize")], field="size")], ret("result"))])
    return module([record("Frame", [("size", "usize")])], helper, entry)


def wide_types():
    return [record("Leaf", [("field" + str(n), "u8") for n in range(64)]),
            record("Wide", [("leaf" + str(n), "Leaf") for n in range(8)])]


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "actual raw Rust candidate requires Linux/Cargo; NOT qualified")
class RustCopyRecordCandidate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        depth_v2.RustBoundDepthParity.setUpClass.__func__(cls)
        cls.normalizations, cls.raw_inputs = [], {}

    def native(self, raw, *arguments):
        before = sha256(self.executable.read_bytes()).hexdigest()
        self.assertEqual(before, self.digest)
        # The child has neither a Python search path nor a repository cwd.
        # Disable Python admission/elaboration/execution during the actual
        # launch; only the later independent oracle may use those functions.
        environment = {"PATH": "/hepta-no-language-interpreter", "LANG": "C", "LC_ALL": "C"}
        with tempfile.TemporaryDirectory(prefix="hia-raw-rust-records-") as directory:
            with patch.object(hia_program, "verify_program", side_effect=AssertionError("Python admission called")), \
                 patch.object(hia_program_composite, "elaborate_program", side_effect=AssertionError("Python normalization called")), \
                 patch.object(hia_program_runtime, "execute_program", side_effect=AssertionError("Python execution called")), \
                 patch.object(hia_program_runtime, "_Machine", side_effect=AssertionError("Python Machine called")):
                result = subprocess.run([str(self.executable), *arguments], input=raw, cwd=directory,
                    env=environment, capture_output=True, timeout=15)
        after = sha256(self.executable.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        type(self).raw_inputs[sha256(raw).hexdigest()] = raw.decode()
        return {"argv": [str(self.executable), *arguments], "stdin_sha256": sha256(raw).hexdigest(),
                "returncode": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
                "executable_sha256_before": before, "executable_sha256_after": after,
                "child_environment": environment, "child_cwd_outside_repository": True,
                "python_admission_elaboration_and_machine_disabled_during_launch": True}

    def normalize(self, source):
        raw = source if isinstance(source, bytes) else wire(source)
        process = self.native(raw, "--composite-record-normalize")
        self.assertEqual((process["returncode"], process["stderr"]), (0, ""), process)
        observed = json.loads(process["stdout"])
        checked = verify_program(raw)
        self.assertEqual(set(observed), {"schema", "profile", "input_sha256", "program_sha256", "core", "claims"})
        self.assertEqual(observed["schema"], "hepta.hia.rust-copy-record-normalization.v1")
        self.assertEqual(observed["profile"], PROFILE)
        self.assertEqual(wire(observed["core"]), checked.canonical_bytes)
        self.assertEqual(observed["input_sha256"], checked.input_sha256)
        self.assertEqual(observed["program_sha256"], checked.sha256)
        self.assertEqual(observed["claims"], CLAIMS)
        self.assertEqual(observed["core"]["exports"], sorted(checked.scalar_entrypoints))
        type(self).normalizations.append({"test": self.id(), "process": process, "report": observed,
            "python_core_utf8": checked.canonical_json, "exact_core_bytes_and_exports_match": True})
        return observed

    def run_raw(self, source, arguments, *, entry="entry", steps=100_000, heap=1024 * 1024, depth=32, fail=None):
        raw = source if isinstance(source, bytes) else wire(source)
        selected = policy(steps=steps, heap=heap, depth=depth, fail=fail)
        process = self.native(raw, "--composite-record-run-bound-v1", entry,
                              wire(list(arguments)).decode(), wire(selected).decode())
        self.assertEqual((process["returncode"], process["stderr"]), (0, ""), process)
        observed = json.loads(process["stdout"])
        checked = verify_program(raw)
        expected_request = {"schema": "hepta.hia.rust-copy-record-request.v1", "profile": PROFILE,
            "input_sha256": checked.input_sha256, "program_sha256": checked.sha256,
            "function": entry, "arguments": list(arguments), "policy": selected}
        self.assertEqual(set(observed), {"schema", "request", "request_sha256", "execution", "claims"})
        self.assertEqual(observed["schema"], "hepta.hia.rust-copy-record-bound-execution.v1")
        self.assertEqual(wire(observed["request"]), wire(expected_request))
        self.assertEqual(observed["request_sha256"], sha256(wire(expected_request)).hexdigest())
        self.assertEqual(observed["claims"], CLAIMS)
        try:
            python = execute_program(checked, entry, arguments, max_steps=steps,
                max_heap_bytes=heap, max_call_depth=depth, allocation_fail_at=fail)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        profile, claims = _execution_claims(checked.as_dict())
        expected = {"schema": "hepta.hia.rust-byte-owner-execution.v2", "status": python["status"],
            "program_sha256": checked.sha256, "function": entry, "steps": python["steps"],
            "profile": profile, "claims": claims, "resources": python["resources"], **selected}
        expected.update({"values": python["values"]} if python["status"] == "returned" else
                        {"error": {"code": python["error"]["code"]}})
        self.assertEqual(wire(observed["execution"]), wire(expected))
        type(self).observations.append({"test": self.id(), "process": process, "report": observed,
            "python_report": python, "matched": True})
        return observed

    def refuse(self, source, *, reason, error=None, arguments=None, python_rejects=False):
        raw = source if isinstance(source, bytes) else wire(source)
        selected = arguments or ("--composite-record-normalize",)
        process = self.native(raw, *selected)
        self.assertEqual((process["returncode"], process["stdout"]), (1, ""), process)
        self.assertTrue(process["stderr"].startswith(error or "E_HIA_"), process)
        self.assertNotIn("panicked", process["stderr"])
        if python_rejects:
            with self.assertRaises(HIAProgramRejected):
                verify_program(raw)
        type(self).refusals.append({"test": self.id(), "reason": reason, "process": process,
                                   "python_rejects": python_rejects, "rejected": True})

    def test_raw_nested_and_empty_records_normalize_and_run_without_python(self):
        source = nested_values()
        normalized = self.normalize(source)
        self.assertEqual(normalized["core"]["exports"], ["entry"])
        for flag in (False, True):
            arguments = [(1 << 64) - 1, -(1 << 63), flag, None]
            result = self.run_raw(source, arguments, fail=(1 << 192) + 2)
            self.assertEqual(result["execution"]["values"], arguments)
        # Noncanonical input JSON is decoded by Rust itself and canonicalized
        # to the same nominal/Core identities before any Python oracle runs.
        pretty = json.dumps(source, indent=2).encode()
        self.assertEqual(self.normalize(pretty)["core"], normalized["core"])

    def test_raw_loops_resource_calls_refusals_traps_and_stopped_ledgers(self):
        loop = record_loop()
        self.normalize(loop)
        for count in (0, 1, 4):
            self.assertEqual(self.run_raw(loop, [count])["execution"]["values"], [count * (count - 1) // 2])
        for trap, fallible in ((False, False), (True, False), (False, True)):
            source = record_resources(trap=trap, fallible=fallible)
            self.normalize(source)
            for size in (0, 3):
                for fail in (None, 1, 2, (1 << 64) + 1):
                    self.run_raw(source, [size], fail=fail)
        source = record_resources()
        normal = self.run_raw(source, [3])
        for steps in range(1, normal["execution"]["steps"]):
            self.run_raw(source, [3], steps=steps, fail=(1 << 64) + 1)
        self.run_raw(source, [3], heap=0)
        self.run_raw(source, [3], depth=1)

    def test_different_nominal_origins_keep_distinct_bound_requests(self):
        first = nominal_identity_program()
        second = nominal_identity_program("Different", "renamed")
        a, b_ = self.normalize(first), self.normalize(second)
        self.assertEqual(a["program_sha256"], b_["program_sha256"])
        self.assertNotEqual(a["input_sha256"], b_["input_sha256"])
        one = self.run_raw(first, [17], entry="public_identity", fail=(1 << 128) + 1)
        two = self.run_raw(second, [17], entry="public_identity", fail=(1 << 128) + 1)
        self.assertNotEqual(one["request_sha256"], two["request_sha256"])
        self.assertEqual(one["execution"], two["execution"])

    def test_distinct_same_layout_types_reject_before_calls_returns_and_edges(self):
        for fields in ([], [("value", "u64")]):
            types = [record("First", fields), record("Second", fields)]
            helper = f("relay", [("v", "Second")], ["Second"], [], [b("entry", [("v", "Second")], [], ret("v"))])
            call = f("bad", [("a", "First")], ["Second"], [], [b("entry", [("a", "First")],
                [i("call", ["a"], [("back", "Second")], function="relay")], ret("back"))])
            wrong_return = f("bad", [("a", "First")], ["Second"], [], [b("entry", [("a", "First")], [], ret("a"))])
            edge = f("bad", [("a", "First")], [], [], [b("entry", [("a", "First")], [], jump("next", "a")),
                b("next", [("other", "Second")], [], ret())])
            for reason, broken in (("call", call), ("return", wrong_return), ("CFG edge", edge)):
                self.refuse(module(types, helper, broken, empty_entry()), reason="same layout " + reason,
                            python_rejects=True)
            container = record("Container", [("member", "First")])
            make = f("bad", [("a", "Second")], [], [], [b("entry", [("a", "Second")],
                [i("record.make", ["a"], [("wrong", "Container")])], ret())])
            self.refuse(module(types + [container], make, empty_entry()), reason="same layout field construction",
                        python_rejects=True)

    def test_zero_width_values_keep_ssa_identity_and_private_entry_eligibility(self):
        source = nested_values()
        selected = wire(policy()).decode()
        for entry in ("zero", "relay"):
            self.refuse(source, reason="nominal entry stays private after erasure",
                arguments=("--composite-record-run-bound-v1", entry, "[]", selected), error="E_HIA_INPUT")
        self.refuse(nominal_identity_program(), reason="one-scalar record is not scalar public ABI",
            arguments=("--composite-record-run-bound-v1", "inspect_packet", "[17]", selected), error="E_HIA_INPUT")
        for invalid in (
            f("bad", [], [], [], [b("entry", [], [i("record.make", [], [("same", "Empty")]),
                i("record.make", [], [("same", "Empty")])], ret())]),
            f("bad", [], [], [], [b("entry", [], [i("record.get", ["missing"], [("z", "Empty")], field="z")], ret())]),
            f("bad", [("z", "Empty")], ["unit"], [], [b("entry", [("z", "Empty")], [], ret("z"))]),
        ):
            self.refuse(module([record("Empty", [])], invalid, empty_entry()),
                        reason="erased zero-width SSA/type error", python_rejects=True)

    def test_unsupported_unused_forms_and_bad_primitive_helpers_refuse_whole_input(self):
        base = module([], empty_entry())
        declarations = [record("Generic", [("value", "T")], ["T"]),
            {"name": "Choice", "kind": "enum", "params": [], "variants": [{"name": "only", "fields": []}]},
            {"name": "Work", "kind": "task", "params": [], "state": "u8", "result": "u8", "poll": "p", "cancel": "c"},
            record("Owned", [("owner", "buffer")]), record("Loan", [("loan", "readbuf")]),
            record("Cycle", [("next", "Cycle")]), record("Unknown", [("value", "Missing")])]
        for declaration in declarations:
            source = deepcopy(base)
            source["types"] = [declaration]
            self.refuse(source, reason="unsupported or invalid unused declaration")
        for schema in ("hepta.hia.composite.v2", "hepta.hia.composite.v3", "hepta.hia.composite.v4", "hepta.hia.program.v2"):
            source = deepcopy(base)
            source["schema"] = schema
            self.refuse(source, reason="explicit input candidate does not widen other schemas")
        for opcode in ("record.borrow", "record.begin", "enum.make", "task.create", "future.unsafe"):
            hidden = f("hidden", [], [], [], [b("entry", [], [i(opcode, [])], ret())])
            self.refuse(module([], hidden, empty_entry()), reason="unsupported unused operation")
        leaked = f("hidden", [("n", "usize")], [], ["alloc", "trap"], [b("entry", [("n", "usize")],
            [i("buffer.new", ["n"], [("owned", "buffer")])], ret())])
        self.refuse(module([], leaked, empty_entry()), reason="unused primitive ownership error", python_rejects=True)

    def test_raw_json_refusals_and_old_primitive_protocol_admission_stay_closed(self):
        source = nominal_identity_program()
        raw = wire(source)
        for malformed in (raw[:-1] + b',"types":[]}', raw[:-1] + b',"ty\\u0070es":[]}',
                          raw + b'{}', raw.replace(b'"types":', b'"unknown":', 1)):
            self.refuse(malformed, reason="raw strict JSON/schema refusal", python_rejects=True)
        for mode in ("--owned-shadow", "--owned-run-bound-v4"):
            args = (mode,) if mode == "--owned-shadow" else (mode, "public_identity", "[3]", wire(policy()).decode())
            self.refuse(source, arguments=args, reason="legacy primitive route still refuses raw nominal input")
        core = verify_program(source)
        self.refuse(core.canonical_bytes, reason="nominal candidate does not guess primitive producer profile")
        bad_policy = policy()
        bad_policy["allocation_fail_at"] = "0x01"
        self.refuse(source, reason="existing exact v4 policy refusal",
            arguments=("--composite-record-run-bound-v1", "public_identity", "[3]", wire(bad_policy).decode()))

    def test_exact_type_name_and_value_slot_boundaries(self):
        self.normalize(module([record("Unused" + str(n), []) for n in range(128)], empty_entry()))
        self.refuse(module([record("Unused" + str(n), []) for n in range(129)], empty_entry()), reason="129 definitions", error="E_HIA_LIMIT")
        self.normalize(module(wide_types(), empty_entry()))
        too_wide = wide_types()
        too_wide[-1]["fields"].append({"name": "extra", "type": "u8"})
        self.refuse(module(too_wide, empty_entry()), reason="513 flattened fields", error="E_HIA_LIMIT")
        too_many = [record("TooMany", [("f" + str(n), "u8") for n in range(65)])]
        self.refuse(module(too_many, empty_entry()), reason="65 fields", error="E_HIA_LIMIT")
        for count in (32, 33):
            types = [record("Nested" + str(n), [("child", "u8" if n == count - 1 else "Nested" + str(n + 1))]) for n in range(count)]
            source = module(types, f("nested", [("root", "Nested0")], [], [], [b("entry", [("root", "Nested0")], [], ret())]), empty_entry())
            self.normalize(source) if count == 32 else self.refuse(source, reason="33 layout levels", error="E_HIA_LIMIT")
        for count in (128, 129):
            blocks = [b("block" + str(n), [("value" + str(n), "Leaf")], [],
                ret() if n == count - 1 else jump("block" + str(n + 1), "value" + str(n))) for n in range(count)]
            source = module(wide_types()[:1], f("many", [("value0", "Leaf")], [], [], blocks), empty_entry())
            self.normalize(source) if count == 128 else self.refuse(source, reason="8192 generated names exceeded", error="E_HIA_LIMIT")
        operations = [i("record.unpack", ["input"], [(f"part_{n}_{j}", "Leaf") for j in range(8)]) for n in range(63)]
        exact = module(wide_types(), f("aliases", [("input", "Wide")], [], [], [b("entry", [("input", "Wide")], operations, ret())]), empty_entry())
        self.normalize(exact)
        excessive = deepcopy(exact)
        excessive["functions"][0]["blocks"][0]["ops"].append(c("extra", "u8", 0))
        self.refuse(excessive, reason="32768 value slots plus one", error="E_HIA_LIMIT")

    def test_erased_return_fanout_refuses_before_wide_name_materialization(self):
        # A small raw program attempts just over the Core-node ceiling. It
        # needs no huge source, allocation workload, or unbounded stress run.
        count = 513
        helper = f("fanout", [("wide", "Wide")], ["Wide"] * count, [], [
            b("entry", [("wide", "Wide")], [], ret(*(["wide"] * count)))])
        source = module(wide_types(), helper, empty_entry())
        self.assertLess(len(wire(source)), 20_000)
        self.refuse(source, reason="513 references times 512 scalar names before erasure allocation", error="E_HIA_LIMIT")
        # Signature expansion must also refuse when a trap has no return args.
        source["functions"][0]["effects"] = ["trap"]
        source["functions"][0]["blocks"][0]["term"] = {"op": "trap", "code": "user"}
        self.refuse(source, reason="result signature fanout before vector materialization", error="E_HIA_LIMIT")
