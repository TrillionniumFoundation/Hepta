"""Composite v4 field origins, independently admitted primitive v8 execution.

Nominal input is not fed to Rust as if Rust independently elaborated it: Rust
parses the actual normalized primitive bytes. Native observations are finite
Linux host tests, not a backend-refinement or public borrowed-ABI proof.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_core
from hepta.hia_program_composite import elaborate_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2,
    COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4, SCHEMA_V7, SCHEMA_V8,
    composite_core_schema, schema_registry)
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_program_composite import module, record, ref
from tests.test_hia_partial_record import partial, task_partial_program, roundtrip_program
from tests.test_hia_returned_loans import build_allocator_observer, CANONICAL_CLANG, loan_program
from tests import test_hia_rust_owned_cfg as cfg

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = os.environ.get("HEPTA_COMPOSITE_V4_EVIDENCE_DIR")


def origin(param, *fields):
    return {"param": param, "fields": list(fields)}


def v4(types, *functions):
    result = module(types, *functions)
    result["schema"] = COMPOSITE_SCHEMA_V4
    return result


def pair_program(mode="read"):
    """Nested two-origin calls while actual owners stay in partial records."""
    loan = mode + "buf"
    own = "OwnedPair"
    empty, left, right, both = (partial(own, *names) for names in
                               [(), ("left",), ("right",), ("left", "right")])
    types = [record(own, [("left", "buffer"), ("right", "buffer")]),
             record("Views", [("prefix", "u16"), ("left", loan), ("right", loan)]),
             record("Envelope", [("header", "u32"), ("inner", "Views")])]
    params = [("views", "Envelope"), ("which", "bool")]
    get = f("get_pair", params, [loan, loan], [], [
        b("entry", params, [], branch("which", ("joined", "views"), ("joined", "views"))),
        b("joined", [("renamed", "Envelope")], [
            i("record.unpack", ["renamed"], [("header", "u32"), ("inner", "Views")]),
            i("record.unpack", ["inner"], [("prefix", "u16"), ("left", loan), ("right", loan)]),
            i("borrow." + mode, ["right"], [("right_child", loan)]),
            i("borrow." + mode, ["left"], [("left_child", loan)]),
        ], ret("right_child", "left_child")),
    ])
    get["return_loans"] = [origin("views", "inner", "right"), origin("views", "inner", "left")]
    relay = f("relay_pair", params, [loan, loan], [], [b("entry", params, [
        i("call", ["views", "which"], [("right", loan), ("left", loan)], function="get_pair"),
    ], ret("right", "left"))])
    relay["return_loans"] = deepcopy(get["return_loans"])
    cleanup_one = f("cleanup_one", [("state", left)], [], ["alloc"], [b("entry", [("state", left)], [
        i("record.take", ["state"], [("owner", "buffer"), ("empty", empty)], field="left"),
        i("owner.drop", ["owner"]), i("record.abandon", ["empty"]),
    ], ret())])
    cleanup_both = f("cleanup_both", [("state", both)], [], ["alloc"], [b("entry", [("state", both)], [
        i("record.take", ["state"], [("last", "buffer"), ("first", left)], field="right"),
        i("owner.drop", ["last"]), i("call", ["first"], function="cleanup_one"),
    ], ret())])
    work = [
        c("zero", "usize", 0),
        i("record.borrow", ["ready"], [("left_init", "mutbuf")], field="left", mode="mut"),
        i("record.borrow", ["ready"], [("right_init", "mutbuf")], field="right", mode="mut"),
        c("offset", "u8", 17), i("int.add.wrap", ["value", "offset"], [("right_value", "u8")]),
        i("buffer.store", ["left_init", "zero", "value"]),
        i("buffer.store", ["right_init", "zero", "right_value"]),
    ]
    if mode == "read":
        work += [i("loan.end", ["left_init"]), i("loan.end", ["right_init"]),
                 i("record.borrow", ["ready"], [("left_parent", loan)], field="left", mode=mode),
                 i("record.borrow", ["ready"], [("right_parent", loan)], field="right", mode=mode)]
        parents = ["left_parent", "right_parent"]
    else:
        parents = ["left_init", "right_init"]
    work += [c("prefix", "u16", 113), c("header", "u32", 114),
        i("record.make", ["prefix", *parents], [("inner", "Views")]),
        i("record.make", ["header", "inner"], [("views", "Envelope")]),
        i("call", ["views", "condition"], [("returned_right", loan), ("returned_left", loan)], function="relay_pair")]
    if mode == "mut":
        work += [c("five", "u8", 5), c("nine", "u8", 9),
            i("int.add.wrap", ["value", "five"], [("new_right", "u8")]),
            i("int.add.wrap", ["value", "nine"], [("new_left", "u8")]),
            i("buffer.store", ["returned_right", "zero", "new_right"]),
            i("buffer.store", ["returned_left", "zero", "new_left"])]
    work += [i("loan.end", ["returned_right"]), i("loan.end", ["returned_left"]),
        i("record.unpack", ["views"], [("old_header", "u32"), ("old_inner", "Views")]),
        i("record.unpack", ["old_inner"], [("old_prefix", "u16"), ("old_left", loan), ("old_right", loan)]),
        i("buffer.load", ["old_left", "zero"], [("left_answer", "u8")]),
        i("buffer.load", ["old_right", "zero"], [("right_answer", "u8")]),
        c("three", "u8", 3), i("int.mul.wrap", ["left_answer", "three"], [("weighted", "u8")]),
        i("int.add.wrap", ["weighted", "right_answer"], [("answer", "u8")]),
        i("loan.end", ["old_left"]), i("loan.end", ["old_right"]),
        i("call", ["ready"], function="cleanup_both")]
    params = [("size", "usize"), ("byte", "u8"), ("which", "bool")]
    main = f("probe", params, ["u8"], ["alloc", "read", "write", "trap"], [
        b("entry", params, [
            i("record.begin", out=[("empty", empty)]),
            i("buffer.try_new", ["size"], [("first", "buffer"), ("ok", "bool")]),
            i("record.insert", ["empty", "first"], [("left_state", left)], field="left"),
        ], branch("ok", ("second", "left_state", "size", "byte", "which"), ("failed_first", "left_state"))),
        b("failed_first", [("failed", left)], [
            i("call", ["failed"], function="cleanup_one"), c("sentinel", "u8", 241),
        ], ret("sentinel")),
        b("second", [("state", left), ("length", "usize"), ("input", "u8"), ("select", "bool")], [
            i("buffer.try_new", ["length"], [("second", "buffer"), ("second_ok", "bool")]),
            i("record.insert", ["state", "second"], [("both", both)], field="right"),
        ], branch("second_ok", ("work", "both", "input", "select"), ("failed_second", "both"))),
        b("failed_second", [("failed_both", both)], [
            i("call", ["failed_both"], function="cleanup_both"), c("second_sentinel", "u8", 242),
        ], ret("second_sentinel")),
        b("work", [("ready", both), ("value", "u8"), ("condition", "bool")], work, ret("answer")),
    ])
    return v4(types, get, relay, cleanup_one, cleanup_both, main)


def task_program():
    """Returned loan is ended during poll before partial-state cancellation."""
    source = task_partial_program()
    source["schema"] = COMPOSITE_SCHEMA_V4
    helper = f("task_view", [("input", "readbuf")], ["readbuf"], [], [
        b("entry", [("input", "readbuf")], [
            i("borrow.read", ["input"], [("child", "readbuf")]),
        ], ret("child"))])
    helper["return_loans"] = [origin("input")]
    poll = source["functions"][0]["blocks"][0]["ops"]
    poll[:0] = [i("record.borrow", ["state"], [("parent_view", "readbuf")], field="first", mode="read"),
                i("call", ["parent_view"], [("returned_view", "readbuf")], function="task_view"),
                i("buffer.len", ["returned_view"], [("view_length", "usize")]),
                i("loan.end", ["returned_view"]), i("loan.end", ["parent_view"])]
    source["functions"].append(helper)
    wrapper = f("task_probe", [("size", "usize"), ("mode", "u8")], ["u8"], ["alloc", "trap"], [
        b("entry", [("size", "usize"), ("mode", "u8")], [
            i("call", ["size", "mode"], [("result", "usize")], function="partial_task"),
            i("int.cast", ["result"], [("byte", "u8")], mode="checked"),
        ], ret("byte"))])
    source["functions"].append(wrapper)
    return source


def expected(mode, byte):
    return ((3 * ((byte + 9) & 255) + ((byte + 5) & 255)) if mode == "mut"
            else 3 * byte + ((byte + 17) & 255)) & 255


def direct_downgrade_program():
    source = loan_program("read", "child")
    source["schema"] = COMPOSITE_SCHEMA_V4
    source["types"] = []
    source.pop("exports", None)
    helper, caller = source["functions"]
    helper["params"][0]["type"] = helper["blocks"][0]["params"][0]["type"] = "mutbuf"
    helper["return_loans"] = [origin("input")]
    parent = next(op for op in caller["blocks"][0]["ops"] if op["op"] == "borrow.read")
    parent["op"], parent["out"][0]["type"] = "borrow.mut", "mutbuf"
    return source


def invalid_flat_calls():
    result = []
    for kind in ("aliased_mutable_arguments", "read_suspended_parent"):
        source = verify_core(pair_program("mut")).as_dict()
        operations = source["functions"][-1]["blocks"][-1]["ops"]
        position = next(n for n, op in enumerate(operations) if op["op"] == "call")
        call = operations[position]
        if kind == "aliased_mutable_arguments":
            call["args"][3] = call["args"][2]
        else:
            operations.insert(position + 1, i("buffer.load", [call["args"][3], "zero"], [("early_read", "u8")]))
        result.append(source)
    return result


class CompositeReturnedLoans(unittest.TestCase):
    def test_new_schema_and_unchanged_legacy_targets(self):
        versions = {row["schema"]: row for row in schema_registry()["composite_versions"]}
        self.assertEqual(versions[COMPOSITE_SCHEMA_V4]["normalizes_to"], SCHEMA_V8)
        self.assertEqual(composite_core_schema(COMPOSITE_SCHEMA_V3), SCHEMA_V7)
        for schema in (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2, COMPOSITE_SCHEMA_V3):
            source = pair_program(); source["schema"] = schema
            with self.subTest(schema=schema), self.assertRaises(HIAProgramRejected):
                verify_core(source)
        old = roundtrip_program()
        self.assertEqual(verify_core(old).as_dict()["schema"], SCHEMA_V7)

    def test_nested_origins_bind_original_entry_slots_after_cfg_renaming(self):
        for mode in ("read", "mut"):
            source = pair_program(mode)
            snapshot = deepcopy(source)
            checked = verify_core(source)
            self.assertEqual(source, snapshot)
            self.assertEqual(json.loads(checked.structured_bytes), source)
            core = checked.as_dict()
            self.assertEqual(core["schema"], SCHEMA_V8)
            self.assertEqual(core["exports"], ["probe"])
            for fn in core["functions"][:2]:
                self.assertEqual(fn["return_loans"], [fn["params"][3]["name"], fn["params"][2]["name"]])
            for choose in (False, True):
                for byte in (0, 37, 250, 255):
                    report = execute_program(checked, "probe", [3, byte, choose])
                    self.assertEqual(report["values"], [expected(mode, byte)])
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["live_local_loans"], 0)
            source["functions"][0]["return_loans"].reverse()
            self.assertEqual(execute_program(checked, "probe", [3, 37, True])["values"], [expected(mode, 37)])

    def test_generic_record_leaf_resolution_keeps_exact_flat_slots(self):
        source = pair_program("mut")
        source["types"][1]["params"] = ["T"]
        for field in source["types"][1]["fields"][1:]:
            field["type"] = "T"
        pending = [source]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if item.get("type") == "Views":
                    item["type"] = ref("Views", "mutbuf")
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        checked = verify_core(source)
        get = checked.as_dict()["functions"][0]
        self.assertEqual(get["return_loans"], [get["params"][3]["name"], get["params"][2]["name"]])
        self.assertEqual(execute_program(checked, "probe", [3, 250, True])["values"], [expected("mut", 250)])

    def test_zero_width_record_dag_does_not_expand_origin_ownership_walk(self):
        types = [record("Empty", [])]
        for n in range(16):
            previous = "Empty" if n == 0 else "Empty" + str(n - 1)
            types.append(record("Empty" + str(n), [("slot" + str(j), previous) for j in range(8)]))
        types.append(record("Views", [("prefix", "Empty15"), ("reader", "readbuf")]))
        reader = f("read_view", [("views", "Views")], ["readbuf"], [], [
            b("entry", [("views", "Views")], [
                i("record.borrow", ["views"], [("result", "readbuf")], field="reader", mode="read"),
            ], ret("result"))])
        reader["return_loans"] = [origin("views", "reader")]
        # Keep a regression failure bounded if the recursive walk reappears.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dag.json"; path.write_text(json.dumps(v4(types, reader)))
            completed = subprocess.run([sys.executable, "-m", "hepta", "hia", "normalize", str(path)],
                                       cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            fn = json.loads(completed.stdout)["functions"][0]
            self.assertEqual(len(fn["params"]), 1)
            self.assertEqual(fn["return_loans"], [fn["params"][0]["name"]])

    def test_direct_mutable_parameter_can_return_checked_read_child(self):
        source = direct_downgrade_program()
        checked = verify_core(source)
        helper = checked.as_dict()["functions"][0]
        self.assertEqual(helper["params"][0]["type"], "mutbuf")
        self.assertEqual(helper["returns"], ["readbuf"])
        self.assertEqual(helper["return_loans"], ["input"])
        self.assertEqual(execute_program(checked, "entry_read_child", [3, 37])["values"], [37])

    def test_missing_extra_forged_metadata_and_field_indices_refuse(self):
        bad = [None, [], [None, None], ["views", "views"],
               [origin("missing", "inner", "right"), origin("views", "inner", "left")],
               [origin("views", "inner", "absent"), origin("views", "inner", "left")],
               [origin("views", "inner", True), origin("views", "inner", "left")],
               [origin("views", "inner", 1), origin("views", "inner", "left")],
               [origin("views", "header"), origin("views", "inner", "left")],
               [origin("views", "inner"), origin("views", "inner", "left")],
               [{"param": "views", "fields": ["inner", "right"], "slot": 3}, origin("views", "inner", "left")],
               [origin("views", *(["inner"] * 33)), origin("views", "inner", "left")]]
        for annotation in bad:
            source = pair_program()
            if annotation is None:
                del source["functions"][0]["return_loans"]
            else:
                source["functions"][0]["return_loans"] = annotation
            with self.subTest(annotation=annotation), self.assertRaises(HIAProgramRejected):
                verify_core(source)
        source = pair_program(); source["functions"][-1]["return_loans"] = [origin("size")]
        with self.assertRaises(HIAProgramRejected):
            verify_core(source)
        source = pair_program(); unused = deepcopy(source["functions"][0]); unused["name"] = "unused"
        unused["return_loans"][0]["param"] = "missing"
        source["functions"].append(unused)
        with self.assertRaises(HIAProgramRejected):
            verify_core(source)

    def test_wrong_original_field_and_parent_conflicts_refuse_in_primitive_checker(self):
        source = pair_program("mut")
        source["functions"][0]["return_loans"].reverse()
        # Elaboration is not authority: its output reaches the independent
        # primitive checker, which sees the wrong original field ancestry.
        untrusted = elaborate_program(source)
        with self.assertRaisesRegex(HIAProgramRejected, "declared parameter"):
            verify_core(untrusted)
        with self.assertRaises(HIAProgramRejected):
            verify_core(source)
        source = pair_program("mut")
        work = source["functions"][-1]["blocks"][-1]["ops"]
        call = next(n for n, op in enumerate(work) if op["op"] == "call")
        work.insert(call + 1, i("record.borrow", ["ready"], [("conflict", "mutbuf")], field="right", mode="mut"))
        with self.assertRaises(HIAProgramRejected):
            verify_core(elaborate_program(source))
        for bad in invalid_flat_calls():
            with self.assertRaises(HIAProgramRejected):
                verify_core(bad)

    def test_stored_borrowed_results_owned_origins_and_permission_escalation_refuse(self):
        source = pair_program()
        source["functions"][0]["returns"] = ["Envelope"]
        source["functions"][0]["return_loans"] = [origin("views")]
        with self.assertRaisesRegex(HIAProgramRejected, "stored loans"):
            verify_core(source)
        source = pair_program()
        source["functions"][0]["returns"][0] = "mutbuf"
        with self.assertRaisesRegex(HIAProgramRejected, "sufficient permission"):
            verify_core(source)
        for parameter in ("buffer", partial("OwnedPair", "left")):
            source = pair_program()
            fn = source["functions"][0]
            fn["params"][0]["type"] = parameter
            with self.subTest(parameter=parameter), self.assertRaisesRegex(HIAProgramRejected, "loan-only parameter"):
                verify_core(source)

    def test_composite_core_binding_is_rechecked_and_nominal_abi_not_promoted(self):
        checked = verify_core(pair_program())
        mutated = checked.as_dict(); mutated["functions"][0]["return_loans"].reverse()
        forged = VerifiedProgram(json.dumps(mutated).encode(), checked.structured_bytes)
        with self.assertRaises(HIAProgramRejected):
            verify_core(forged)
        core = checked.as_dict(); core["exports"].append("get_pair")
        with self.assertRaisesRegex(HIAProgramRejected, "public exports"):
            verify_core(core)

    def test_partial_owner_failure_cleanup_and_cooperative_cancellation(self):
        for mode in ("read", "mut"):
            for failure, answer in ((1, 241), (2, 242)):
                result = execute_program(pair_program(mode), "probe", [3, 37, True], allocation_fail_at=failure)
                self.assertEqual(result["values"], [answer])
                self.assertEqual(result["resources"]["live_owners"], 0)
                self.assertEqual(result["resources"]["allocations"], result["resources"]["frees"])
        for mode, answer in ((0, 30), (1, 10), (2, 27)):
            self.assertEqual(execute_program(task_program(), "task_probe", [7, mode])["values"], [answer])

    def test_actual_cli_nominal_verify_inspect_and_execute_roundtrip(self):
        records = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "composite.json"
            path.write_text(json.dumps(pair_program("mut")))
            normalized = Path(temporary) / "core.json"
            for command in (["verify", str(path)], ["inspect", str(path)],
                            ["normalize", str(path), "-o", str(normalized)],
                            ["run", str(path), "--function", "probe", "--arguments", "[3,37,true]"],
                            ["run", str(normalized), "--function", "probe", "--arguments", "[3,37,true]"]):
                completed = subprocess.run([sys.executable, "-m", "hepta", "hia", *command],
                                           cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                result = json.loads(completed.stdout)
                if command[0] == "run":
                    self.assertEqual(result["values"], [expected("mut", 37)])
                if command[0] == "normalize":
                    self.assertEqual(verify_core(normalized.read_bytes()).canonical_bytes,
                                     verify_core(path.read_bytes()).canonical_bytes)
                records.append({"argv": completed.args, "returncode": completed.returncode,
                                "stdout": completed.stdout, "stderr": completed.stderr})
        if EVIDENCE:
            destination = Path(EVIDENCE); destination.mkdir(parents=True, exist_ok=True)
            (destination / "cli.json").write_text(json.dumps(records, indent=2) + "\n")


@unittest.skipUnless(shutil.which("cargo"), "actual Rust toolchain required")
class CompositeReturnedLoansRust(unittest.TestCase):
    execution_profile = "bounded-cfg-byte-owner-loan-returns-v4"
    raw_run = cfg.RustByteOwnerCfgParity.raw_run
    parity = cfg.RustByteOwnerCfgParity.parity

    @classmethod
    def setUpClass(cls):
        cfg.RustByteOwnerCfgParity.setUpClass.__func__(cls)
        cls.rejections = []

    @classmethod
    def tearDownClass(cls):
        print(f"Composite v4/Python/Rust ledger observations: {len(cls.observations)}; raw Rust refusals: {len(cls.rejections)}")
        if EVIDENCE:
            directory = Path(EVIDENCE) / "rust"
            directory.mkdir(parents=True, exist_ok=False)
            shutil.copy2(cls.executable, directory / "hia-core-shadow")
            (directory / "observations.json").write_text(json.dumps({"build": cls.build,
                "sources": cls.sources, "observations": cls.observations, "rejections": cls.rejections}, indent=2) + "\n")

    def test_actual_rust_values_failures_and_every_selected_step_cut(self):
        self.assertEqual(self.parity(direct_downgrade_program(), "entry_read_child", [3, 37])["values"], [37])
        for mode in ("read", "mut"):
            source = pair_program(mode)
            for byte in (0, 37, 250, 255):
                for choose in (False, True):
                    self.assertEqual(self.parity(source, "probe", [3, byte, choose])["values"], [expected(mode, byte)])
            for fail in (1, 2):
                self.parity(source, "probe", [3, 37, True], fail=fail)
            self.parity(source, "probe", [0, 37, True])  # bounds trap, stopped resources retained
            completed = self.parity(source, "probe", [3, 37, True])
            for step in range(1, completed["steps"] + 1):
                self.parity(source, "probe", [3, 37, True], steps=step)

    def test_actual_rust_task_partial_state_and_cancel_cleanup(self):
        source = task_program()
        for size in (0, 1, 7):
            for mode in (0, 1, 2):
                for fail in (None, 1):
                    self.parity(source, "task_probe", [size, mode], fail=fail)
        completed = self.parity(source, "task_probe", [7, 1])
        for step in range(1, completed["steps"] + 1):
            self.parity(source, "task_probe", [7, 1], steps=step)

    def test_independent_rust_rejects_wrong_flat_origins_and_loan_conflicts(self):
        invalid = []
        source = pair_program("mut"); source["functions"][0]["return_loans"].reverse()
        invalid.append(elaborate_program(source))
        source = verify_core(pair_program("mut")).as_dict()
        fn = source["functions"][0]; fn["blocks"][-1]["term"]["values"][1] = fn["blocks"][-1]["term"]["values"][0]
        invalid.append(source)
        source = verify_core(pair_program("mut")).as_dict()
        source["functions"][0]["return_loans"] = [None, None]
        invalid.append(source)
        invalid.extend(invalid_flat_calls())
        for source in invalid:
            with self.assertRaises(HIAProgramRejected):
                verify_core(source)
            raw = json.dumps(source).encode()
            for budget in (1, 1000):
                process = self.raw_run(raw, "probe", [3, 37, True], steps=budget, fail=1)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(process.stdout, b"")
                type(self).rejections.append({"raw_core": source, "argv": process.args,
                    "returncode": process.returncode, "stdout": process.stdout.decode(), "stderr": process.stderr.decode()})
        raw = json.dumps(pair_program()).encode()
        nominal = self.raw_run(raw, "probe", [3, 37, True])
        self.assertNotEqual(nominal.returncode, 0)  # no false independent nominal elaboration claim
        type(self).rejections.append({"raw_nominal": json.loads(raw), "argv": nominal.args,
            "returncode": nominal.returncode, "stdout": nominal.stdout.decode(), "stderr": nominal.stderr.decode()})


@unittest.skipUnless(CANONICAL_CLANG and sys.platform == "linux", "actual Linux Clang allocator observer required")
class CompositeReturnedLoansNative(unittest.TestCase):
    def test_actual_allocator_observations_and_wrong_native_control(self):
        observations = []
        temporary = None
        if EVIDENCE:
            root = Path(EVIDENCE) / "native"; root.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        try:
            for mode in ("read", "mut", "task"):
                directory = root / mode; directory.mkdir()
                source = task_program() if mode == "task" else pair_program(mode)
                entry = "task_probe" if mode == "task" else "probe"
                cases = ([(7, 0), (7, 1), (7, 2), (0, 0), (0, 1), (0, 2)] if mode == "task" else
                         [(1, 0, False), (1, 255, True), (3, 37, False), (3, 37, True),
                          (7, 250, False), (7, 255, True)])
                target = next(fn for fn in source["functions"] if fn["name"] == entry)
                calls = {}
                for index, arguments in enumerate(cases):
                    name = "native_case_" + str(index)
                    constants = [c("arg_" + str(n), param["type"], value)
                                 for n, (param, value) in enumerate(zip(target["params"], arguments))]
                    source["functions"].append(f(name, [], ["u8"], target["effects"], [
                        b("entry", [], constants + [i("call", ["arg_" + str(n) for n in range(len(arguments))],
                                                       [("answer", "u8")], function=entry)], ret("answer"))]))
                    calls[name] = ("void", name + "()")
                (directory / "nominal.json").write_text(json.dumps(source, indent=2) + "\n")
                (directory / "core.json").write_bytes(verify_core(source).canonical_bytes)
                binary, receipt = build_allocator_observer(source, directory, calls)
                for wrapper, arguments in zip(calls, cases):
                    for failure in (0, 1, 2):
                        completed = subprocess.run([str(binary), wrapper, str(failure)], capture_output=True, text=True, timeout=15)
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertEqual(completed.stderr, "")
                        native = json.loads(completed.stdout)
                        vm = execute_program(source, wrapper, [], allocation_fail_at=failure or None)
                        self.assertEqual(native["result"], vm["result"])
                        for name in ("allocations", "frees", "live_bytes", "peak_bytes"):
                            self.assertEqual(native[name], vm["resources"][name])
                        self.assertEqual(native["bad_frees"], 0)
                        observations.append({"mode": mode, "case": wrapper, "arguments": arguments,
                            "failure": failure, "build": receipt, "argv": completed.args,
                            "returncode": completed.returncode, "stdout": completed.stdout,
                            "stderr": completed.stderr, "native": native, "python": vm})
                # Deliberate C implementations are observer controls only,
                # never admitted HIA artifacts or optimization candidates.
                first = next(iter(calls))
                reference = execute_program(source, first, [])
                for label in ("wrong_value", "missing_free"):
                    wrong = directory / (label + ".c")
                    body = "return 0;"
                    if label == "missing_free":
                        size = cases[0][0]
                        body = "".join("retained[%d] = calloc(%d,1);" % (n, size)
                                       for n in range(reference["resources"]["allocations"]))
                        body += "return " + str(reference["result"]) + ";"
                    wrong.write_text("#include <stdint.h>\n#include <stdlib.h>\nstatic void *volatile retained[2];\n" +
                                     "\n".join("uint8_t " + name + "(void){" + body + "}" for name in calls))
                    command = [CANONICAL_CLANG, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                               str(directory / "observer.c"), str(wrong), "-o", str(directory / label)]
                    built = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    rejected = subprocess.run([str(directory / label), first, "0"], capture_output=True, text=True, timeout=15)
                    self.assertEqual(rejected.returncode, 0)
                    actual = json.loads(rejected.stdout)
                    if label == "wrong_value":
                        self.assertNotEqual(actual["result"], reference["result"])
                    else:
                        self.assertEqual(actual["result"], reference["result"])
                        self.assertEqual(actual["allocations"], reference["resources"]["allocations"])
                        self.assertNotEqual(actual["frees"], reference["resources"]["frees"])
                        self.assertGreater(actual["live_bytes"], 0)
                    observations.append({"mode": mode, "control": "unqualified_C_" + label,
                        "build_argv": built.args, "build_returncode": built.returncode, "build_stdout": built.stdout,
                        "build_stderr": built.stderr, "argv": rejected.args, "returncode": rejected.returncode,
                        "stdout": rejected.stdout, "stderr": rejected.stderr, "mismatch_detected": True})
            (root / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        finally:
            if temporary is not None:
                temporary.cleanup()


class CompositeOriginConvergenceTests(unittest.TestCase):
    def test_mixed_primitive_and_field_origins_share_exact_core_and_refusals(self):
        params = [("views", "Views"), ("direct", "readbuf"), ("which", "bool")]
        helper = f("mixed", params, ["readbuf", "readbuf"], [], [
            b("entry", params, [], branch("which", ("joined", "views", "direct"),
                                         ("joined", "views", "direct"))),
            b("joined", [("renamed", "Views"), ("alias", "readbuf")], [
                i("record.unpack", ["renamed"], [("tag", "u16"), ("field", "readbuf")]),
                i("borrow.read", ["field"], [("field_child", "readbuf")]),
                i("borrow.read", ["alias"], [("direct_child", "readbuf")]),
            ], ret("field_child", "direct_child")),
        ])
        helper["return_loans"] = [origin("views", "loan"), "direct"]
        source = v4([record("Views", [("tag", "u16"), ("loan", "readbuf")])], helper)
        checked = verify_core(source)
        explicit = deepcopy(source)
        explicit["functions"][0]["return_loans"][1] = origin("direct")
        self.assertEqual(checked.canonical_bytes, verify_core(explicit).canonical_bytes)
        self.assertEqual(checked.scalar_entrypoints, frozenset())
        for annotations in (["views", "direct"], [origin("views", "loan"), "alias"],
                            ["direct", origin("views", "loan")]):
            changed = deepcopy(source)
            changed["functions"][0]["return_loans"] = annotations
            with self.subTest(annotations=annotations), self.assertRaises(HIAProgramRejected):
                verify_core(changed)


# Preserve the original public 13-method selector identities without changing
# the newer field-origin fixtures or discovering the support classes twice.
from tests import hia_composite_primitive_returns as _primitive_return_tests


class CompositeReturnedLoanSemantics(_primitive_return_tests.CompositeReturnedLoanSemantics):
    """Legacy primitive-formal origin syntax on the current elaborator."""


class CompositeReturnedLoanRust(_primitive_return_tests.CompositeReturnedLoanRust):
    """Original v4 corpus through the existing sealed Rust execution path."""


class CompositeReturnedLoanNative(_primitive_return_tests.CompositeReturnedLoanNative):
    """Original direct-LLVM scalar and allocator observations."""


if __name__ == "__main__":
    unittest.main()
