"""Complete-query HIA witnesses; an explicit cold or development compiler is required.

The original Python query and graph encoder are test-only comparison oracles.
They never construct the input supplied to NativeAgentQuery.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import ast
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_query_native import (
    CORE_OFFSET, CUSTODY, HEADER, MAGIC, MAX_QUERY, OUTPUT_BYTES, RECORD,
    REFUSALS, RESULT_MAGIC, SCHEMA, SOURCE, NativeAgentQuery,
    call_admitted_query_image, capture_request, capture_string,
    installed_agent_query, prepare_native_query,
)
from hepta.hia_program import verify_program
from hepta.hia_program_tools import HIAEditRejected

ROOT = Path(__file__).resolve().parents[1]
SELECTOR = "HEPTA_HIA_AGENT_QUERY_MANIFEST"
COLD = "HEPTA_HIA_AGENT_QUERY_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_AGENT_QUERY_DEVELOPMENT_COMPILER"
EVIDENCE = "HEPTA_HIA_AGENT_QUERY_EVIDENCE"


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}


def json_wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def record(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def original_query(document, **selection):
    from hepta.hia_edit_query import prepare_edit
    with patch.dict(os.environ, clean_environment(), clear=True):
        return prepare_edit(document, **selection)


def cases():
    from tests.test_hia_edit_query import fixture
    from tests.test_hia_edit_cfg_context import across_three_blocks, branch_and_join
    from tests.test_hia_returned_loan_interfaces import choose_loan, scalar
    result = [
        ("local", fixture(), dict(function="calculate", block="entry", output="y", fields=["op"])),
        ("cfg", across_three_blocks(), dict(function="calc", block="entry", output="first", fields=["attrs", "op", "args"])),
        ("join", branch_and_join(), dict(function="calc", block="entry", output="selected", fields=("args", "op"))),
        ("borrow", choose_loan(), dict(function="entrypoint", block="entry", output="left_byte", fields=["attrs"])),
    ]
    result.extend(("version-" + str(version), scalar(version),
                   dict(function="scalar", block="entry", output="seven", fields=["attrs"]))
                  for version in range(1, 9))
    from tests.test_hia_program import b, c, f, m, ret
    for name, typ, value in (("signed-min", "i64", -(1 << 63)),
                             ("unsigned-max", "u64", (1 << 64) - 1),
                             ("bool", "bool", True)):
        document = m(f("constant", [], [typ], [], [b("entry", [],
            [c("value", typ, value)], ret("value"))]))
        result.append((name, document, dict(function="constant", block="entry",
                                            output="value", fields=["attrs"])))
    return result


def original_packet(checked, selection):
    from hepta.hia_agent_slice_native import encode_function
    document = checked.as_dict()
    function = next(fn for fn in document["functions"] if fn["name"] == selection["function"])
    block = next(block for block in function["blocks"] if block["id"] == selection["block"])
    index = next(index for index, operation in enumerate(block["ops"])
                 if any(out["name"] == selection["output"] for out in operation["out"]))
    packet, _names, _ranges = encode_function(function, block, index)
    return packet, block["ops"][index]


@contextmanager
def poisoned_query_construction():
    # Whole Core verification and unrelated render/apply policy stay active.
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in ("_reference_edit_slice", "_cfg_downstream_slice", "function_signature", "_wire"):
            stack.enter_context(patch("hepta.hia_edit_query." + name,
                                      side_effect=AssertionError("hosted query construction: " + name)))
        stack.enter_context(patch("hepta.hia_agent_slice_native.encode_function",
                                  side_effect=AssertionError("hosted graph encoder")))
        stack.enter_context(patch("hepta.hia_agent_slice_native.native_edit_slice",
                                  side_effect=AssertionError("hosted slice reconstruction")))
        yield


@contextmanager
def observe_entry(native, *, before=None):
    """Transparent single entry call; retain the actual buffers and return value."""
    entry = native._entry
    observations = []
    def observed(source, size, output, capacity, workspace, workspace_size):
        frozen = ctypes.string_at(source, size)
        if before is not None:
            before()
        result = entry(source, size, output, capacity, workspace, workspace_size)
        observations.append({"return": result, "input": frozen,
            "input_after": ctypes.string_at(source, size),
            "output": ctypes.string_at(output, capacity),
            "workspace": ctypes.string_at(workspace, workspace_size)})
        return result
    native._entry = observed
    try:
        yield observations
    finally:
        native._entry = entry


def private_graph(observation):
    state = struct.unpack_from("<Q", observation["workspace"], 40)[0]
    start, length = struct.unpack_from("<2Q", observation["workspace"], state + 64)
    assert start + length <= len(observation["workspace"])
    return observation["workspace"][start:start + length], state


def vm_query(request, returned_bytes, *, observation=None):
    """Execute the complete HIA; observe actual buffers before their real drops."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta import hia_program_runtime as runtime
    canonical_size = struct.unpack_from("<Q", request, 16)[0]
    workspace_size = 456 * min(canonical_size, 262144) + canonical_size + 268560
    body, owners, views = Body(0), [], []
    for size, initial in ((len(request), request), (OUTPUT_BYTES, b""), (workspace_size, b"")):
        owner = body.value("buffer", "buffer.new", [body.const("usize", size)])
        view = body.value("mutbuf", "borrow.mut", [owner])
        for offset, value in enumerate(initial):
            if value:
                body.effect("buffer.store", [view, body.const("usize", offset), body.const("u8", value)])
        owners.append(owner)
        views.append(view)
    body.effect("loan.end", [views[0]])
    views[0] = body.value("readbuf", "borrow.read", [owners[0]])
    result = body.value("u32", "call", views, {"function": "f0"})
    for view in views:
        body.effect("loan.end", [view])
    for owner in owners:
        body.effect("owner.drop", [owner])
    wrapper = (
        "hia-asm.v1 hepta.hia.program.v8 agent_query_vm\n"
        "fn observe() -> (u32) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
        + body.text() + "  ret(" + result + ")\nend\n"
        + SOURCE.read_text().split("\n", 1)[1])
    snapshots = []
    observation_error = None
    original_drop = runtime._Machine.drop
    def observed_drop(machine, owner):
        # Read the actual VM bytes before the original destructor clears them.
        # Even an observation failure cannot prevent or replace the real drop.
        nonlocal observation_error
        snapshot = None
        try:
            if type(owner) is runtime._Owner:
                snapshot = (machine, owner.ident, bytes(owner.data))
        except BaseException as exc:
            if observation_error is None:
                observation_error = exc
        returned = original_drop(machine, owner)
        if snapshot is not None:
            snapshots.append(snapshot)
        return returned
    with patch.object(runtime._Machine, "drop", observed_drop):
        actual = execute_program(assemble_program(wrapper), "observe", [], max_steps=3_000_000)
    if observation_error is not None:
        raise observation_error
    assert actual["status"] == "returned", actual
    resources = actual["resources"]
    assert resources["live_owners"] == resources["live_local_loans"] == 0
    assert resources["owners_created"] == resources["owners_dropped"] == 3
    assert resources["allocations"] == resources["frees"] == 3
    assert len(snapshots) == 3
    machine = snapshots[0][0]
    assert all(entry[0] is machine for entry in snapshots)
    assert resources == machine.resources()
    dropped_ids = [entry[1] for entry in snapshots]
    assert dropped_ids == [1, 2, 3]
    assert snapshots[0][2] == request
    assert len(snapshots[1][2]) == OUTPUT_BYTES
    assert len(snapshots[2][2]) == workspace_size
    code, = actual["values"]
    raw = snapshots[1][2][:returned_bytes]
    assert len(raw) == returned_bytes
    if observation is not None:
        observation.update({"resources": resources, "dropped_owner_ids": dropped_ids,
            "single_vm_machine_observed": True,
            "input_sha256": sha256(snapshots[0][2]).hexdigest(),
            "output_bytes": len(raw), "output_sha256": sha256(raw).hexdigest(),
            "return": code, "original_drop_called_once_per_owner": True})
    return code, raw


class AgentQueryFixture:
    """A fixture mixin, deliberately not a TestCase or a discovered parent suite."""
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get(COLD)
        development = os.environ.get(DEVELOPMENT)
        if (COLD in os.environ and not cold) or (DEVELOPMENT in os.environ and not development):
            raise ValueError("empty query qualification selector")
        if bool(cold) == bool(development):
            raise ValueError("select exactly one matching query cold report or explicit development compiler")
        cls.cold = Path(cold).resolve(strict=True) if cold else None
        if cls.cold is not None:
            from tools.build_hia_json_preflight import admit_cold_build
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            nested = json.loads(Path(report["nested_report"]).read_bytes())
            cls.compiler = Path(nested["generations"][-1]["produced_image"]).resolve(strict=True)
            admit_cold_build(cls.compiler.read_bytes(), cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
        cls.temporary = None
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-query-")
            cls.folder = Path(cls.temporary.name)
        source_bytes = SOURCE.read_bytes()
        compiler_bytes = cls.compiler.read_bytes()
        if cls.cold is not None:
            from tools.build_hia_agent_query import build
            cls.manifest = build(cls.folder / "qualified", cls.compiler, cls.cold)
            manifest = json.loads(cls.manifest.read_bytes())
            cls.compile_receipt = json.loads((cls.manifest.parent / "build.json").read_bytes())["native_compile_receipt"]
            mode = "MATCHING_CURRENT_SOURCE_COLD_BUILD"
        else:
            from tools.qualify_hia_selfhost import compile_stage
            image, cls.compile_receipt = compile_stage(cls.folder, "agent-query-development",
                                                       cls.compiler, source_bytes)
            manifest = {"schema": SCHEMA, "source_sha256": sha256(source_bytes).hexdigest(),
                "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                "compiler_sha256": sha256(compiler_bytes).hexdigest()}
            cls.manifest = cls.folder / "manifest.json"
            record(cls.manifest, manifest)
            mode = "EXPLICIT_DEVELOPMENT_COMPILER_NOT_CURRENT_COLD"
        image = cls.manifest.parent / manifest["image_path"]
        image_bytes = image.read_bytes()
        if SOURCE.read_bytes() != source_bytes or cls.compiler.read_bytes() != compiler_bytes:
            raise ValueError("query fixture compiler/source changed")
        if not 0 < len(image_bytes) <= 1048576:
            raise ValueError("unchanged native image profile exceeded")
        cls.image_path = image
        cls.native = NativeAgentQuery(image_bytes, manifest["image_sha256"])
        cls.build_mode = mode
        record(cls.folder / "build-observation.json", {
            "schema": "hepta.hia.agent-query-test-build.v1", "mode": mode,
            "matching_current_source_cold_qualified": cls.cold is not None,
            "manifest": manifest, "compiler_receipt": cls.compile_receipt,
            "original_core_verifier_still_hosted": True,
            "ordinary_default_provisioning_proved": False, "whole_native_closure": False})

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def directory(self):
        directory = self.folder / self._testMethodName
        directory.mkdir(mode=0o700)
        return directory

    def native_query(self, document, **selection):
        return prepare_native_query(document, native=self.native, **selection)


class AgentQuerySourceTests(unittest.TestCase):
    def test_actual_generator_reproduces_source_and_original_profile(self):
        from tools.generate_hia_agent_query import document, profile_inventory
        from hepta.hia_agent_assembly import render_assembly
        actual = document()
        source = render_assembly(actual)
        self.assertEqual(source.encode(), SOURCE.read_bytes())
        profile = profile_inventory(actual, source)
        self.assertTrue(profile["static_generated_profile_within_existing_limits"])
        self.assertFalse(profile["native_compile_executed"])
        self.assertIsNone(profile["native_relocations"])

    def test_exact_capture_does_not_coerce_or_alias_untrusted_selectors(self):
        from tests.test_hia_edit_query import fixture
        checked = verify_program(fixture())
        class Foreign:
            def __str__(self):
                raise AssertionError("host selector coercion")
        fields = ["attrs", "op"]
        request = capture_request(checked, function="calculate", block="entry",
                                  output="y", fields=fields)
        fields[:] = ["bad"]
        self.assertEqual(struct.unpack_from("<3Q", request, HEADER)[:2], (1, 5))
        self.assertEqual(request[CORE_OFFSET:CORE_OFFSET + len(checked.canonical_bytes)],
                         checked.canonical_bytes)
        self.assertEqual(capture_string(Foreign()), bytes(RECORD))
        self.assertEqual(struct.unpack_from("<I", capture_string("\ud800"), 24)[0], 0xd800)
        raw = capture_request(checked, function=Foreign(), block=1, output=False, fields={})
        self.assertEqual(struct.unpack_from("<2Q", raw, 32), (0, 0))
        for offset in (HEADER + 3 * RECORD, HEADER + 4 * RECORD, HEADER + 5 * RECORD):
            self.assertEqual(struct.unpack_from("<Q", raw, offset)[0], 0)

    def test_invalid_cold_rejects_before_compile_and_output_creation(self):
        from tools.build_hia_agent_query import build
        with tempfile.TemporaryDirectory(prefix="hia-query-cold-refusal-") as directory:
            root = Path(directory)
            compiler = root / "compiler.bin"
            compiler.write_bytes(b"recording fixture, never executed")
            cold = root / "cold.json"
            cold.write_text(json.dumps({"schema": "wrong", "source_manifest": {}}))
            with patch("tools.qualify_hia_selfhost.compile_stage",
                       side_effect=AssertionError("compile must not be reached")) as stage:
                with self.assertRaises(ValueError):
                    build(root / "output", compiler, cold)
            self.assertEqual(stage.call_count, 0)
            self.assertFalse((root / "output").exists())


class AgentQueryNativeTests(AgentQueryFixture, unittest.TestCase):
    def test_complete_queries_and_actual_graph_packets_match_original_owners(self):
        directory = self.directory()
        observations = []
        for name, document, selection in cases():
            checked = verify_program(document)
            expected = original_query(checked, **selection)
            packet, operation = original_packet(checked, selection)
            request = capture_request(checked, **selection)
            with poisoned_query_construction(), observe_entry(self.native) as calls:
                actual = call_admitted_query_image(self.native, checked, **selection)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["input"], request)
            self.assertEqual(calls[0]["input_after"], request)
            self.assertEqual(actual, expected)
            code = calls[0]["return"]
            self.assertEqual(calls[0]["output"][64:code], json_wire(expected))
            actual_packet, state = private_graph(calls[0])
            self.assertEqual(actual_packet, packet)
            self.assertEqual(calls[0]["workspace"][state + 640:state + 704],
                             sha256(json_wire(operation)).hexdigest().encode())
            (directory / (name + ".request")).write_bytes(request)
            (directory / (name + ".query.json")).write_bytes(calls[0]["output"][64:code])
            (directory / (name + ".graph.bin")).write_bytes(actual_packet)
            observations.append({"case": name, "source_sha256": checked.sha256,
                "input_sha256": checked.input_sha256, "request_sha256": sha256(request).hexdigest(),
                "query_sha256": sha256(json_wire(expected)).hexdigest(),
                "graph_sha256": sha256(packet).hexdigest(), "native_return": code})
        record(directory / "observations.json", observations)
        self.assertEqual(self.compile_receipt["forbidden_compiler_modules_loaded"], [])

    def test_real_core_vm_and_native_complete_output_are_byte_equal(self):
        from tests.test_hia_returned_loan_interfaces import scalar
        document = scalar(8)
        selection = dict(function="scalar", block="entry", output="seven", fields=["attrs"])
        checked = verify_program(document)
        expected = json_wire(original_query(checked, **selection))
        request = capture_request(checked, **selection)
        vm_observation = {}
        observed = vm_query(request, 64 + len(expected), observation=vm_observation)
        with observe_entry(self.native) as calls:
            actual = self.native.transition(request)
        self.assertEqual(observed, (calls[0]["return"], calls[0]["output"][:64 + len(expected)]))
        self.assertEqual(actual.query_wire, expected)
        directory = self.directory()
        (directory / "request.bin").write_bytes(request)
        (directory / "vm-native-output.bin").write_bytes(observed[1])
        record(directory / "witness.json", {"native_return": observed[0],
            "full_vm_native_bytes_equal": True, "max_steps": 3_000_000,
            "vm_observation": vm_observation,
            "source_sha256": sha256(SOURCE.read_bytes()).hexdigest()})

    def test_original_field_identity_and_lookup_refusal_order(self):
        from tests.test_hia_edit_query import fixture
        original = fixture()
        selections = [
            dict(function=None, block=None, output=None, fields=[]),
            dict(function=None, block=None, output=None, fields=["op"]),
            dict(function="absent", block="absent", output="absent", fields=["op"]),
            dict(function="calculate", block="absent", output="absent", fields=["op"]),
            dict(function="calculate", block="entry", output="absent", fields=["op"]),
            dict(function="calculate", block="entry", output="y", fields=["op", "op"]),
            dict(function="calculate", block="entry", output="y", fields=["op", 1]),
            dict(function="\ud800", block="entry", output="y", fields=["op"]),
            dict(function="calculate" + "x" * 128, block="entry", output="y", fields=["op"]),
        ]
        outcomes = []
        for selection in selections:
            with self.subTest(selection=repr(selection)):
                try:
                    original_query(original, **selection)
                except (ValueError, TypeError) as reference:
                    kind, message = type(reference), str(reference)
                else:
                    self.fail("refusal fixture unexpectedly accepted")
                with self.assertRaises(kind) as actual:
                    self.native_query(original, **selection)
                self.assertEqual(str(actual.exception), message)
                outcomes.append({"selection": repr(selection), "exception": kind.__name__, "message": message})
        invalid = deepcopy(original)
        invalid["functions"][0]["blocks"][0]["term"]["values"] = ["unknown"]
        with patch.object(self.native, "transition",
                          side_effect=AssertionError("verify_program must refuse first")) as transition:
            with self.assertRaises(ValueError) as first:
                self.native_query(invalid, function=None, block=None, output=None, fields=[])
        self.assertNotIsInstance(first.exception, AssertionError)
        self.assertEqual(transition.call_count, 0)
        record(self.directory() / "refusals.json", outcomes)

    def test_exact_original_operation_block_and_cycle_limits(self):
        from tests.test_hia_program import b, f, i, m, ret, jump
        from tests.test_hia_edit_cfg_context import backedge
        observations = []
        examples = []
        for size in (255, 256, 257):
            operations = [i("int.add.wrap", ["x" if k == 0 else "v" + str(k - 1), "x"],
                            [("v" + str(k), "u32")]) for k in range(size)]
            document = m(f("work", [("x", "u32")], ["u32"], [],
                [b("entry", [("x", "u32")], operations, ret("v" + str(size - 1)))]))
            examples.append(("operations-" + str(size), document,
                dict(function="work", block="entry", output="v0", fields=["op"])))
        for size in (63, 64, 65):
            blocks = []
            for k in range(size):
                operations = [i("int.add.wrap", ["x0", "x0"], [("chosen", "u32")])] if k == 0 else []
                value = "chosen" if k == 0 else "x" + str(k)
                blocks.append(b("b" + str(k), [("x" + str(k), "u32")], operations,
                    ret(value) if k + 1 == size else jump("b" + str(k + 1), value)))
            examples.append(("blocks-" + str(size), m(f("work", [("x0", "u32")], ["u32"], [], blocks)),
                dict(function="work", block="b0", output="chosen", fields=["op"])))
        examples.append(("cycle", backedge(), dict(function="loop", block="head", output="changed", fields=["op"])))
        for name, document, selection in examples:
            with self.subTest(case=name):
                try:
                    expected = original_query(document, **selection)
                except HIAEditRejected as reference:
                    with self.assertRaises(HIAEditRejected) as actual:
                        self.native_query(document, **selection)
                    self.assertEqual(str(actual.exception), str(reference))
                    observations.append({"case": name, "refusal": str(reference)})
                else:
                    actual = self.native_query(document, **selection)
                    self.assertEqual(json_wire(actual), json_wire(expected))
                    observations.append({"case": name, "query_sha256": sha256(json_wire(actual)).hexdigest()})
        record(self.directory() / "limits.json", observations)

    def test_operation_wire_gate_precedes_complete_query_wire_gate(self):
        from tests.test_hia_program import b, f, i, m, ret
        directory = self.directory()
        observations = []
        # A long repeated valid operand makes the operation cross the existing
        # 1 MiB wire gate without inflating the callee's short parameter names.
        argument = "a" * 128
        for target in (MAX_QUERY - 1, MAX_QUERY, MAX_QUERY + 1):
            count = max(1, (target - 150) // 131)
            while True:
                base = i("call", [argument] * count, [("r", "u8")], function="h")
                difference = target - len(json_wire(base))
                if 0 <= difference <= 254:
                    break
                count += 1 if difference > 254 else -1
            function_name = "h" * (1 + min(difference, 127))
            output_name = "r" * (1 + max(0, difference - 127))
            operation = i("call", [argument] * count, [(output_name, "u8")], function=function_name)
            self.assertEqual(len(json_wire(operation)), target)
            parameters = [("p" + str(k), "u8") for k in range(count)]
            callee = f(function_name, parameters, ["u8"], [], [b("entry", parameters, [], ret("p0"))])
            caller = f("caller", [(argument, "u8")], ["u8"], [],
                       [b("entry", [(argument, "u8")], [operation], ret(output_name))])
            checked = verify_program(m(caller, callee))
            selection = dict(function="caller", block="entry", output=output_name, fields=["args"])
            with self.assertRaisesRegex(HIAEditRejected, "JSON encoding exceeds byte budget") as reference:
                original_query(checked, **selection)
            with observe_entry(self.native) as calls:
                with self.assertRaises(HIAEditRejected) as actual:
                    call_admitted_query_image(self.native, checked, **selection)
            self.assertEqual(str(actual.exception), str(reference.exception))
            self.assertEqual(len(calls), 1)
            _packet, state = private_graph(calls[0])
            digest = calls[0]["workspace"][state + 640:state + 704]
            self.assertEqual(digest, sha256(json_wire(operation)).hexdigest().encode()
                             if target <= MAX_QUERY else bytes(64))
            observations.append({"operation_wire_bytes": target, "core_bytes": len(checked.canonical_bytes),
                "source_sha256": checked.sha256, "native_return": calls[0]["return"],
                "operation_hash_completed": target <= MAX_QUERY, "refusal": str(actual.exception)})
        record(directory / "wire-limits.json", observations)

    def test_real_native_operation_chains_and_core_arena_are_preserved(self):
        """Read-only HIA snapshots bracket the original writer calls."""
        from tools import generate_hia_agent_query as generator
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_agent_assembly import render_assembly
        from tests.test_hia_returned_loan_interfaces import choose_loan
        directory = self.directory()
        authoring = ast.parse(generator.source_program())
        entry = authoring.body[0]
        changed = []
        inserted = {"core_before": 0, "operation_before_after": 0, "core_after": 0}
        for statement in entry.body:
            changed.append(statement)
            value = (statement.value if isinstance(statement, (ast.Assign, ast.Expr)) else None)
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
                continue
            if value.func.id == "initialize_query_constants":
                changed.extend(ast.parse("query_capture(o, w, 1310720, 64, get(w, 24) - 64)").body)
                inserted["core_before"] += 1
            if value.func.id == "query_wire" and isinstance(value.args[-1], ast.Name):
                if value.args[-1].id == "operation":
                    changed.pop()
                    changed.extend(ast.parse("query_capture(o, w, 2097152, qget(w, 256), qget(w, 264) * 64)").body)
                    changed.append(statement)
                    changed.extend(ast.parse("query_capture(o, w, 3145728, qget(w, 256), qget(w, 264) * 64)").body)
                    inserted["operation_before_after"] += 1
                elif value.args[-1].id == "root":
                    changed.extend(ast.parse("query_capture(o, w, 1572864, 64, get(w, 24) - 64)").body)
                    inserted["core_after"] += 1
        self.assertEqual(inserted, {"core_before": 1, "operation_before_after": 1, "core_after": 1})
        entry.body = changed
        authoring.body.extend(ast.parse("""
def query_capture(o:mutbuf, w:mutbuf, destination:u64, source:u64, size:u64) -> u64:
    if size > 262136 or destination > length(o) or size + 8 > length(o) - destination:
        return 0
    if source > length(w) or size > length(w) - source:
        return 0
    put(o, destination, size)
    index = 0
    while index < size:
        store(o, destination + 8 + index, byte(w, source + index))
        index = index + 1
    return 1
""").body)
        witness_authoring = ast.unparse(ast.fix_missing_locations(authoring)) + "\n"
        with patch.object(generator, "source_program", return_value=witness_authoring):
            witness_document = generator.document()
        witness_source = render_assembly(witness_document).encode()
        # The unchanged production limits also govern this test-only observer.
        witness_profile = generator.profile_inventory(witness_document, witness_source.decode())
        (directory / "instrumented-writer.hepta").write_bytes(witness_source)
        image, receipt = compile_stage(directory, "instrumented-query-writer",
                                        self.compiler, witness_source)
        native = NativeAgentQuery(image.read_bytes(), sha256(image.read_bytes()).hexdigest())
        document = choose_loan()
        selection = dict(function="entrypoint", block="entry", output="left_byte", fields=["attrs"])
        checked = verify_program(document)
        expected = json_wire(original_query(checked, **selection))
        request = capture_request(checked, **selection)
        with observe_entry(native) as calls:
            result = native.transition(request)
        self.assertEqual(result.query_wire, expected)
        self.assertEqual(len(calls), 1)
        snapshots = {}
        for name, offset in (("core-before", 1310720), ("core-after", 1572864),
                             ("operation-before", 2097152), ("operation-after", 3145728)):
            size = struct.unpack_from("<Q", calls[0]["output"], offset)[0]
            self.assertTrue(0 < size <= 262136)
            snapshots[name] = calls[0]["output"][offset + 8:offset + 8 + size]
            (directory / (name + ".bin")).write_bytes(snapshots[name])
        self.assertEqual(snapshots["core-before"], snapshots["core-after"])
        self.assertEqual(snapshots["operation-before"], snapshots["operation-after"])
        self.assertEqual(len(snapshots["operation-before"]) % 64, 0)
        self.assertEqual(struct.unpack_from("<2Q", snapshots["operation-before"], 8),
                         ((1 << 64) - 1, (1 << 64) - 1))
        record(directory / "instrumented-witness.json", {
            "scope": "test-only native read snapshots, not the production image or a new qualification",
            "production_source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
            "observer_source_sha256": sha256(witness_source).hexdigest(),
            "observer_image_sha256": sha256(image.read_bytes()).hexdigest(),
            "receipt": receipt, "unchanged_profile_limits": witness_profile,
            "core_nodes_and_string_pool_equal": True,
            "detached_operation_entire_private_nodes_equal": True,
            "native_calls": 1, "matching_source_cold_qualification_claimed_for_observer": False})

    def test_manifest_source_image_schema_refusals(self):
        from hepta.hia_json_preflight_native import _installed_json_image
        directory = self.directory()
        manifest = json.loads(self.manifest.read_bytes())
        image_bytes = self.image_path.read_bytes()
        for field, value in (("schema", "wrong"), ("source_sha256", "0" * 64),
                             ("image_sha256", "0" * 64)):
            child = directory / field
            child.mkdir()
            (child / "image.bin").write_bytes(image_bytes)
            changed = dict(manifest, image_path="image.bin")
            changed[field] = value
            path = child / "manifest.json"
            record(path, changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                installed_agent_query(str(path))
        # Unknown factories are denied by the explicit worker bundle, never by
        # broad isinstance/issubclass admission; the integration suite owns it.
        self.assertIsInstance(installed_agent_query(str(self.manifest)), NativeAgentQuery)

    def test_captured_input_survives_caller_mutation_and_parallel_queries(self):
        from tests.test_hia_edit_query import fixture
        source = fixture()
        selection = dict(function="calculate", block="entry", output="y", fields=["op"])
        expected = original_query(source, **selection)
        def mutate():
            source["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 99
            selection["fields"][:] = ["attrs"]
        checked = verify_program(source)
        request = capture_request(checked, **selection)
        with observe_entry(self.native, before=mutate) as calls:
            receipt = self.native.transition(request)
        self.assertEqual(receipt.query_wire, json_wire(expected))
        self.assertEqual(calls[0]["input"], calls[0]["input_after"])
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(self.native.transition, [request] * 12))
        self.assertTrue(all(result.query_wire == receipt.query_wire for result in results))
        record(self.directory() / "capture.json", {
            "request_sha256": sha256(request).hexdigest(), "native_calls": 13,
            "caller_mutated_after_capture": True, "parallel_outputs_identical": True})

        from hepta import hia_agent_query_native as adapter
        growth_records = []
        real_len, real_tuple = len, tuple
        for initial in ([], ["op"], ["op", "args", "attrs"]):
            with self.subTest(growth_after_length=real_len(initial)):
                fields = list(initial)
                observed_lengths, copied_arguments = [], []
                def racing_len(value):
                    amount = real_len(value)
                    if value is fields and not observed_lengths:
                        observed_lengths.append(amount)
                        fields.extend(["args"] * 8192)
                    return amount
                def observed_tuple(value):
                    copied_arguments.append((value is fields, real_len(value)))
                    return real_tuple(value)
                selected = dict(function="calculate", block="entry", output="y", fields=fields)
                with observe_entry(self.native) as growth_calls:
                    with patch.object(adapter, "len", racing_len, create=True), \
                         patch.object(adapter, "tuple", observed_tuple, create=True):
                        with self.assertRaises(HIAEditRejected) as native_error:
                            call_admitted_query_image(self.native, checked, **selected)
                self.assertEqual(observed_lengths, [real_len(initial)])
                self.assertEqual(copied_arguments, [(False, 4)])
                self.assertEqual(real_len(fields), real_len(initial) + 8192)
                self.assertEqual(len(growth_calls), 1)
                call = growth_calls[0]
                self.assertEqual(call["return"], 0xfffffff0)
                self.assertEqual(call["input"], call["input_after"])
                self.assertEqual(struct.unpack_from("<2Q", call["input"], 32), (1, 4))
                with self.assertRaises(HIAEditRejected) as reference_error:
                    original_query(checked, **selected)
                self.assertEqual((type(native_error.exception), str(native_error.exception)),
                                 (type(reference_error.exception), str(reference_error.exception)))
                growth_records.append({"initial_count": real_len(initial),
                    "live_count_after_growth": real_len(fields), "copied_count": 4,
                    "copied_live_collection": False, "native_calls": 1,
                    "native_return": call["return"],
                    "request_sha256": sha256(call["input"]).hexdigest(),
                    "exception": type(native_error.exception).__name__,
                    "message": str(native_error.exception)})
        record(self.folder / self._testMethodName / "capture-growth.json", growth_records)
