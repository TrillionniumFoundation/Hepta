"""CLI v75 continuation differentials; original callers and limits stay separate.

Source tests require no image. Native tests use the same explicit cold/development
fixture as the retained CLI-native module; no compiler or parser fallback exists.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import ctypes
import gc
from hashlib import sha256
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import unittest
import weakref
from unittest.mock import patch

from hepta import cli
from hepta import hia_cli_native as bridge
from tests import test_hia_cli_native as native_fixture
from tests.test_hia_cli_native import (
    environment, entry_outcome, ROOT, SELECTOR,
)


class CliContinuationSourceTests(unittest.TestCase):
    def test_v74_original_reference_body_is_byte_exact(self):
        self.assertEqual(sha256(inspect.getsource(cli._reference_hia_main).encode()).hexdigest(),
                         "2502a29f616377c969fbad19c2340e479167ab1b10dc5e0c6f6082eb5755f1a0")

    def test_hia_owns_new_backend_and_one_use_claim_protocol(self):
        from tools import generate_hia_cli_control as grammar
        from tools import hia_cli_control_phases as phases
        self.assertEqual(grammar.FIELDS[17:], ("selfhost_manifest", "selfhost_manifest_sha256"))
        self.assertEqual(phases.COMMANDS[42], "build_selfhost")
        self.assertEqual(phases.COMMANDS[43], "release_handler_temporaries")
        self.assertIn("return control_claim(s, o, w)", grammar.SOURCE)
        self.assertIn("put(w, C_CLAIMED, 1)", phases.SOURCE)
        self.assertIn("get(w, C_CLAIMED) != 1", phases.SOURCE)
        self.assertIn("control_consumes(w, operation, c)", phases.SOURCE)
        self.assertIn("if get(w, C_SELFHOST) != 0:", phases.SOURCE)
        self.assertNotIn("args.backend", inspect.getsource(bridge.CliSession._effect))
        self.assertNotIn("argparse", inspect.getsource(bridge.CliSession._effect))

    def test_default_keeps_arbitrary_argv_object_reference_route(self):
        marker = object()
        observed = []
        with (patch.dict(os.environ, environment(), clear=True),
              patch.object(cli, "_reference_hia_main",
                           new=lambda value: observed.append(value) or 71)):
            self.assertEqual(cli.hia_main(marker), 71)
        self.assertEqual(len(observed), 1)
        self.assertIs(observed[0], marker)


class CliContinuationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_fixture.CliNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        native_fixture.CliNativeTests.tearDownClass.__func__(cls)

    def prepare(self, argv):
        with patch.dict(os.environ, environment(), clear=True):
            return self.owner.prepare(argv, cli)

    def compare(self, argv, install):
        rows = []
        for selected in (False, True):
            events = []
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, environment(), clear=True))
                install(stack, events)
                if selected:
                    actual = entry_outcome(argv, self.manifest)
                else:
                    actual = entry_outcome(argv)
            rows.append((actual, events))
        self.observations.append({"test": self.id(), "argv": argv,
                                  "reference": rows[0], "native": rows[1]})
        self.assertEqual(rows[1], rows[0])
        return rows

    def test_selfhost_parser_pair_errors_precede_all_file_or_build_effects(self):
        from hepta import hia_program_tools
        cases = [
            ["build", "unused", "-o", "out", "--backend", "selfhost"],
            ["build", "unused", "-o", "out", "--backend", "selfhost",
             "--selfhost-manifest", "manifest"],
            ["build", "unused", "-o", "out", "--backend", "selfhost",
             "--selfhost-manifest-sha256", "pin"],
            ["build", "unused", "-o", "out", "--backend", "selfhost",
             "--selfhost-manifest=", "--selfhost-manifest-sha256=pin"],
            ["build", "unused", "-o", "out", "--backend", "selfhost",
             "--selfhost-manifest=manifest", "--selfhost-manifest-sha256="],
            ["build", "unused", "-o", "out", "--selfhost-manifest="],
            ["build", "unused", "-o", "out", "--selfhost-manifest-sha256=pin"],
            ["build", "--backend", "selfhost"],
            ["build", "unused", "-o", "out", "--backend", "bad", "--help"],
            ["build", "unused", "-o", "out", "--help", "--backend", "bad"],
            ["build", "unused", "-o", "out", "--selfhost-man", "ambiguous"],
            ["build", "unused", "-o", "out", "--backend", "selfhost", "--extra"],
        ]
        def forbidden(*args, **kwargs):
            raise AssertionError("parse refusal launched a file or build effect")
        for argv in cases:
            with self.subTest(argv=argv):
                rows = self.compare(argv, lambda stack, events:
                                    stack.enter_context(patch.object(hia_program_tools,
                                                                     "read_bounded", new=forbidden)))
                self.assertEqual(rows[0][0][0][0], "exit")

    def test_selfhost_and_native_dispatch_preserve_input_output_pin_objects(self):
        from hepta import hia_program, hia_program_tools, hia_program_selfhost, hia_program_native
        input_path = "".join(["input", "-", "original-object"] * 3)
        output_path = "".join(["output", "-", "original-object"] * 3)
        manifest = "".join(["manifest", "-", "original-object"] * 3)
        pin = "".join(["a" * 32, "b" * 32])
        checked = object()
        for backend in ("native", "selfhost"):
            argv = ["build", input_path, "-o", output_path, "--backend", backend]
            if backend == "selfhost":
                argv += ["--selfhost-manifest", manifest, "--selfhost-manifest-sha256", pin]
            def install(stack, events):
                def read(path, *, limit=8 << 20):
                    events.append(["read", path is input_path, limit])
                    return b"raw"
                def verify(raw):
                    events.append(["verify", raw == b"raw"])
                    return checked
                def native(program, output, *, kind, linker):
                    events.append(["native", program is checked, output is output_path, kind, linker])
                    return {"ok": True, "backend": "native"}
                def selfhost(program, output, *, manifest, manifest_sha256, kind, target):
                    events.append(["selfhost", program is checked, output is output_path,
                                   manifest is argv[-3], manifest_sha256 is pin, kind, target])
                    return {"ok": True, "backend": "selfhost"}
                stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=read))
                stack.enter_context(patch.object(hia_program, "verify_program", new=verify))
                stack.enter_context(patch.object(hia_program_native, "build_program_machine", new=native))
                stack.enter_context(patch.object(hia_program_selfhost, "build_program_selfhost", new=selfhost))
            rows = self.compare(argv, install)
            self.assertEqual(rows[0][0][0], ("return", 0))
            self.assertEqual(rows[0][1][0], ["read", True, 8 << 20])
            self.assertEqual(rows[0][1][-1][0], backend)
            self.assertTrue(all(value is True for value in rows[0][1][-1][1:3]))

    def test_native_temporary_read_releases_before_program_report(self):
        from hepta import hia_program, hia_program_tools
        def install(stack, events):
            class Raw:
                def __del__(self):
                    events.append("raw-drop")
            class Program:
                def report(self):
                    events.append("report")
                    return {"ok": True}
                def __del__(self):
                    events.append("program-drop")
            def read(*args, **kwargs):
                events.append("read")
                return Raw()
            def verify(raw):
                events.append("verify")
                return Program()
            def output(value):
                events.append("output")
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=read))
            stack.enter_context(patch.object(hia_program, "verify_program", new=verify))
            stack.enter_context(patch.object(cli, "output_json", new=output))
        rows = self.compare(["verify", "unused"], install)
        events = rows[0][1]
        self.assertLess(events.index("raw-drop"), events.index("report"))
        self.assertLess(events.index("output"), events.index("program-drop"))

    def test_report_unpack_temporary_releases_before_output_mutation(self):
        from hepta import hia_program, hia_program_tools
        def install(stack, events):
            state = {"released": False}
            class Mapping(dict):
                def __del__(self):
                    state["released"] = True
                    events.append("mapping-drop")
            class Program:
                def report(self):
                    return Mapping(ok=True)
            def output(value):
                events.append(["output", state["released"],
                               value["status"], value["native_executed"]])
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=lambda *a, **k: b"x"))
            stack.enter_context(patch.object(hia_program, "verify_program", new=lambda value: Program()))
            stack.enter_context(patch.object(cli, "output_json", new=output))
        rows = self.compare(["verify", "unused"], install)
        self.assertEqual(rows[0][1][-1], ["output", True, "standalone_core_checked", False])

    def test_as_dict_temporary_releases_after_output_before_program(self):
        from hepta import hia_program, hia_program_tools
        def install(stack, events):
            class Mapping(dict):
                def __del__(self):
                    events.append("mapping-drop")
            class Program:
                def as_dict(self):
                    return Mapping(ok=True)
                def __del__(self):
                    events.append("program-drop")
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=lambda *a, **k: b"x"))
            stack.enter_context(patch.object(hia_program, "verify_program", new=lambda value: Program()))
            stack.enter_context(patch.object(cli, "output_json", new=lambda value: events.append("output")))
        rows = self.compare(["normalize", "unused"], install)
        self.assertEqual(rows[0][1], ["output", "mapping-drop", "program-drop"])

    def test_query_argument_release_can_modify_returned_query_before_output(self):
        from hepta import hia_program, hia_program_tools, hia_edit_batch
        def install(stack, events):
            returned = {}
            class Raw:
                def __del__(self):
                    events.append("raw-query-drop")
            class Decoded:
                def __del__(self):
                    events.append("decoded-query-drop")
                    returned["finalized"] = True
            def read(path, **kwargs):
                return b"program" if path == "program" else Raw()
            def decode(raw):
                events.append("decode")
                return Decoded()
            def prepare(program, decoded):
                events.append("prepare")
                return returned
            def output(value):
                events.append(["output", value.get("finalized") is True])
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=read))
            stack.enter_context(patch.object(hia_program_tools, "decode_json", new=decode))
            stack.enter_context(patch.object(hia_program, "verify_program", new=lambda value: object()))
            stack.enter_context(patch.object(hia_edit_batch, "prepare_batch", new=prepare))
            stack.enter_context(patch.object(cli, "output_json", new=output))
        rows = self.compare(["edit-batch-query", "program", "--selections", "query"], install)
        self.assertEqual(rows[0][1][-1], ["output", True])
        self.assertLess(rows[0][1].index("raw-query-drop"), rows[0][1].index("prepare"))

    def test_apply_edit_stack_argument_and_named_local_destruction_order(self):
        from hepta import hia_program, hia_program_tools, hia_edit_query
        def install(stack, events):
            class Raw:
                def __init__(self, tag): self.tag = tag
                def __del__(self): events.append("drop-" + self.tag)
            class Query:
                def __del__(self): events.append("drop-decoded")
            class Program:
                def __init__(self, tag): self.tag = tag
                def as_dict(self): return {"ok": True}
                def __del__(self): events.append("drop-" + self.tag)
            class Receipt(dict):
                def __del__(self): events.append("drop-receipt")
            def read(path, **kwargs):
                events.append("read-" + path)
                return Raw(path)
            def verify(raw):
                events.append("verify")
                return Program("program")
            def decode(raw):
                events.append("decode")
                return Query()
            def apply(program, query, response):
                events.append("apply")
                return Program("revised"), Receipt(ok=True)
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=read))
            stack.enter_context(patch.object(hia_program_tools, "decode_json", new=decode))
            stack.enter_context(patch.object(hia_program, "verify_program", new=verify))
            stack.enter_context(patch.object(hia_edit_query, "apply_edit", new=apply))
            stack.enter_context(patch.object(cli, "output_json", new=lambda value: events.append("output")))
        rows = self.compare(["edit-apply", "program-input", "--query", "query-input",
                             "--response", "response-input"], install)
        events = rows[0][1]
        self.assertLess(events.index("drop-query-input"), events.index("read-response-input"))
        self.assertLess(events.index("apply"), events.index("drop-decoded"))

    def test_assembly_named_raw_program_text_are_retained_in_original_order(self):
        from hepta import hia_program, hia_program_tools, hia_agent_assembly
        def install(stack, events):
            class Raw:
                def __del__(self): events.append("raw-drop")
            class Program:
                def __del__(self): events.append("program-drop")
            class Text(str):
                def __del__(self): events.append("text-drop")
            def render(program):
                events.append("render")
                return Text("assembly\n")
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=lambda *a, **k: Raw()))
            stack.enter_context(patch.object(hia_program, "verify_program", new=lambda value: Program()))
            stack.enter_context(patch.object(hia_agent_assembly, "render_assembly", new=render))
        rows = self.compare(["render-assembly", "unused"], install)
        expected = {
            312: ["render", "raw-drop", "program-drop", "text-drop"],
            314: ["render", "text-drop", "program-drop", "raw-drop"],
            31410: ["render", "text-drop", "program-drop", "raw-drop"],
        }[bridge._runtime_profile()]
        self.assertEqual(rows[0][1], expected)


    def test_pending_query_releases_during_read_unwind_before_handler_context(self):
        from hepta import hia_program, hia_program_tools
        def install(stack, events):
            class Query:
                def __del__(self):
                    active = sys.exception()
                    events.append(["query-drop", None if active is None else type(active).__name__])
            class ReadError(OSError):
                def __str__(self):
                    events.append(["error-str", sys.exception() is self])
                    return "second read failed"
            def read(path, **kwargs):
                if path == "response":
                    raise ReadError()
                return b"program" if path == "program" else b"query"
            stack.enter_context(patch.object(hia_program_tools, "read_bounded", new=read))
            stack.enter_context(patch.object(hia_program_tools, "decode_json", new=lambda raw: Query()))
            stack.enter_context(patch.object(hia_program, "verify_program", new=lambda raw: object()))
        rows = self.compare(["edit-apply", "program", "--query", "query", "--response", "response"], install)
        self.assertEqual(rows[0][0][0], ("return", 2))
        self.assertEqual(rows[0][1], [["query-drop", None], ["error-str", True]])

    def test_independent_vm_matches_complete_claim_and_selfhost_continuation_bytes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(bridge.SOURCES["control"].read_bytes())
        nonce = 913479
        cases = [
            (["capabilities"], [(1, (2, 0, 0)), (22, (0, 0, 0))], []),
            (["build", "in", "-o", "out", "--backend", "selfhost",
              "--selfhost-manifest", "manifest", "--selfhost-manifest-sha256", "pin"],
             [(35, (0, 0, 0)), (3, (2, 0, 0)), (4, (3, 0, 0)),
              (42, (4, 0, 0)), (22, (0, 0, 0)), (31, (1, 0, 0))], [4, 3]),
        ]
        for argv, replies, release in cases:
            raw = bytearray(bridge._frame(argv, "hia " + cli.__version__, environment(),
                bridge._runtime_profile(), 80, False, False, sys.get_int_max_str_digits()))
            struct.pack_into("<Q", raw, 80, nonce)
            capacity = 65536 + len(argv) * 80 + len(raw)
            actual_workspace = ctypes.create_string_buffer(capacity)
            actual_output = ctypes.create_string_buffer(128)
            expected_workspace = bytearray(capacity)
            expected_output = bytearray(128)
            observations = []
            def invoke(packet):
                nonlocal expected_workspace, expected_output
                source = ctypes.create_string_buffer(bytes(packet), len(packet))
                actual = self.owner.control._entry(source, len(packet), actual_output,
                                                   128, actual_workspace, capacity)
                owners = [_Owner(-1, bytearray(packet)), _Owner(-2, expected_output),
                          _Owner(-3, expected_workspace)]
                machine = _Machine(program, 25000000, 64 << 20, None, 128)
                expected = machine.invoke(program.as_dict()["functions"][0],
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                self.assertEqual(actual, expected)
                self.assertEqual(ctypes.string_at(actual_output, 128), bytes(owners[1].data))
                self.assertEqual(ctypes.string_at(actual_workspace, capacity), bytes(owners[2].data))
                self.assertEqual(ctypes.string_at(source, len(packet)), bytes(packet))
                expected_output, expected_workspace = owners[1].data, owners[2].data
                observations.append({"status": int(actual),
                    "output_sha256": sha256(bytes(expected_output)).hexdigest(),
                    "workspace_sha256": sha256(bytes(expected_workspace)).hexdigest()})
                return actual
            self.assertEqual(invoke(raw), 0)
            self.assertEqual(invoke(struct.pack("<12Q", bridge.STEP_MAGIC, 4, 0, 0, 0,
                                                1, 0, 0, 0, 0, 0, nonce)), 1)
            for index, (operation, values) in enumerate(replies, 1):
                self.assertEqual(struct.unpack_from("<Q", actual_output, 8)[0], operation)
                claim = struct.pack("<12Q", bridge.CLAIM_MAGIC, 4, index, operation,
                                    nonce, 0, 0, 0, 0, 0, 0, 0)
                self.assertEqual(invoke(claim), 3)
                reply = struct.pack("<12Q", bridge.STEP_MAGIC, 4, index, operation,
                                    0, *values, 0, 0, 0, nonce)
                self.assertEqual(invoke(reply), 2 if index == len(replies) else 1)
            count = struct.unpack_from("<Q", actual_output, 64)[0]
            # This ABI vector must follow the same admitted runtime as the
            # real reference differential, rather than hard-code 3.12 order.
            expected_release = (release if struct.unpack_from("<Q", raw, 24)[0] == 312
                                else list(reversed(release)))
            self.assertEqual(list(struct.unpack_from("<" + "Q" * count,
                                                    actual_workspace, 2816)), expected_release)
            self.observations.append({"test": self.id(), "argv": argv,
                                      "independent_vm_full_buffers": observations})


    def test_all_profiles_keep_complete_native_vm_frames_and_local_retirement_order(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(bridge.SOURCES["control"].read_bytes())
        canary = b"\xa5" * 32
        cases = [
            (["capabilities"], [(1, (2, 0, 0)), (22, (0, 0, 0))], []),
            (["render-assembly", "input"],
             [(35, (0, 0, 0)), (36, (0, 0, 0)), (3, (2, 0, 0)),
              (4, (3, 0, 0)), (7, (4, 0, 0)), (23, (0, 0, 0))], [2, 3, 4]),
            (["build", "in", "-o", "out", "--backend", "selfhost",
              "--selfhost-manifest", "manifest", "--selfhost-manifest-sha256", "pin"],
             [(35, (0, 0, 0)), (3, (2, 0, 0)), (4, (3, 0, 0)),
              (42, (4, 0, 0)), (22, (0, 0, 0)), (31, (1, 0, 0))], [4, 3]),
        ]
        for profile in (312, 314, 31410):
            for case, (argv, replies, forward_release) in enumerate(cases):
                with self.subTest(profile=profile, action=argv[0]):
                    nonce = 913479 + 10 * profile + case
                    raw = bytearray(bridge._frame(argv, "hia " + cli.__version__,
                        environment(), profile, 80, False, False,
                        sys.get_int_max_str_digits()))
                    struct.pack_into("<Q", raw, 80, nonce)
                    capacity = 65536 + len(argv) * 80 + len(raw)
                    actual_workspace = ctypes.create_string_buffer(capacity + 32)
                    actual_output = ctypes.create_string_buffer(160)
                    ctypes.memmove(ctypes.addressof(actual_workspace) + capacity, canary, 32)
                    ctypes.memmove(ctypes.addressof(actual_output) + 128, canary, 32)
                    expected_workspace = bytearray(capacity)
                    expected_output = bytearray(128)
                    observations = []
                    def invoke(packet):
                        nonlocal expected_workspace, expected_output
                        packet = bytes(packet)
                        source = ctypes.create_string_buffer(packet + canary, len(packet) + 32)
                        actual = self.owner.control._entry(source, len(packet), actual_output,
                                                           128, actual_workspace, capacity)
                        owners = [_Owner(-1, bytearray(packet)), _Owner(-2, expected_output),
                                  _Owner(-3, expected_workspace)]
                        machine = _Machine(program, 25000000, 64 << 20, None, 128)
                        expected = machine.invoke(program.as_dict()["functions"][0],
                            [_View(owners[0], False), _View(owners[1], True),
                             _View(owners[2], True)])[0]
                        self.assertEqual(actual, expected)
                        self.assertEqual(ctypes.string_at(actual_output, 160),
                                         bytes(owners[1].data) + canary)
                        self.assertEqual(ctypes.string_at(actual_workspace, capacity + 32),
                                         bytes(owners[2].data) + canary)
                        self.assertEqual(ctypes.string_at(source, len(packet) + 32),
                                         packet + canary)
                        expected_output, expected_workspace = owners[1].data, owners[2].data
                        observations.append({"status": int(actual),
                            "output_sha256": sha256(bytes(expected_output)).hexdigest(),
                            "workspace_sha256": sha256(bytes(expected_workspace)).hexdigest(),
                            "all_source_output_workspace_canaries_unchanged": True})
                        return actual
                    self.assertEqual(invoke(raw), 0)
                    self.assertEqual(invoke(struct.pack("<12Q", bridge.STEP_MAGIC, 4,
                        0, 0, 0, 1, 0, 0, 0, 0, 0, nonce)), 1)
                    for index, (operation, values) in enumerate(replies, 1):
                        self.assertEqual(struct.unpack_from("<Q", actual_output, 8)[0], operation)
                        self.assertEqual(invoke(struct.pack("<12Q", bridge.CLAIM_MAGIC, 4,
                            index, operation, nonce, 0, 0, 0, 0, 0, 0, 0)), 3)
                        reply = struct.pack("<12Q", bridge.STEP_MAGIC, 4, index,
                                            operation, 0, *values, 0, 0, 0, nonce)
                        self.assertEqual(invoke(reply), 2 if index == len(replies) else 1)
                    count = struct.unpack_from("<Q", actual_output, 64)[0]
                    release = list(struct.unpack_from("<" + "Q" * count,
                                                       actual_workspace, 2816))
                    expected_release = (forward_release if profile == 312
                                        else list(reversed(forward_release)))
                    self.assertEqual(release, expected_release)
                    self.observations.append({"test": self.id(), "profile": profile,
                        "argv": argv, "native_release": release,
                        "expected_release": expected_release,
                        "independent_vm_full_buffers": observations})

    def test_preclaim_ack_loss_never_launches_a_foreign_effect(self):
        class Stop(BaseException): pass
        for before in (True, False):
            with self.subTest(before=before):
                session = self.prepare(["capabilities"])
                self.assertEqual(session.step(), 1)
                original = self.owner.control._entry
                returned = []
                def interrupted(*args):
                    self.assertEqual(struct.unpack("<Q", ctypes.string_at(args[0], 8))[0],
                                     bridge.CLAIM_MAGIC)
                    if not before:
                        returned.append(original(*args))
                    raise Stop("claim ACK lost")
                effects = []
                with (patch.object(self.owner.control, "_entry", new=interrupted),
                      patch.object(cli, "agent_capabilities", new=lambda: effects.append(1) or {})):
                    with self.assertRaises(Stop):
                        session.observe()
                self.assertEqual(returned, [] if before else [3])
                self.assertEqual(effects, [])
                self.assertEqual(struct.unpack_from("<Q", session.workspace, 2256)[0],
                                 0 if before else 1)
                with self.assertRaises(RuntimeError): session.observe()
                with self.assertRaises(RuntimeError): session.step()
                self.assertIs(bridge._ACTIVE_SESSIONS[session.nonce], session)

    def test_foreign_result_ack_loss_keeps_owner_and_forbids_replay(self):
        class Stop(BaseException): pass
        class Value: pass
        session = self.prepare(["capabilities"])
        self.assertEqual(session.step(), 1)
        references, effects = [], []
        def effect():
            value = Value()
            references.append(weakref.ref(value))
            effects.append("effect")
            return value
        def lose(*args):
            raise Stop("foreign result ACK lost")
        with (patch.object(cli, "agent_capabilities", new=effect),
              patch.object(session, "_packet", new=lose)):
            with self.assertRaises(Stop): session.observe()
        gc.collect()
        self.assertIsNotNone(references[0]())
        self.assertEqual(effects, ["effect"])
        self.assertEqual(struct.unpack_from("<Q", session.workspace, 2256)[0], 1)
        self.assertIs(bridge._ACTIVE_SESSIONS[session.nonce], session)
        with self.assertRaises(RuntimeError): session.observe()
        with self.assertRaises(RuntimeError): session.step()
        self.assertEqual(effects, ["effect"])


    def test_closed_instance_nonces_never_reuse_and_old_claim_cannot_move(self):
        closed = []
        with (patch.dict(os.environ, environment(), clear=True),
              patch.object(cli, "output_json", new=lambda value: None)):
            for _ in range(32):
                session = self.owner.prepare(["capabilities"], cli)
                closed.append(session.nonce)
                self.assertEqual(session.run(), 0)
                self.assertNotIn(session.nonce, bridge._ACTIVE_SESSIONS)
                del session
            target = self.owner.prepare(["capabilities"], cli)
        self.assertEqual(closed, sorted(set(closed)))
        self.assertGreater(target.nonce, closed[-1])
        self.assertEqual(target.step(), 1)
        old = struct.pack("<12Q", bridge.CLAIM_MAGIC, 4, 1, 1,
                          closed[0], 0, 0, 0, 0, 0, 0, 0)
        source = ctypes.create_string_buffer(old, len(old))
        self.assertEqual(self.owner.control._entry(source, len(old), target.output, 128,
                                                   target.workspace, len(target.workspace)), 199)
        with patch.object(cli, "agent_capabilities", new=lambda: self.fail("late claim executed")):
            with self.assertRaises(RuntimeError): target.observe()
        self.observations.append({"test": self.id(), "closed_nonces": closed,
                                  "new_nonce": target.nonce, "old_claim_status": 199})

    def test_nonce_exhaustion_refuses_before_control_entry_without_wrap(self):
        original = self.owner.control._entry
        entered = []
        def record(*args):
            entered.append(struct.unpack("<Q", ctypes.string_at(args[0], 8))[0])
            return original(*args)
        with (patch.dict(os.environ, environment(), clear=True),
              patch.object(bridge, "_SESSION_NONCES", iter([(1 << 64) - 1, 1 << 64])),
              patch.object(self.owner.control, "_entry", new=record)):
            last = self.owner.prepare(["capabilities"], cli)
            self.assertEqual(last.nonce, (1 << 64) - 1)
            self.assertEqual(last.kind, 0)
            self.assertEqual(len(entered), 1)
            with self.assertRaisesRegex(RuntimeError, "nonce namespace exhausted"):
                self.owner.prepare(["capabilities"], cli)
            self.assertEqual(len(entered), 1)

    def test_cross_session_claim_and_repeated_claim_are_native_refusals(self):
        one, two = self.prepare(["capabilities"]), self.prepare(["capabilities"])
        self.assertEqual(one.step(), 1)
        self.assertEqual(two.step(), 1)
        op, seq = one.command[:2]
        wrong = struct.pack("<12Q", bridge.CLAIM_MAGIC, 4, seq, op,
                            two.nonce, 0, 0, 0, 0, 0, 0, 0)
        source = ctypes.create_string_buffer(wrong, len(wrong))
        self.assertEqual(self.owner.control._entry(source, len(wrong), one.output, len(one.output),
                                                   one.workspace, len(one.workspace)), 199)
        with self.assertRaises(RuntimeError): one.observe()
        two._claim_effect()
        with self.assertRaises(RuntimeError): two._claim_effect()
        self.assertEqual(struct.unpack_from("<Q", two.workspace, 2080)[0], 1)

    def test_same_session_reentry_fences_but_independent_nested_call_is_allowed(self):
        session = self.prepare(["capabilities"])
        calls, output = [], []
        def reenter():
            calls.append("outer")
            with self.assertRaises(RuntimeError): session.run()
            return {}
        with (patch.object(cli, "agent_capabilities", new=reenter),
              patch.object(cli, "output_json", new=lambda value: output.append(value))):
            with self.assertRaises(RuntimeError): session.run()
        self.assertEqual(calls, ["outer"])
        self.assertEqual(output, [])

        level = [0]
        def nested():
            level[0] += 1
            if level[0] == 1:
                self.assertEqual(self.owner.run(["capabilities"], cli), 0)
            return {"level": level[0]}
        with (patch.dict(os.environ, environment(), clear=True),
              patch.object(cli, "agent_capabilities", new=nested),
              patch.object(cli, "output_json", new=lambda value: None)):
            self.assertEqual(self.owner.run(["capabilities"], cli), 0)
        self.assertEqual(level, [2])

    def test_normal_terminal_releases_owned_locals_without_gc_or_retained_pool(self):
        from hepta import hia_program, hia_program_tools
        references = []
        class Program:
            def report(self): return {"ok": True}
        def verify(raw):
            value = Program()
            references.append(weakref.ref(value))
            return value
        session = self.prepare(["verify", "unused"])
        with (patch.object(hia_program_tools, "read_bounded", new=lambda *a, **k: b"x"),
              patch.object(hia_program, "verify_program", new=verify),
              patch.object(cli, "output_json", new=lambda value: None)):
            self.assertEqual(session.run(), 0)
        self.assertIsNone(references[0]())
        self.assertNotIn(session.nonce, bridge._ACTIVE_SESSIONS)
        self.assertTrue(all(value is bridge._RELEASED for value in session.handles))

    def test_warm_disk_image_drift_or_missing_is_rejected_before_entry(self):
        case = self.folder / "warm-image-custody"
        shutil.copytree(self.manifest.parent, case)
        manifest = case / self.manifest.name
        metadata = json.loads(manifest.read_bytes())
        bridge.installed_cli_strict(manifest)
        for name in ("control", "format"):
            child = case / metadata[name + "_manifest"]
            image = child.parent / json.loads(child.read_bytes())["image_path"]
            raw = image.read_bytes()
            for missing in (False, True):
                with self.subTest(name=name, missing=missing):
                    if missing: image.unlink()
                    else: image.write_bytes(raw + b"\0")
                    try:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            bridge.installed_cli_strict(manifest)
                    finally:
                        image.write_bytes(raw)
            self.assertIsInstance(bridge.installed_cli_strict(manifest), bridge.NativeCli)

    def test_published_warm_loader_keeps_actual_immutable_mappings(self):
        case = self.folder / "published-warm-image-custody"
        shutil.copytree(self.manifest.parent, case)
        manifest = case / self.manifest.name
        metadata = json.loads(manifest.read_bytes())
        admitted = bridge.installed_cli(manifest)
        for name, expected in (("control", admitted.control), ("format", admitted.formatter)):
            child = case / metadata[name + "_manifest"]
            image = child.parent / json.loads(child.read_bytes())["image_path"]
            raw = image.read_bytes()
            for mutation in ("changed", "missing"):
                with self.subTest(component=name, mutation=mutation):
                    try:
                        if mutation == "changed":
                            image.write_bytes(b"changed disk bytes after original mapping")
                        else:
                            image.unlink()
                        warm = bridge.installed_cli(manifest)
                        actual = warm.control if name == "control" else warm.formatter
                        self.assertIs(actual, expected)
                        self.assertEqual(actual._mapping[:], raw)
                    finally:
                        image.write_bytes(raw)



if __name__ == "__main__":
    unittest.main()
