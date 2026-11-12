"""Full native value diagnostics and their original ordinary caller boundaries.

The existing Core admission test module is retained without changed assertions.
Only the two value-lookup diagnostic families claim complete message equality.
"""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_core_admission_native import (
    SOURCE, SCHEMA, SELECTOR, ERROR_CODES, NativeCoreAdmission, scratch_sizes,
    DIAGNOSTIC_BYTES, DIAGNOSTIC_HEADER, DIAGNOSTIC_CAPACITY, DIAGNOSTIC_MAGIC,
)
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program

COLD = "HEPTA_HIA_CORE_DIAGNOSTICS_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_CORE_DIAGNOSTICS_DEVELOPMENT_COMPILER"
EVIDENCE = "HEPTA_HIA_CORE_DIAGNOSTICS_EVIDENCE"


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def block(name="entry", params=(), ops=(), term=None):
    return {"id": name, "params": [{"name": n, "type": t} for n, t in params],
            "ops": deepcopy(list(ops)), "term": deepcopy(term or {"op": "ret", "values": []})}


def program(name="f", entry="entry", params=(), returns=(), effects=(), blocks=None):
    return {"schema": "hepta.hia.program.v8", "module": "diagnostics", "functions": [
        {"name": name, "params": [{"name": n, "type": t} for n, t in params],
         "returns": list(returns), "effects": list(effects), "entry": entry,
         "blocks": deepcopy(blocks if blocks is not None else [block(entry, params)])}]}


def instruction(op, args=(), outputs=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [{"name": n, "type": t} for n, t in outputs], "attrs": attrs}


@contextmanager
def reference_environment():
    clean = {k: v for k, v in os.environ.items()
             if not (k.startswith("HEPTA_HIA_") and k.endswith("_MANIFEST"))}
    with patch.dict(os.environ, clean, clear=True):
        yield


def reference_error(value):
    with reference_environment():
        try:
            verify_program(value)
        except HIAProgramRejected as error:
            return type(error), error.code, str(error)
    raise AssertionError("the independent reference unexpectedly admitted this case")


def value_cases():
    missing_return = program()
    missing_return["functions"][0]["blocks"][0]["term"]["values"] = ["missing_return"]
    missing_arg = program(blocks=[block(ops=[
        instruction("int.add", ["first_argument", "second_argument"], [("sum", "u32")])])])
    missing_cond = program(blocks=[
        block(term={"op": "branch", "cond": "missing_condition",
                    "then": {"target": "left", "args": []},
                    "else": {"target": "right", "args": []}}),
        block("left"), block("right")])
    missing_jump = program(blocks=[
        block(term={"op": "jump", "target": "tail", "args": ["missing_edge"]}),
        block("tail", [("tail_value", "u32")])])
    then_arg = program(params=[("condition", "bool")], blocks=[
        block(params=[("condition", "bool")], term={"op": "branch", "cond": "condition",
              "then": {"target": "left", "args": ["missing_then"]},
              "else": {"target": "right", "args": ["missing_else"]}}),
        block("left", [("left_value", "u32")]), block("right", [("right_value", "u32")])])
    else_arg = program(params=[("condition", "bool")], blocks=[
        block(params=[("condition", "bool")], term={"op": "branch", "cond": "condition",
              "then": {"target": "left", "args": []},
              "else": {"target": "right", "args": ["missing_else"]}}),
        block("left"), block("right", [("right_value", "u32")])])
    nonlocal_value = program(returns=["u32"], blocks=[
        block(ops=[instruction("const", (), [("local_value", "u32")], value=1)],
              term={"op": "jump", "target": "tail", "args": []}),
        block("tail", term={"op": "ret", "values": ["local_value"]})])
    forward_value = program(blocks=[block(ops=[
        instruction("int.add", ["later", "later"], [("sum", "u32")]),
        instruction("const", (), [("later", "u32")], value=1)])])
    consumed = program(params=[("owner", "buffer")], effects=["alloc"], blocks=[
        block(params=[("owner", "buffer")], ops=[
            instruction("owner.drop", ["owner"]), instruction("owner.drop", ["owner"])])])
    return [("return", missing_return), ("instruction", missing_arg), ("condition", missing_cond),
            ("jump_argument", missing_jump), ("then_argument", then_arg), ("else_argument", else_arg),
            ("nonlocal", nonlocal_value), ("forward", forward_value), ("consumed", consumed)]


class _NativeFixture:
    @classmethod
    def setUpClass(cls):
        cls.temporary = None
        present = [key for key in (COLD, DEVELOPMENT) if key in os.environ]
        if len(present) != 1 or not os.environ[present[0]]:
            raise ValueError("one nonempty explicit diagnostics cold/development compiler is required")
        if EVIDENCE in os.environ:
            if not os.environ[EVIDENCE]:
                raise ValueError("empty diagnostics evidence path")
            cls.folder = Path(os.environ[EVIDENCE]) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-core-diagnostics-")
            cls.folder = Path(cls.temporary.name)
        source = SOURCE.read_bytes()
        if present[0] == COLD:
            from tools.build_hia_core_admission import build
            cold = Path(os.environ[COLD]).resolve(strict=True)
            cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes)
            nested_bytes = Path(report["nested_report"]).read_bytes()
            if sha256(nested_bytes).hexdigest() != report["nested_report_sha256"]:
                raise ValueError("diagnostics nested cold bytes differ")
            nested = json.loads(nested_bytes)
            compiler = Path(nested["generations"][-1]["produced_image"]).resolve(strict=True)
            cls.manifest = build(cls.folder / "native", compiler, cold)
            manifest = json.loads(cls.manifest.read_bytes())
            image = cls.manifest.parent / manifest["image_path"]
            if cold.read_bytes() != cold_bytes:
                raise ValueError("diagnostics cold input changed")
            scope = "matching-current-source-cold-builder"
        else:
            from tools.qualify_hia_selfhost import compile_stage
            compiler = Path(os.environ[DEVELOPMENT]).resolve(strict=True)
            compiler_bytes = compiler.read_bytes()
            image, cls.compile_receipt = compile_stage(
                cls.folder, "core-diagnostics-development", compiler, source)
            if compiler.read_bytes() != compiler_bytes:
                raise ValueError("development compiler changed")
            cls.manifest = cls.folder / "manifest.json"
            manifest = {"schema": SCHEMA, "source_sha256": sha256(source).hexdigest(),
                        "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                        "compiler_sha256": sha256(compiler_bytes).hexdigest()}
            cls.manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            scope = "explicit-development-image-not-current-source-cold"
        image_bytes = image.read_bytes()
        if SOURCE.read_bytes() != source or sha256(image_bytes).hexdigest() != manifest["image_sha256"]:
            raise ValueError("diagnostics source/image changed")
        cls.native = NativeCoreAdmission(image_bytes, sha256(image_bytes).hexdigest())
        cls.image_sha256 = sha256(image_bytes).hexdigest()
        (cls.folder / "fixture.json").write_text(json.dumps({
            "scope": scope, "source": str(SOURCE), "source_sha256": sha256(source).hexdigest(),
            "compiler": str(compiler), "compiler_sha256": sha256(compiler.read_bytes()).hexdigest(),
            "image": str(image), "image_sha256": cls.image_sha256, "image_bytes": len(image_bytes),
            "manifest": str(cls.manifest), "manifest_sha256": sha256(cls.manifest.read_bytes()).hexdigest(),
            "production_default_changed": False}, sort_keys=True, indent=2) + "\n")

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def setUp(self):
        self.observations = []

    def tearDown(self):
        destination = self.folder / (self._testMethodName + ".observations.json")
        with destination.open("x") as stream:
            json.dump(self.observations, stream, sort_keys=True, indent=2)
            stream.write("\n")

    def compare(self, value, *, raw=None):
        raw = wire(value) if raw is None else raw
        expected_type, expected_code, expected_message = reference_error(raw)
        observed = []
        original = self.native.receipt

        def capture(*args, **kwargs):
            receipt = original(*args, **kwargs)
            observed.append(receipt)
            return receipt

        with patch.object(self.native, "receipt", capture):
            with self.assertRaises(HIAProgramRejected) as found:
                self.native.admit(raw)
        self.assertIs(type(found.exception), expected_type)
        self.assertEqual(found.exception.code, expected_code)
        self.assertEqual(str(found.exception), expected_message)
        self.assertEqual(len(observed), 1)
        receipt = observed[0]
        self.assertTrue(receipt.native_executed)
        self.assertIn(receipt.diagnostic_kind, (1, 2))
        self.assertEqual(receipt.message, expected_message[len(expected_code) + 2:])
        self.assertEqual(receipt.raw[64:], receipt.message.encode("ascii"))
        self.observations.append({"input_hex": raw.hex(), "input_sha256": sha256(raw).hexdigest(),
                                  "image_sha256": self.image_sha256, "status": receipt.status,
                                  "diagnostic_kind": receipt.diagnostic_kind,
                                  "native_frame_hex": receipt.raw.hex(),
                                  "exception_type": type(found.exception).__name__,
                                  "code": found.exception.code, "message": str(found.exception)})
        return receipt


class CoreValueDiagnosticNativeTests(_NativeFixture, unittest.TestCase):
    def test_every_value_use_matches_complete_reference_type_code_and_message(self):
        for label, value in value_cases():
            with self.subTest(label=label):
                self.compare(value)

    def test_argument_function_and_breadth_first_block_refusal_order(self):
        value = program(name="source_first")
        value["functions"][0]["blocks"][0]["term"]["values"] = ["argument_first", "argument_second"]
        other = program(name="alphabetically_earlier")["functions"][0]
        other["blocks"][0]["term"]["values"] = ["other_function"]
        value["functions"].append(other)
        self.compare(value)
        condition = [("condition", "bool")]
        value = program(params=condition, blocks=[
            block(params=condition, term={"op": "branch", "cond": "condition",
                  "then": {"target": "left", "args": []}, "else": {"target": "right", "args": []}}),
            block("right", term={"op": "ret", "values": ["right_missing"]}),
            block("left", term={"op": "ret", "values": ["left_missing"]})])
        receipt = self.compare(value)
        self.assertEqual(receipt.message, "f/left: undefined/nonlocal value left_missing")
        value = value_cases()[1][1]
        value["functions"][0]["blocks"][0]["ops"][0]["op"] = "not_an_opcode"
        self.compare(value)  # value lookup precedes opcode selection in the original body.

    def test_longest_names_and_raw_escape_spelling_are_not_truncated(self):
        value = program("F" * 128, "B" * 128)
        value["functions"][0]["blocks"][0]["term"]["values"] = ["V" * 128]
        receipt = self.compare(value)
        self.assertEqual(len(receipt.raw) - 64, 412)
        raw = wire(value).replace(b'"' + b"V" * 128 + b'"', b'"' + b"\\u0056" * 128 + b'"')
        self.compare(value, raw=raw)
        for name in ("a" * 129, "\u00e9", "__hia_private"):
            bad = program()
            bad["functions"][0]["blocks"][0]["term"]["values"] = [name]
            expected = reference_error(wire(bad))
            receipt = self.native.receipt(wire(bad))
            self.assertEqual(ERROR_CODES[receipt.status], expected[1])
            with self.assertRaises(HIAProgramRejected) as found:
                self.native.admit(wire(bad))
            self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
            self.assertTrue(receipt.native_executed)
            self.assertEqual(receipt.diagnostic_kind, 17)
            self.assertEqual(receipt.message, expected[2][len(expected[1]) + 2:])
            self.assertEqual(receipt.raw[64:], receipt.message.encode("utf-8"))
            self.assertEqual(len(receipt.raw), 64 + len(receipt.message.encode("utf-8")))

    def test_private_suffix_publishes_complete_bytes_and_preserves_canaries(self):
        for label, value in [("success", program()), value_cases()[0], value_cases()[-1]]:
            with self.subTest(label=label):
                raw = wire(value)
                state_size, arena_size = scratch_sizes(len(raw))
                source = ctypes.create_string_buffer(raw, max(1, len(raw)))
                state = ctypes.create_string_buffer(state_size + 16)
                arena = ctypes.create_string_buffer(arena_size + 16)
                ctypes.memset(ctypes.addressof(state) + state_size - 512, 0xa5, 512 + 16)
                ctypes.memset(ctypes.addressof(arena) + arena_size, 0x6b, 16)
                code = self.native._entry(source, len(raw), state, state_size, arena, arena_size)
                suffix = state.raw[state_size - DIAGNOSTIC_BYTES:state_size]
                magic, version, status, kind, size, capacity, r0, r1 = struct.unpack_from("<8Q", suffix)
                self.assertEqual((magic, version, status, capacity, r0, r1),
                                 (DIAGNOSTIC_MAGIC, 1, code, DIAGNOSTIC_CAPACITY, 0, 0))
                if label == "success":
                    self.assertEqual((code, kind, size), (0, 0, 0))
                else:
                    expected = reference_error(raw)
                    self.assertEqual(suffix[64:64 + size].decode("ascii"),
                                     expected[2][len(expected[1]) + 2:])
                self.assertEqual(suffix[64 + size:], b"\xa5" * (512 - size))
                self.assertEqual(state.raw[state_size:], b"\xa5" * 16)
                self.assertEqual(arena.raw[arena_size:], b"\x6b" * 16)
                self.assertEqual(source.raw[:len(raw)], raw)
                self.observations.append({"case": label, "status": code, "frame_hex": suffix[:64 + size].hex(),
                                          "source_sha256": sha256(raw).hexdigest(), "canaries_preserved": True})
        raw = wire(value_cases()[0][1])
        state_size, arena_size = scratch_sizes(len(raw))
        source = ctypes.create_string_buffer(raw)
        state = ctypes.create_string_buffer(b"\x71" * state_size, state_size)
        arena = ctypes.create_string_buffer(b"\x39" * arena_size, arena_size)
        before = (state.raw, arena.raw)
        code = self.native._entry(source, len(raw), state, state_size - 1, arena, arena_size)
        self.assertEqual(code, 0xfffffffd)
        self.assertEqual((state.raw, arena.raw), before)
        self.assertEqual(source.raw[:len(raw)], raw)

    def test_selected_core_uses_native_diagnostics_without_reference_fallback(self):
        value = value_cases()[0][1]
        expected = reference_error(wire(value))
        with reference_environment(), patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with (patch("hepta.hia_program._reference_primitive_structure", side_effect=AssertionError("reference declarations")),
                  patch("hepta.hia_program._verify_function", side_effect=AssertionError("reference body"))):
                with self.assertRaises(HIAProgramRejected) as found:
                    verify_program(value)
                self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
                self.assertEqual(verify_program(program()).as_dict(), program())

    def test_original_snapshot_and_legacy_refusals_precede_native_body_admission(self):
        class ForeignDictionary(dict):
            pass
        legacy = program()
        legacy["schema"] = "hepta.hia.program.v2"
        legacy["types"] = []
        invalid_float = program()
        invalid_float["functions"][0]["blocks"][0]["ops"] = [
            instruction("const", (), [("bad", "u32")], value=1.0)]
        cycle = {}
        cycle["cycle"] = cycle
        capsule = VerifiedProgram(wire(program()), bytearray(b"{}"))
        for label, value in [("subclass", ForeignDictionary(program())), ("legacy", legacy),
                             ("float", invalid_float), ("cycle", cycle), ("capsule", capsule)]:
            with self.subTest(label=label):
                expected = reference_error(value)
                with reference_environment(), patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
                    with patch.object(NativeCoreAdmission, "receipt",
                                      side_effect=AssertionError("native called before original snapshot/legacy refusal")) as capture:
                        with self.assertRaises(HIAProgramRejected) as found:
                            verify_program(value)
                self.assertEqual((type(found.exception), found.exception.code, str(found.exception)), expected)
                self.assertEqual(capture.call_count, 0)

    def test_frame_faults_cannot_publish_a_partial_or_host_reconstructed_message(self):
        raw = wire(value_cases()[0][1])
        original = self.native._entry
        for label, field, value in [("magic", 0, 0), ("version", 8, 2), ("status", 16, 0),
                                   ("kind", 24, 3), ("empty_partial", 32, 0),
                                   ("overrun", 32, 513), ("capacity", 40, 511),
                                   ("reserved", 48, 1)]:
            with self.subTest(label=label):
                calls = []
                def corrupt(*args):
                    result = original(*args)
                    base = ctypes.addressof(args[2]) + int(args[3]) - DIAGNOSTIC_BYTES
                    ctypes.memmove(base + field, struct.pack("<Q", value), 8)
                    calls.append(result)
                    return result
                with patch.object(self.native, "_entry", corrupt):
                    with self.assertRaises(RuntimeError):
                        self.native.admit(raw)
                self.assertEqual(calls, [0xfffffff5])
        calls = []
        def bad_ascii(*args):
            result = original(*args)
            base = ctypes.addressof(args[2]) + int(args[3]) - DIAGNOSTIC_BYTES
            ctypes.memmove(base + 64, b"\xff", 1)
            calls.append(result)
            return result
        with patch.object(self.native, "_entry", bad_ascii):
            with self.assertRaises(RuntimeError):
                self.native.admit(raw)
        self.assertEqual(calls, [0xfffffff5])

    def test_old_schema_empty_selection_and_changed_image_never_fall_back(self):
        manifest = json.loads(self.manifest.read_bytes())
        bad_schema = self.folder / (self._testMethodName + ".old-schema.json")
        bad_schema.write_text(json.dumps({**manifest, "schema": "hepta.hia.core-admission-native.v1",
                                        "image_path": str((self.manifest.parent / manifest["image_path"]).resolve())}))
        image_path = self.manifest.parent / manifest["image_path"]
        changed_image = self.folder / (self._testMethodName + ".changed-image.bin")
        image_bytes = bytearray(image_path.read_bytes())
        image_bytes[-1] ^= 1
        with changed_image.open("xb") as stream:
            stream.write(image_bytes)
        bad_image = self.folder / (self._testMethodName + ".changed-image.json")
        bad_image.write_text(json.dumps({**manifest, "image_path": changed_image.name}))
        for selector in ("", str(bad_schema), str(bad_image)):
            with self.subTest(selector=selector):
                with reference_environment(), patch.dict(os.environ, {SELECTOR: selector}):
                    with patch("hepta.hia_program._reference_primitive_structure",
                               side_effect=AssertionError("selected admission fell back")):
                        with self.assertRaises((ValueError, RuntimeError)):
                            verify_program(program())


class CoreValueDiagnosticAgentTests(_NativeFixture, unittest.TestCase):
    @contextmanager
    def service(self):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient
        with tempfile.TemporaryDirectory(prefix="core-diagnostic-agent-") as temporary:
            root = Path(temporary)
            files = root / "files"
            files.mkdir()
            service = HIAAgentService(root / "state", artifact_roots=(files,))
            replies = []
            original_call = service.call
            def transport(*args, **kwargs):
                result = original_call(*args, **kwargs)
                replies.append((args[0], result))
                return result
            client = ToolClient(transport)
            session = Session(client, prefix=self._testMethodName)
            try:
                yield service, session, replies
            finally:
                service.close()

    def test_public_verify_preserves_complete_rejection_and_request_journal(self):
        from tools.hia_agent_native_qualification import exhaustive_u8_workload
        value = value_cases()[0][1]
        expected = reference_error(wire(value))
        native_calls = []
        original = NativeCoreAdmission.receipt
        def observed(image, *args, **kwargs):
            receipt = original(image, *args, **kwargs)
            native_calls.append((image.image_sha256, receipt))
            return receipt
        errors = []
        for selected in (False, True):
            with reference_environment():
                environment = {SELECTOR: str(self.manifest)} if selected else {}
                with patch.dict(os.environ, environment), self.service() as (service, session, replies):
                    session.freeze(exhaustive_u8_workload())
                    reference = session.artifact(value)
                    before = service.store.db.execute(
                        "SELECT COUNT(*) FROM artifacts WHERE kind='verification-receipt'").fetchone()[0]
                    context = patch.object(NativeCoreAdmission, "receipt", observed) if selected else patch.dict(os.environ, {})
                    with context:
                        with (patch("hepta.hia_program._verify_function",
                                    side_effect=AssertionError("reference body")) if selected else patch.dict(os.environ, {})):
                            try:
                                session.verify(reference)
                            except Exception:
                                pass
                    verify_replies = [reply for tool, reply in replies if tool == "hia_verify"]
                    self.assertEqual(len(verify_replies), 1)
                    response = verify_replies[0]
                    self.assertEqual(response["status"], "rejected")
                    self.assertEqual(response["error"]["code"], expected[1])
                    self.assertEqual(response["error"]["message"], expected[2])
                    self.assertEqual(service.store.db.execute(
                        "SELECT COUNT(*) FROM artifacts WHERE kind='verification-receipt'").fetchone()[0], before)
                    row = service.store.db.execute(
                        "SELECT state,response FROM requests WHERE tool='hia_verify'").fetchone()
                    self.assertEqual(row[0], "completed")
                    self.assertEqual(json.loads(row[1]), response)
                    errors.append(response["error"])
        self.assertEqual(errors[0], errors[1])
        self.assertTrue(native_calls)
        self.assertTrue(all(image_sha == self.image_sha256 and receipt.native_executed
                            for image_sha, receipt in native_calls))
        self.observations.append({"caller": "_hia_verify", "complete_error": errors[1],
                                  "actual_native_calls": len(native_calls),
                                  "native_frames": [r.raw.hex() for _, r in native_calls]})

    def test_real_emitted_native_artifact_rechecks_core_with_selected_whole_owner(self):
        from tools.hia_agent_native_qualification import add_program, exhaustive_u8_workload
        with reference_environment(), patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with self.service() as (service, session, replies):
                session.freeze(exhaustive_u8_workload())
                candidate = session.import_program(add_program())
                verification = session.verify(candidate)
                built = session.emit(candidate, receipts=[verification["verification_receipt"]])
                native_calls = []
                original = NativeCoreAdmission.receipt
                def observed(image, *args, **kwargs):
                    receipt = original(image, *args, **kwargs)
                    native_calls.append((image.image_sha256, receipt))
                    return receipt
                with (patch.object(NativeCoreAdmission, "receipt", observed),
                      patch("hepta.hia_program._reference_primitive_structure", side_effect=AssertionError("reference declarations")),
                      patch("hepta.hia_program._verify_function", side_effect=AssertionError("reference body"))):
                    actual, metadata, checked = service._native(built["native_artifact"])
                retained, _ = service.store.get(built["native_artifact"], kind="native")
                self.assertEqual(actual, retained)
                self.assertEqual(metadata["candidate"], candidate)
                self.assertEqual(checked.sha256, metadata["core_sha256"])
                self.assertTrue(native_calls)
                self.assertTrue(all(image_sha == self.image_sha256 and receipt.status == 0
                                    and receipt.native_executed for image_sha, receipt in native_calls))
                self.observations.append({"caller": "_native", "artifact_sha256": sha256(actual).hexdigest(),
                                          "candidate": candidate, "native_frames": [r.raw.hex() for _, r in native_calls]})
