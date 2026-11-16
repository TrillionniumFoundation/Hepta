"""Actual native continuation controls; no Cell/model qualification transfer."""
from __future__ import annotations
import base64
import ctypes
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from tools.cell_bridge_native import (
    BridgeIntegrityError, BridgeRejected, HEADER, MAX_EXTENT,
    NativeCellBridge, build_native_bridge, encode_request,
)

ROOT = Path(__file__).resolve().parents[1]
D = lambda value: sha256(value).hexdigest()


class HiaCellBridgeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-cell-native-", dir="/dev/shm")
        out = Path(os.environ.get("HIA_CELL_BRIDGE_TEST_OUTPUT", cls.temporary.name + "/build"))
        cls.build = build_native_bridge(ROOT, out)
        cls.bridge = NativeCellBridge(ROOT, cls.build["image_path"], cls.build["image_sha256"],
                                     expected_source_sha256=cls.build["source_sha256"])

    @classmethod
    def tearDownClass(cls):
        cls.bridge.close()
        cls.temporary.cleanup()

    def begin(self, payload=b"actual input", **changes):
        values = dict(candidate_sha256=D(b"candidate"), cell_sha256=D(b"cell"),
                      request_sha256=D(b"canonical authorized request"), input_bytes=payload,
                      sequence=17, result_limit=65536)
        values.update(changes)
        return self.bridge.begin(bytes(HEADER), **values)

    def raw(self, request, state, *, output_size=None):
        count = len(request) if output_size is None else output_size
        sentinel = b"\x93" * 16
        initial_output = b"\xa5" * count
        src = ctypes.create_string_buffer(sentinel + request + sentinel)
        out = ctypes.create_string_buffer(sentinel + initial_output + sentinel)
        work = ctypes.create_string_buffer(sentinel + state + sentinel)
        code = int(self.bridge._entry(ctypes.byref(src, 16), len(request), ctypes.byref(out, 16), count,
                                      ctypes.byref(work, 16), len(state)))
        self.assertEqual(src.raw[16:16 + len(request)], request)
        for array, size in ((src, len(request)), (out, count), (work, len(state))):
            self.assertEqual(array.raw[:16], sentinel)
            self.assertEqual(array.raw[size + 16:size + 32], sentinel)
        output, after = out.raw[16:16 + count], work.raw[16:16 + len(state)]
        if code:
            self.assertEqual(after, state, "refusal changed continuation")
            self.assertEqual(output, initial_output, "refusal published response")
        return code, output, after

    def test_generated_source_is_exact_and_original_compiler_is_pinned(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_cell_bridge_continuation import document
        source = (ROOT / "examples/hia_cell_bridge/continuation.hepta").read_bytes()
        self.assertEqual(render_assembly(document()).encode(), source)
        self.assertEqual(D(source), self.build["source_sha256"])
        self.assertEqual(self.build["compiler_commit"], "f33d8da316de8fdf27b504371f1a5310997ff548")
        self.assertFalse(self.build["receipt"]["claims"]["fallback_used"])
        self.assertFalse(self.build["receipt"]["claims"]["self_hosted"])
        self.assertGreater(self.build["compile_wall_ns"], 0)

    def test_actual_native_roundtrip_complete_state_and_full_payload_bound(self):
        for size in (0, 1, 257, 65536):
            with self.subTest(size=size):
                payload = bytes(index % 251 for index in range(size))
                first = self.begin(payload)
                self.assertEqual(first.action, "INVOKE_CELL")
                self.assertEqual(first.payload, payload)
                state = bytearray(HEADER)
                state[:8] = b"HCLSTA01"
                struct.pack_into("<3Q", state, 8, 1, 1, 17)
                for offset, value in zip((32, 64, 96, 128),
                                          (D(b"candidate"), D(b"cell"), D(b"canonical authorized request"), D(payload))):
                    state[offset:offset + 32] = bytes.fromhex(value)
                struct.pack_into("<2Q", state, 160, size, 65536)
                self.assertEqual(first.state, bytes(state))
                result = self.bridge.resume(first.state, binding=first.binding, outcome="success", result_bytes=payload)
                self.assertEqual(result.action, "COMPLETE")
                self.assertEqual(result.payload, payload)
                struct.pack_into("<Q", state, 16, 2)
                struct.pack_into("<Q", state, 176, size)
                state[192:224] = sha256(payload).digest()
                self.assertEqual(result.state, bytes(state))

    def test_complete_failure_and_cancellation_are_actual_result_observations(self):
        for outcome, expected in (("success", "COMPLETE"), ("failed", "FAILED"), ("cancelled", "CANCELLED")):
            with self.subTest(outcome=outcome):
                first = self.begin()
                result = self.bridge.resume(first.state, binding=first.binding, outcome=outcome, result_bytes=b"observed")
                self.assertEqual(result.action, expected)
                self.assertEqual(result.payload, b"observed")
                with self.assertRaises(BridgeRejected):
                    self.bridge.resume(result.state, binding=first.binding, outcome=outcome, result_bytes=b"observed")
                with self.assertRaises(BridgeRejected):
                    self.bridge.recover(result.state, binding=first.binding)

    def test_unknown_and_cold_recovery_never_reissue_an_invocation(self):
        first = self.begin()
        state = first.state
        for _ in range(3):
            recovered = self.bridge.recover(state, binding=first.binding)
            self.assertEqual(recovered.action, "UNKNOWN")
            self.assertEqual(recovered.payload, b"")
            state = recovered.state
        observed = self.bridge.resume(state, binding=first.binding, outcome="unknown")
        self.assertEqual(observed.action, "UNKNOWN")
        late = self.bridge.resume(observed.state, binding=first.binding, outcome="success", result_bytes=b"retained original")
        self.assertEqual(late.action, "COMPLETE")

    def test_cancellation_is_one_request_and_success_can_win_the_race(self):
        for outcome, expected in (("cancelled", "CANCELLED"), ("success", "COMPLETE")):
            with self.subTest(outcome=outcome):
                first = self.begin()
                cancel = self.bridge.cancel(first.state, binding=first.binding)
                self.assertEqual(cancel.action, "CANCEL_REQUEST")
                with self.assertRaises(BridgeRejected):
                    self.bridge.cancel(cancel.state, binding=first.binding)
                unknown = self.bridge.recover(cancel.state, binding=first.binding)
                self.assertEqual(unknown.action, "UNKNOWN")
                with self.assertRaises(BridgeRejected):
                    self.bridge.cancel(unknown.state, binding=first.binding)
                terminal = self.bridge.resume(unknown.state, binding=first.binding, outcome=outcome)
                self.assertEqual(terminal.action, expected)

    def test_pending_and_terminal_continuations_cannot_begin_again(self):
        first = self.begin()
        states = [first.state, self.bridge.recover(first.state, binding=first.binding).state,
                  self.bridge.resume(first.state, binding=first.binding, outcome="success").state]
        request = encode_request(1, first.binding, b"actual input")
        for state in states:
            with self.subTest(phase=struct.unpack_from("<Q", state, 16)[0]):
                self.assertEqual(self.raw(request, state)[0], 9)

    def test_every_identity_digest_byte_is_bound_and_mismatches_are_atomic(self):
        first = self.begin()
        original = encode_request(2, first.binding, b"observed", 1)
        for index in range(32, 160):
            with self.subTest(index=index):
                request = bytearray(original)
                request[index] ^= 1
                self.assertEqual(self.raw(bytes(request), first.state)[0], 10)
        for changed in (replace(first.binding, sequence=18), replace(first.binding, result_limit=65535)):
            self.assertEqual(self.raw(encode_request(2, changed, b"observed", 1), first.state)[0], 10)

    def test_malformed_requests_refuse_without_state_or_output_writes(self):
        first = self.begin()
        original = encode_request(1, first.binding, b"actual input")
        cases = []
        for offset, value in ((0, 0), (8, 2), (16, 0), (16, 5), (24, 0),
                              (160, 999), (168, 1), (176, 0), (176, 65537), (184, 1), (224, 1)):
            request = bytearray(original)
            struct.pack_into("<Q", request, offset, value)
            cases.append((f"field-{offset}-{value}", bytes(request), bytes(256), None))
        for offset in (32, 64, 96, 128):
            request = bytearray(original)
            request[offset:offset + 32] = bytes(32)
            cases.append((f"zero-digest-{offset}", bytes(request), bytes(256), None))
        wrong_digest = bytearray(original)
        wrong_digest[192] ^= 1
        cases.append(("mismatched-input-digest", bytes(wrong_digest), bytes(256), None))
        cases.extend((
            ("short-header", original[:255], bytes(256), None),
            ("long-request", original + bytes(MAX_EXTENT), bytes(256), None),
            ("short-state", original, bytes(255), None),
            ("long-state", original, bytes(257), None),
            ("short-output", original, bytes(256), 255),
        ))
        for label, request, state, output_size in cases:
            with self.subTest(label=label):
                self.assertNotEqual(self.raw(request, state, output_size=output_size)[0], 0)

    def test_corrupted_pending_state_and_invalid_results_refuse_atomically(self):
        first = self.begin(result_limit=16)
        original = encode_request(2, first.binding, b"observed", 1)
        for offset, value in ((0, 0), (8, 2), (16, 2), (16, 9), (24, 0),
                              (160, 65537), (168, 0), (176, 1), (184, 1), (192, 1), (224, 1)):
            with self.subTest(offset=offset, value=value):
                state = bytearray(first.state)
                struct.pack_into("<Q", state, offset, value)
                self.assertNotEqual(self.raw(original, bytes(state))[0], 0)
        for status in (0, 4, 5):
            request = bytearray(original)
            struct.pack_into("<Q", request, 168, status)
            self.assertEqual(self.raw(bytes(request), first.state)[0], 11)
        request = bytearray(original)
        request[192:224] = bytes(32)
        self.assertEqual(self.raw(bytes(request), first.state)[0], 11)
        oversized = bytearray(encode_request(2, replace(first.binding, result_limit=32), b"x" * 17, 1))
        struct.pack_into("<Q", oversized, 176, 16)
        self.assertEqual(self.raw(bytes(oversized), first.state)[0], 11)

    def test_wrapper_checks_actual_payload_preimages_and_native_image_hash(self):
        first = self.begin()
        request = bytearray(encode_request(2, first.binding, b"observed", 1))
        request[-1] ^= 1
        with self.assertRaises(ValueError):
            self.bridge.step(bytes(request), first.state, binding=first.binding)
        with self.assertRaises(BridgeIntegrityError):
            NativeCellBridge(ROOT, self.build["image_path"], D(b"different image"))
        with self.assertRaises(ValueError):
            self.bridge.resume(first.state, binding=first.binding, outcome="unknown", result_bytes=b"invented")

    def test_original_native_abi_rejects_aliases_before_core(self):
        first = self.begin()
        request = encode_request(1, first.binding, b"actual input")
        shared = ctypes.create_string_buffer(request)
        state = ctypes.create_string_buffer(bytes(256), 256)
        before = shared.raw
        code = int(self.bridge._entry(shared, len(request), shared, len(request), state, 256))
        self.assertEqual(code, 4 << 32)
        self.assertEqual(shared.raw, before)
        self.assertEqual(state.raw, bytes(256))

    def test_new_process_loads_original_state_and_accepts_retained_result(self):
        first = self.begin()
        document = {"root": str(ROOT), "image": self.build["image_path"], "sha": self.build["image_sha256"],
                    "state": base64.b64encode(first.state).decode(), "binding": first.binding.to_dict()}
        program = '''import base64,json,sys
from tools.cell_bridge_native import NativeCellBridge,BridgeBinding
d=json.load(sys.stdin)
with NativeCellBridge(d["root"],d["image"],d["sha"]) as bridge:
 binding=BridgeBinding.from_dict(d["binding"])
 pending=bridge.recover(base64.b64decode(d["state"]),binding=binding)
 result=bridge.resume(pending.state,binding=binding,outcome="success",result_bytes=b"original retained result")
 print(json.dumps({"actions":[pending.action,result.action],"payload":base64.b64encode(result.payload).decode(),"native_calls":2}))
'''
        result = subprocess.run([sys.executable, "-c", program], input=json.dumps(document), text=True,
                                cwd=ROOT, capture_output=True, timeout=20, check=True)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["actions"], ["UNKNOWN", "COMPLETE"])
        self.assertEqual(base64.b64decode(observed["payload"]), b"original retained result")
        self.assertEqual(observed["native_calls"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
