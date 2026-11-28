"""Actual native refusal and ownership controls for the two HIA carrier policies.

These controls call the compiled HIA machine images. They do not replace the
unchanged CPython exporter, cell, exception-identity or GC component controls.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import struct
import sys
import unittest

REFUSAL = 0xFFFFFFFD


class Policy:
    def __init__(self, kind, path, digest):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.kind = kind
        self.raw = path.read_bytes()
        if sha256(self.raw).hexdigest() != digest:
            raise ValueError("policy differs from its explicitly supplied SHA256")
        self.image = NativeHiaJsonImage(self.raw, digest)
        self.path = path
        self.magic = int.from_bytes(b"HIACIP01" if kind == "image" else b"HIACCP01", "little")
        self.size = 256 if kind == "image" else 512
        self.calls = 0

    def request(self, mode, *, state=None, status=0, value=0, owned=0):
        sequence, action = (0, 0) if state is None else struct.unpack_from("<2Q", state, 16)
        return bytearray(struct.pack("<8Q", self.magic, mode, sequence, action, status, value, owned, 0))

    def invoke(self, source, state, *, lengths=None):
        output = bytearray(b"\xA7" * 32)
        inputs = bytes(source)
        a = (ctypes.c_ubyte * len(source)).from_buffer(source)
        b = (ctypes.c_ubyte * len(output)).from_buffer(output)
        c = (ctypes.c_ubyte * len(state)).from_buffer(state)
        ns, no, nw = lengths or (64, 32, self.size)
        code = self.image._entry(a, ns, b, no, c, nw)
        self.calls += 1
        if bytes(source) != inputs:
            raise AssertionError("native carrier policy mutated its readonly request")
        return code, output

    def first(self, mode):
        state = bytearray(self.size)
        code, output = self.invoke(self.request(mode), state)
        if code != 1:
            raise AssertionError("valid initial policy request was not admitted")
        return state, output

    def stable(self):
        return self.path.read_bytes() == self.raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in ("image", "cell"):
        parser.add_argument("--" + kind, type=Path, required=True)
        parser.add_argument("--" + kind + "-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    policies = {
        kind: Policy(kind, getattr(args, kind).resolve(strict=True), getattr(args, kind + "_sha256"))
        for kind in ("image", "cell")
    }
    controls = []

    class NativePolicyControls(unittest.TestCase):
        def refusal(self, policy, label, request, state, lengths=None):
            before = bytes(state)
            code, output = policy.invoke(request, state, lengths=lengths)
            self.assertEqual(code, REFUSAL, label)
            self.assertEqual(bytes(state), before, label)
            self.assertEqual(output, b"\xA7" * 32, label)
            controls.append({"id": policy.kind + ":" + label, "refused": True})

        def test_exact_input_output_state_extents_and_initial_shape(self):
            for p in policies.values():
                for lengths in ((63, 32, p.size), (65, 32, p.size), (64, 31, p.size),
                                (64, 33, p.size), (64, 32, p.size - 1), (64, 32, p.size + 1)):
                    self.refusal(p, "extent-" + str(lengths), p.request(1), bytearray(p.size), lengths)
                for offset, value in ((0, p.magic ^ 1), (8, 0), (8, 6), (16, 1),
                                      (24, 1), (32, 1), (40, 1), (48, 1), (56, 1)):
                    request = p.request(1)
                    struct.pack_into("<Q", request, offset, value)
                    self.refusal(p, "initial-request-" + str(offset) + "-" + str(value),
                                 request, bytearray(p.size))
                for offset in (8, 31, p.size - 1):
                    state = bytearray(p.size)
                    state[offset] = 1
                    self.refusal(p, "nonzero-initial-state-" + str(offset), p.request(1), state)

        def test_pending_acknowledgement_sequence_action_mode_and_types(self):
            for p in policies.values():
                pending, _ = p.first(1)
                for offset, value in ((0, p.magic ^ 1), (8, 2), (16, 0), (16, 2),
                                      (24, 0), (24, 99), (32, 2), (56, 1)):
                    request = p.request(1, state=pending)
                    struct.pack_into("<Q", request, offset, value)
                    self.refusal(p, "pending-request-" + str(offset) + "-" + str(value),
                                 request, bytearray(pending))
                fields = ((0, p.magic ^ 1), (8, 2), (104, 1), (56, 2))
                fields += ((40, 4), (48, 4), (112, 2)) if p.kind == "image" else (
                    (40, 65), (48, 65), (64, 65), (128, 65), (72, 256))
                for offset, value in fields:
                    state = bytearray(pending)
                    struct.pack_into("<Q", state, offset, value)
                    self.refusal(p, "pending-state-" + str(offset), p.request(1, state=pending), state)

        def test_image_three_exports_reverse_release_and_receiver_lifetime(self):
            p = policies["image"]
            for failed_export in (None, 0, 1, 2):
                state, output = p.first(1)
                trace = []
                for _ in range(100):
                    operation, a, b, reserved = struct.unpack("<4Q", output)
                    self.assertEqual(reserved, 0)
                    trace.append((operation, a, b))
                    failed = operation == 5 and a == failed_export
                    value = 1 if operation in (3, 4, 5) else 123 if operation == 6 else 0
                    code, output = p.invoke(p.request(1, state=state, status=int(failed), value=value), state)
                    if code == 0:
                        break
                    self.assertEqual(code, 1)
                else:
                    self.fail("native image policy did not terminate within its fixed sequence")
                self.assertEqual(trace[0][0], 1)
                releases = [a for op, a, b in trace if op == 7]
                self.assertEqual(releases, [2, 1, 0] if failed_export is None else list(range(failed_export - 1, -1, -1)))
                self.assertEqual([op for op, a, b in trace].count(6), int(failed_export is None))
                self.assertEqual(trace[-1][0], 9)
                self.assertEqual(struct.unpack("<4Q", output), (0, int(failed_export is not None), 0, 0))
                self.refusal(p, "terminal-replay-" + str(failed_export), p.request(1, state=state), state)
                controls.append({"id": "image:reverse-unwind-" + str(failed_export), "trace": trace, "passed": True})

        def test_cell_callback_ownership_and_original_temporary_release_order(self):
            p = policies["cell"]
            acquire = {1: 128, 43: 4, 44: 8, 45: 16, 46: 32, 47: 64}
            for failure in (None, 43, 44, 45, 46, 47):
                state, output = p.first(5)
                mask = 0
                trace = []
                for _ in range(100):
                    operation, a, b, reserved = struct.unpack("<4Q", output)
                    self.assertEqual(reserved, 0)
                    trace.append((operation, a, b))
                    failed = operation == failure
                    if operation == 80:
                        self.assertTrue(mask & a)
                        mask ^= a
                    elif operation in acquire and not failed:
                        mask |= acquire[operation]
                    value = 1 if operation == 42 else 0
                    code, output = p.invoke(p.request(5, state=state, status=int(failed),
                                                        value=value, owned=mask), state)
                    if code == 0:
                        break
                    self.assertEqual(code, 1)
                else:
                    self.fail("native cell policy did not terminate within its fixed sequence")
                if failure is None:
                    self.assertEqual([a for op, a, b in trace if op == 80], [8, 16, 4, 32, 128])
                self.assertEqual(struct.unpack("<4Q", output), (0, int(failure is not None), 64 if failure is None else 0, 0))
                self.assertEqual(mask, 64 if failure is None else 0)
                self.refusal(p, "terminal-callback-replay-" + str(failure), p.request(5, state=state, owned=mask), state)
                controls.append({"id": "cell:owned-cleanup-" + str(failure), "trace": trace, "passed": True})

        def test_cell_owned_mask_cannot_invent_drop_or_duplicate_an_acquisition(self):
            p = policies["cell"]
            state, output = p.first(5)
            # Actual parse and live-factory observations lead to receiver retention.
            code, output = p.invoke(p.request(5, state=state), state)
            self.assertEqual(code, 1)
            self.assertEqual(struct.unpack_from("<Q", output)[0], 42)
            code, output = p.invoke(p.request(5, state=state, value=1), state)
            self.assertEqual(code, 1)
            self.assertEqual(struct.unpack_from("<Q", output)[0], 1)
            for wrong in (0, 1, 64, 129, 255, 256):
                self.refusal(p, "receiver-ack-mask-" + str(wrong),
                             p.request(5, state=state, owned=wrong), bytearray(state))
            code, output = p.invoke(p.request(5, state=state, owned=128), state)
            self.assertEqual(code, 1)
            self.assertEqual(struct.unpack_from("<Q", output)[0], 43)
            for wrong in (0, 4, 128, 255):
                self.refusal(p, "dictionary-ack-mask-" + str(wrong),
                             p.request(5, state=state, owned=wrong), bytearray(state))
            for wrong in (1, 64, 255):
                self.refusal(p, "failed-allocation-mask-" + str(wrong),
                             p.request(5, state=state, status=1, owned=wrong), bytearray(state))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativePolicyControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    stable = all(p.stable() for p in policies.values())
    report = {"schema": "hepta.hia.carrier-native-policy-controls.v1",
              "status": "PASS" if result.wasSuccessful() and stable else "HOLD",
              "methods": result.testsRun, "controls": controls,
              "actual_native_calls": {k: p.calls for k, p in policies.items()},
              "images_unchanged": stable, "full_worker_qualification_claimed": False}
    (args.output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "methods", "actual_native_calls", "images_unchanged")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
