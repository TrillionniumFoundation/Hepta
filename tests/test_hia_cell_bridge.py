"""Actual native continuation controls; no Cell/model qualification transfer."""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
from dataclasses import replace
import errno
import fcntl
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from tools import cell_bridge_native as native
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
        cls.fixtures = {}
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_native import build_program_machine
        fixture_dir = out / "loader-fixtures"
        fixture_dir.mkdir()
        # Distinct native returns detect stale dlopen images. These ABI probes
        # do not replace the actual continuation or its original controls.
        for label, symbol, code in (("first", "cell_bridge_step", 17),
                                    ("second", "cell_bridge_step", 23),
                                    ("missing-entry", "other_bridge_step", 29)):
            source = (f"hia-asm.v1 hepta.hia.program.v8 loader_probe_{code}\n"
                      f"fn {symbol}(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                      "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n"
                      f'  v3:u32 = const() {{"value":{code}}}\n'
                      "  ret(v3)\nend\n").encode()
            (fixture_dir / (label + ".hepta")).write_bytes(source)
            image = fixture_dir / (label + ".so")
            receipt = build_program_machine(assemble_program(source).as_dict(), image, kind="shared",
                                            foreign_buffer_exports=((symbol, MAX_EXTENT),))
            record = {"source_sha256": D(source), "image": str(image), "code": code,
                      "sha256": D(image.read_bytes()), "receipt": receipt}
            (fixture_dir / (label + ".json")).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            cls.fixtures[label] = record

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

    def probe(self, bridge, code):
        with self.assertRaises(BridgeRejected) as rejection:
            bridge.begin(bytes(HEADER), candidate_sha256=D(b"candidate"), cell_sha256=D(b"cell"),
                         request_sha256=D(b"request"), input_bytes=b"input", sequence=1)
        self.assertEqual(rejection.exception.native_return, code)

    def load_probe(self, label):
        fixture = self.fixtures[label]
        return NativeCellBridge(ROOT, fixture["image"], fixture["sha256"])

    def child_control(self, label, program):
        document = {"root": str(ROOT), "fixtures": self.fixtures, "scratch": self.temporary.name}
        result = subprocess.run([sys.executable, "-c", program], input=json.dumps(document), text=True,
                                cwd=ROOT, capture_output=True, timeout=30)
        record = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        path = Path(self.build["image_path"]).parent / "loader-fixtures" / (label + "-control.json")
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_loader_actual_multi_image_close_reopen_and_simultaneous_handles(self):
        first = self.load_probe("first")
        same = self.load_probe("first")
        first_fd, first_handle = first._fd, first._library._handle
        self.assertEqual(same._fd, first_fd)
        self.assertEqual(same._library._handle, first_handle)
        self.probe(first, 17)
        first.close()
        first.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            self.probe(first, 17)
        self.probe(same, 17)
        with self.load_probe("second") as second:
            self.assertNotEqual(second._fd, first_fd)
            self.assertNotEqual(second._library._handle, first_handle)
            self.probe(second, 23)
            self.probe(same, 17)
        same.close()
        with self.load_probe("first") as reopened:
            self.assertEqual(reopened._fd, first_fd)
            self.probe(reopened, 17)
        with self.load_probe("second") as reopened:
            self.probe(reopened, 23)

    def test_loader_concurrent_loads_share_one_retained_image_per_digest(self):
        def work(index):
            label = "first" if index % 2 == 0 else "second"
            with self.load_probe(label) as bridge:
                self.probe(bridge, self.fixtures[label]["code"])
                return label, bridge._fd
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = list(executor.map(work, range(64)))
        descriptors = {label: {fd for item, fd in observed if item == label} for label in ("first", "second")}
        self.assertEqual(len(descriptors["first"]), 1)
        self.assertEqual(len(descriptors["second"]), 1)
        self.assertFalse(descriptors["first"] & descriptors["second"])
        for label in descriptors:
            self.assertEqual(native._IMAGE_REGISTRY.entries[self.fixtures[label]["sha256"]]["fd"],
                             next(iter(descriptors[label])))

    def test_loader_close_waits_for_admitted_native_call_then_revokes_instance(self):
        bridge = self.load_probe("first")
        actual_entry = bridge._entry
        entered, release, closing, closed = (threading.Event() for _ in range(4))

        def gated_entry(*args):
            entered.set()
            if not release.wait(5):
                raise AssertionError("native call was not released")
            return actual_entry(*args)

        def close():
            closing.set()
            bridge.close()
            closed.set()

        bridge._entry = gated_entry
        with ThreadPoolExecutor(max_workers=2) as executor:
            call = executor.submit(self.probe, bridge, 17)
            try:
                self.assertTrue(entered.wait(5))
                revoke = executor.submit(close)
                self.assertTrue(closing.wait(5))
                self.assertFalse(closed.wait(0.05))
            finally:
                release.set()
            call.result(timeout=5)
            revoke.result(timeout=5)
        self.assertTrue(closed.is_set())
        with self.assertRaisesRegex(ValueError, "closed"):
            self.probe(bridge, 17)
        with self.load_probe("first") as other:
            self.probe(other, 17)

    def test_loader_seals_bytes_and_rechecks_changed_source_even_on_cache_hit(self):
        original = self.fixtures["first"]
        changed = self.fixtures["second"]
        path = Path(self.temporary.name) / "mutable-image.so"
        path.write_bytes(Path(original["image"]).read_bytes())
        with NativeCellBridge(ROOT, path, original["sha256"]) as first:
            self.assertEqual(fcntl.fcntl(first._fd, native.F_GET_SEALS) & native.REQUIRED_IMAGE_SEALS,
                             native.REQUIRED_IMAGE_SEALS)
            for mutate in (lambda: os.pwrite(first._fd, b"x", 0),
                           lambda: os.ftruncate(first._fd, 0),
                           lambda: os.ftruncate(first._fd, os.fstat(first._fd).st_size + 1)):
                with self.subTest(mutation=mutate.__code__.co_firstlineno):
                    with self.assertRaises(OSError) as denied:
                        mutate()
                    self.assertEqual(denied.exception.errno, errno.EPERM)
            path.write_bytes(Path(changed["image"]).read_bytes())
            self.probe(first, 17)
            with self.assertRaisesRegex(BridgeIntegrityError, "digest mismatch"):
                NativeCellBridge(ROOT, path, original["sha256"])
            with NativeCellBridge(ROOT, path, changed["sha256"]) as second:
                self.probe(second, 23)
                path.unlink()
                self.probe(first, 17)
                self.probe(second, 23)
                with self.assertRaises(FileNotFoundError):
                    NativeCellBridge(ROOT, path, changed["sha256"])

    def test_loader_rechecks_pinned_hia_source(self):
        fake_root = Path(self.temporary.name) / "source-pin"
        source = fake_root / native.SOURCE_PATH
        source.parent.mkdir(parents=True)
        source.write_bytes((ROOT / native.SOURCE_PATH).read_bytes())
        with NativeCellBridge(fake_root, self.build["image_path"], self.build["image_sha256"],
                              expected_source_sha256=self.build["source_sha256"]):
            pass
        source.write_bytes(source.read_bytes() + b"\n")
        with self.assertRaisesRegex(BridgeIntegrityError, "HIA source digest mismatch"):
            NativeCellBridge(fake_root, self.build["image_path"], self.build["image_sha256"],
                             expected_source_sha256=self.build["source_sha256"])

    def test_loader_registry_survives_independent_wrapper_imports(self):
        name = "hepta_test_independent_transport"
        spec = importlib.util.spec_from_file_location(name, ROOT / "tools/cell_bridge_native.py")
        alias = importlib.util.module_from_spec(spec)
        sys.modules[name] = alias
        try:
            spec.loader.exec_module(alias)
            self.assertIs(alias._IMAGE_REGISTRY, native._IMAGE_REGISTRY)
            fixture = self.fixtures["first"]
            with self.load_probe("first") as first, alias.NativeCellBridge(ROOT, fixture["image"], fixture["sha256"]) as other:
                self.assertEqual(first._fd, other._fd)
                with self.assertRaises(alias.BridgeRejected) as rejection:
                    other.begin(bytes(HEADER), candidate_sha256=D(b"candidate"), cell_sha256=D(b"cell"),
                                request_sha256=D(b"request"), input_bytes=b"input", sequence=1)
                self.assertEqual(rejection.exception.native_return, 17)
        finally:
            del sys.modules[name]

    def test_loader_retained_image_count_is_bounded_and_duplicates_still_work(self):
        observed = self.child_control("count-bound", '''import json,os,sys
from hashlib import sha256
from pathlib import Path
from tools import cell_bridge_native as n
d=json.load(sys.stdin)
source=Path(d["fixtures"]["first"]["image"]).read_bytes()
images=[]
for index in range(n.MAX_RETAINED_IMAGES+1):
 path=Path(d["scratch"])/("quota-"+str(index)+".so")
 data=source+bytes([index])
 path.write_bytes(data)
 images.append((path,sha256(data).hexdigest()))
for path,digest in images[:-1]:
 bridge=n.NativeCellBridge(d["root"],path,digest)
 assert int(bridge._entry(None,0,None,0,None,0))==17
 bridge.close()
assert len(n._IMAGE_REGISTRY.entries)==n.MAX_RETAINED_IMAGES
before=len(os.listdir("/proc/self/fd"))
try:
 n.NativeCellBridge(d["root"],*images[-1])
 raise AssertionError("count quota was bypassed")
except n.BridgeCapacityError:
 pass
assert len(os.listdir("/proc/self/fd"))==before
with n.NativeCellBridge(d["root"],*images[0]) as bridge:
 assert int(bridge._entry(None,0,None,0,None,0))==17
print(json.dumps({"retained_images":len(n._IMAGE_REGISTRY.entries),"retained_bytes":n._IMAGE_REGISTRY.total_bytes,
                  "count_limit":n.MAX_RETAINED_IMAGES,"duplicate_at_capacity":True,"rejection_fd_leak":False}))
''')
        self.assertEqual(observed["retained_images"], native.MAX_RETAINED_IMAGES)
        self.assertTrue(observed["duplicate_at_capacity"])

    def test_loader_retained_byte_and_individual_image_bounds(self):
        observed = self.child_control("byte-bound", '''import json,os,sys
from hashlib import sha256
from pathlib import Path
from tools import cell_bridge_native as n
d=json.load(sys.stdin)
f=d["fixtures"]["first"]
n.NativeCellBridge(d["root"],f["image"],f["sha256"]).close()
path=Path(d["scratch"])/"quota-oversize.so"
path.write_bytes(Path(f["image"]).read_bytes())
with path.open("r+b") as stream:
 stream.truncate(n.MAX_IMAGE_BYTES)
h=sha256()
with path.open("rb") as stream:
 while chunk:=stream.read(1024*1024):
  h.update(chunk)
before=(len(os.listdir("/proc/self/fd")),len(n._IMAGE_REGISTRY.entries),n._IMAGE_REGISTRY.total_bytes)
try:
 n.NativeCellBridge(d["root"],path,h.hexdigest())
 raise AssertionError("byte quota was bypassed")
except n.BridgeCapacityError:
 pass
with path.open("r+b") as stream:
 stream.truncate(n.MAX_IMAGE_BYTES+1)
try:
 n.NativeCellBridge(d["root"],path,h.hexdigest())
 raise AssertionError("individual extent bound was bypassed")
except n.BridgeIntegrityError as error:
 assert "extent" in str(error)
assert before==(len(os.listdir("/proc/self/fd")),len(n._IMAGE_REGISTRY.entries),n._IMAGE_REGISTRY.total_bytes)
print(json.dumps({"aggregate_bound_refused":True,"individual_bound_refused":True,"byte_limit":n.MAX_RETAINED_IMAGE_BYTES,
                  "retained_images":len(n._IMAGE_REGISTRY.entries),"retained_bytes":n._IMAGE_REGISTRY.total_bytes,
                  "rejection_fd_leak":False}))
''')
        self.assertTrue(observed["aggregate_bound_refused"])
        self.assertTrue(observed["individual_bound_refused"])

    def test_loader_load_failure_and_missing_entry_keep_bounded_custody(self):
        observed = self.child_control("failed-admission", '''import json,os,sys
from hashlib import sha256
from pathlib import Path
from tools import cell_bridge_native as n
d=json.load(sys.stdin)
path=Path(d["scratch"])/"invalid-image.so"
data=b"not an ELF image"
path.write_bytes(data)
before=len(os.listdir("/proc/self/fd"))
for _ in range(3):
 try:
  n.NativeCellBridge(d["root"],path,sha256(data).hexdigest())
  raise AssertionError("invalid ELF accepted")
 except OSError:
  pass
assert len(os.listdir("/proc/self/fd"))==before and not n._IMAGE_REGISTRY.entries
fifo=Path(d["scratch"])/"image-fifo"
os.mkfifo(fifo)
try:
 n.NativeCellBridge(d["root"],fifo,sha256(data).hexdigest())
 raise AssertionError("FIFO accepted")
except n.BridgeIntegrityError:
 pass
assert len(os.listdir("/proc/self/fd"))==before and not n._IMAGE_REGISTRY.entries
f=d["fixtures"]["missing-entry"]
for _ in range(3):
 try:
  n.NativeCellBridge(d["root"],f["image"],f["sha256"])
  raise AssertionError("missing entry accepted")
 except n.BridgeIntegrityError:
  pass
assert len(n._IMAGE_REGISTRY.entries)==1
record=n._IMAGE_REGISTRY.entries[f["sha256"]]
assert record["entry"] is None
assert len(os.listdir("/proc/self/fd"))==before+1
valid=d["fixtures"]["first"]
with n.NativeCellBridge(d["root"],valid["image"],valid["sha256"]) as bridge:
 assert bridge._fd!=record["fd"]
 assert int(bridge._entry(None,0,None,0,None,0))==17
print(json.dumps({"invalid_elf_fd_leak":False,"fifo_refused_without_blocking":True,
                  "quarantined_images":1,"quarantined_fd_retained":True,
                  "next_image_native_return":17,"retained_images":len(n._IMAGE_REGISTRY.entries)}))
''')
        self.assertEqual(observed["quarantined_images"], 1)
        self.assertEqual(observed["next_image_native_return"], 17)

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
