"""Twelve independent source/VM controls for the committed WAL snapshot core.

These tests are authored, not yet executed. They do not acquire a lock, open a
database connection, compile C/HIA, or alter the default AgentStore backend.
The reference uses retained format bytes and Fibonacci checksum weights; it does
not call the HIA author, bridge, or a shared rolling-checksum implementation.
"""
from __future__ import annotations

import ast
import ctypes
from dataclasses import FrozenInstanceError
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest

from hepta import hia_sqlite_wal_snapshot_native as bridge
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools import generate_hia_sqlite_wal_snapshot as author

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_NAMES = (
    "test_01_Core_roundtrip_and_original_nine_caps",
    "test_02_last_commit_and_latest_same_page_in_both_orders",
    "test_03_checksum_valid_uncommitted_frames_are_not_visible",
    "test_04_partial_tail_at_header_and_frame_structural_edges",
    "test_05_first_corrupt_frame_stops_before_later_valid_commit",
    "test_06_header_admission_order_and_all_page_sizes",
    "test_07_fixed_snapshot_ignores_later_append_and_rejects_changed_prefix",
    "test_08_commit_truncation_database_fallback_and_u32_pages",
    "test_09_large_extent_uses_bounded_packets_without_whole_WAL_limit",
    "test_10_protocol_refusals_and_one_use_states_preserve_spans",
    "test_11_bridge_caught_reentry_exception_identity_and_custody",
    "test_12_retained_official_recovery_and_reused_arithmetic_are_exact",
)


def weighted_checksum(raw, order, initial=(0, 0)):
    """Closed-form Fibonacci weights, independently of rolling-update code."""
    if len(raw) < 8 or len(raw) % 8:
        raise ValueError("oracle requires nonempty pairs of u32 words")
    count = len(raw) // 8
    fib = [0, 1]
    for _ in range(2 * count):
        fib.append((fib[-2] + fib[-1]) % (1 << 32))
    a = fib[2 * count - 1] * initial[0] + fib[2 * count] * initial[1]
    b = fib[2 * count] * initial[0] + fib[2 * count + 1] * initial[1]
    for pair in range(count):
        x = int.from_bytes(raw[8 * pair:8 * pair + 4], order)
        y = int.from_bytes(raw[8 * pair + 4:8 * pair + 8], order)
        remaining = count - pair - 1
        a += fib[2 * remaining + 1] * x + fib[2 * remaining] * y
        b += fib[2 * remaining + 2] * x + fib[2 * remaining + 1] * y
    return a % (1 << 32), b % (1 << 32)


def make_header(order="little", page_size=512, checkpoint=0,
                salts=(0x12345678, 0xabcdef01), version=3007000, magic=None):
    if magic is None:
        magic = 0x377f0682 + int(order == "big")
    first = struct.pack(">6I", magic, version, page_size, checkpoint, *salts)
    return first + struct.pack(">2I", *weighted_checksum(first, order))


def make_frame(page, seed, *, order="little", pgno=1, commit=0,
               salts=(0x12345678, 0xabcdef01)):
    first = struct.pack(">2I", pgno, commit)
    pair = weighted_checksum(first + page, order, seed)
    return first + struct.pack(">4I", *salts, *pair) + page, pair


def make_wal(specs, *, order="little", page_size=512, salts=(0x12345678, 0xabcdef01)):
    header = make_header(order, page_size, salts=salts)
    seed = weighted_checksum(header[:24], order)
    chunks = [header]
    for pgno, commit, fill in specs:
        page = bytes((fill,)) * page_size
        frame, seed = make_frame(page, seed, order=order, pgno=pgno, commit=commit, salts=salts)
        chunks.append(frame)
    return b"".join(chunks)


def reference_scan(raw, *, base_page_size=512, base_page_count=9):
    """Finite test oracle: retain a small list, choose commit only after parsing."""
    result = {"page_size": base_page_size, "database_pages": base_page_count,
              "committed_frame": 0, "committed_end_offset": 0,
              "valid_frames_scanned": 0, "stop_reason": 1, "frames": []}
    if len(raw) <= 32:
        return result
    magic, version, size, checkpoint, salt0, salt1, ck0, ck1 = struct.unpack(">8I", raw[:32])
    if magic not in (0x377f0682, 0x377f0683) or size < 512 or size > 65536 or size & (size - 1):
        result["stop_reason"] = 3
        return result
    order = "big" if magic & 1 else "little"
    seed = weighted_checksum(raw[:24], order)
    if seed != (ck0, ck1):
        result["stop_reason"] = 4
        return result
    if version != 3007000:
        raise ValueError("unsupported WAL format version")
    width = size + 24
    complete = (len(raw) - 32) // width
    result["stop_reason"] = 2 if (len(raw) - 32) % width else 0
    for index in range(complete):
        offset = 32 + index * width
        frame = raw[offset:offset + width]
        pgno, commit, a, b, expected0, expected1 = struct.unpack(">6I", frame[:24])
        if (a, b) != (salt0, salt1):
            result["stop_reason"] = 5
            break
        if pgno == 0:
            result["stop_reason"] = 6
            break
        after = weighted_checksum(frame[:8] + frame[24:], order, seed)
        if after != (expected0, expected1):
            result["stop_reason"] = 7
            break
        result["frames"].append({"number": index + 1, "page": pgno, "commit": commit,
                                 "offset": offset, "before": seed, "after": after})
        seed = after
        result["valid_frames_scanned"] = index + 1
    commits = [frame for frame in result["frames"] if frame["commit"]]
    if commits:
        chosen = commits[-1]
        result.update(page_size=size, database_pages=chosen["commit"],
                      committed_frame=chosen["number"],
                      committed_end_offset=chosen["offset"] + width)
    return result


def reference_location(model, page):
    common = (page, model["database_pages"], model["committed_frame"], model["committed_end_offset"])
    if page > model["database_pages"]:
        return ("missing", 0, 0, 0, *common, (0, 0), (0, 0))
    matches = [frame for frame in model["frames"]
               if frame["number"] <= model["committed_frame"] and frame["page"] == page]
    if matches:
        frame = matches[-1]
        return ("wal", frame["offset"] + 24, model["page_size"], frame["number"],
                *common, frame["before"], frame["after"])
    return ("database", (page - 1) * model["page_size"], model["page_size"], 0,
            *common, (0, 0), (0, 0))


def location_tuple(value):
    return (value.source, value.offset, value.size, value.frame_number, value.page_number,
            value.database_pages, value.committed_frame, value.committed_end_offset,
            value.checksum_before, value.checksum_after)


class VMImage:
    def __init__(self, program):
        self.program = program
        self.calls = []
        self.label = "unlabelled"

    def raw(self, source, output, state):
        owners = [_Owner(-1, bytearray(source)), _Owner(-2, bytearray(output)), _Owner(-3, bytearray(state))]
        machine = _Machine(self.program, 200000, 1 << 20, None, 256)
        row = {"case": self.label, "source_before_hex": bytes(source).hex(),
               "output_before_hex": bytes(output).hex(), "state_before_hex": bytes(state).hex(),
               "actual_returned": False}
        self.calls.append(row)
        try:
            status = machine.invoke(self.program.as_dict()["functions"][0],
                                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            row.update(status=status, actual_returned=True)
        except BaseException as exc:
            row["exception_type"] = type(exc).__module__ + "." + type(exc).__qualname__
            raise
        finally:
            row.update(source_after_hex=bytes(owners[0].data).hex(),
                       output_after_hex=bytes(owners[1].data).hex(), state_after_hex=bytes(owners[2].data).hex())
        return status, bytes(owners[1].data), bytes(owners[2].data)

    def _entry(self, s, n, o, m, w, k):
        status, output, state = self.raw(ctypes.string_at(s, n), ctypes.string_at(o, m), ctypes.string_at(w, k))
        ctypes.memmove(o, output, m)
        ctypes.memmove(w, state, k)
        return status


class SQLiteWalSnapshotSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = author.document()
        cls.program = verify_program(cls.document)
        cls.assembly = render_assembly(cls.document)
        cls.vm = VMImage(cls.program)
        cls.kernel = object.__new__(bridge.NativeSQLiteWalSnapshot)
        cls.kernel._entry = cls.vm._entry

    def setUp(self):
        self.vm.label = self.id()

    @classmethod
    def tearDownClass(cls):
        evidence = os.environ.get("HEPTA_SQLITE_WAL_SNAPSHOT_SOURCE_EVIDENCE")
        if evidence is None:
            return
        root = Path(evidence)
        values = {"sqlite_wal_snapshot.hiaasm": cls.assembly,
                  "CORE.json": json.dumps(cls.document, sort_keys=True, indent=2) + "\n",
                  "VM-RAW.json": json.dumps({"schema": "hia.sqlite.wal-snapshot.vm-raw.v1",
                                            "native_executed": False, "compiler_executed": False,
                                            "calls": cls.vm.calls}, sort_keys=True, indent=2) + "\n"}
        for name, body in values.items():
            with (root / name).open("x", encoding="utf-8") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())

    def drive(self, raw, *, snapshot=None, page=None, base_page_size=512, base_page_count=9):
        session = (self.kernel.scanner(wal_bytes=len(raw), base_page_size=base_page_size,
                                       base_page_count=base_page_count)
                   if snapshot is None else self.kernel.locator(snapshot, page))
        requests = []
        while session.request is not None:
            request = session.request
            requests.append(request)
            session.provide(raw[request.offset:request.offset + request.size])
        return session.finish(), requests

    def check_model(self, raw, pages=(1, 2, 3), **base):
        model = reference_scan(raw, **base)
        snapshot, requests = self.drive(raw, **base)
        for field in ("page_size", "database_pages", "committed_frame", "committed_end_offset",
                      "valid_frames_scanned", "stop_reason"):
            self.assertEqual(getattr(snapshot, field), model[field], field)
        for page in pages:
            location, reads = self.drive(raw, snapshot=snapshot, page=page)
            self.assertEqual(location_tuple(location), reference_location(model, page))
            if reads:
                self.assertLessEqual(max(read.offset + read.size for read in reads), snapshot.committed_end_offset)
        return snapshot, requests

    def test_01_Core_roundtrip_and_original_nine_caps(self):
        self.assertEqual(assemble_program(self.assembly).as_dict(), self.program.as_dict())
        self.assertEqual(self.assembly, render_assembly(author.document()))
        self.assertLessEqual(len(self.assembly.encode()), 1 << 20)
        self.assertLessEqual(len(self.assembly.split("\n")), 16384)
        functions = self.document["functions"]
        self.assertEqual(len(functions), 13)
        self.assertLessEqual(len(functions), 128)
        blocks = [block for function in functions for block in function["blocks"]]
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(block["ops"]) for block in blocks), 8192)
        for function in functions:
            self.assertLessEqual(len(function["blocks"]), 256)
            self.assertLessEqual(len(function["params"]), 16)
            self.assertLessEqual(len(function["returns"]), 3)
            for block in function["blocks"]:
                for op in block["ops"]:
                    self.assertLessEqual(len(op.get("out", [])), 3)
        def values(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("args", "params") and isinstance(value, list):
                        self.assertLessEqual(len(value), 16)
                    yield from values(value)
            elif isinstance(node, list):
                for value in node:
                    yield from values(value)
            elif isinstance(node, str) and node.startswith("v") and node[1:].isdigit():
                yield int(node[1:])
        self.assertLessEqual(max(values(self.document)), 2047)

    def test_02_last_commit_and_latest_same_page_in_both_orders(self):
        for order in ("little", "big"):
            raw = make_wal(((1, 0, 11), (2, 2, 22), (1, 0, 33), (1, 2, 44), (1, 0, 55)), order=order)
            snapshot, _ = self.check_model(raw)
            self.assertEqual((snapshot.valid_frames_scanned, snapshot.committed_frame, snapshot.database_pages), (5, 4, 2))
            location, _ = self.drive(raw, snapshot=snapshot, page=1)
            self.assertEqual(location.frame_number, 4)
            location, _ = self.drive(raw, snapshot=snapshot, page=2)
            self.assertEqual(location.frame_number, 2)

    def test_03_checksum_valid_uncommitted_frames_are_not_visible(self):
        for order in ("little", "big"):
            raw = make_wal(((1, 0, 17), (2, 0, 29)), order=order)
            snapshot, _ = self.check_model(raw, base_page_count=3, pages=(1, 3, 4))
            self.assertEqual((snapshot.valid_frames_scanned, snapshot.committed_frame, snapshot.committed_end_offset), (2, 0, 0))
            location, reads = self.drive(raw, snapshot=snapshot, page=1)
            self.assertEqual(location.source, "database")
            self.assertEqual(reads, [])
        for count in (0, 1, 7, 31, 32):
            snapshot, reads = self.check_model(b"\xff" * count, base_page_count=0, pages=(1,))
            self.assertEqual((snapshot.database_pages, snapshot.committed_frame, reads), (0, 0, []))

    def test_04_partial_tail_at_header_and_frame_structural_edges(self):
        raw = make_wal(((1, 1, 3), (1, 1, 7)))
        boundary = 32 + 536
        cuts = (0, 1, 7, 8, 23, 24, 31, 32, 33, boundary - 1, boundary,
                *(boundary + offset for offset in (1, 7, 8, 15, 16, 23, 24, 25, 511, 535)), len(raw))
        for cut in cuts:
            with self.subTest(cut=cut):
                snapshot, _ = self.check_model(raw[:cut], pages=(1,))
                self.assertEqual(snapshot.committed_frame, 0 if cut < boundary else (2 if cut == len(raw) else 1))
        session = self.kernel.scanner(wal_bytes=len(raw), base_page_size=512, base_page_count=9)
        with self.assertRaises(ValueError):
            session.provide(raw[:31])
        with self.assertRaises(bridge.SQLiteWalSnapshotProtocolError):
            session.finish()

    def test_05_first_corrupt_frame_stops_before_later_valid_commit(self):
        raw = make_wal(((1, 1, 9), (1, 0, 10), (1, 1, 11)))
        start = 32 + 536
        for offset in (8, 12, 15, 4, 7, 16, 20, 24, 535):
            changed = bytearray(raw)
            changed[start + offset] ^= 1
            with self.subTest(offset=offset):
                snapshot, _ = self.check_model(bytes(changed), pages=(1,))
                self.assertEqual((snapshot.valid_frames_scanned, snapshot.committed_frame), (1, 1))
        changed = bytearray(raw)
        changed[start:start + 4] = b"\0" * 4
        snapshot, _ = self.check_model(bytes(changed), pages=(1,))
        self.assertEqual((snapshot.stop_reason, snapshot.committed_frame), (6, 1))
        for offset in (8, 16, 24):
            changed = bytearray(raw)
            changed[32 + offset] ^= 1
            snapshot, _ = self.check_model(bytes(changed), pages=(1,))
            self.assertEqual(snapshot.committed_frame, 0)

    def test_06_header_admission_order_and_all_page_sizes(self):
        for order in ("little", "big"):
            for exponent in range(9, 17):
                page_size = 1 << exponent
                self.check_model(make_header(order, page_size) + b"x", base_page_size=page_size, pages=(1,))
        for magic in (0, 0x377f0680, 0xffffffff):
            self.check_model(make_header(magic=magic) + b"x", pages=(1,))
        for size in (0, 1, 511, 513, 65535, 65537):
            self.check_model(make_header(page_size=size) + b"x", pages=(1,))
        header = bytearray(make_header(version=0))
        header[24] ^= 1
        snapshot, _ = self.check_model(bytes(header) + b"x", pages=(1,))
        self.assertEqual(snapshot.stop_reason, 4)
        for version in (0, 3007001, 0xffffffff):
            with self.assertRaises(bridge.SQLiteWalSnapshotRejected) as caught:
                self.drive(make_header(version=version) + b"x")
            self.assertEqual(caught.exception.status, bridge.REFUSE_VERSION)

    def test_07_fixed_snapshot_ignores_later_append_and_rejects_changed_prefix(self):
        raw = make_wal(((1, 0, 19), (1, 2, 21)))
        later = make_wal(((1, 0, 19), (1, 2, 21), (1, 0, 31), (1, 2, 41)))
        snapshot, _ = self.drive(raw)
        location, reads = self.drive(later, snapshot=snapshot, page=1)
        self.assertEqual((location.frame_number, max(read.offset + read.size for read in reads)), (2, len(raw)))
        changed = bytearray(raw)
        changed[12] ^= 1
        changed[24:32] = struct.pack(">2I", *weighted_checksum(bytes(changed[:24]), "little"))
        with self.assertRaises(bridge.SQLiteWalSnapshotRejected) as caught:
            self.drive(bytes(changed), snapshot=snapshot, page=1)
        self.assertEqual(caught.exception.status, bridge.REFUSE_SNAPSHOT)
        changed = bytearray(raw)
        changed[32 + 24] ^= 1
        with self.assertRaises(bridge.SQLiteWalSnapshotRejected):
            self.drive(bytes(changed), snapshot=snapshot, page=1)
        valid_different = make_wal(((1, 0, 88), (1, 2, 21)))
        with self.assertRaises(bridge.SQLiteWalSnapshotRejected):
            self.drive(valid_different, snapshot=snapshot, page=1)
        self.assertEqual(self.drive(raw, snapshot=snapshot, page=1)[0].frame_number, 2)
        with self.assertRaises(FrozenInstanceError):
            snapshot.committed_frame = 99

    def test_08_commit_truncation_database_fallback_and_u32_pages(self):
        raw = make_wal(((5, 5, 8), (1, 0, 9), (1, 2, 10), (5, 0, 11)))
        snapshot, _ = self.check_model(raw, pages=(1, 2, 3, 5))
        location, reads = self.drive(raw, snapshot=snapshot, page=5)
        self.assertEqual((location.source, reads), ("missing", []))
        location, _ = self.drive(raw, snapshot=snapshot, page=2)
        self.assertEqual((location.source, location.offset, location.size), ("database", 512, 512))
        snapshot, _ = self.drive(b"", base_page_size=65536, base_page_count=0xffffffff)
        location, _ = self.drive(b"", snapshot=snapshot, page=0xffffffff)
        self.assertEqual(location.offset, 0xfffffffe * 65536)
        self.assertEqual(location.size, 65536)
        raw = make_wal(((0xffffffff, 0xffffffff, 99),))
        self.check_model(raw, pages=(0xffffffff,))

    def test_09_large_extent_uses_bounded_packets_without_whole_WAL_limit(self):
        extent = (1 << 50) + 123
        session = self.kernel.scanner(wal_bytes=extent, base_page_size=512, base_page_count=9)
        header = make_header()
        session.provide(header)
        self.assertEqual((session.request.offset, session.request.size, session.request.frame_number), (32, 536, 1))
        frame, _ = make_frame(b"\x12" * 512, weighted_checksum(header[:24], "little"), commit=1)
        session.provide(frame)
        self.assertEqual((session.request.offset, session.request.size, session.request.frame_number), (568, 536, 2))
        session.provide(b"\0" * 536)
        snapshot = session.finish()
        self.assertEqual((snapshot.wal_extent, snapshot.committed_frame, snapshot.committed_end_offset), (extent, 1, 568))
        session = self.kernel.scanner(wal_bytes=(1 << 63) - 1, base_page_size=65536, base_page_count=0xffffffff)
        session.provide(make_header(page_size=65536))
        self.assertEqual(session.request.size, 65560)
        session._seal()
        # This is a packet/representation boundary control, not a claim that a
        # petabyte WAL or a full 65536-byte page was executed by the VM.
        for row in self.vm.calls:
            self.assertLessEqual(len(bytes.fromhex(row["source_before_hex"])), bridge.MAX_INPUT_BYTES)
            self.assertEqual(len(bytes.fromhex(row["state_before_hex"])), 256)
        for bad in (-1, True, 1 << 63, 1.5):
            with self.assertRaises(ValueError):
                self.kernel.scanner(wal_bytes=bad, base_page_size=512, base_page_count=9)

    def test_10_protocol_refusals_and_one_use_states_preserve_spans(self):
        def packet(operation, *fields):
            return struct.pack("<" + "Q" * (2 + len(fields)), bridge.COMMAND_MAGIC, operation, *fields)
        state = b"\0" * 256
        out = b"\xa5" * 128
        for request in (b"", b"x" * 15, packet(0), packet(2) + make_header(),
                        packet(1, 100, 9, 513), packet(1, 1 << 63, 9, 512)):
            status, after_out, after_state = self.vm.raw(request, out, state)
            self.assertEqual((status, after_out, after_state), (bridge.REFUSE_PROTOCOL, out, state))
        status, _, issued = self.vm.raw(packet(1, 0, 9, 512), out, state)
        self.assertEqual(status, 128)
        status, _, issued = self.vm.raw(packet(5), out, issued)
        self.assertEqual(status, 128)
        for request in (packet(5), packet(1, 0, 9, 512), packet(3) + b"\0" * 536):
            self.assertEqual(self.vm.raw(request, out, issued), (bridge.REFUSE_PROTOCOL, out, issued))
        snapshot, _ = self.drive(b"")
        for page in (0, -1, True, 1 << 32, 1.0):
            with self.assertRaises(ValueError):
                self.kernel.locator(snapshot, page)
        other = object.__new__(bridge.NativeSQLiteWalSnapshot)
        other._entry = self.vm._entry
        with self.assertRaises(TypeError):
            other.locator(snapshot, 1)

    def test_11_bridge_caught_reentry_exception_identity_and_custody(self):
        raw = make_wal(((1, 1, 4),))
        original_entry = self.vm._entry
        for callback in ("entry-reentry", "entry-error", "source", "output-tail", "state-tail", "boolean"):
            with self.subTest(callback=callback):
                box = []
                failure = KeyboardInterrupt("the original external exception")
                def entry(s, n, o, m, w, k):
                    if box:
                        if callback == "entry-reentry":
                            try:
                                box[0].finish()
                            except bridge.SQLiteWalSnapshotProtocolError:
                                pass
                        if callback == "entry-error":
                            raise failure
                    returned = original_entry(s, n, o, m, w, k)
                    if box:
                        if callback == "source":
                            ctypes.memset(s, 0, 1)
                        if callback == "output-tail":
                            ctypes.memset(ctypes.addressof(o) + m, 255, 1)
                        if callback == "state-tail":
                            ctypes.memset(ctypes.addressof(w) + k, 255, 1)
                        if callback == "boolean":
                            return True
                    return returned
                kernel = object.__new__(bridge.NativeSQLiteWalSnapshot)
                kernel._entry = entry
                session = kernel.scanner(wal_bytes=len(raw), base_page_size=512, base_page_count=9)
                box.append(session)
                if callback == "entry-error":
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        session.provide(raw[:32])
                    self.assertIs(caught.exception, failure)
                else:
                    with self.assertRaises(bridge.SQLiteWalSnapshotProtocolError):
                        session.provide(raw[:32])
                with self.assertRaises(bridge.SQLiteWalSnapshotProtocolError):
                    session.finish()
        session = self.kernel.scanner(wal_bytes=0, base_page_size=512, base_page_count=9)
        self.assertEqual(session.finish().committed_frame, 0)
        with self.assertRaises(bridge.SQLiteWalSnapshotProtocolError):
            session.finish()
        session = self.kernel.scanner(wal_bytes=len(raw), base_page_size=512, base_page_count=9)
        class BytesSubclass(bytes):
            pass
        with self.assertRaises(ValueError):
            session.provide(BytesSubclass(raw[:32]))
        with self.assertRaises(bridge.SQLiteWalSnapshotProtocolError):
            session.provide(raw[:32])

    def test_12_retained_official_recovery_and_reused_arithmetic_are_exact(self):
        expected = {
            "3.46.0": (174376, "d4a104b5f3cb807e026a9dbcdb77519358b06b66f76cb6b6ef70e3793379dd62"),
            "3.53.2": (177651, "64d2a6695fbf5d661a9ccb82d160a5fb18698d7175e41828c5ed9428992c7752"),
        }
        for version, pin in expected.items():
            raw = (ROOT / "reference" / ("sqlite-" + version) / "wal.c.original").read_bytes()
            self.assertEqual((len(raw), sha256(raw).hexdigest()), pin)
            excerpt = (ROOT / "reference" / ("sqlite-" + version) / "walIndexRecover.original.c").read_bytes()
            self.assertIn(excerpt, raw)
            self.assertIn(b"if( nTruncate ){", excerpt)
            self.assertIn(b"pWal->hdr.mxFrame = iFrame;", excerpt)
            self.assertIn(b"pWal->hdr.nPage = nTruncate;", excerpt)
            self.assertIn(b"pWal->hdr.aFrameCksum[0] = aFrameCksum[0];", excerpt)
            finder = (ROOT / "reference" / ("sqlite-" + version) / "walFindFrame.original.c").read_bytes()
            self.assertIn(finder, raw)
            self.assertIn(b"iFrame<=iLast", finder)
        original = (ROOT / "reference/retained-generate_hia_sqlite_wal.py").read_text()
        module = ast.parse(original)
        legacy = ast.literal_eval(next(node.value for node in module.body if isinstance(node, ast.Assign)
                                       and any(isinstance(target, ast.Name) and target.id == "SOURCE" for target in node.targets)))
        def function_text(text, name):
            node = next(item for item in ast.parse(text).body if isinstance(item, ast.FunctionDef) and item.name == name)
            return "\n".join(text.splitlines()[node.lineno - 1:node.end_lineno])
        for name in ("checksum_region", "word", "control_word"):
            self.assertEqual(function_text(author.source(), name), function_text(legacy, name))
        abi = json.loads((ROOT / "inputs/hepta/hia_sqlite_wal_snapshot_abi.json").read_bytes())
        self.assertEqual((abi["state_bytes"], abi["output_bytes"], abi["maximum_input_bytes"]), (256, 128, 65576))
        self.assertFalse(abi["external_locks_io_checkpoint_and_AgentStore_default_implemented"])
        self.assertFalse(abi["historical_byte_kernel_PASS_grants_snapshot_qualification"])
        self.assertNotIn("sqlite3", bridge.__dict__)
        actual = tuple(sorted(name for name in self.__class__.__dict__ if name.startswith("test_")))
        self.assertEqual(actual, EXPECTED_NAMES)


if __name__ == "__main__":
    unittest.main()
