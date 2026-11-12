"""Mechanical raw transport for the separate HIA scalar/text controllers.

This private module does not import json, format an object in Python, choose
integer policy, sort, or select the public CLI.  HIA chooses each observation,
representation conversion, formatting call and reference release.  Borrowed
object pointers stay rooted by the caller; all actual object/error results
stay in its existing C owner.  No result is converted to ctypes.py_object.

The dynamic _pylong extension remains an explicit original foreign operation.
Complete allocation/signal equivalence and all graph profiles remain pending
actual controls.  Source4's earlier result does not execute these new bytes.
"""
from __future__ import annotations

import ctypes
import struct

from hepta.hia_cli_json_raw_native import RawTransactions, exact_word, native_entry

WORD = struct.Struct('<Q')
MAGIC = int.from_bytes(b'HCLISCL1', 'little')
TEXT_MAGIC = int.from_bytes(b'HCLIJTX1', 'little')
MAX_SIZE = (1 << 63) - 1
STATE_BYTES = 1024
LITERALS = {
    512: b'_pylong\0',
    544: b'int_to_decimal_string\0',
    608: b'_pylong.int_to_decimal_string did not return a str\0',
}
LEAVES = frozenset((6, 10, 17, 20, 38, 39, 44, 45, 46, 55, 68, 69,
                    70, 71, 72, 73, 74, 75, 76))


class ScalarTextTransport:
    """Image binding only; each call creates a distinct one-use continuation."""

    def __init__(self, scalar_image, text_image):
        self.scalar_image = scalar_image
        self.text_image = text_image

    def run_raw(self, raw, object_pointer, kind, quoted):
        session = ScalarSession(self.scalar_image, self.text_image, raw,
                                object_pointer=object_pointer,
                                kind=kind, quoted=quoted)
        status = session.run()
        # This returned dictionary contains no Python view of the actual
        # result/error object.  The shared C owner remains authoritative.
        return {
            'schema': 'hia.cli-json.raw-scalar-return.v1',
            'status': status,
            'native_returns': tuple(session.actual_native_returns),
            'text_returns': tuple(session.actual_text_returns),
            'leaf_returns_begin': session.leaf_begin,
            'leaf_returns_end': len(raw.actual_leaf_returns),
            'result_address': session.result_address,
            'error_address': session.error_address,
            'finished': session.finished,
        }


class ScalarSession:
    """One fixed scalar continuation; status is checked before output length."""

    def __init__(self, scalar_image, text_image, raw, *, object_pointer, kind, quoted):
        self.finished = True
        self.pending = self.busy = self.finish_pending = self.aborting = False
        self.quarantined = False
        if type(raw) is not RawTransactions:
            raise TypeError('the existing raw C transaction owner is required')
        self.raw = raw
        self.scalar_image, self.text_image = scalar_image, text_image
        self.entry, self.text_entry = native_entry(scalar_image), native_entry(text_image)
        self.state = ctypes.create_string_buffer(STATE_BYTES)
        self.packet = ctypes.create_string_buffer(1)
        self.text_work = None
        self.text_output = None
        self.source_address = self.source_bytes = 0
        self.packet_request = None
        self.measured_packet_bytes = self.measured_count = None
        self.emitted_count = None
        self.last_issued = self.last_consumed = 0
        self.status = self.result_address = self.error_address = None
        self.actual_native_returns = []
        self.actual_text_returns = []
        self.unwind_failure = None
        self.leaf_begin = len(raw.actual_leaf_returns)
        for offset, value in ((0, MAGIC), (120, object_pointer),
                              (128, kind), (136, quoted)):
            self.put(offset, exact_word(value))
        self.finished = False

    def get(self, offset):
        return WORD.unpack_from(self.state, offset)[0]

    def put(self, offset, value):
        WORD.pack_into(self.state, offset, value)

    def views(self):
        view = self.raw.refresh()
        self.put(48, view[8])
        self.put(320, view[5])
        return view

    def literal(self, offset, length=None):
        if offset not in LITERALS:
            raise RuntimeError('HIA scalar literal address differs')
        raw = LITERALS[offset]
        if length is not None and length != len(raw):
            raise RuntimeError('HIA scalar literal extent differs')
        if self.state.raw[offset:offset + len(raw)] != raw:
            raise RuntimeError('HIA scalar literal bytes differ')
        return ctypes.addressof(self.state) + offset

    def step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA scalar continuation is terminal or active')
        self.pending = False
        self.busy = True
        try:
            self.views()
            status = self.entry(self.source_address, self.source_bytes,
                                self.packet, ctypes.sizeof(self.packet),
                                self.state, STATE_BYTES)
            self.status = status
            # Keep all post-entry operations inside the same abort boundary.
            self.actual_native_returns.append(status)
            if status == 2:
                sequence = self.get(16)
                if self.get(24) != 1 or sequence <= self.last_issued:
                    raise RuntimeError('HIA scalar request permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status in (0, 1):
                view = self.views()
                if self.get(112) != status + 1:
                    raise RuntimeError('HIA scalar terminal marker differs')
                if status == 0:
                    if not view[5] or view[8]:
                        raise RuntimeError('HIA scalar success ownership differs')
                elif view[5] or not view[8]:
                    raise RuntimeError('HIA scalar failure ownership differs')
                self.finish_pending = True
            else:
                raise RuntimeError('HIA scalar protocol refused')
            return status
        finally:
            self.busy = False

    def allocate_packet(self, required):
        if required < 64 or required > MAX_SIZE:
            raise RuntimeError('HIA scalar packet allocation extent differs')
        if self.packet_request is not None:
            raise RuntimeError('HIA scalar packet allocation was repeated')
        # A fresh immutable-input packet is populated only by HIA.  This
        # transport does not inspect, rebase or encode its actual contents.
        self.packet_request = required
        self.packet = ctypes.create_string_buffer(required)

    def text_call(self, operation, packet_bytes, requested_count):
        if (self.packet_request is None or packet_bytes < 64
                or packet_bytes > ctypes.sizeof(self.packet)):
            raise RuntimeError('HIA scalar text packet extent differs')
        if operation == 211:
            if self.text_work is not None or requested_count != 0:
                raise RuntimeError('HIA scalar text measure permission differs')
            # The packet is opaque here.  Maximum admitted scalar scratch is
            # mechanically bounded by its bytes, with no semantic branching.
            # Integer HIA needs 14 * uint32-limb count + 8449 bytes.  For all
            # other kinds this is an over-allocation, not an input policy.
            units = (packet_bytes - 64 + 3) // 4
            if units > (MAX_SIZE - 8449) // 14:
                raise MemoryError('HIA scalar workspace address range exceeded')
            self.text_work = ctypes.create_string_buffer(8449 + 14 * units)
            output, output_bytes = None, 0
        elif operation == 212:
            if (self.measured_packet_bytes != packet_bytes
                    or self.measured_count != requested_count
                    or self.text_work is None or self.text_output is not None
                    or requested_count > MAX_SIZE // 4):
                raise RuntimeError('HIA scalar text emit permission differs')
            self.text_output = ctypes.create_string_buffer(max(1, requested_count * 4))
            output, output_bytes = self.text_output, requested_count * 4
        else:
            raise RuntimeError('unknown HIA scalar text operation')
        status = self.text_entry(self.packet, packet_bytes, output, output_bytes,
                                 self.text_work, ctypes.sizeof(self.text_work))
        magic, recorded_status, count, detail = struct.unpack_from('<QQQQ', self.text_work)
        if magic != TEXT_MAGIC or status != recorded_status:
            raise RuntimeError('HIA scalar text return/header differs')
        # Never use the successful length following a nonzero native return.
        successful_count = count if status == 0 else 0
        if status == 0:
            if successful_count > MAX_SIZE // 4:
                raise RuntimeError('HIA scalar text successful length differs')
            if operation == 211:
                self.measured_packet_bytes = packet_bytes
                self.measured_count = successful_count
            else:
                if successful_count != requested_count:
                    raise RuntimeError('HIA scalar measured/emitted lengths differ')
                self.emitted_count = successful_count
        self.actual_text_returns.append((operation, status, recorded_status,
                                         successful_count, detail))
        return (status, recorded_status, successful_count, detail, 0, 0, 0, 0)

    def leaf_arguments(self, operation, args):
        result = list(args)
        if operation == 10:
            if result[1] != 608:
                raise RuntimeError('HIA scalar error literal selector differs')
            result[1] = self.literal(result[1], result[2])
        elif operation == 71:
            if result[0] != 512:
                raise RuntimeError('HIA scalar import literal selector differs')
            result[0] = self.literal(512)
        elif operation == 72:
            if result[1] != 544 or result[2] != self.get(120):
                raise RuntimeError('HIA scalar dynamic call binding differs')
            result[1] = self.literal(544)
        elif operation in (68, 75):
            if (result[0] != 0 or self.text_output is None
                    or self.emitted_count != result[1]
                    or result[1] * 4 > ctypes.sizeof(self.text_output)):
                raise RuntimeError('HIA scalar result storage binding differs')
            result[0] = ctypes.addressof(self.text_output)
        return result

    def observe(self):
        if not self.pending or self.busy or self.finished or self.quarantined:
            raise RuntimeError('HIA scalar has no effect permission')
        self.pending = False
        self.busy = True
        try:
            sequence, operation = self.get(16), self.get(64)
            if sequence != self.last_issued or sequence <= self.last_consumed:
                raise RuntimeError('HIA scalar effect already consumed')
            self.last_consumed = sequence
            args = tuple(self.get(72 + index * 8) for index in range(5))
            if operation == 210:
                self.allocate_packet(args[0])
                result = (0,) * 8
            elif operation in (211, 212):
                result = self.text_call(operation, args[0], args[1])
            else:
                if operation not in LEAVES:
                    raise RuntimeError('HIA scalar issued an unrelated leaf')
                frame = self.raw.call(operation, self.leaf_arguments(operation, args))
                result = tuple(frame[9:17])
                if operation in (38, 69) and not self.raw.view[8]:
                    if args[0] != self.get(120):
                        raise RuntimeError('HIA scalar borrowed object binding differs')
                    if operation == 38:
                        count, width, pointer = result[:3]
                    else:
                        count, pointer, width = result[0], result[3], result[4]
                    if width not in (1, 2, 4) or count > MAX_SIZE // width or not pointer:
                        raise RuntimeError('HIA scalar raw representation extent differs')
                    self.source_address, self.source_bytes = pointer, count * width
            self.views()
            for index, value in enumerate(result):
                self.put(256 + index * 8, value)
            self.put(32, sequence)
            self.put(40, operation)
        finally:
            self.busy = False

    def start_abort(self):
        self.pending = self.finish_pending = False
        self.finished = False
        self.source_address = self.source_bytes = 0
        self.raw.install_external_after_except()
        self.aborting = True
        # Even a post-terminal bookkeeping failure must discard an owned
        # success result and query C cells before claiming failed closure.
        self.put(112, 0)
        self.put(56, 1)

    def run(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA scalar cannot be re-entered')
        try:
            while True:
                failed = False
                try:
                    while not self.finish_pending:
                        if self.step() == 2:
                            self.observe()
                    self.finish_pending = False
                    view = self.views()
                    self.result_address, self.error_address = view[5], view[8]
                    self.source_address = self.source_bytes = 0
                    self.finished = True
                    return self.status
                except BaseException as error:
                    if self.aborting or self.raw.protocol_failed:
                        raise
                    self.raw.capture_external(error)
                    failed = True
                if failed:
                    # Release plans run only after the active Python except
                    # and its bound error target have both been left.
                    self.start_abort()
        except BaseException as error:
            self.quarantined = True
            self.pending = self.finish_pending = False
            self.raw.protocol_failed = True
            self.unwind_failure = error
            raise
