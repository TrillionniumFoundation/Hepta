"""Raw transport for HIA's deferred Python-profile chunk list.

This module never tests a yielded object's type, joins a partial prefix, or
runs a Python JSON encoder. A successful return leaves the complete actual
list in the existing C owner. The caller must assign that list to its original
encoding-frame local before the separate final join. Frame activation and
the operation-230 HIA generator dispatcher remain independent prerequisites.
"""
from __future__ import annotations

import ctypes
import struct

from hepta.hia_cli_json_raw_native import RawTransactions, exact_word, native_entry

WORD = struct.Struct('<Q')
MAGIC = int.from_bytes(b'HCLIJCH1', 'little')
STATE_BYTES = 512
LEAVES = frozenset((6, 22, 26, 44, 45, 46, 51, 87, 88, 89, 90, 91, 92, 93))


class Py312ChunksSession:
    def __init__(self, image, raw, iterable_pointer, *, generator_dispatch=None):
        self.finished = True
        self.pending = self.busy = self.finish_pending = self.aborting = False
        self.quarantined = False
        if type(raw) is not RawTransactions or raw.leaves.profile != 31214:
            raise TypeError('the existing CPython 3.12.14 raw owner is required')
        if not getattr(raw.leaves, 'runtime_312_binding', None):
            raise ValueError('the exact mapped runtime must be independently admitted')
        self.raw, self.image = raw, image
        self.entry = native_entry(image)
        self.generator_dispatch = generator_dispatch
        self.state = ctypes.create_string_buffer(STATE_BYTES)
        self.last_issued = self.last_consumed = 0
        self.actual_native_returns = []
        self.actual_generator_returns = []
        self.unwind_failure = None
        self.status = self.result_address = self.error_address = None
        self.leaf_begin = len(raw.actual_leaf_returns)
        for offset, value in ((0, MAGIC), (120, iterable_pointer),
                              (128, int(generator_dispatch is not None))):
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

    def step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA chunk continuation is terminal or active')
        self.pending = False
        self.busy = True
        try:
            self.views()
            status = self.entry(None, 0, None, 0, self.state, STATE_BYTES)
            self.status = status
            self.actual_native_returns.append(status)
            if status == 2:
                sequence = self.get(16)
                if self.get(24) != 1 or sequence <= self.last_issued:
                    raise RuntimeError('HIA chunk request permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status in (0, 1):
                view = self.views()
                if self.get(112) != status + 1:
                    raise RuntimeError('HIA chunk terminal marker differs')
                if status == 0:
                    if not view[5] or view[8]:
                        raise RuntimeError('HIA chunk success ownership differs')
                elif view[5] or not view[8]:
                    raise RuntimeError('HIA chunk failure ownership differs')
                self.finish_pending = True
            else:
                raise RuntimeError('HIA chunk protocol refused')
            return status
        finally:
            self.busy = False

    def observe(self):
        if not self.pending or self.busy or self.finished or self.quarantined:
            raise RuntimeError('HIA chunk has no effect permission')
        self.pending = False
        self.busy = True
        try:
            sequence, operation = self.get(16), self.get(64)
            if sequence != self.last_issued or sequence <= self.last_consumed:
                raise RuntimeError('HIA chunk effect already consumed')
            self.last_consumed = sequence
            args = tuple(self.get(72 + index * 8) for index in range(5))
            if operation == 230:
                if self.generator_dispatch is None or args[2:] != (0, 0, 0):
                    raise RuntimeError('the HIA generator dispatcher is not bound')
                # This is a required, separately admitted HIA continuation;
                # no fallback to the retained JSON generator body is present.
                result = self.generator_dispatch.resume_raw(self.raw, args[0], args[1])
                self.actual_generator_returns.append(result)
                answer = (0,) * 8
            else:
                if operation not in LEAVES:
                    raise RuntimeError('HIA chunk issued an unrelated leaf')
                frame = self.raw.call(operation, args)
                answer = tuple(frame[9:17])
            self.views()
            for index, value in enumerate(answer):
                self.put(256 + 8 * index, value)
            self.put(32, sequence)
            self.put(40, operation)
        finally:
            self.busy = False

    def start_abort(self):
        self.pending = self.finish_pending = False
        self.finished = False
        self.raw.install_external_after_except()
        self.aborting = True
        self.put(112, 0)
        self.put(56, 1)

    def run_raw(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA chunk continuation cannot be re-entered')
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
                    self.finished = True
                    return self.status
                except BaseException as error:
                    if self.aborting or self.raw.protocol_failed:
                        raise
                    self.raw.capture_external(error)
                    failed = True
                if failed:
                    self.start_abort()
        except BaseException as error:
            self.quarantined = True
            self.pending = self.finish_pending = False
            self.raw.protocol_failed = True
            self.unwind_failure = error
            raise
