"""One-use raw transport for the HIA-owned 3.12 generator terminal plan.

The actual generator and its parent are borrowed from the already-admitted
body driver, which must retain their original owners. This module stores only
integer addresses; it does not invent a replacement generator or own a locals
dictionary. C leaves temporarily expose the actual frame/handled exception
for traceback and reverse-stack decrefs, then unlink before Python transport.

This is uncompiled private development source. Per-leaf frame exposure does
not close the full evaluator/GC/signal/monitoring schedule. No public selector
imports this module, and no retained generator body is called as a fallback.
"""
from __future__ import annotations

import ctypes
import struct

from hepta.hia_cli_json_raw_native import RawTransactions, exact_word, native_entry

WORD = struct.Struct('<Q')
MAGIC = int.from_bytes(b'HCLIGLF1', 'little')
STATE_BYTES = 512
LEAVES = frozenset((6, 17, 95, 96, 97, 100, 106, 107))


class Py312LifetimeSession:
    def __init__(self, image, raw, *, generator_pointer, code_pointer,
                 parent_pointer, instruction, mode):
        self.finished = True
        self.busy = self.pending = self.finish_pending = False
        self.quarantined = False
        self.failure = None
        if type(raw) is not RawTransactions or raw.leaves.profile != 31214:
            raise TypeError('exact existing 3.12 raw owner required')
        if not getattr(raw.leaves, 'runtime_312_binding', None):
            raise ValueError('actual mapped private runtime admission is missing')
        if type(mode) is not int or mode not in (0, 1, 2):
            raise ValueError('mode is exhausted, error, or yielded')
        self.raw, self.image = raw, image
        self.entry = native_entry(image)
        self.generator_pointer = exact_word(generator_pointer)
        self.code_pointer = exact_word(code_pointer)
        self.parent_pointer = exact_word(parent_pointer)
        self.instruction = exact_word(instruction)
        self.mode = mode
        if not self.generator_pointer or not self.code_pointer:
            raise ValueError('actual generator and original code addresses are required')
        self.state = ctypes.create_string_buffer(STATE_BYTES)
        self.actual_native_returns = []
        self.actual_effect_returns = []
        self.last_issued = self.last_consumed = 0
        self.status = self.result_address = self.error_address = None
        for offset, value in ((0, MAGIC), (120, self.generator_pointer),
                              (128, self.code_pointer), (136, self.parent_pointer),
                              (144, self.instruction), (152, mode)):
            self.put(offset, value)
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

    def seal_failure(self, error):
        # The raw owner continues to own every committed result/exception and
        # unreleased live slot. No cleanup leaf is replayed after a bookkeeping
        # exception, including one after frame-clear. The caller must keep this
        # quarantined session until the development owner records the failure.
        self.pending = self.finish_pending = False
        self.quarantined = True
        self.finished = True
        self.raw.protocol_failed = True
        self.failure = error

    def step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('generator lifetime continuation is terminal or active')
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
                    raise RuntimeError('lifetime effect permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status in (0, 1, 3):
                view = self.views()
                if self.get(112) != status + 1:
                    raise RuntimeError('lifetime terminal marker differs')
                if status == 0 and (view[5] or view[8] or self.mode != 0):
                    raise RuntimeError('exhausted generator ownership differs')
                if status == 1 and (view[5] or not view[8] or self.mode != 1):
                    raise RuntimeError('failed generator ownership differs')
                if status == 3 and (not view[5] or view[8] or self.mode != 2):
                    raise RuntimeError('yielded generator ownership differs')
                self.finish_pending = True
            else:
                raise RuntimeError('HIA generator lifetime protocol refused')
            return status
        except BaseException as error:
            self.seal_failure(error)
            raise
        finally:
            self.busy = False

    def observe(self):
        if not self.pending or self.busy or self.finished or self.quarantined:
            raise RuntimeError('generator lifetime has no effect permission')
        self.pending = False
        self.busy = True
        try:
            sequence, operation = self.get(16), self.get(64)
            phase = self.get(8)
            if sequence != self.last_issued or sequence <= self.last_consumed:
                raise RuntimeError('generator lifetime effect already consumed')
            self.last_consumed = sequence
            if operation not in LEAVES:
                raise RuntimeError('unrelated generator lifetime leaf')
            args = tuple(self.get(72 + index * 8) for index in range(5))
            # HIA wrote the following phase. Exactly these error-unwind
            # requests run with the actual dying generator's handled state;
            # frame-clear and final result/exc disposal run after unlink.
            framed = ((operation == 97 and phase == 20)
                      or (operation == 100 and phase == 21)
                      or (operation == 6 and phase == 22))
            if framed:
                frame = self.raw.call(operation, args,
                    generator_pointer=self.generator_pointer,
                    parent_pointer=self.parent_pointer, instruction=self.instruction)
            else:
                frame = self.raw.call(operation, args)
            answer = tuple(frame[9:17])
            self.views()
            for index, value in enumerate(answer):
                self.put(256 + 8 * index, value)
            self.put(32, sequence)
            self.put(40, operation)
            self.actual_effect_returns.append((sequence, operation, args, answer, framed))
        except BaseException as error:
            self.seal_failure(error)
            raise
        finally:
            self.busy = False

    def run_raw(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('generator lifetime cannot be re-entered')
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
            if not self.quarantined:
                self.seal_failure(error)
            raise
