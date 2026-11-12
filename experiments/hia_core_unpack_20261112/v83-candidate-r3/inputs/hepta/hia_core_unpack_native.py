"""Experimental HIA UNPACK adapter with explicit transitional CPython leaves.

This module does NOT close the Python object runtime. The fixed transaction
primitive moves the current raised error, calls one leaf and captures its error.
HIA alone chooses iteration, cardinality, messages, tuple assembly and releases.
No complete unpack, list(value), tuple(value), length hint or iterator loop is
available in the bridge. Ordinary Core selection is deliberately not changed.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import mmap
import platform
import struct
import sys
import sysconfig

MAGIC = int.from_bytes(b'HIAUNP01', 'little')
FRAME = struct.Struct('<16Q')
REFUSAL = 0xfffffffd
TRANSACTION_ABI = 'hepta.hia.core-unpack-cpython-transaction.v1'

# Literal image of hia_core_unpack_transaction.S. Independently reassembled
# only in development controls; the runtime never invokes an assembler.
TRANSACTION = bytes.fromhex(
    '53 4889fb 48c7436801000000 488b7b40 ff5348 48c7436802000000 '
    '488b7b08 488b7310 488b5318 488b4b20 4c8b4328 4c8b4b30 '
    '31c0 ff13 48894358 48c7436803000000 ff5350 48894360 '
    '48c7436804000000 31c0 5b c3')
LOAD_WORD = bytes.fromhex('488b07c3')
SHIM = TRANSACTION + LOAD_WORD
SHIM_SHA256 = sha256(SHIM).hexdigest()


def _address(symbol):
    return ctypes.cast(getattr(ctypes.pythonapi, symbol), ctypes.c_void_p).value


class CpythonLeaves:
    """Pinned single-call C-API mechanisms; never an unpack strategy."""

    def __init__(self):
        version = tuple(sys.version_info[:3])
        if (sys.implementation.name != 'cpython' or version not in ((3, 12, 14), (3, 14, 4))
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or sysconfig.get_config_var('Py_GIL_DISABLED')
                or sysconfig.get_config_var('Py_TRACE_REFS')
                or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
            raise ValueError('unadmitted experimental CPython UNPACK ABI')
        self.profile = 31214 if version == (3, 12, 14) else 31404
        # These assertions bind the small public-object prefix used for raw
        # Py_TYPE and tp_name facts; no user attribute access is substituted.
        if ctypes.c_uint64.from_address(id(None) + 8).value != id(type(None)):
            raise ValueError('CPython object prefix differs')
        name = ctypes.c_uint64.from_address(id(int) + 24).value
        if not name or ctypes.string_at(name) != b'int':
            raise ValueError('CPython type prefix differs')
        self.functions = {name: _address(name) for name in (
            'PyErr_SetRaisedException', 'PyErr_GetRaisedException',
            'PyObject_GetIter', 'PyIter_Next', 'PyErr_GivenExceptionMatches',
            'PyType_GetSlot', 'PySequence_Check', 'PyErr_Format',
            'Py_DecRef', 'PyTuple_Size', 'PyList_Size', 'PyDict_Size',
            'PyTuple_New', 'PyTuple_SetItem', 'PyGILState_Check')}
        mapped = mmap.mmap(-1, len(SHIM), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        mapped.write(SHIM)
        address = ctypes.addressof(ctypes.c_char.from_buffer(mapped))
        protect = ctypes.CDLL(None, use_errno=True).mprotect
        protect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        protect.restype = ctypes.c_int
        if protect(address, len(SHIM), mmap.PROT_READ | mmap.PROT_EXEC):
            error = ctypes.get_errno()
            mapped.close()
            raise OSError(error, 'mprotect UNPACK primitive')
        self.mapping = mapped
        # PYFUNCTYPE both retains the GIL and checks the final Python error
        # indicator. The transaction clears that indicator before returning.
        self.entry = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(address)
        self.load_word = address + len(TRANSACTION)
        self.raise_error = ctypes.PYFUNCTYPE(None, ctypes.c_void_p)(
            self.functions['PyErr_SetRaisedException'])


class UnpackSession:
    """One owned invocation. Intermediate object references stay out of Core.

    The raw cells contain one owned reference each (source cell 1 is borrowed).
    HIA chooses when to transfer/drop them. A successful C call is reconciled
    even if Python accounting raises immediately after the real machine entry.
    Public observation permission is consumed before every primitive effect.
    """

    def __init__(self, image, leaves, source, count):
        # Partial initialization never leaves __del__ consulting missing
        # lifecycle flags after an ABI/admission exception.
        self.finished = True
        self.pending = self.finish_pending = self.busy = self.aborting = False
        self.returned = None
        if type(count) is not int:
            raise TypeError('exact UNPACK ABI arity required')
        self.source, self.leaves, self.image = source, leaves, image
        self.cells = (ctypes.c_uint64 * 10)()
        self.cells[1] = id(source)
        self.transaction = (ctypes.c_uint64 * 14)()
        self.state = ctypes.create_string_buffer(256)
        self.output = ctypes.create_string_buffer(256)
        self.input = ctypes.create_string_buffer(128)
        address = ctypes.cast(image._entry, ctypes.c_void_p).value
        self.entry = ctypes.PYFUNCTYPE(ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)
        self.initial = FRAME.pack(MAGIC, 0, 0, count, leaves.profile,
                                  id(tuple), id(list), id(dict), *([0] * 8))
        self.finished = self.pending = self.finish_pending = self.busy = False
        self.aborting = False
        self.request = None
        self.returned = None
        self.status = None
        self.actual_steps = []
        self.actual_primitives = []
        self.abort_failure = None
        self.type_word = self.name_word = 0

    def _seal(self):
        self.finished, self.pending, self.finish_pending = True, False, False

    def _idle(self):
        if self.busy:
            self._seal()
            raise RuntimeError('UNPACK primitive is already active')

    def _pointer(self, slot):
        if type(slot) is not int or not 1 <= slot <= 9 or not self.cells[slot]:
            raise RuntimeError('UNPACK requested an empty raw object cell')
        return self.cells[slot]

    def _transaction(self, function, args, *, destination=0, consumed=0, restore_error=True):
        if len(args) > 6:
            raise RuntimeError('UNPACK C-API frame is too large')
        if destination and (not 2 <= destination <= 8 or self.cells[destination]):
            raise RuntimeError('UNPACK destination cell is not empty')
        if consumed and not 2 <= consumed <= 9:
            raise RuntimeError('UNPACK cannot consume a borrowed cell')
        frame = self.transaction
        for index in range(14):
            frame[index] = 0
        frame[0] = function
        for index, value in enumerate(args, 1):
            frame[index] = value
        frame[8] = self.cells[9] if restore_error else 0
        frame[9] = self.leaves.functions['PyErr_SetRaisedException']
        frame[10] = self.leaves.functions['PyErr_GetRaisedException']
        old_consumed = self.cells[consumed] if consumed else 0
        if consumed:
            self.cells[consumed] = 0
        if restore_error:
            self.cells[9] = 0
        try:
            returned = self.leaves.entry(frame)
        finally:
            marker = frame[13]
            if marker == 0:
                if consumed:
                    self.cells[consumed] = old_consumed
                if restore_error:
                    self.cells[9] = frame[8]
            elif marker == 4:
                # Ref ownership adoption is independent of later ledger/ACK
                # construction; no complete iterator policy is performed.
                self.cells[9] = frame[12]
                frame[12] = 0
                if destination:
                    self.cells[destination] = frame[11]
            else:
                raise RuntimeError('UNPACK C transaction did not reach its return marker')
        if returned != 0 or frame[13] != 4:
            raise RuntimeError('UNPACK C transaction return differs')
        return frame[11]

    def _primitive(self, header):
        _, seq, opcode, destination, a, b, c, *reserved = header
        if any(reserved):
            raise RuntimeError('UNPACK primitive reserved words differ')
        functions = self.leaves.functions
        call = self._transaction
        if opcode == 1:
            value = call(functions['PyObject_GetIter'], (self._pointer(a),), destination=destination)
        elif opcode == 2:
            value = call(functions['PyIter_Next'], (self._pointer(a),), destination=destination)
        elif opcode == 3:
            value = call(functions['PyErr_GivenExceptionMatches'], (self._pointer(a), id(TypeError)))
        elif opcode == 4:
            value = call(self.leaves.load_word, (self._pointer(a) + 8,))
            self.type_word = value
        elif opcode == 5:
            if not a or a != self.type_word:
                raise RuntimeError('UNPACK type address was not actually observed')
            value = call(functions['PyType_GetSlot'], (a, 62))
        elif opcode == 6:
            value = call(functions['PySequence_Check'], (self._pointer(a),))
        elif opcode == 7:
            if not a or a != self.type_word:
                raise RuntimeError('UNPACK name type was not actually observed')
            value = call(self.leaves.load_word, (a + 24,))
            self.name_word = value
        elif opcode == 8:
            # The HIA request supplies the exception class ID, complete NUL
            # format bytes and both scalar/pointer arguments. No diagnostic
            # or cardinality is selected here.
            if a not in (1, 2) or not b'\0' in self.output.raw[128:256]:
                raise RuntimeError('UNPACK error-format frame differs')
            if a == 1 and (not b or b != self.name_word):
                raise RuntimeError('UNPACK name address was not actually observed')
            exception = TypeError if a == 1 else ValueError
            value = call(functions['PyErr_Format'],
                         (id(exception), ctypes.addressof(self.output) + 128, b, c))
        elif opcode == 9:
            call(functions['Py_DecRef'], (self._pointer(a),), consumed=a)
            value = 0  # void return has no semantic result register
        elif opcode == 10:
            names = {1: 'PyTuple_Size', 2: 'PyList_Size', 3: 'PyDict_Size'}
            value = call(functions[names[b]], (self._pointer(a),))
        elif opcode == 11:
            value = call(functions['PyTuple_New'], (a,), destination=destination)
        elif opcode == 12:
            value = call(functions['PyTuple_SetItem'],
                         (self._pointer(a), b, self._pointer(c)), consumed=c)
        elif opcode == 13:
            if self.cells[9]:
                raise RuntimeError('UNPACK exported with a raised error')
            # ctypes' py_object O_get returns Py_NewRef; the owned raw tuple
            # remains in cell 8 until a separate HIA-selected DECREF.
            self.returned = ctypes.py_object.from_address(
                ctypes.addressof(self.cells) + a * 8).value
            value = 0
        elif opcode == 14:
            pointer = self._pointer(a)
            self.cells[a] = 0
            self._seal()
            # Transfer the owned exception to CPython. Its existing context,
            # cause and traceback are not rewritten with synthetic raise.
            self.leaves.raise_error(pointer)
            raise RuntimeError('UNPACK final raised error did not propagate')
        elif opcode == 15:
            call(functions['Py_DecRef'], (self._pointer(a),), consumed=a, restore_error=False)
            value = 0
        else:
            raise RuntimeError('UNPACK requested an unknown primitive')
        self.actual_primitives.append((seq, opcode, destination))
        return value

    def _step(self, packet):
        if type(packet) is not bytes or len(packet) != 128:
            raise TypeError('exact 128-byte UNPACK packet required')
        self.pending = False
        ctypes.memmove(self.input, packet, 128)
        status = self.entry(self.input, 128, self.output, 256, self.state, 256)
        self.actual_steps.append(status)
        header = FRAME.unpack_from(self.output)
        if header[0] != MAGIC or status not in (0, 1, 2):
            raise RuntimeError('HIA UNPACK protocol refused: ' + hex(status))
        self.status, self.request = status, header
        if status == 1:
            self.pending = True
        else:
            self.finished, self.finish_pending = True, status == 0
        return status

    def step(self, packet):
        self._idle()
        try:
            if self.finished:
                raise RuntimeError('UNPACK session is closed')
            return self._step(packet)
        except BaseException:
            self._seal()
            self._abort()
            raise

    def _observe(self):
        self.pending = False
        header = self.request
        value = self._primitive(header)
        return FRAME.pack(MAGIC, 1, header[1], header[2], value,
                          int(bool(self.cells[9])), *([0] * 10))

    def observe(self):
        self._idle()
        try:
            if self.finished or not self.pending or self.status != 1:
                raise RuntimeError('UNPACK observation is not pending')
            self.busy = True
            try:
                packet = self._observe()
            finally:
                self.busy = False
            if self.finished:
                raise RuntimeError('UNPACK was closed during a primitive')
            return packet
        except BaseException:
            self._seal()
            self._abort()
            raise

    def finish(self):
        self._idle()
        if not self.finish_pending or self.status != 0:
            self._seal()
            raise RuntimeError('UNPACK result is not pending')
        self.finish_pending = False
        returned, self.returned = self.returned, None
        return returned

    def _abort(self):
        if self.aborting or self.busy:
            return
        mask = sum(1 << slot for slot in range(2, 9) if self.cells[slot])
        if not mask and not self.cells[9]:
            self.returned = None
            return
        self.aborting = True
        try:
            seq = struct.unpack_from('<Q', self.state, 16)[0]
            packet = FRAME.pack(MAGIC, 2, seq, mask, int(bool(self.cells[9])), *([0] * 11))
            while self._step(packet) == 1:
                packet = self._observe()
            if self.status != 2 or any(self.cells[2:]):
                raise RuntimeError('HIA UNPACK abort did not release its owned cells')
        except BaseException as error:
            # Never switch to a host release loop or overwrite the original
            # semantic/infrastructure exception. A failed private abort is an
            # explicit open resource-failure path, retained for diagnostics.
            self.abort_failure = error
        finally:
            self.aborting = False
            self._seal()
            self.returned = None

    def close(self):
        self._idle()
        self._seal()
        self._abort()

    def run(self):
        packet = self.initial
        try:
            while self.step(packet) == 1:
                packet = self.observe()
            return self.finish()
        except BaseException:
            self._seal()
            self._abort()
            raise

    def __del__(self):
        if hasattr(self, 'cells'):
            self.close()


class NativeUnpack:
    """Explicit experimental composition; never loaded by a default selector."""

    def __init__(self, image):
        self.image = image
        self.leaves = CpythonLeaves()

    def session(self, value, count):
        return UnpackSession(self.image, self.leaves, value, count)

    def unpack(self, value, count):
        return self.session(value, count).run()
