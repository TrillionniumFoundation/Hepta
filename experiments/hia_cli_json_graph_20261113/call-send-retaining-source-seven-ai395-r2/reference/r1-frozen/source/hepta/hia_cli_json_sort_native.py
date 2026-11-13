"""Experimental transport for HIA-controlled, actual-list no-key sorting.

No default selector imports this module.  The caller supplies a separately
admitted native HIA image and the independently built/pinned CPython leaf DSO.
This transport has no Python sort/comparison/merge implementation.  In-flight
object/error ownership is recorded by the leaf DSO, not by Python bookkeeping.
The generated controller owns comparison choice, merge-tail restoration,
mutation-error priority and reverse release of comparison-added list entries.

Public graph compatibility, resource-allocation and signal schedules remain
unqualified until the fixed trace controls actually execute on each profile.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import os
from pathlib import Path
import platform
import stat
import struct
import sys
import sysconfig

MAGIC = int.from_bytes(b'HCLISRT1', 'little')
LEAF_ABI = 0x31464c4a43414948
REFUSAL = 0xfffffffd
STATE_BYTES = 20480
WORD = struct.Struct('<Q')
FRAME_WORDS = 24
PROFILES = {(3, 12, 14): 31214, (3, 14, 4): 31404, (3, 14, 10): 31410}
OFFSETS = {
    'phase': 8, 'sequence': 16, 'pending': 24, 'reply_sequence': 32,
    'reply_operation': 40, 'reply_error': 48, 'abort': 56,
    'operation': 64, 'arguments': 72, 'final_status': 112,
    'root_object': 120, 'answer': 160, 'context_slot': 448,
    'context_phase': 456, 'displaced_count': 464,
}


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _pinned_dso(path, expected):
    """Development input pin; no compilation, download or manifest fabrication."""
    if type(expected) is not str or len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('exact leaf DSO SHA256 required')
    path = Path(path).absolute()
    chain = []
    current = Path('/')
    for part in path.parts[1:-1]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('leaf DSO parent is not a physical directory')
        chain.append((current, _identity(info)))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('leaf DSO must be a regular single-link input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise ValueError('leaf DSO name/descriptor differ')
        digest = sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        if size != before.st_size or _identity(os.fstat(fd)) != _identity(before):
            raise ValueError('leaf DSO changed during read')
    finally:
        os.close(fd)
    if (_identity(path.lstat()) != _identity(before) or digest.hexdigest() != expected
            or any(_identity(parent.lstat()) != pin for parent, pin in chain)):
        raise ValueError('leaf DSO input binding differs')
    return path, {'path': str(path), 'bytes': size, 'sha256': expected,
                  'identity': list(_identity(before))}


class CpythonJsonLeaves:
    """Pinned native leaf mechanism; all semantic strategy belongs to HIA."""

    def __init__(self, path, *, sha256_pin):
        version = tuple(sys.version_info[:3])
        if (sys.implementation.name != 'cpython' or version not in PROFILES
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or sysconfig.get_config_var('Py_GIL_DISABLED')
                or sysconfig.get_config_var('Py_TRACE_REFS')
                or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
            raise ValueError('unadmitted experimental CLI JSON CPython ABI')
        self.path, self.input_pin = _pinned_dso(path, sha256_pin)
        self.library = ctypes.PyDLL(str(self.path), mode=os.RTLD_LOCAL | os.RTLD_NOW)

        def address(name):
            return ctypes.cast(getattr(self.library, name), ctypes.c_void_p).value

        self.layout = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)(
            address('hia_cli_json_leaf_layout'))
        self.init = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)(
            address('hia_cli_json_leaf_init'))
        self.views = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p)(
            address('hia_cli_json_leaf_views'))
        self.entry = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(address('hia_cli_json_leaf'))
        self.capture_external = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.py_object)(
            address('hia_cli_json_capture_external'))
        self.raise_pending = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(
            address('hia_cli_json_raise_pending'))
        self.transfer_closed_error = ctypes.PYFUNCTYPE(
            ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p)(
                address('hia_cli_json_transfer_closed_error'))
        record = (ctypes.c_uint64 * 8)()
        if self.layout(record, 8) != 0:
            raise ValueError('CLI JSON leaf layout refused')
        if tuple(record[:2]) != (LEAF_ABI, FRAME_WORDS * 8) or record[3] != PROFILES[version] or record[4] != sys.hexversion or record[5] != 256:
            raise ValueError('CLI JSON leaf compiled/runtime layout differs')
        self.context_bytes = record[2]
        if self.context_bytes < 2048 or self.context_bytes > 4096 or record[6] not in (15, 30) or record[7] not in (2, 4):
            raise ValueError('CLI JSON leaf representation differs')
        self.profile = record[3]
        self.layout_record = tuple(record)
        # Admission before dlopen and a complete stable read after dlopen are
        # distinct observations.  Neither is claimed to hold an OS lock.
        _, after = _pinned_dso(self.path, sha256_pin)
        if after != self.input_pin:
            raise ValueError('CLI JSON leaf changed during loading')

    def bind_runtime_312(self, path, *, sha256_pin, bytes_pin):
        """Additional exact-runtime admission, never an ordinary-call fallback."""
        if self.profile != 31214:
            raise ValueError('private CALL binding belongs to CPython 3.12.14')
        from hepta.hia_cli_json_runtime312 import admit_runtime
        words, record = admit_runtime(path, sha256_pin=sha256_pin, bytes_pin=bytes_pin)
        address = ctypes.cast(self.library.hia_cli_json_bind_runtime_312,
                              ctypes.c_void_p).value
        entry = ctypes.PYFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p,
                                 ctypes.c_uint64)(address)
        wire = (ctypes.c_uint64 * len(words))(*words)
        if entry(wire, len(words)) != 0:
            raise ValueError('exact private runtime binding refused')
        self.runtime_312_binding = record
        return record


class SortSession:
    """One managed private invocation; not a new public list-sort domain."""

    def __init__(self, image, leaves, items):
        self._initialize(image, leaves, id(items), items, False)

    @classmethod
    def from_raw(cls, image, leaves, borrowed_items_pointer):
        # The outer HIA graph owns this exact PyMapping_Items list.  This
        # constructor never converts the pointer to a Python object or adds
        # another reference that could delay a comparison-visible finalizer.
        if type(borrowed_items_pointer) is not int or borrowed_items_pointer <= 0:
            raise ValueError('actual borrowed items-list pointer required')
        result = cls.__new__(cls)
        result._initialize(image, leaves, borrowed_items_pointer, None, True)
        return result

    def _initialize(self, image, leaves, items_pointer, items, raw_terminal):
        self.finished = True
        self.quarantined = False
        self.busy = self.pending = self.finish_pending = self.aborting = False
        self.image, self.leaves, self.items = image, leaves, items
        self.raw_terminal = raw_terminal
        self.state = ctypes.create_string_buffer(STATE_BYTES)
        self.context = ctypes.create_string_buffer(leaves.context_bytes)
        self.frame = (ctypes.c_uint64 * FRAME_WORDS)()
        self.view = (ctypes.c_uint64 * 9)()
        if leaves.init(self.context, leaves.context_bytes) != 0:
            raise ValueError('CLI JSON leaf context initialization refused')
        entry = ctypes.cast(image._entry, ctypes.c_void_p).value
        self.entry = ctypes.PYFUNCTYPE(ctypes.c_uint32, *([ctypes.c_void_p, ctypes.c_uint64] * 3))(entry)
        self._put(0, MAGIC)
        self._put(OFFSETS['root_object'], items_pointer)
        self.actual_native_returns = []
        self.actual_leaf_returns = []
        self.last_issued = self.last_executed = 0
        self.status = None
        self.unwind_failure = None
        self.finished = False

    def _get(self, offset):
        return WORD.unpack_from(self.state, offset)[0]

    def _put(self, offset, value):
        WORD.pack_into(self.state, offset, value)

    def _views(self):
        if self.leaves.views(self.context, self.leaves.context_bytes, self.view) != 0:
            raise RuntimeError('CLI JSON raw storage view refused')
        self._put(OFFSETS['context_slot'], self.view[5])
        self._put(OFFSETS['context_phase'], self.view[4])
        self._put(OFFSETS['displaced_count'], self.view[6])
        self._put(OFFSETS['reply_error'], self.view[8])

    def _call_leaf(self, operation, args):
        frame = self.frame
        for index in range(FRAME_WORDS):
            frame[index] = 0
        frame[0], frame[1], frame[2] = LEAF_ABI, operation, ctypes.addressof(self.context)
        for index, value in enumerate(args, 3):
            frame[index] = value
        if operation == 10:
            offset, size = frame[4], frame[5]
            if offset != 416 or size != 26 or self.state.raw[offset:offset + size] != b'list modified during sort\0':
                raise RuntimeError('HIA mutation error payload differs')
            frame[4] = ctypes.addressof(self.state) + offset
        # The C context acquires/consumes all raw result and exception owners
        # before marker 2, independent of this Python result assignment.
        returned = self.leaves.entry(frame)
        if returned != 0 or frame[18] != 2:
            raise RuntimeError('CLI JSON leaf transaction refused')
        self._views()
        for index in range(8):
            self._put(OFFSETS['answer'] + index * 8, frame[9 + index])

    def _step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('CLI JSON sort session is terminal or active')
        self.pending = False
        self.busy = True
        try:
            self._views()
            status = self.entry(self.view[0], self.view[1], self.view[2], self.view[3],
                                self.state, STATE_BYTES)
            self.status = status
            # This append is intentionally inside the BaseException boundary.
            # An exception here cannot abandon a detached list or owned error.
            self.actual_native_returns.append(status)
            if status == 2:
                sequence = self._get(OFFSETS['sequence'])
                if self._get(OFFSETS['pending']) != 1 or sequence <= self.last_issued:
                    raise RuntimeError('CLI JSON sort request permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status in (0, 1):
                self._views()
                if self.view[4] not in (0, 3) or self.view[5] != 0 or self._get(OFFSETS['final_status']) != status + 1:
                    raise RuntimeError('CLI JSON sort terminal ownership differs')
                self.finish_pending = True
            else:
                raise RuntimeError('CLI JSON HIA protocol refused: ' + hex(status))
            return status
        finally:
            self.busy = False

    def _observe(self):
        if not self.pending or self.finished or self.busy or self.quarantined:
            raise RuntimeError('CLI JSON sort has no observation permission')
        self.pending = False
        self.busy = True
        try:
            sequence = self._get(OFFSETS['sequence'])
            operation = self._get(OFFSETS['operation'])
            if sequence != self.last_issued or sequence <= self.last_executed:
                raise RuntimeError('CLI JSON sort effect already consumed')
            self.last_executed = sequence
            args = tuple(self._get(OFFSETS['arguments'] + index * 8) for index in range(4))
            if operation not in (1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20):
                raise RuntimeError('CLI JSON sort issued a non-sort leaf')
            self._call_leaf(operation, args)
            self.actual_leaf_returns.append((sequence, operation, tuple(self.frame[9:17]), self.frame[17]))
            self._put(OFFSETS['reply_sequence'], sequence)
            self._put(OFFSETS['reply_operation'], operation)
        finally:
            self.busy = False

    def _capture(self, error):
        # This is acquisition only.  Do not invoke HIA, DECREF a result, or
        # restore a list while the transport's except owns handled state.
        if self.leaves.capture_external(self.context, error) != 0:
            raise RuntimeError('CLI JSON external exception acquisition refused')

    def _start_abort(self):
        self.pending = self.finish_pending = False
        self._call_leaf(40, (0, 0, 0, 0))
        if self.view[4] in (0, 3) and self.view[5] == 0 and self._get(OFFSETS['final_status']) != 0:
            # Native cleanup already completed before Python bookkeeping
            # failed.  Do not replay the terminal HIA entry or any leaf.
            self.status = 1
            self.finish_pending = True
            self.aborting = True
            return
        self._put(OFFSETS['abort'], 1)
        self.aborting = True

    def run(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('CLI JSON sort session cannot be re-entered')
        try:
            while True:
                failed = False
                try:
                    while not self.finish_pending:
                        if self._step() == 2:
                            self._observe()
                except BaseException as error:
                    # A failed cleanup is not another permission to replay
                    # an effect. Preserve this context for explicit diagnosis.
                    if self.aborting:
                        raise
                    self._capture(error)
                    failed = True
                # The exception target has now been cleared and the caller's
                # handled exception restored. Only now may cleanup call __del__.
                if failed:
                    self._start_abort()
                    continue
                return self.finish()
        except BaseException as error:
            if self.finished and not self.raw_terminal:
                # finish consumed the actual business exception for the
                # legacy private object-returning diagnostic entry.
                raise
            self.quarantined = True
            self.pending = self.finish_pending = False
            self.unwind_failure = error
            raise

    def finish(self):
        if self.finished or self.busy or self.quarantined or not self.finish_pending:
            raise RuntimeError('CLI JSON sort has no finish permission')
        self.finish_pending = False
        self.finished = True
        if self.raw_terminal:
            if (self.status == 0) != (self.view[8] == 0):
                raise RuntimeError('nested sort status and owned exception differ')
            return self.status
        if self.view[8]:
            self.leaves.raise_pending(self.context)
            raise RuntimeError('CLI JSON actual raised exception did not propagate')
        if self.status != 0:
            raise RuntimeError('CLI JSON sort failed without an actual exception')
        return None

    def close(self):
        if self.quarantined:
            raise RuntimeError('CLI JSON sort cleanup is not confirmed')
        if self.finished:
            return
        # Cancellation is an explicit private lifecycle error, never an
        # alternative host sorting implementation or silent native success.
        error = RuntimeError('unfinished CLI JSON sort session')
        self._capture(error)
        del error
        self._start_abort()
        try:
            self.run()
        except RuntimeError as error:
            if not self.finished:
                self.unwind_failure = error
                raise


def sort_items(image, leaves, items):
    """Development-only explicit selector; ordinary CLI remains unchanged."""
    session = SortSession(image, leaves, items)
    try:
        session.run()
        return {'native_returns': tuple(session.actual_native_returns),
                'leaf_returns': tuple(session.actual_leaf_returns),
                'profile': leaves.profile, 'status': 'SORTED_DEVELOPMENT_ONLY'}
    finally:
        session.close()
