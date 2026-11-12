"""Mechanical effects for the HIA bounded-file read continuation.

STATIC CANDIDATE, not yet generated/compiled/qualified. HIA chooses every
filesystem observation, byte-limit branch, close point and error disposition.
Path, CPython file buffering and context-manager protocol remain foreign
runtime operations. The dynamically selected _reject helper remains a foreign
callable, including its ordinary diagnostic prefix/constructor; HIA supplies
the original reason and chooses the continuation if that callable returns.
This file is not a Python-free OS implementation.
"""
from __future__ import annotations

from collections import Counter
import ctypes
from hashlib import sha256
import struct

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)
from .hia_worker_report_native import (
    _activation_state, _restore_activation, _reraise_foreign,
    _with_foreign_exception,
)

SOURCE = _source_resource_path("examples/hia_bootstrap/bounded_read.hiaasm")
SCHEMA = "hepta.hia.bounded-read-native.v2"
SELECTOR = "HEPTA_HIA_BOUNDED_READ_MANIFEST"
MAGIC = int.from_bytes(b"HIARDB02", "little")


class _ContextCapsule:
    """One real CPython with protocol, resumed only by a HIA request.

    The capsule carries no file admission, byte count, retry, read or error
    conversion rule. It preserves the runtime's special-method lookup,
    exception-aware __exit__, and suppression behavior. Catching before the
    final yield prevents PEP479 from converting a real foreign StopIteration.
    """
    def __init__(self, manager):
        self.terminal = False
        self.injected = None
        self.activation = None
        self.frame = self._frame(manager)

    def _frame(self, manager):
        try:
            with manager as stream:
                try:
                    yield (0, stream)
                except BaseException as exception:
                    if exception is self.injected:
                        _restore_activation(exception, self.activation)
                    raise
        except BaseException as exception:
            yield (1, exception)
        else:
            yield (2, None)

    def enter(self):
        kind, value = next(self.frame)
        if kind == 0:
            return value
        self.terminal = True
        self.frame.close()
        if kind != 1:
            raise RuntimeError("file context entered without a value")
        _reraise_foreign(value)

    def exit(self, exception=None):
        if self.terminal:
            raise RuntimeError("file context close permission is already consumed")
        # Consume before any foreign callback. An exception cannot reopen it.
        self.terminal = True
        try:
            if exception is None:
                kind, value = self.frame.send(None)
            else:
                self.injected = exception
                self.activation = _activation_state(exception)
                kind, value = self.frame.throw(exception)
        finally:
            self.injected = None
            self.activation = None
        self.frame.close()
        if kind == 1:
            _reraise_foreign(value)
        if kind != 2:
            raise RuntimeError("file context close did not produce a terminal outcome")


def _unbound_payload():
    # Use the target CPython's own exception class and diagnostic; this branch
    # is reachable if a foreign context suppresses an error before assignment.
    if False:
        payload = None
    return payload


class BoundedReadSession:
    def __init__(self, owner, bindings, path, limit):
        self.owner, self.bindings = owner, bindings
        self.values = [None]
        self.identities = {}
        self.contexts = {}
        self.workspace = ctypes.create_string_buffer(1024)
        self.output = ctypes.create_string_buffer(b"\xa5" * 24, 24)
        self.packet = struct.pack("<8Q", MAGIC, 0, 0, 0, 0, 0,
                                  self.register(path), self.register(limit))
        self.finished = False
        self.pending = False
        self.prepared = True
        self.finish_pending = False

    def register(self, value):
        key = id(value)
        handle = self.identities.get(key)
        if handle is None:
            handle = len(self.values)
            self.values.append(value)
            self.identities[key] = handle
        elif self.values[handle] is not value:
            raise RuntimeError("bounded-read object identity changed")
        return handle

    def value(self, handle):
        if not 0 < handle < len(self.values):
            raise RuntimeError("bounded-read unknown object handle")
        return self.values[handle]

    def literal(self, offset, count):
        if offset != 512 or not 0 < count <= 192:
            raise RuntimeError("bounded-read literal span differs")
        return bytes(self.workspace[offset:offset + count]).decode("utf-8")

    def _seal(self):
        self.finished = True
        self.pending = False
        self.prepared = False
        self.finish_pending = False

    def step(self, packet=None):
        try:
            if self.finished or self.pending or (packet is None and not self.prepared):
                raise RuntimeError("bounded-read continuation is terminal or unacknowledged")
            raw = self.packet if packet is None else packet
            if type(raw) is not bytes:
                raise TypeError("bounded-read packet must be exact bytes")
            self.pending = False
            self.prepared = False
            status = self.owner._entry(raw, len(raw), self.output, len(self.output),
                                       self.workspace, len(self.workspace))
            self.owner.transitions += 1
            if status == 1:
                self.pending = True
            else:
                self.finished = True
                self.finish_pending = status == 0
            return status
        except BaseException:
            self._seal()
            raise

    def observe(self):
        try:
            if self.finished or not self.pending:
                raise RuntimeError("bounded-read has no unconsumed effect permission")
            self.pending = False
            opcode, sequence = struct.unpack_from("<2Q", self.workspace, 8)
            a, b, c = struct.unpack_from("<3Q", self.workspace, 256)
            self.owner.effect_attempts[opcode] += 1
            error = truth = 0
            try:
                result, truth = self._effect(opcode, a, b, c)
            except BaseException as exception:
                error, result, truth = 1, exception, 0
                self.owner.effect_errors[opcode] += 1
            else:
                self.owner.effect_returns[opcode] += 1
            self.packet = struct.pack("<8Q", MAGIC, opcode, sequence, error,
                                      self.register(result), truth, 0, 0)
            self.prepared = True
            return self.packet
        except BaseException:
            self._seal()
            raise

    def _effect(self, opcode, a, b, c):
        value, bindings = self.value, self.bindings
        truth = 0
        if opcode == 1:
            result = bindings.Path(value(a))
        elif opcode == 2:
            result = bindings.os.O_RDONLY
        elif opcode == 3:
            result = getattr(bindings.os, "O_NOFOLLOW", 0)
        elif opcode == 4:
            result = value(a) | value(b)
        elif opcode == 5:
            result = getattr(bindings.os, "O_NONBLOCK", 0)
        elif opcode == 6:
            result = bindings.os.fdopen
        elif opcode == 7:
            result = bindings.os.open
        elif opcode == 8:
            result = value(a)(value(b), value(c))
        elif opcode == 9:
            result = value(a)(value(b), "rb")
        elif opcode == 10:
            context = _ContextCapsule(value(a))
            self.contexts[a] = context
            result = context.enter()
        elif opcode == 11:
            result = bindings.os.fstat
        elif opcode == 12:
            result = value(a).fileno
        elif opcode == 13:
            result = value(a)()
        elif opcode == 14:
            result = value(a)(value(b))
        elif opcode == 15:
            result = bindings.stat.S_ISREG
        elif opcode == 16:
            result = value(a).st_mode
        elif opcode == 17:
            result = bool(value(a))
            truth = int(result)
        elif opcode == 18:
            result = value(a).st_size
        elif opcode == 19:
            result = value(a) > value(b)
        elif opcode == 20:
            result = value(a).read
        elif opcode == 21:
            result = value(a) + 1
        elif opcode == 22:
            result = self.contexts[a].exit()
        elif opcode == 23:
            result = len(value(a))
        elif opcode == 24:
            # Bind and invoke the current foreign helper exactly at the HIA
            # request. Its result is discarded here, before any next effect;
            # a returning helper is not an ABI error or a terminal result.
            bindings._reject(self.literal(a, b))
            result = None
        elif opcode == 25:
            result = self.contexts[a].exit(value(b))
        elif opcode == 26:
            # Exception matching uses the actual exception type, never a
            # user-visible __class__ attribute on the exception instance.
            result = issubclass(type(value(a)), OSError)
            truth = int(result)
        elif opcode == 27:
            result = _unbound_payload()
        else:
            raise RuntimeError("unknown bounded-read effect instruction")
        return result, truth

    def finish(self):
        try:
            if not self.finished or not self.finish_pending:
                raise RuntimeError("bounded-read has no unconsumed terminal result")
            # Consume before envelope decoding or any foreign constructor,
            # rethrow, cause/context observation, or returned-object lookup.
            self.finish_pending = False
            kind, handle, count = struct.unpack("<3Q", self.output)
            if kind == 1:
                if count != 0:
                    raise RuntimeError("bounded-read return envelope differs")
                return self.value(handle)
            if kind == 2:
                if count != 0:
                    raise RuntimeError("bounded-read rethrow envelope differs")
                _reraise_foreign(self.value(handle))
            if kind == 3:
                cause = self.value(handle)
                text = self.literal(512, count)
                def raise_converted():
                    raise self.bindings.HIAEditRejected(text) from cause
                return _with_foreign_exception(cause, raise_converted)
            raise RuntimeError("bounded-read terminal envelope differs")

        except BaseException:
            self._seal()
            raise

    def close(self, exception=None):
        self._seal()
        for context in self.contexts.values():
            if not context.terminal:
                context.exit(exception)


class NativeBoundedRead(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.calls = 0
        self.transitions = 0
        self.effect_attempts = Counter()
        self.effect_returns = Counter()
        self.effect_errors = Counter()

    def identity(self):
        current = sha256(SOURCE.read_bytes()).hexdigest()
        if current != self.admitted_source_sha256:
            raise ValueError("bounded-read mapped image no longer matches its admitted source")
        return {"source_sha256": current, "image_sha256": self.image_sha256}

    def read(self, path, limit, *, bindings=None):
        if bindings is None:
            from . import hia_program_tools as bindings
        self.identity()
        session = BoundedReadSession(self, bindings, path, limit)
        self.calls += 1
        try:
            status = session.step()
            while status == 1:
                session.observe()
                status = session.step()
            if status != 0:
                raise RuntimeError("bounded-read HIA protocol refused: " + hex(status))
            return session.finish()
        except BaseException as exception:
            session.close(exception)
            raise
        finally:
            session.close()


def installed_bounded_read(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeBoundedRead)
