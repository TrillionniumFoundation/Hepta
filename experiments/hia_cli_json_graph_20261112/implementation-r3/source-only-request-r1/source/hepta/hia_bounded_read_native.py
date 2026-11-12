"""Mechanical effects for the explicitly selected HIA bounded-file reader.

HIA chooses filesystem observations, byte-limit branches, close points, error
dispositions and reference-release plans. Path, CPython buffering, context
protocol and dynamically resolved foreign operations remain hosted.
The retained public policy is used when no manifest is selected. A selected
manifest must bind this source and its immutable executable image.

The r4b control was exercised by run 43175489773 on CPython 3.14.4: 55 finite
cases and the original eight methods with seven unchanged CLI children. Those
observations do not establish arbitrary foreign-object/cyclic-GC equivalence,
a matching-current-source cold qualification, or whole-project migration.
"""
from __future__ import annotations

from collections import Counter
import ctypes
from hashlib import sha256
import struct
import os
from pathlib import Path
from types import FunctionType

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)
from .hia_worker_report_native import (
    _activation_state, _restore_activation, _reraise_foreign,
    _with_foreign_exception,
)

SOURCE = _source_resource_path("examples/hia_bootstrap/bounded_read.hiaasm")
SCHEMA = "hepta.hia.bounded-read-native.v3"
SELECTOR = "HEPTA_HIA_BOUNDED_READ_MANIFEST"
MAGIC = int.from_bytes(b"HIARDB03", "little")


class _ForeignGlobals:
    """Mechanical LOAD_GLOBAL and literal identity for the original code.

    The reference function is an explicit oracle/input identity, never invoked.
    No original byte-limit, regular-file, close or exception-conversion branch
    is executed here. Capturing __builtins__ from the actual function also
    preserves its definition-time binding if globals['__builtins__'] changes.
    """
    def __init__(self, reference):
        if type(reference) is not FunctionType:
            raise TypeError("bounded-read requires its exact reference function environment")
        self.globals = reference.__globals__
        self.builtins = reference.__builtins__
        self.names = {name: name for name in reference.__code__.co_names}
        self.constants = tuple(value for value in reference.__code__.co_consts
                               if type(value) is str)

    def __call__(self, name):
        name = self.names[name]
        # This mirrors the target interpreter's exact-dict fast path and its
        # mapping slow path. In the fast path a KeyError raised by key equality
        # propagates; only an actually missing entry falls back to builtins.
        if type(self.globals) is dict and type(self.builtins) is dict:
            missing = object()
            value = dict.get(self.globals, name, missing)
            if value is not missing:
                return value
            value = dict.get(self.builtins, name, missing)
            if value is not missing:
                return value
        else:
            try:
                return self.globals[name]
            except KeyError:
                pass
            try:
                return self.builtins[name]
            except KeyError:
                pass
        raise NameError("name '" + name + "' is not defined", name=name)

    def constant(self, text):
        for value in self.constants:
            if value == text:
                return value
        raise RuntimeError("HIA literal is not a constant of the bound original code")


_TYPE_FLAGS = ctypes.pythonapi.PyType_GetFlags
_TYPE_FLAGS.argtypes = (ctypes.py_object,)
_TYPE_FLAGS.restype = ctypes.c_ulong
_EXCEPTION_MATCHES = ctypes.pythonapi.PyErr_GivenExceptionMatches
_EXCEPTION_MATCHES.argtypes = (ctypes.py_object, ctypes.py_object)
_EXCEPTION_MATCHES.restype = ctypes.c_int
_BASE_EXCEPTION_SUBCLASS = 1 << 30


def _exception_matches(exception, expected):
    # CPython CHECK_EXC_MATCH's flat tuple/type validation uses actual type
    # flags, not a foreign __class__, __subclasscheck__, tuple __len__/getitem,
    # or an added Python isinstance/issubclass policy.
    def is_exception_class(value):
        return (issubclass(type(value), type)
                and bool(_TYPE_FLAGS(value) & _BASE_EXCEPTION_SUBCLASS))
    if issubclass(type(expected), tuple):
        for index in range(tuple.__len__(expected)):
            if not is_exception_class(tuple.__getitem__(expected, index)):
                raise TypeError("catching classes that do not inherit from BaseException is not allowed")
    elif not is_exception_class(expected):
        raise TypeError("catching classes that do not inherit from BaseException is not allowed")
    return bool(_EXCEPTION_MATCHES(exception, expected))


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
        # The constructor releases its manager parameter before enter() is
        # called. The generator receives only the cell; its with expression
        # pops the last extra reference before actual special-method lookup.
        self.frame = self._frame([manager])

    def _frame(self, pending):
        try:
            with pending.pop() as stream:
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
    def __init__(self, owner, bindings, path, limit, reference=None):
        self.owner, self.bindings = owner, bindings
        self.globals = _ForeignGlobals(bindings.read_bounded if reference is None else reference)
        self.values = [None]
        self.live = set()
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
        # Handles represent independent owned references, not object identity.
        # Aliased locals and temporaries must be releasable independently.
        handle = len(self.values)
        self.values.append(value)
        self.live.add(handle)
        return handle

    def value(self, handle):
        if type(handle) is not int or handle not in self.live:
            raise RuntimeError("bounded-read unknown or consumed object handle")
        return self.values[handle]

    def take(self, handle):
        value = self.value(handle)
        self.live.remove(handle)
        self.values[handle] = None
        return value

    def release(self, handle):
        # The temporary call reference is released before this method returns.
        self.take(handle)

    def _local_plan(self):
        handles = struct.unpack_from("<6Q", self.workspace, 304)
        nonzero = [handle for handle in handles if handle]
        if len(nonzero) != len(set(nonzero)) or any(h not in self.live for h in nonzero):
            raise RuntimeError("bounded-read HIA local-root plan differs")
        return handles

    def _unwind_temporaries(self, exception_handle):
        keep = set(self._local_plan())
        if exception_handle:
            self.value(exception_handle)
            keep.add(exception_handle)
        # The HIA-selected plan leaves only the original named locals and
        # current exception alive. Reverse handle order mirrors pending
        # expression-stack ownership; moved operands already left the table.
        for handle in range(len(self.values) - 1, 0, -1):
            if handle in self.live and handle not in keep:
                self.release(handle)

    def _release_return_locals(self):
        # HIA emits the CPython3.14.4 reverse-fast-local cleanup order:
        # payload, info, stream, flags, limit, path. finish() protects the
        # actual returned value while these original local roots disappear.
        for handle in self._local_plan():
            if handle:
                self.release(handle)
        for handle in range(len(self.values) - 1, 0, -1):
            if handle in self.live:
                self.release(handle)

    def literal(self, offset, count):
        if offset != 512 or not 0 < count <= 192:
            raise RuntimeError("bounded-read literal span differs")
        text = bytes(self.workspace[offset:offset + count]).decode("utf-8")
        return self.globals.constant(text)

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
            a, b, c, ownership = struct.unpack_from("<4Q", self.workspace, 256)
            if ownership & ~15:
                raise RuntimeError("bounded-read unknown ownership mask")
            self.owner.effect_attempts[opcode] += 1
            error = truth = 0
            try:
                result, truth = self._effect(opcode, a, b, c, ownership)
            except BaseException as exception:
                error, result, truth = 1, exception, 0
                self.owner.effect_errors[opcode] += 1
            else:
                self.owner.effect_returns[opcode] += 1
            handle = self.register(result)
            if not error and ownership & 8:
                # Assign/protect the converted result before releasing the
                # original named path, exactly as STORE_FAST replaces it.
                self.release(a)
            self.packet = struct.pack("<8Q", MAGIC, opcode, sequence, error,
                                      handle, truth, 0, 0)
            self.prepared = True
            return self.packet
        except BaseException:
            self._seal()
            raise

    def _effect(self, opcode, a, b, c, ownership):
        value, global_value = self.value, self.globals
        def operand(handle, bit):
            return self.take(handle) if ownership & bit else value(handle)
        truth = 0
        if opcode == 1:
            result = global_value("Path")(value(a))
        elif opcode == 2:
            result = global_value("os").O_RDONLY
        elif opcode == 3:
            result = global_value("getattr")(global_value("os"),
                                            global_value.constant("O_NOFOLLOW"), 0)
        elif opcode == 4:
            result = operand(a, 1) | operand(b, 2)
        elif opcode == 5:
            result = global_value("getattr")(global_value("os"),
                                            global_value.constant("O_NONBLOCK"), 0)
        elif opcode == 6:
            result = global_value("os").fdopen
        elif opcode == 7:
            result = global_value("os").open
        elif opcode == 8:
            result = operand(a, 1)(operand(b, 2), operand(c, 4))
        elif opcode == 9:
            result = operand(a, 1)(operand(b, 2), global_value.constant("rb"))
        elif opcode == 10:
            context = _ContextCapsule(operand(a, 1))
            self.contexts[a] = context
            result = context.enter()
        elif opcode == 11:
            result = global_value("os").fstat
        elif opcode == 12:
            result = value(a).fileno
        elif opcode == 13:
            result = operand(a, 1)()
        elif opcode == 14:
            result = operand(a, 1)(operand(b, 2))
        elif opcode == 15:
            result = global_value("stat").S_ISREG
        elif opcode == 16:
            result = value(a).st_mode
        elif opcode == 17:
            result = bool(operand(a, 1))
            truth = int(result)
        elif opcode == 18:
            result = value(a).st_size
        elif opcode == 19:
            result = operand(a, 1) > operand(b, 2)
        elif opcode == 20:
            result = value(a).read
        elif opcode == 21:
            result = value(a) + 1
        elif opcode == 22:
            result = self.contexts[a].exit()
        elif opcode == 23:
            result = global_value("len")(value(a))
        elif opcode == 24:
            # The actual dynamic helper is still foreign. Its returned object
            # dies at this expression statement before HIA's continuation.
            global_value("_reject")(self.literal(a, b))
            result = None
        elif opcode == 25:
            result = self.contexts[a].exit(value(b))
        elif opcode == 26:
            def match_under_original_exception():
                return _exception_matches(value(a), global_value("OSError"))
            result = _with_foreign_exception(value(a), match_under_original_exception)
            truth = int(result)
        elif opcode == 27:
            result = _unbound_payload()
        elif opcode == 28:
            self._unwind_temporaries(a)
            result = None
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
                returned = self.value(handle)
                self._release_return_locals()
                return returned
            if kind == 2:
                if count != 0:
                    raise RuntimeError("bounded-read rethrow envelope differs")
                _reraise_foreign(self.value(handle))
            if kind == 3:
                cause = self.value(handle)
                text = self.literal(512, count)
                def raise_converted():
                    raise self.globals("HIAEditRejected")(text) from cause
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

    def read(self, path, limit, *, bindings=None, reference=None):
        if bindings is None:
            from . import hia_program_tools as bindings
        self.identity()
        session = BoundedReadSession(self, bindings, path, limit, reference)
        # Only the session's independently owned local slots retain inputs.
        # Keeping these outer call parameters would defer foreign finalizers.
        del path, limit
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


def selected_bounded_read():
    """Select the explicit, source-bound development manifest if present.

    An explicit empty/invalid selector is an admission error, not permission
    to call the retained Python policy. Cold-report integration is separate.
    """
    if SELECTOR not in os.environ:
        return None
    return installed_bounded_read(Path(os.environ[SELECTOR]))
