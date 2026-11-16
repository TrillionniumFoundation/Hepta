"""Explicit source-bound HIA div/rem image; no default interpreter selection.

The component is a mathematical VM slice, not a replacement VM or a sandbox.
Mapping requires an operator-supplied full manifest digest. Every call reads
the same complete component closure, source, manifest and image again. Old
worker bundles have no implicit registration for this new executable.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import threading

from .hia_native_admission_io import regular_bytes, resolve_path, source_resource_path
from .hia_native_delivery import (NativeCall, NativeDeliveryUnknown,
    bind_resource_lifetime, check_resource_retirement, check_current)
from .hia_json_preflight_native import NativeHiaJsonImage
from . import hia_native_helpers
from . import hia_vm_integer_divrem_protocol as wire

_LIMIT = 1 << 20
_GUARD = b"DIVREM-CANARY-v1!"
_NONCE_LOCK = threading.RLock()
_NONCE_PID = os.getpid()
_NONCE_SERIAL = 0


def _after_fork():
    global _NONCE_LOCK, _NONCE_PID, _NONCE_SERIAL
    _NONCE_LOCK = threading.RLock()
    _NONCE_PID, _NONCE_SERIAL = os.getpid(), 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _nonce():
    global _NONCE_SERIAL
    pid = os.getpid()
    with _NONCE_LOCK:
        if pid != _NONCE_PID or not 0 < pid < (1 << 32):
            raise ValueError("div/rem nonce process identity differs")
        if _NONCE_SERIAL == (1 << 32) - 1:
            raise OverflowError("div/rem process nonce domain is exhausted")
        _NONCE_SERIAL += 1
        return (pid << 32) | _NONCE_SERIAL


def _digest(value):
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate div/rem manifest field")
        result[name] = value
    return result


def _input_path(name):
    # Python inputs are the actually imported package files, not mirrored data.
    # HIA resources use the existing checkout/installed resource resolver.
    if name.startswith("hepta/") and name.endswith(".py"):
        return Path(__file__).parent / name[len("hepta/"):]
    return source_resource_path(__file__, name)


def _scope(path, source):
    # Existing scope guards run before executable mapping. There is currently
    # no registered worker-helper entry for this standalone explicit component.
    pinned = hia_native_helpers.pinned_image(path, source, wire.SCHEMA,
        NativeDivRemImage, _admission_resolver=resolve_path)
    if pinned is not None:
        raise ValueError("div/rem worker bundle registration is not implemented")


class NativeDivRemUnknown(NativeDeliveryUnknown):
    """A real selected div/rem call has no complete current invocation ACK."""


class NativeDivRemImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        address = ctypes.cast(self._entry, ctypes.c_void_p).value
        # Fixed private buffers contain no Python object pointers. Keep the
        # GIL through this bounded call so the original VM state stays hosted.
        self._entry = ctypes.PYFUNCTYPE(ctypes.c_uint64,
            *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)


class NativeDivRemBinding:
    """One explicit process/thread-owned source authority; calls are fresh."""
    def __init__(self, manifest_path, expected_manifest_sha256):
        if not _digest(expected_manifest_sha256):
            raise ValueError("div/rem requires an explicit full manifest SHA256")
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.path = resolve_path(manifest_path, strict=True)
        self.source = _input_path(wire.SOURCE_NAME)
        self.expected_manifest_sha256 = expected_manifest_sha256
        self._busy = False
        self._loss = None
        self.native_returns = self.acknowledgements = 0
        _scope(self.path, self.source)
        raw = regular_bytes(self.path, 65536)
        if sha256(raw).hexdigest() != expected_manifest_sha256:
            raise ValueError("div/rem manifest differs from explicit authority")
        record = json.JSONDecoder(object_pairs_hook=_pairs).decode(raw.decode("utf-8"))
        if (type(record) is not dict or set(record) != {
                "schema", "source_sha256", "image_path", "image_sha256",
                "compiler_sha256", "component_inputs", "scope"}
                or record["schema"] != wire.SCHEMA
                or record["image_path"] != wire.IMAGE_NAME
                or record["scope"] not in (
                    "DEVELOPMENT_COMPONENT", "MATCHING_SOURCE_COLD_COMPONENT")
                or any(not _digest(record[key]) for key in
                    ("source_sha256", "image_sha256", "compiler_sha256"))
                or type(record["component_inputs"]) is not dict
                or set(record["component_inputs"]) != set(wire.COMPONENT_INPUTS)
                or any(not _digest(value) for value in record["component_inputs"].values())):
            raise ValueError("div/rem manifest has a different closed schema")
        paths, inputs = [], {}
        for name in wire.COMPONENT_INPUTS:
            path = _input_path(name)
            value = regular_bytes(path, _LIMIT)
            if sha256(value).hexdigest() != record["component_inputs"][name]:
                raise ValueError("div/rem current component source differs: " + name)
            paths.append((path, value))
            inputs[name] = value
        if sha256(inputs[wire.SOURCE_NAME]).hexdigest() != record["source_sha256"]:
            raise ValueError("div/rem HIA source differs")
        image_path = resolve_path(self.path.parent / wire.IMAGE_NAME, strict=True)
        image_raw = regular_bytes(image_path, _LIMIT)
        if sha256(image_raw).hexdigest() != record["image_sha256"]:
            raise ValueError("div/rem executable differs")
        self._captured = tuple([(self.path, raw), *paths, (image_path, image_raw)])
        self._manifest_raw = raw
        self.manifest = record
        self.component_inputs = inputs
        self._stable()
        selected = NativeDivRemImage(image_raw, record["image_sha256"])
        self._stable()
        self.image = selected
        self.image.admitted_source_sha256 = record["source_sha256"]
        bind_resource_lifetime(self, unknown=NativeDivRemUnknown)

    def _context(self):
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise NativeDivRemUnknown("div/rem binding cannot transfer process or thread")
        if self._loss is not None:
            raise NativeDivRemUnknown("this div/rem binding has unconfirmed delivery") from self._loss.error
        check_resource_retirement(self, unknown=NativeDivRemUnknown)
        check_current()
        _scope(self.path, self.source)

    def _stable(self):
        for path, raw in self._captured:
            if regular_bytes(path, _LIMIT) != raw:
                raise ValueError("div/rem captured source, manifest or image changed")
        if sha256(self._manifest_raw).hexdigest() != self.expected_manifest_sha256:
            raise ValueError("div/rem manifest authority changed")

    def check(self):
        self._context()
        self._stable()

    def evaluate(self, operation, typ, lhs, rhs, *, vm_owner=None):
        """Return the complete HIA status/value; no Python arithmetic fallback."""
        self._context()
        if self._busy:
            raise ValueError("div/rem binding is already in an invocation")
        self._busy = True
        try:
            self._stable()
            raw = wire.request(operation, typ, lhs, rhs, _nonce())
            source = ctypes.create_string_buffer(raw + _GUARD, wire.REQUEST_BYTES + len(_GUARD))
            output = ctypes.create_string_buffer(b"\xa5" * wire.REPLY_BYTES + _GUARD,
                                                 wire.REPLY_BYTES + len(_GUARD))
            workspace = ctypes.create_string_buffer(_GUARD, len(_GUARD))
            if (ctypes.sizeof(source) != wire.REQUEST_BYTES + len(_GUARD)
                    or ctypes.sizeof(output) != wire.REPLY_BYTES + len(_GUARD)
                    or ctypes.sizeof(workspace) != len(_GUARD)):
                raise ValueError("div/rem private buffer capacities differ")
            entry = self.image._entry
            call_arguments = (source, wire.REQUEST_BYTES, output, wire.REPLY_BYTES, workspace, 0)
            next_returns = self.native_returns + 1
            next_acknowledgements = self.acknowledgements + 1
            with NativeCall((self, vm_owner, raw, source, output, workspace)) as record:
                record.associate(self, unknown=NativeDivRemUnknown)
                try:
                    self._context()
                    record.check(NativeDivRemUnknown)
                    # Every argument object and target has already been captured.
                    record.enter_native()
                    written = entry(*call_arguments)
                    self.native_returns = next_returns
                    if (source.raw != raw + _GUARD
                            or output.raw[wire.REPLY_BYTES:] != _GUARD
                            or workspace.raw != _GUARD):
                        raise ValueError("div/rem native call changed a guarded extent")
                    decoded = wire.reply(raw, output.raw[:wire.REPLY_BYTES], written)
                    # Complete result construction and all final custody/source
                    # checks precede terminal confirmation, even for trap status.
                    self._stable()
                    self._context()
                    result = (decoded["status"], decoded["value"])
                    record.check(NativeDivRemUnknown)
                    self.acknowledgements = next_acknowledgements
                    record.confirmed(terminal=True)
                    return result
                except BaseException as error:
                    record.failed(error)
                    if record.loss is not None:
                        self._loss = record.loss
                    record.propagate(error, NativeDivRemUnknown,
                                     (ValueError, TypeError, OSError, OverflowError))
                    raise
        finally:
            self._busy = False
