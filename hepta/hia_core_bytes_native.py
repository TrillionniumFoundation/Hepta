"""Mechanical transport for the native exact-bytes Core prelude.

No JSON decoding, canonical serialization, namespace policy or error text is
computed here. The immutable input is bounded before copying; HIA decides the
original length refusal, the complete UTF-8/preflight/integer ordering and the
published canonical bytes. Typed objects and composite elaboration remain
separate owners.
"""
from __future__ import annotations
import ctypes
import os
from dataclasses import dataclass
import struct
import sys

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_json_decode_native import arena_sizes

SOURCE = _source_resource_path("examples/hia_bootstrap/core_bytes.hepta")
SCHEMA = "hepta.hia.core-bytes-native.v1"
SELECTOR = "HEPTA_HIA_CORE_BYTES_MANIFEST"
REQUEST_MAGIC = int.from_bytes(b"HIACBR01", "little")
RESULT_MAGIC = int.from_bytes(b"HIACBF01", "little")
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 64
FRAMING = 0xfffffffd
ERROR_CODES = {2: "E_HIA_FORMAT", 3: "E_HIA_LIMIT",
               4: "E_HIA_LIMIT", 5: "E_HIA_VERSION_COLLISION"}


@dataclass(frozen=True)
class CoreBytesCapture:
    original_size: int
    prefix: bytes
    digit_limit: int


@dataclass(frozen=True)
class CoreBytesReceipt:
    status: int
    payload: bytes
    nodes: int
    original_size: int
    digit_limit: int
    raw: bytes
    native_executed: bool
    stage: int


@dataclass(frozen=True)
class CompositeCoreBytes:
    """A namespace handoff, never a primitive verification receipt."""
    canonical_bytes: bytes


def capture_bytes(wire: bytes) -> CoreBytesCapture:
    if type(wire) is not bytes:
        raise TypeError("native Core byte transport requires exact immutable bytes")
    # Capture a sufficient bounded prefix and the true original length. This
    # does not decide whether that length is admissible.
    limit = sys.get_int_max_str_digits()
    return CoreBytesCapture(len(wire), wire[:MAX_BYTES + 1], limit)


def scratch_sizes(capture: CoreBytesCapture) -> tuple[int, int]:
    arena, keys = arena_sizes(len(capture.prefix), MAX_NODES, MAX_DEPTH)
    return max(256, 64 + len(capture.prefix), 64 + keys), arena


class NativeCoreBytes(NativeHiaJsonImage):
    def receipt(self, wire: bytes) -> CoreBytesReceipt:
        capture = capture_bytes(wire)
        output_size, workspace_size = scratch_sizes(capture)
        source = ctypes.create_string_buffer(capture.prefix, max(1, len(capture.prefix)))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        struct.pack_into("<8Q", workspace, 0, REQUEST_MAGIC, 1,
                         capture.original_size, capture.digit_limit, 0, 0, 0, 0)
        result = self._entry(source, len(capture.prefix), output, output_size,
                             workspace, workspace_size)
        if source.raw[:len(capture.prefix)] != capture.prefix:
            raise RuntimeError("native Core bytes changed its captured input")
        if type(result) is not int or result == FRAMING or not 64 < result <= output_size:
            raise RuntimeError("native Core bytes private framing or scratch refusal")
        words = struct.unpack("<8Q", output.raw[:64])
        magic, version, status, size, nodes, original_size, digit_limit, stage = words
        if (magic != RESULT_MAGIC or version != 1 or status not in {0, 1, *ERROR_CODES}
                or size != result - 64
                or stage not in {0: {5}, 1: {5}, 2: {1, 2, 3}, 3: {0}, 4: {2}, 5: {4}}.get(status, ())
                or original_size != capture.original_size or digit_limit != capture.digit_limit):
            raise RuntimeError("native Core bytes published frame identity differs")
        if status in (0, 1):
            if not 0 < size <= min(MAX_BYTES, capture.original_size) or not 0 < nodes <= MAX_NODES:
                raise RuntimeError("native Core bytes published canonical bounds differ")
        elif nodes != 0 or not 0 < size <= 192:
            raise RuntimeError("native Core bytes published diagnostic bounds differ")
        raw = bytes(output.raw[:result])
        return CoreBytesReceipt(status, raw[64:], nodes, original_size,
                                digit_limit, raw, True, stage)

    def prepare(self, wire: bytes) -> CoreBytesReceipt:
        from .hia_program import HIAProgramRejected
        receipt = self.receipt(wire)
        if receipt.status in ERROR_CODES:
            try:
                message = receipt.payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RuntimeError("native Core bytes diagnostic is not UTF-8") from error
            raise HIAProgramRejected(message, ERROR_CODES[receipt.status])
        return receipt


class NativeCoreBytesVerifier:
    """Two admitted HIA images; no foreign JSON graph between their calls.

    The composite result is an explicit handoff to the still-existing nominal
    owner. It is not a fallback on a native refusal. This object supplies no
    implicit selector and does not remove the typed-object or execution-plan
    owners from ordinary verification.
    """
    def __init__(self, frontend: NativeCoreBytes, core):
        from .hia_core_admission_native import NativeCoreAdmission
        if not isinstance(frontend, NativeCoreBytes) or not isinstance(core, NativeCoreAdmission):
            raise TypeError("native Core bytes composition requires admitted image interfaces")
        self.frontend = frontend
        self.core = core
        from . import hia_native_helpers as helpers
        self._bundle_identity = helpers.native_helpers_identity()
        self._binding = helpers._ACTIVE

    def _check_custody(self):
        from . import hia_native_helpers as helpers
        identity = helpers.native_helpers_identity()
        if identity != self._bundle_identity or helpers._ACTIVE is not self._binding:
            raise ValueError("native Core bytes composition left its captured helper scope")

    def verify_bytes(self, wire: bytes):
        from .hia_program import VerifiedProgram
        self._check_custody()
        try:
            receipt = self.frontend.prepare(wire)
            if receipt.status == 1:
                return CompositeCoreBytes(receipt.payload)
            self.core.admit(receipt.payload)
            return VerifiedProgram(receipt.payload)
        finally:
            self._check_custody()


def installed_core_bytes(path) -> NativeCoreBytes:
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCoreBytes)


def installed_core_bytes_verifier(path) -> NativeCoreBytesVerifier:
    """Load two standard manifests at the fixed adjacent dependency boundary.

    A selected worker bundle must capture both image factories, both sources
    and both complete five-field manifests before either executable is mapped.
    Standalone explicit selection keeps the ordinary immutable-image loader
    behavior; it does not establish a matching current-source cold result.
    """
    from pathlib import Path
    from .hia_core_admission_native import installed_core_admission
    from . import hia_native_helpers as helpers
    manifest = Path(path).resolve(strict=True)
    before = helpers.native_helpers_identity()
    binding = helpers._ACTIVE
    frontend = installed_core_bytes(str(manifest))
    core = installed_core_admission(str(manifest.parent / "admission-manifest.json"))
    if helpers.native_helpers_identity() != before or helpers._ACTIVE is not binding:
        raise ValueError("native Core bytes dependency scope changed during selection")
    return NativeCoreBytesVerifier(frontend, core)


def selected_core_bytes_verifier() -> NativeCoreBytesVerifier | None:
    """Select the explicit two-image byte owner without an implicit default.

    Present-empty, invalid manifests, scope drift and native refusals propagate.
    The ordinary caller retains the separate nominal elaboration owner when the
    frontend returns its explicit composite namespace handoff.
    """
    if SELECTOR not in os.environ:
        return None
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError("Core bytes manifest selection is empty")
    return installed_core_bytes_verifier(path)
