"""Fixed byte/buffer transport for the HIA retained ObjectToken renderer.

No JSON payload parser, object-token decoder, nominal type or source-tree
materializer is used here. All dynamic protocol state lives in the HIA image.
"""
from __future__ import annotations

import ctypes
import mmap
import struct
import sys
from threading import RLock

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_tokens.hepta')
SCHEMA = 'hepta.hia.nominal-tokens-native.v1'
REQUEST_MAGIC = int.from_bytes(b'HIANTK01', 'little')
REPLY_MAGIC = int.from_bytes(b'HIANTR01', 'little')
HEADER = struct.Struct('<8Q')
MAX_ADDRESS = min(sys.maxsize, (1 << 63) - 1)


class NominalTokensProtocolError(RuntimeError):
    """The retained native stream or fixed transport contract refused."""


def _mapping(size):
    return mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)


def _address(mapping):
    # The temporary ctypes export is destroyed before a mapping can be closed,
    # including on an exception traceback. Mappings themselves retain storage.
    return ctypes.addressof(ctypes.c_char.from_buffer(mapping))


class NativeNominalTokens(NativeHiaJsonImage):
    def session(self):
        return NominalTokensSession(self)


class NominalTokensSession:
    """One source snapshot, retained dictionaries and one active native stream."""

    def __init__(self, image):
        self.image = image
        self._lock = RLock()
        self._workspace = self._output = None
        self._broken = self._closed = False
        self._source_wire = None
        self.sequence = self.token_count = 0
        self.final = False
        self.root_kind = None
        try:
            self._workspace = _mapping(4096)
            self._output = _mapping(4096)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        self._live()
        return self

    def __exit__(self, *_):
        self.close()

    def _live(self):
        if self._closed or self._broken:
            raise NominalTokensProtocolError('nominal token session is closed or poisoned')

    def _refuse(self, message):
        self._broken = True
        raise NominalTokensProtocolError(message)

    def _word(self, value):
        if type(value) is not int or not 0 <= value < 1 << 64:
            self._refuse('stream identity must contain exact unsigned 64-bit integers')
        return value

    def _bytes(self, value):
        if type(value) is not bytes:
            self._refuse('native token transport requires exact immutable bytes')
        return value

    def _grow(self, attribute, required):
        previous = getattr(self, attribute)
        if not len(previous) < required <= MAX_ADDRESS:
            self._refuse('native capacity retry did not request a larger addressable mapping')
        capacity = max(required, min(MAX_ADDRESS, len(previous) * 2))
        fresh = _mapping(capacity)
        try:
            if attribute == '_workspace':
                ctypes.memmove(_address(fresh), _address(previous), len(previous))
        except BaseException:
            fresh.close()
            raise
        setattr(self, attribute, fresh)
        previous.close()

    def _invoke(self, operation, payload=b'', identity=(0, 0, 0, 0, 0)):
        with self._lock:
            return self._invoke_locked(operation, payload, identity)

    def _invoke_locked(self, operation, payload, identity):
        self._live()
        payload = self._bytes(payload)
        identity = tuple(self._word(value) for value in identity)
        wire = HEADER.pack(REQUEST_MAGIC, operation, *identity, len(payload)) + payload
        source = ctypes.create_string_buffer(wire, len(wire))
        try:
            while True:
                result = self.image._entry(source, len(wire), _address(self._output), len(self._output),
                                           _address(self._workspace), len(self._workspace))
                if type(result) is not int or result != HEADER.size:
                    self._refuse('native token return is not a complete zero-extended 64-byte reply')
                if memoryview(source).cast('B') != wire:
                    self._refuse('native token invocation changed its immutable request bytes')
                reply = HEADER.unpack_from(self._output)
                magic, status, final, sequence, workspace, output, tokens, kind = reply
                if magic != REPLY_MAGIC or status not in (0, 1, 2, 3) or final not in (0, 1):
                    self._refuse('native token reply has invalid fixed fields')
                if status == 3:
                    self._refuse('HIA rejected the typed source, object stream or retained identity')
                if status == 1:
                    self._grow('_workspace', workspace)
                    continue
                if status == 2:
                    if operation not in (3, 6):
                        self._refuse('output capacity request came from a non-serialization operation')
                    self._grow('_output', output)
                    continue
                if kind not in (0, 1, 2, 4, 5, 6, (1 << 64) - 1):
                    self._refuse('native token root has no admitted transport kind')
                self.sequence, self.token_count = sequence, tokens
                self.final = bool(final)
                self.root_kind = None if kind == (1 << 64) - 1 else kind
                if operation in (3, 6):
                    if final != 1 or not HEADER.size < output <= len(self._output):
                        self._refuse('native serialized result has an invalid publication extent')
                    return self._output[HEADER.size:output]
                return self.final
        except BaseException:
            self._broken = True
            raise

    def begin(self, source_wire, stream_magic, action, *, serial=0, slots=0, request=0):
        with self._lock:
            self._live()
            source_wire = self._bytes(source_wire)
            if self._source_wire is not None:
                self._refuse('source snapshot has already been admitted')
            self._invoke(1, source_wire, (stream_magic, action, serial, slots, request))
            self._source_wire = source_wire
        return self

    def feed(self, frame):
        return self._invoke(2, frame)

    def canonical(self):
        return self._invoke(3)

    def packet(self):
        """Return exact typed transport bytes, preserving dictionary insertion order."""
        return self._invoke(6)

    def restart(self, stream_magic, action, *, serial=0, slots=0, request=0):
        self._invoke(4, identity=(stream_magic, action, serial, slots, request))
        return self

    def seal(self, handle):
        self._invoke(5, identity=(handle, 0, 0, 0, 0))

    def close(self):
        with self._lock:
            self._closed = True
            self._source_wire = None
            for attribute in ('_output', '_workspace'):
                mapping = getattr(self, attribute, None)
                setattr(self, attribute, None)
                if mapping is not None:
                    mapping.close()


def installed_nominal_tokens(manifest_path):
    return _installed_json_image(str(manifest_path), SOURCE, SCHEMA, NativeNominalTokens)
