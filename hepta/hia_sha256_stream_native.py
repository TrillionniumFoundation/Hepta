"""Operator-selected HIA incremental SHA-256; Python owns buffers, not hashing."""
from __future__ import annotations
import ctypes
from pathlib import Path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/sha256_stream.hiaasm'
SCHEMA = 'hepta.hia.sha256-stream-native.v1'
STATE_BYTES = 1184
MAX_CHUNK = 8 << 20
MAX_TOTAL = (1 << 61) - 1


class NativeSha256Stream(NativeHiaJsonImage):
    def new(self, wire: bytes = b'') -> Sha256State:
        return Sha256State(self, wire)

    def digest(self, wire: bytes) -> bytes:
        return self.new(wire).digest()


class Sha256State:
    """An independent mutable stream; concurrent access to ONE state is unsupported.

    digest()/copy() leave the original stream reusable. Native state has no
    executable pointers. The state is private, not an authenticated checkpoint.
    """
    def __init__(self, image: NativeSha256Stream, wire: bytes = b''):
        self._image = image
        self._state = ctypes.create_string_buffer(STATE_BYTES)
        self._call(b'\x00', 0)
        self.update(wire)

    def _call(self, command: bytes, expected: int) -> bytes:
        source = ctypes.create_string_buffer(command, len(command))
        output = ctypes.create_string_buffer(32)
        result = self._image._entry(source, len(command), output, 32, self._state, STATE_BYTES)
        if result != expected:
            raise ValueError('native HIA SHA-256 stream rejected transition')
        return output.raw

    def update(self, wire: bytes) -> None:
        if type(wire) is not bytes:
            raise TypeError('HIA SHA-256 streams require bytes')
        # The high-level call is atomic for length refusals even if wire would
        # otherwise be split into several native transitions.
        total = int.from_bytes(self._state.raw[1088:1096], 'little')
        if len(wire) > MAX_TOTAL - total:
            raise ValueError('SHA-256 bit length exceeds the 64-bit standard')
        for offset in range(0, len(wire), MAX_CHUNK):
            self._call(b'\x01' + wire[offset:offset + MAX_CHUNK], 0)

    def copy(self) -> Sha256State:
        other = object.__new__(type(self))
        other._image = self._image
        other._state = ctypes.create_string_buffer(self._state.raw, STATE_BYTES)
        return other

    def digest(self) -> bytes:
        return self.copy()._call(b'\x02', 32)

    def hexdigest(self) -> str:
        return self.digest().hex()


def installed_stream_hasher(manifest_path: str) -> NativeSha256Stream:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeSha256Stream)
