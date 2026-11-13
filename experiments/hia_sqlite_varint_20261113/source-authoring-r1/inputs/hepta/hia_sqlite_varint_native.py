"""Bounded byte bridge for an explicitly supplied SQLite-varint HIA image.

The Python code moves bytes, validates the raw result and materializes a u64.
It does not inspect continuation bits, calculate varint lengths or call a
retained SQLite codec. No AgentStore selector or SQLite engine hook is enabled.
"""
from __future__ import annotations

import ctypes
import struct

from .hia_json_preflight_native import NativeHiaJsonImage

MAGIC = int.from_bytes(b'HIASVR01', 'little')
DECODE = 1
ENCODE = 2
REFUSE_PROTOCOL = 0xfffffffd
REFUSE_TRUNCATED = 0xfffffffe
REFUSE_CAPACITY = 0xfffffffc
_CANARY = bytes(range(64))
_FILL = 0xa5


class SQLiteVarintProtocolError(RuntimeError):
    pass


class SQLiteVarintTruncated(ValueError):
    pass


class SQLiteVarintCapacity(ValueError):
    pass


class NativeSQLiteVarint(NativeHiaJsonImage):
    """Private buffers for every call; the raw SQLite algorithm is stateless.

    The inherited constructor binds and maps a supplied executable. This small
    development component has no implicit default, manifest search, install
    selection or database authority. Callers must separately qualify its exact
    source/compiler/image before integrating it into a persistence engine.
    """

    def _invoke(self, operation, raw, capacity):
        if type(operation) is not int or operation not in (DECODE, ENCODE):
            raise ValueError('unknown SQLite varint operation')
        if type(raw) is not bytes or type(capacity) is not int:
            raise TypeError('SQLite varint transport requires exact bytes and int')
        if ((operation == DECODE and (len(raw) > 9 or capacity != 8))
                or (operation == ENCODE and (len(raw) != 8 or not 0 <= capacity <= 9))):
            raise ValueError('SQLite varint transport extents differ')
        command = struct.pack('<QQ', MAGIC, operation)
        source_bytes = raw + _CANARY
        output_bytes = bytes([_FILL]) * capacity + _CANARY
        workspace_bytes = command + _CANARY
        source = ctypes.create_string_buffer(source_bytes, len(source_bytes))
        output = ctypes.create_string_buffer(output_bytes, len(output_bytes))
        workspace = ctypes.create_string_buffer(workspace_bytes, len(workspace_bytes))
        status = self._entry(source, len(raw), output, capacity, workspace, len(command))
        observed = output.raw
        if (source.raw != source_bytes or workspace.raw != workspace_bytes
                or observed[capacity:] != _CANARY):
            raise SQLiteVarintProtocolError('SQLite varint buffer custody differs')
        if type(status) is not int:
            raise SQLiteVarintProtocolError('SQLite varint status is not an exact int')
        if status in (REFUSE_PROTOCOL, REFUSE_TRUNCATED, REFUSE_CAPACITY):
            if observed != output_bytes:
                raise SQLiteVarintProtocolError('refused SQLite varint mutated its output')
            if status == REFUSE_TRUNCATED and operation == DECODE:
                raise SQLiteVarintTruncated('SQLite varint ended before its terminal byte')
            if status == REFUSE_CAPACITY and operation == ENCODE:
                raise SQLiteVarintCapacity('SQLite varint output capacity is insufficient')
            raise SQLiteVarintProtocolError('SQLite varint protocol refused')
        if not 1 <= status <= 9:
            raise SQLiteVarintProtocolError('SQLite varint returned an invalid byte count')
        if operation == DECODE:
            if status > len(raw):
                raise SQLiteVarintProtocolError('SQLite varint consumed unprovided bytes')
            return struct.unpack('<Q', observed[:8])[0], status
        if status > capacity or observed[status:capacity] != bytes([_FILL]) * (capacity - status):
            raise SQLiteVarintProtocolError('SQLite varint wrote beyond its returned prefix')
        return observed[:status], status

    def decode_from(self, payload, offset=0):
        """Return the u64 bit pattern and consumed length at an exact offset.

        At most nine bytes are copied. No canonicality condition is imposed:
        original SQLite also accepts a legal value encoded in extra bytes.
        The caller owns exclusion of concurrent mutation of a bytearray.
        """
        if type(payload) not in (bytes, bytearray) or type(offset) is not int:
            raise TypeError('SQLite varint input requires builtin bytes/bytearray and int')
        if not 0 <= offset <= len(payload):
            raise ValueError('SQLite varint offset is outside its input')
        return self._invoke(DECODE, bytes(payload[offset:offset + 9]), 8)

    def encode(self, value):
        if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
            raise ValueError('SQLite varint input must be an exact u64 bit pattern')
        result, _ = self._invoke(ENCODE, struct.pack('<Q', value), 9)
        return result

    def encode_into(self, value, target, offset=0, capacity=None):
        """Write the exact HIA-produced prefix, leaving the remainder intact.

        All public object/range checks precede the native call. No foreign
        callback, pointer ownership or concurrent-mutation contract is inferred
        from accepting a bytearray. SQL integer-to-u64 coercion remains outside.
        """
        if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
            raise ValueError('SQLite varint input must be an exact u64 bit pattern')
        if type(target) is not bytearray or type(offset) is not int:
            raise TypeError('SQLite varint target requires builtin bytearray and int')
        if not 0 <= offset <= len(target):
            raise ValueError('SQLite varint offset is outside its output')
        if capacity is None:
            capacity = len(target) - offset
        if type(capacity) is not int or not 0 <= capacity <= len(target) - offset:
            raise ValueError('SQLite varint target capacity is outside its output')
        # Nine is the format maximum, not a limit on the caller's allocation.
        window = min(capacity, 9)
        result, count = self._invoke(ENCODE, struct.pack('<Q', value), window)
        target[offset:offset + count] = result
        return count
