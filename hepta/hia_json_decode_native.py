"""HIA-produced JSON value arena with a foreign Python-object bridge.

The HIA image performs syntax, budget, Unicode, key and hierarchy decoding.
Python still loads trusted code, allocates buffers, and materializes foreign
objects (including arbitrary precision integers). This is not a HIA runtime,
an executable sandbox, a release promotion or an all-input refinement proof.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, scratch_sizes, MAX_BYTES, MAX_NODES, MAX_DEPTH

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/json_decode.hepta')
SCHEMA = 'hepta.hia.json-decode-native.v1'
MAGIC = 5208772604367785521
NONE = (1 << 64) - 1
HEADER = struct.Struct('<8Q')
RECORD = struct.Struct('<7Q')


def arena_sizes(size: int, maximum: int, depth: int) -> tuple[int, int]:
    keys, _ = scratch_sizes(size, maximum, depth)
    # Every valid N-node JSON wire needs at least 2*N-1 bytes. This is only
    # an allocation upper bound; the HIA parser counts actual nodes first.
    bound = min(maximum, (size + 1) // 2 + 1)
    output = max(128 + (depth + 1) * 32, 64 + bound * 56 + size)
    return output, max(keys, 128 + (depth + 1) * 48)


class NativeJsonDecoder(NativeHiaJsonImage):
    """Same three-buffer native ABI, distinct image and result protocol."""

    def arena(self, wire: bytes, *, max_nodes: int, max_depth: int) -> bytes:
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(max_nodes) is not int or not 1 <= max_nodes <= MAX_NODES
                or type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH):
            raise ValueError('outside native HIA JSON decoder profile')
        output_size, workspace_size = arena_sizes(len(wire), max_nodes, max_depth)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        struct.pack_into('<QQ', workspace, 48, max_nodes, max_depth)
        result = self._entry(source, len(wire), output, output_size, workspace, workspace_size)
        if result == 0xfffffffe:
            raise OverflowError('HIA JSON exceeds node/depth budget before decoding')
        if result == 0xfffffffc:
            raise ValueError('HIA JSON decoder: duplicate decoded object key')
        if result == 0xffffffff:
            raise ValueError('HIA JSON decoder: invalid JSON syntax or Unicode')
        if result == 0xfffffffd:
            raise RuntimeError('native HIA JSON decoder rejected its scratch profile')
        if not 64 <= result <= output_size:
            raise RuntimeError('invalid native HIA JSON decoder return')
        return output.raw[:result]

    def decode(self, wire: bytes, *, max_nodes: int, max_depth: int,
               object_pairs_hook=None, parse_int=None):
        arena = self.arena(wire, max_nodes=max_nodes, max_depth=max_depth)
        return materialize(arena, wire, object_pairs_hook=object_pairs_hook, parse_int=parse_int)


def materialize(arena: bytes, wire: bytes, *, object_pairs_hook=None, parse_int=None):
    """Translate an already decoded immutable arena, not JSON syntax.

    Check ranges and one-parent tree ownership before exposing foreign objects.
    No stdlib JSON decoder/tokenizer is used in this bridge.
    """
    def invalid():
        raise ValueError('invalid HIA JSON value arena')

    if type(arena) is not bytes or len(arena) < 64 or type(wire) is not bytes:
        invalid()
    magic, count, base, end, used, size, version, reserved = HEADER.unpack_from(arena)
    if (magic != MAGIC or not 1 <= count <= MAX_NODES or base != 64 + count * 56
            or not base <= end == used == len(arena) or size != len(wire)
            or version != 1 or reserved != 0):
        invalid()
    rows = [RECORD.unpack_from(arena, 64 + i * 56) for i in range(count)]
    if rows[0][1:3] != (NONE, NONE):
        invalid()
    linked = bytearray(count)
    linked[0] = 1
    children = {}
    for i, (kind, parent, sibling, start, length, key, key_size) in enumerate(rows):
        if kind > 6 or (i and not parent < i) or (sibling != NONE and not i < sibling < count):
            invalid()
        if kind in (5, 6):
            if length > count:
                invalid()
            child = start
            chain = []
            for _ in range(length):
                if not i < child < count or linked[child] or rows[child][1] != i:
                    invalid()
                linked[child] = 1
                chain.append(child)
                child = rows[child][2]
            if child != NONE:
                invalid()
            children[i] = chain
        elif kind == 4:
            if not base <= start <= end or length > end - start:
                invalid()
        elif kind == 3:
            if start > len(wire) or not 1 <= length <= len(wire) - start:
                invalid()
        if i and rows[parent][0] == 6:
            if not base <= key <= end or key_size > end - key:
                invalid()
        elif key or key_size:
            invalid()
    if 0 in linked:
        invalid()
    values = [None] * count
    integer = int if parse_int is None else parse_int
    # Match the stdlib's source-order, children-before-parent callback order.
    # Reversing a preorder arena alone would reverse sibling hook side effects.
    pending = [(0, False)]
    order = []
    while pending:
        node, exiting = pending.pop()
        if exiting:
            order.append(node)
        else:
            pending.append((node, True))
            pending.extend((child, False) for child in reversed(children.get(node, ())))
    for i in order:
        kind, _, _, start, length, _, _ = rows[i]
        if kind < 3:
            value = (None, False, True)[kind]
        elif kind == 3:
            value = integer(wire[start:start + length].decode('ascii'))
        elif kind == 4:
            value = arena[start:start + length].decode('utf-8')
        elif kind == 5:
            value = [values[c] for c in children[i]]
        else:
            pairs = [(arena[rows[c][5]:rows[c][5] + rows[c][6]].decode('utf-8'), values[c])
                     for c in children[i]]
            if len({key for key, _ in pairs}) != len(pairs):
                invalid()
            value = dict(pairs) if object_pairs_hook is None else object_pairs_hook(pairs)
        values[i] = value
    return values[0]


def installed_decoder(manifest_path: str) -> NativeJsonDecoder:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeJsonDecoder)
