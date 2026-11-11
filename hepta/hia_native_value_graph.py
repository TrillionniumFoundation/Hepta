"""Lossless, instruction-independent native object transport.

Ordinary nodes use the existing typed-tree representation. Native output can
also reference an original input node, or concatenate original input arrays.
Those encodings preserve large repeated arrays without repeating their string
bytes on the wire. An append-only private pool also holds complete values from
earlier native owners. This module makes no opcode, type or ownership choice.
"""
from __future__ import annotations

import math
import struct

MAX_NODES = 8388608
MAX_DEPTH = 128
MAX_EXPANDED_ELEMENTS = 262144 * 512


def _external_height(root):
    """Validate one held JSON graph without copying or expanding its aliases."""
    active, heights = set(), {}

    def visit(value, depth):
        kind = type(value)
        if value is None or kind in (bool, int, str):
            return 0
        if kind is float:
            if not math.isfinite(value):
                raise ValueError('native external value float is not finite')
            return 0
        if kind not in (list, dict) and not (kind is tuple and depth == 0):
            raise ValueError('native external value is not an exact JSON value')
        identity = id(value)
        if identity in active:
            raise ValueError('native external value graph contains a cycle')
        if identity in heights:
            height = heights[identity]
            if depth + height > MAX_DEPTH:
                raise ValueError('native external value depth differs')
            return height
        if depth >= MAX_DEPTH:
            raise ValueError('native external value depth differs')
        active.add(identity)
        height = 1
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise ValueError('native external value has a non-string key')
            children = value.values()
        else:
            children = value
        for child in children:
            height = max(height, 1 + visit(child, depth + 1))
        active.remove(identity)
        heights[identity] = height
        return height

    return visit(root, 0)


class NativeValuePool:
    """Append-only custody of complete, already held JSON values.

    ``add`` validates representation once and returns an opaque transport ID.
    JSON values retain their identities. An exact outer tuple is also accepted
    as an immutable array snapshot; a reference materializes only its outer
    list. The private owner must not mutate held JSON containers after adding
    them; freeze an outer list/dict before adding when later changes are needed.
    This avoids deep-copying previously produced large Core arrays. IDs carry
    no opcode, type or dispatch policy.
    """
    def __init__(self):
        self._values = []
        self._heights = []

    def add(self, value):
        height = _external_height(value)
        identifier = len(self._values)
        self._values.append(value)
        self._heights.append(height)
        return identifier

    def __len__(self):
        return len(self._values)

    def get(self, identifier):
        if type(identifier) is not int or not 0 <= identifier < len(self._values):
            raise ValueError('native external reference is outside the held pool')
        return self._values[identifier]


def _index(raw, *, references=False):
    if type(raw) is not bytes:
        raise ValueError('native object arena must contain exact bytes')
    nodes = {}
    frames = [[len(raw), 1]]
    at = 0
    while frames:
        stop, remaining = frames[-1]
        if not remaining:
            if at != stop:
                raise ValueError('native object container extent differs')
            frames.pop()
            continue
        if at > stop or stop - at < 16:
            raise ValueError('native object node header is truncated')
        kind, size = struct.unpack_from('<2Q', raw, at)
        if kind > (11 if references else 7) or size > stop - at - 16:
            raise ValueError('native object node extent/kind differs')
        end = at + 16 + size
        frames[-1][1] -= 1
        nodes[at] = (kind, size, end)
        if len(nodes) > MAX_NODES:
            raise ValueError('native object node budget exceeded')
        if kind in (5, 6):
            if size < 8 or len(frames) >= MAX_DEPTH + 1:
                raise ValueError('native object container/depth differs')
            count, = struct.unpack_from('<Q', raw, at + 16)
            children = count * (2 if kind == 6 else 1)
            if children > MAX_NODES:
                raise ValueError('native object child budget exceeded')
            frames.append([end, children])
            at += 24
        else:
            if ((kind in (0, 7) and size) or
                    (kind == 1 and (size != 1 or raw[at + 16] > 1)) or
                    (kind in (8, 10) and size != 8) or
                    (kind in (9, 11) and (size < 8 or size % 8))):
                raise ValueError('native object scalar/reference extent differs')
            if kind in (9, 11):
                count, = struct.unpack_from('<Q', raw, at + 16)
                if count > MAX_NODES or size != 8 + count * 8:
                    raise ValueError('native object concatenation extent differs')
            at = end
    if at != len(raw):
        raise ValueError('native object arena has trailing bytes')
    return nodes


def decode_native_graph(encoded, original, external=()):
    """Decode a complete native-produced object; original bytes are immutable.

    Tag 8 contains one u64 original-node offset. Tag 9 contains a u64 count
    followed by that many original-array offsets. Original nodes cannot hold
    references, so the graph is acyclic. Referenced data is decoded from held
    immutable bytes into ordinary Python JSON values. Repeated references may
    share decoder-owned containers; no caller-owned Python object is reused.
    Tag 10 references a complete held external value by pool ID; tag 11
    concatenates held external arrays. A NativeValuePool validates stable
    private entries on insertion. Exact tuple/list pools validate referenced
    entries on each decode. External references reuse caller-held identities;
    freeze outer collections before pooling if they will otherwise be mutated.
    An exact outer tuple is an array snapshot: references materialize a fresh
    outer list while retaining its child identities. Nested tuples are not
    JSON values. All concatenations create fresh outer lists. Existing external elements
    are not copied or charged again against this invocation's expansion quota.
    Newly materialized arrays are charged, including source concatenations.
    This is a per-decode bound, not an aggregate bound on earlier owners.
    """
    source_nodes = _index(original)
    output_nodes = _index(encoded, references=True)
    if type(external) not in (tuple, list, NativeValuePool):
        raise ValueError('native external pool must be a held exact sequence')
    cache = {}
    external_cache = {}
    expanded = 0

    def charge(amount):
        nonlocal expanded
        if amount > MAX_EXPANDED_ELEMENTS - expanded:
            raise ValueError('native object expanded-element budget exceeded')
        expanded += amount

    def source(offset):
        if offset not in source_nodes:
            raise ValueError('native object reference is not an original node')
        if offset not in cache:
            cache[offset] = decode(original, source_nodes, offset, False)
        return cache[offset]

    def pooled(identifier, depth):
        if identifier >= len(external):
            raise ValueError('native external reference is outside the held pool')
        if type(external) is NativeValuePool:
            value, height = external.get(identifier), external._heights[identifier]
        else:
            if identifier not in external_cache:
                value = external[identifier]
                external_cache[identifier] = (value, _external_height(value))
            value, height = external_cache[identifier]
        if depth + height > MAX_DEPTH:
            raise ValueError('native external value depth differs')
        return value

    def decode(raw, nodes, offset, output, depth=0):
        kind, size, end = nodes[offset]
        payload = raw[offset + 16:end]
        if kind == 0:
            return None
        if kind == 1:
            return payload == b'\x01'
        if kind == 2:
            value = int(payload.decode('ascii'))
            if str(value).encode('ascii') != payload:
                raise ValueError('native object integer is not canonical')
            return value
        if kind == 3:
            value = float(payload.decode('ascii'))
            if not math.isfinite(value):
                raise ValueError('native object float is not finite')
            return value
        if kind == 4:
            return payload.decode('utf-8', 'surrogatepass')
        if kind == 8:
            return source(struct.unpack('<Q', payload)[0])
        if kind == 9:
            count, = struct.unpack_from('<Q', payload)
            result = []
            for index in range(count):
                target, = struct.unpack_from('<Q', payload, 8 + index * 8)
                if target not in source_nodes or source_nodes[target][0] != 5:
                    raise ValueError('native object concatenation needs original arrays')
                values = source(target)
                charge(len(values))
                result.extend(values)
            return result
        if kind == 10:
            value = pooled(struct.unpack('<Q', payload)[0], depth)
            if type(value) is tuple:
                charge(len(value))
                return list(value)
            return value
        if kind == 11:
            count, = struct.unpack_from('<Q', payload)
            result = []
            for index in range(count):
                identifier, = struct.unpack_from('<Q', payload, 8 + index * 8)
                values = pooled(identifier, depth)
                if type(values) not in (list, tuple):
                    raise ValueError('native external concatenation needs held arrays')
                charge(len(values))
                result.extend(values)
            return result
        if kind not in (5, 6):
            raise ValueError('native object contains an opaque host value')
        count, = struct.unpack_from('<Q', payload)
        charge(count)
        cursor = offset + 24
        if kind == 5:
            result = []
            for _ in range(count):
                result.append(decode(raw, nodes, cursor, output, depth + 1))
                cursor = nodes[cursor][2]
            return result
        result = {}
        for _ in range(count):
            key = decode(raw, nodes, cursor, output, depth + 1)
            cursor = nodes[cursor][2]
            if type(key) is not str or key in result:
                raise ValueError('native object has a duplicate/non-string key')
            result[key] = decode(raw, nodes, cursor, output, depth + 1)
            cursor = nodes[cursor][2]
        return result

    return decode(encoded, output_nodes, 0, True)
