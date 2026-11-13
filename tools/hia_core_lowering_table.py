"""Lossless authoring representation for the fixed HIA-owned control table.

Tokens 0..127 carry 1..128 literal bytes. Tokens 128..255 carry a 3..130-byte
copy followed by a positive little-endian u16 backward distance. Overlap has
ordinary byte-at-a-time copy semantics. No runtime host decompressor is used.
"""
from collections import defaultdict, deque


def compress_table(data):
    if type(data) is not bytes:
        raise TypeError('immutable authoring table required')
    positions = defaultdict(lambda: deque(maxlen=2048))
    out, pending = bytearray(), bytearray()
    offset = 0
    def flush():
        if pending:
            out.append(len(pending) - 1)
            out.extend(pending)
            pending.clear()
    def remember(at):
        if at + 3 <= len(data):
            positions[data[at:at + 3]].append(at)
    while offset < len(data):
        size, distance = 0, 0
        if offset + 3 <= len(data):
            for previous in reversed(positions.get(data[offset:offset + 3], ())):
                delta = offset - previous
                if delta > 65535:
                    continue
                count = 3
                while count < 130 and offset + count < len(data) and data[previous + count] == data[offset + count]:
                    count += 1
                if count > size:
                    size, distance = count, delta
                    if size == 130:
                        break
        if size >= 4:
            flush()
            out.append(128 + size - 3)
            out.extend(distance.to_bytes(2, 'little'))
            for at in range(offset, offset + size):
                remember(at)
            offset += size
        else:
            pending.append(data[offset])
            remember(offset)
            offset += 1
            if len(pending) == 128:
                flush()
    flush()
    return bytes(out)


def reference_expand(encoded):
    """Independent representation-only reference for source controls."""
    result = bytearray()
    position = 0
    while position < len(encoded):
        token = encoded[position]
        position += 1
        if token < 128:
            count = token + 1
            if position + count > len(encoded):
                raise ValueError('truncated table literal')
            result.extend(encoded[position:position + count])
            position += count
        else:
            count = token - 128 + 3
            if position + 2 > len(encoded):
                raise ValueError('truncated table reference')
            distance = int.from_bytes(encoded[position:position + 2], 'little')
            position += 2
            if not 0 < distance <= len(result):
                raise ValueError('invalid table reference')
            for _ in range(count):
                result.append(result[-distance])
    return bytes(result)


BODY = r'''
def expand_policy(o:mutbuf) -> u64:
    source = TABLE_BYTES
    end = TABLE_BYTES + PACKED_BYTES
    target = 0
    while source < end:
        token = byte(o, source)
        source = source + 1
        if token < 128:
            count = token + 1
            if count > end - source or count > TABLE_BYTES - target:
                return ABI
            i = 0
            while i < count:
                store(o, target, byte(o, source))
                source = source + 1
                target = target + 1
                i = i + 1
        else:
            count = token - 128 + 3
            if end - source < 2 or count > TABLE_BYTES - target:
                return ABI
            distance = byte(o, source) | (byte(o, source + 1) << 8)
            source = source + 2
            if distance == 0 or distance > target:
                return ABI
            i = 0
            while i < count:
                store(o, target, byte(o, target - distance))
                target = target + 1
                i = i + 1
    if target != TABLE_BYTES:
        return ABI
    return target
'''
