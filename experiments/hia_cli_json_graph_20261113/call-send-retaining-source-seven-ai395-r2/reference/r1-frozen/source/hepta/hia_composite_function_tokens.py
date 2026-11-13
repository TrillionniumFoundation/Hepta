"""Generic native object-token materialization; no nominal language decisions.

The native owner chooses every container, scalar and immutable source reference.
Source references address a detached, losslessly decoded input packet. A stream
has no total size ceiling; its native producer uses bounded chunks. This codec
does not admit Core programs or provide execution authority.
"""
from __future__ import annotations

import struct


class TokenProtocolError(ValueError):
    pass


def detached_packet_index(wire):
    """Decode generic typed transport and index exact node offsets.

    This is a custody copy, independent of the mutable Python objects originally
    encoded by transport(). Repeated scalar strings share a bounded intern table.
    The native initializer independently checks its own packet representation.
    """
    if type(wire) is not bytes:
        raise TokenProtocolError('packet is not exact bytes')
    index, strings = {}, {}
    # Frames hold end offset, remaining child count, object, and pending key.
    frames = []
    root = None
    have_root = False
    at = 0
    while at < len(wire) or frames:
        if frames and frames[-1][1] == 0:
            if at != frames[-1][0] or frames[-1][3] is not None:
                raise TokenProtocolError('inconsistent completed packet container')
            frames.pop()
            continue
        if at > len(wire) - 16:
            raise TokenProtocolError('truncated packet node')
        start = at
        kind, size = struct.unpack_from('<QQ', wire, at)
        at += 16
        stop = at + size
        if stop > len(wire) or (frames and stop > frames[-1][0]):
            raise TokenProtocolError('packet node crosses its parent')
        children = 0
        if kind == 0:
            if size:
                raise TokenProtocolError('nonempty null packet node')
            value = None
        elif kind == 1:
            if size != 1 or wire[at] > 1:
                raise TokenProtocolError('invalid boolean packet node')
            value = bool(wire[at])
        elif kind == 2:
            try:
                text = wire[at:stop].decode('ascii')
                value = int(text)
            except (ValueError, UnicodeError) as exc:
                raise TokenProtocolError('invalid integer packet node') from exc
            if str(value) != text:
                raise TokenProtocolError('noncanonical integer packet node')
        elif kind == 4:
            try:
                value = wire[at:stop].decode('utf-8', errors='surrogatepass')
            except UnicodeError as exc:
                raise TokenProtocolError('invalid string packet node') from exc
            if len(strings) < 262144:
                value = strings.setdefault(value, value)
        elif kind in (5, 6):
            if size < 8:
                raise TokenProtocolError('truncated packet container')
            children = struct.unpack_from('<Q', wire, at)[0]
            if kind == 6:
                children *= 2
            if children > (size - 8) // 16:
                raise TokenProtocolError('impossible packet child count')
            value = [] if kind == 5 else {}
            at += 8
        else:
            raise TokenProtocolError('unsupported exact packet scalar')
        index[start] = value
        if frames:
            frame = frames[-1]
            frame[1] -= 1
            if type(frame[2]) is list:
                frame[2].append(value)
            elif frame[3] is None:
                if type(value) is not str or value in frame[2]:
                    raise TokenProtocolError('invalid or repeated packet dictionary key')
                frame[3] = value
            else:
                frame[2][frame[3]] = value
                frame[3] = None
        elif have_root:
            raise TokenProtocolError('multiple packet roots')
        else:
            root, have_root = value, True
        if kind in (5, 6):
            frames.append([stop, children, value, None])
        else:
            at = stop
    if not have_root or at != len(wire):
        raise TokenProtocolError('missing or incomplete packet root')
    return root, index


class ObjectTokenDecoder:
    """Incrementally materialize generic scalar/list/map tokens exactly once."""

    def __init__(self, source_index):
        self.source_index = source_index
        self.frames = []
        self.strings = {}
        self.root = None
        self.have_root = False
        self.complete = False
        self.failed = False
        self.token_count = 0

    def _put(self, value):
        if self.frames:
            frame = self.frames[-1]
            if frame[1] <= 0:
                raise TokenProtocolError('token exceeds container arity')
            frame[1] -= 1
            if type(frame[0]) is list:
                frame[0].append(value)
            elif frame[2] is None:
                if type(value) is not str or value in frame[0]:
                    raise TokenProtocolError('invalid or repeated token dictionary key')
                frame[2] = value
            else:
                frame[0][frame[2]] = value
                frame[2] = None
        elif self.have_root:
            raise TokenProtocolError('token after complete root')
        else:
            self.root, self.have_root = value, True

    def feed(self, payload, *, final=False):
        if self.failed:
            raise TokenProtocolError('token decoder has a failed protocol')
        try:
            return self._feed(payload, final=final)
        except TokenProtocolError:
            self.failed = True
            raise

    def _feed(self, payload, *, final=False):
        if self.complete or type(payload) is not bytes or type(final) is not bool:
            raise TokenProtocolError('invalid or repeated token chunk')
        at = 0
        while at < len(payload):
            if at > len(payload) - 16:
                raise TokenProtocolError('truncated token header')
            kind, value = struct.unpack_from('<QQ', payload, at)
            at += 16
            count = None
            if kind == 0:
                if value not in self.source_index:
                    raise TokenProtocolError('unissued source reference')
                value = self.source_index[value]
            elif kind == 1:
                if value > len(payload) - at:
                    raise TokenProtocolError('truncated native string token')
                raw = payload[at:at + value]
                at += value
                try:
                    value = raw.decode('utf-8')
                except UnicodeError as exc:
                    raise TokenProtocolError('invalid native string token') from exc
                # The complete native owner has at most 8192 generated names
                # and a fixed vocabulary. This is only an allocation cache;
                # an uncached scalar remains accepted with identical content.
                if len(self.strings) < 16384:
                    value = self.strings.setdefault(value, value)
            elif kind == 2:
                pass
            elif kind == 3:
                if value > 1:
                    raise TokenProtocolError('invalid native boolean token')
                value = bool(value)
            elif kind == 4:
                if value:
                    raise TokenProtocolError('nonzero native null token')
                value = None
            elif kind in (5, 6):
                count = value if kind == 5 else 2 * value
                value = [] if kind == 5 else {}
            else:
                raise TokenProtocolError('unknown token kind')
            self._put(value)
            self.token_count += 1
            if count is not None:
                self.frames.append([value, count, None])
            while self.frames and self.frames[-1][1] == 0:
                if self.frames[-1][2] is not None:
                    raise TokenProtocolError('incomplete dictionary pair')
                self.frames.pop()
        if final:
            if not self.have_root or self.frames:
                raise TokenProtocolError('native final chunk has incomplete containers')
            self.complete = True
        return self.root if self.complete else None
