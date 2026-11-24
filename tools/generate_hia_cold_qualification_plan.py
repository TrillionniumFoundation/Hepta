"""Development serializer for immutable HIAQPL01 plans, not a runtime runner."""
import struct

U64 = (1 << 64) - 1


class Plan:
    def __init__(self):
        self.nodes = []
        self.live = set()
        self.available = []
        self.next_id = 1

    def op(self, number, args=(), data=b'', *, output=True, label=''):
        args = tuple(args)
        data = bytes(data)
        if not 1 <= number <= 17 or len(args) > 128 or len(data) > 1 << 20:
            raise ValueError('qualification plan node exceeds its declared wire domain')
        identifier = 0
        if output:
            identifier = self.available.pop() if self.available else self.next_id
            if identifier == self.next_id:
                self.next_id += 1
            if identifier > 4096 or identifier in self.live:
                raise ValueError('qualification live handle domain exhausted')
            self.live.add(identifier)
        raw = struct.pack('<4Q', number, identifier, len(args), len(data))
        raw += struct.pack('<' + 'Q' * len(args), *args) + data
        self.nodes.append((raw, {'operation': number, 'id': identifier, 'args': list(args),
                                 'payload_bytes': len(data), 'label': label}))
        return identifier

    def imported(self, name):
        return self.op(1, data=name.encode('ascii'), label='import:' + name)

    def literal(self, raw, label=''):
        return self.op(2, data=raw, label=label)

    def slice(self, source, offset=0, size=U64, label=''):
        return self.op(3, (source, offset, size), label=label)

    def concat(self, *handles, label=''):
        return self.op(4, handles, label=label)

    def run(self, image, data, *, seconds=20, shared=0, owned=False, passed=(), argv=('child',), label=''):
        encoded = [a.encode('utf-8') if isinstance(a, str) else bytes(a) for a in argv]
        payload = struct.pack('<Q', len(encoded)) + b''.join(struct.pack('<Q', len(a)) + a for a in encoded)
        return self.op(5, (image, data, seconds, shared, int(owned), *passed), payload, label=label)

    def compare(self, first, second, *, different=False, label=''):
        self.op(6, (first, second, int(different)), output=False, label=label)

    def word(self, source, offset, value, *, width=8, mask=U64, label=''):
        self.op(7, (source, offset, width, value & U64, mask), output=False, label=label)

    def shared(self, initial, label=''):
        return self.op(8, (initial,), label=label)

    def fdword(self, source):
        return self.op(9, (source,))

    def length(self, source):
        return self.op(10, (source,))

    def drop(self, *handles):
        if len(handles) != len(set(handles)) or not set(handles) <= self.live:
            raise ValueError('cannot drop missing or repeated handles')
        self.op(11, handles, output=False)
        self.live.difference_update(handles)
        self.available.extend(handles)

    def publish(self, source, name):
        self.op(12, (source,), name.encode('ascii'), output=False, label='publish:' + name)

    def sha256(self, source):
        return self.op(13, (source,))

    def resultpart(self, result, part=1):
        return self.op(14, (result, part))

    def number(self, source, amount, *, subtract=False, offset=0, width=8, maximum=U64):
        return self.op(15, (source, offset, width, int(subtract), amount, maximum))

    def snapshot(self, initial, label=''):
        return self.op(16, (initial,), label=label)

    def allocator_buffer(self, initial, label=''):
        return self.op(17, (initial,), label=label)

    def pack(self):
        if not 1 <= len(self.nodes) <= 65536:
            raise ValueError('qualification plan node inventory outside its domain')
        result = b'HIAQPL01' + struct.pack('<3Q', len(self.nodes), 0, 0)
        result += b''.join(raw for raw, _ in self.nodes)
        if len(result) > 64 << 20:
            raise ValueError('qualification plan exceeds its bounded transport')
        return result

    def describe(self):
        return [row for _, row in self.nodes]
