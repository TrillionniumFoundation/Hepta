"""Compare the path window codec with original JSON/UTF-8 surrogateescape."""
from __future__ import annotations
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import platform
import random
import struct
from tools import generate_hia_native_path_string_codec as author


def get(data, at):
    return struct.unpack_from('<Q', data, at)[0]


def put(data, at, value):
    struct.pack_into('<Q', data, at, value)


def request(mode, raw, *, limit=None, final=0):
    s = bytearray(128 + len(raw))
    s[:8] = b'HIAPCDQ1'
    for at, value in ((8, mode), (16, len(raw)), (24, len(raw) if limit is None else limit), (32, final)):
        put(s, at, value)
    s[128:] = raw
    return s


class Client:
    def __init__(self, image=None):
        self.calls = 0
        if image is None:
            self.image = None
            self.ns = {'length': len, 'byte': lambda b, at: b[at], 'word_load': get,
                       'store': lambda b, at, value: b.__setitem__(at, value & 255)}
            exec(compile('from __future__ import annotations\n' + author.source_program(), '<exact-path-codec-author>', 'exec'), self.ns)
        else:
            from tools.qualify_hia_multiversion_components import Image
            self.image = Image(image)

    def raw(self, raw, on=65536):
        self.calls += 1
        if self.image is None:
            out, work = bytearray(b'\xa5' * on), bytearray(32)
            rc = self.ns['path_string_codec'](raw, out, work)
            return rc, bytes(out)
        out, work = C.create_string_buffer(b'\xa5' * on, on), C.create_string_buffer(32)
        return self.image(bytes(raw), out, work), out.raw

    def call(self, mode, data, *, limit=None, final=0):
        rc, out = self.raw(request(mode, data, limit=limit, final=final))
        assert rc == 0 and out[:8] == b'HIAPCDR1', (rc, out[:128].hex())
        consumed, written, required = (get(out, at) for at in (8, 16, 24))
        assert required == 128 + written and out[32:128] == bytes(96)
        return consumed, out[128:required]

    def filesystem(self, raw, chunk=8192):
        position, pieces = 0, []
        while position < len(raw):
            part = raw[position:position + chunk + 3]
            n, encoded = self.call(1, part, limit=min(chunk, len(part)), final=int(len(part) == len(raw) - position))
            assert 0 < n <= len(part)
            pieces.append(encoded)
            position += n
        return b''.join(pieces)

    def quote(self, raw, chunk=8192):
        result = []
        for at in range(0, len(raw), chunk):
            consumed, encoded = self.call(0, raw[at:at + chunk])
            assert consumed == min(chunk, len(raw) - at)
            result.append(encoded)
        return b''.join(result)


def main():
    p = argparse.ArgumentParser()
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--author', action='store_true')
    modes.add_argument('--image', type=Path)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    client = Client(a.image)
    groups = []
    for value in range(256):
        raw = bytes([value])
        consumed, result = client.call(1, raw, final=1)
        assert consumed == 1 and result == raw.decode('utf-8', 'surrogateescape').encode('utf-8', 'surrogatepass'), value
    groups.append({'name': 'every-single-filesystem-byte', 'comparisons': 256, 'passed': True})
    for value in range(65536):
        raw = value.to_bytes(2, 'little')
        consumed, result = client.call(1, raw, final=1)
        expected = raw.decode('utf-8', 'surrogateescape').encode('utf-8', 'surrogatepass')
        assert consumed == 2 and result == expected, (value, result, expected)
    groups.append({'name': 'every-two-byte-filesystem-sequence', 'comparisons': 65536, 'passed': True})
    text = ''.join(map(chr, range(0x110000)))
    quoted = client.quote(text.encode('utf-8', 'surrogatepass'))
    assert json.loads((b'"' + quoted + b'"').decode('utf-8', 'surrogatepass')) == text
    groups.append({'name': 'all-Unicode-codepoints-including-lone-surrogates-quote-roundtrip', 'codepoints': 0x110000, 'passed': True})
    valid = text[:0xd800] + text[0xe000:]
    raw = valid.encode('utf-8')
    assert client.filesystem(raw) == raw
    groups.append({'name': 'all-Unicode-scalars-filesystem-decode', 'codepoints': len(valid), 'bytes': len(raw), 'passed': True})
    rng = random.Random(481957)
    comparisons = 0
    for i in range(2048):
        raw = rng.randbytes(rng.randrange(0, 129))
        expected = raw.decode('utf-8', 'surrogateescape').encode('utf-8', 'surrogatepass')
        for chunk in (1, 2, 3, 7, 31):
            assert client.filesystem(raw, chunk) == expected, (i, chunk)
            comparisons += 1
    groups.append({'name': 'random-malformed-and-window-boundary-sequences', 'comparisons': comparisons, 'seed': 481957, 'passed': True})
    for text in ('', '\x00\x01\b\f\n\r\t', '"\\/abc', '\ud800\udcff\U0010ffff', '路径\n"\\'):
        raw = text.encode('utf-8', 'surrogatepass')
        for chunk in (1, 2, 3, 7):
            out = client.quote(raw, chunk)
            assert json.loads((b'"' + out + b'"').decode('utf-8', 'surrogatepass')) == text
    groups.append({'name': 'quote-byte-splits-and-control-characters', 'comparisons': 20, 'passed': True})
    source = request(0, b'\x00"\\x')
    _, correct = client.raw(source)
    required = get(correct, 24)
    for extent in (128, 129, required - 1):
        rc, out = client.raw(source, extent)
        assert rc == 1 and get(out, 24) == required and out[128:] == b'\xa5' * (extent - 128)
    rc, out = client.raw(source, required)
    assert rc == 0 and out == correct[:required]
    groups.append({'name': 'exact-output-and-no-partial-short-body', 'comparisons': 4, 'passed': True})
    guards = 0
    for at, number in ((0, 0), (8, 2), (16, 3), (24, 5), (32, 1), (40, 1), (120, 1)):
        changed = bytearray(source)
        put(changed, at, number)
        rc, out = client.raw(changed)
        assert rc == 0xfffffffd and out == b'\xa5' * len(out), (at, rc)
        guards += 1
    for extent in (0, 1, 127):
        rc, out = client.raw(source[:extent])
        assert rc == 0xfffffffd and out == b'\xa5' * len(out)
        guards += 1
    for extent in (0, 1, 127):
        rc, out = client.raw(source, extent)
        assert rc == 0xfffffffd and out == b'\xa5' * len(out)
        guards += 1
    for raw, limit in ((b'', 0), (b'a', 1), (b'abcd', 2)):
        rc, out = client.raw(request(1, raw, limit=limit, final=0))
        assert rc == 0xfffffffd and out == b'\xa5' * len(out)
        guards += 1
    groups.append({'name': 'private-frame-refusal-before-output-write', 'comparisons': guards, 'passed': True})
    root = Path(__file__).resolve().parents[1]
    sources = ('tools/generate_hia_native_path_string_codec.py', 'examples/hia_bootstrap/native_path_string_codec.hepta')
    report = {'schema': 'hepta.hia.native-path-string-codec.qualification.v1',
              'scope': 'development-author-transitions-only' if a.author else 'actual-native-image',
              'native_image_executed': not a.author, 'whole_native_runtime_qualified': False,
              'oracle': platform.python_implementation() + ' ' + platform.python_version(),
              'calls': client.calls, 'groups': groups, 'passed_groups': len(groups), 'failed': 0,
              'source_pins': {s: hashlib.sha256((root / s).read_bytes()).hexdigest() for s in sources}}
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('scope', 'native_image_executed', 'calls', 'passed_groups')}), flush=True)


if __name__ == '__main__':
    main()
