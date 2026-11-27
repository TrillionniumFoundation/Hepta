"""Complete streaming evidence reads; no product imports or payload cache.

The original capture() limit is unchanged.  An aggregate JSON object is
visited one value at a time; each value retains the original 16 MiB bound.
Every descriptor is established by fresh held-FD reads and complete hashes.
Only the fixed producer's UTF-8 JSON object form is accepted, without a BOM.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

CHUNK_BYTES = 65536
VALUE_BYTES = 16 << 20
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns',
          'st_ctime_ns', 'st_nlink')


def _require(value, message):
    if not value:
        raise AssertionError(message)


def _seven(info):
    return {key: getattr(info, key) for key in FIELDS}


def _pairs(items):
    value = {}
    for key, item in items:
        _require(type(key) is str and key not in value,
                 'duplicate/nonstring JSON key')
        value[key] = item
    return value


def _decode(raw):
    return json.loads(raw, object_pairs_hook=_pairs)


class _Reader:
    def __init__(self, path, expected=None):
        self.path = Path(path)
        _require(self.path.is_absolute() and '..' not in self.path.parts,
                 'absolute fixed path required')
        if expected is not None:
            _require(type(expected) is dict and set(expected) == {'path', 'pin', 'stat'}
                     and expected['path'] == str(self.path)
                     and set(expected['stat']) == set(FIELDS),
                     'complete expected streaming binding required')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC |
                          os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(self.fd)
            self.before = _seven(before)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and before.st_size >= 0
                     and self.before == _seven(self.path.lstat()),
                     'unique held/named regular input required')
            if expected is not None:
                _require(self.before == expected['stat']
                         and before.st_size == expected['pin']['bytes'],
                         'expected streaming identity changed before read')
            self.expected = expected
            self.length = before.st_size
            self.mode = '100755' if before.st_mode & 0o111 else '100644'
            self.sha = hashlib.sha256()
            self.git = hashlib.sha1(b'blob ' + str(self.length).encode() + b'\0')
            self.total = 0
            self.buffer = b''
            self.position = 0
            self.eof = False
        except BaseException:
            os.close(self.fd)
            raise

    def _fill(self):
        if self.position < len(self.buffer):
            return True
        if self.eof:
            return False
        self.buffer = os.read(self.fd, CHUNK_BYTES)
        self.position = 0
        if not self.buffer:
            self.eof = True
            return False
        self.total += len(self.buffer)
        _require(self.total <= self.length, 'streaming input grew during read')
        self.sha.update(self.buffer)
        self.git.update(self.buffer)
        return True

    def peek(self):
        return self.buffer[self.position] if self._fill() else None

    def take(self):
        value = self.peek()
        _require(value is not None, 'truncated streaming JSON')
        self.position += 1
        return value

    def white(self):
        while self.peek() in (9, 10, 13, 32):
            self.position += 1

    def expect(self, expected):
        self.white()
        _require(self.take() == expected, 'unexpected streaming JSON delimiter')

    def value(self):
        self.white()
        first = self.take()
        raw = bytearray((first,))
        stack = [first] if first in (91, 123) else []
        quoted = first == 34
        string_root = quoted
        escaped = False
        if stack or quoted:
            while stack or quoted:
                token = self.take()
                raw.append(token)
                _require(len(raw) <= VALUE_BYTES, 'one JSON value exceeds original 16 MiB bound')
                if quoted:
                    if escaped:
                        escaped = False
                    elif token == 92:
                        escaped = True
                    elif token == 34:
                        quoted = False
                        if string_root:
                            break
                elif token == 34:
                    quoted = True
                elif token in (91, 123):
                    stack.append(token)
                elif token in (93, 125):
                    _require(stack and stack[-1] == (91 if token == 93 else 123),
                             'mismatched streaming JSON delimiter')
                    stack.pop()
        else:
            while self.peek() not in (None, 9, 10, 13, 32, 44, 93, 125):
                raw.append(self.take())
                _require(len(raw) <= VALUE_BYTES, 'one JSON value exceeds original 16 MiB bound')
        return _decode(raw)

    def finish(self):
        self.white()
        _require(self.peek() is None and self.total == self.length,
                 'trailing data or incomplete streaming read')
        _require(_seven(os.fstat(self.fd)) == self.before == _seven(self.path.lstat()),
                 'streaming input changed during full read')
        row = {'path': str(self.path), 'pin': {'bytes': self.length, 'mode': self.mode,
            'sha256': self.sha.hexdigest(), 'git_blob': self.git.hexdigest()},
            'stat': self.before}
        if self.expected is not None:
            _require(row == self.expected, 'complete streaming bytes or mode differ')
        return row

    def close(self):
        os.close(self.fd)


def _full_read(path, expected=None):
    reader = _Reader(path, expected)
    try:
        while reader._fill():
            reader.position = len(reader.buffer)
        return reader.finish()
    finally:
        reader.close()


def stream_checked(row):
    """One new complete read, preserving the original checked() descriptor."""
    return _full_read(row['path'], row)


def stream_capture(path):
    """Two complete fresh reads, like capture() and its fixed() readback."""
    row = _full_read(path)
    _require(stream_checked(row) == row, 'streaming capture readback differs')
    return row


def stream_index(path, after_paths, started_calls, read_after):
    """Compare every original frames element and both original count fields.

    Individual AFTER objects are freshly reread for this comparison.  The
    aggregate index is never converted to one raw byte string or frames list.
    Other root values remain subject to the original duplicate-key decoder.
    """
    binding = stream_capture(path)
    reader = _Reader(path, binding)
    try:
        reader.expect(123)
        seen = set()
        header = {}
        count = 0
        reader.white()
        if reader.peek() != 125:
            while True:
                key = reader.value()
                _require(type(key) is str and key not in seen, 'duplicate/nonstring INDEX key')
                seen.add(key)
                reader.expect(58)
                if key == 'frames':
                    reader.expect(91)
                    reader.white()
                    if reader.peek() != 93:
                        while True:
                            value = reader.value()
                            _require(count < len(after_paths), 'INDEX has an extra complete frame')
                            _require(value == read_after(after_paths[count]),
                                     'final journal differs from actual frames')
                            count += 1
                            reader.white()
                            if reader.peek() == 93:
                                break
                            reader.expect(44)
                    reader.expect(93)
                else:
                    header[key] = reader.value()
                reader.white()
                if reader.peek() == 125:
                    break
                reader.expect(44)
        reader.expect(125)
        actual = reader.finish()
        _require('frames' in seen and count == len(after_paths)
                 and header['started_calls'] == started_calls
                 and header['complete_calls'] == len(after_paths),
                 'final journal differs from actual frames')
        return {'binding': actual, 'complete_calls': count,
                'started_calls': header['started_calls'],
                'chunk_bytes': CHUNK_BYTES, 'maximum_value_bytes': VALUE_BYTES}
    finally:
        reader.close()


def read_mapping_stream(row):
    """Decode an aggregate path/state mapping without a whole raw byte copy."""
    reader = _Reader(row['path'], row)
    try:
        reader.expect(123)
        value = {}
        reader.white()
        if reader.peek() != 125:
            while True:
                key = reader.value()
                _require(type(key) is str and key not in value, 'duplicate/nonstring STATE key')
                reader.expect(58)
                value[key] = reader.value()
                reader.white()
                if reader.peek() == 125:
                    break
                reader.expect(44)
        reader.expect(125)
        reader.finish()
        return value
    finally:
        reader.close()


def _json_chunks(value):
    encoder = json.JSONEncoder(sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
    for text in encoder.iterencode(value):
        raw = text.encode()
        for offset in range(0, len(raw), CHUNK_BYTES):
            yield raw[offset:offset + CHUNK_BYTES]
    yield b'\n'


def stream_json_pin(value):
    """Original canonical encoded() identity without joining the aggregate."""
    total = 0
    first = hashlib.sha256()
    for raw in _json_chunks(value):
        total += len(raw)
        first.update(raw)
    second = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(total).encode() + b'\0')
    counted = 0
    for raw in _json_chunks(value):
        counted += len(raw)
        second.update(raw)
        git.update(raw)
    _require(counted == total and first.digest() == second.digest(),
             'canonical metadata changed between complete encodings')
    return {'bytes': total, 'mode': '100644', 'sha256': second.hexdigest(),
            'git_blob': git.hexdigest()}


def publish_mapping_stream(path, value):
    """Write only new metadata, then read every byte back twice."""
    expected = stream_json_pin(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        for raw in _json_chunks(value):
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                _require(written > 0, 'short streaming metadata write')
                offset += written
    finally:
        os.close(fd)
    row = stream_capture(path)
    _require(row['pin'] == expected, 'complete streaming metadata readback differs')
    return row
