"""HIA-owned parser error graph; explicit CPython profile, no argv decisions."""
from __future__ import annotations

import argparse
import ctypes
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

from .hia_cli_native import _q, _text, _print_parser_message
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_cli_parser_context_data import PROFILE, NODE_COUNT, SHARED_PATHS, SHARED_SIGNATURES
from .hia_cli_parser_context_foreign import PhysicalObjects, shared_objects

SOURCE_NAME = 'examples/hia_bootstrap/cli_parser_context.hepta'
SOURCE = _source_resource_path(SOURCE_NAME)
SCHEMA = 'hepta.hia.cli-parser-context-native.v1'
MAGIC = int.from_bytes(b'HCLCTX01', 'little')
COMMAND = int.from_bytes(b'HCLCOUT1', 'little')
STATE = int.from_bytes(b'HCLCSTA1', 'little')
_UNKNOWN = {}


class ParserContext:
    def __init__(self, owner, parent, message):
        if type(message) is not str or _q(parent.raw, 24) != PROFILE:
            raise ValueError('parser context requires its exact admitted interpreter')
        self.owner = owner
        self.parent = parent
        self.nonce = parent.nonce
        self.output = ctypes.create_string_buffer(4096)
        self.workspace = ctypes.create_string_buffer(131072)
        tail = message.encode('utf-32-le', 'surrogatepass')
        capped_columns, color = parent.parser_formatter_facts
        columns_at, columns_count = struct.unpack_from('<2Q', parent.raw, 176)
        columns = parent.raw[columns_at:columns_at + columns_count * 4]
        self.original_input = struct.pack('<16Q', MAGIC, 0, self.nonce, 0, 0, 0,
            PROFILE, _q(parent.workspace, 24), _q(parent.workspace, 40),
            _q(parent.workspace, 32), len(tail), color, _q(parent.raw, 32),
            columns_count, (_q(parent.raw, 72) >> 5) & 1, capped_columns) + tail + columns
        start, size = struct.unpack_from('<2Q', parent.raw, 96)
        version = _text(parent.raw[start:start+size*4])
        self.objects = PhysicalObjects(shared_objects(parent.cli, SHARED_PATHS,
            SHARED_SIGNATURES), NODE_COUNT, version, self.original_input)
        self.packet = self.original_input
        self.pending = None
        self.claimed = False
        self.busy = False
        self.closed = False
        self.unknown = False
        self.terminal = None
        self.entries = 0

    def _packet(self, command, sequence, operation, observation=0):
        return struct.pack('<16Q', MAGIC, command, self.nonce, sequence,
                           operation, observation, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    def _entry(self, packet):
        source = ctypes.create_string_buffer(packet, len(packet))
        self.entries += 1
        result = self.owner._entry(source, len(packet), self.output, len(self.output),
                                  self.workspace, len(self.workspace))
        if bytes(source.raw) != packet:
            raise RuntimeError('parser context modified its read-only request')
        return result, struct.unpack_from('<16Q', self.output)

    def _fence(self):
        self.unknown = True
        self.closed = True
        _UNKNOWN[id(self)] = self

    def step(self):
        if self.closed or self.unknown or self.busy or self.pending is not None:
            raise RuntimeError('parser context is consumed or awaiting acknowledgement')
        self.busy = True
        try:
            result, words = self._entry(self.packet)
            if words[0] != COMMAND:
                raise RuntimeError('parser context output magic differs')
            if result == 2:
                if (words[2] or words[7] not in (0, 1, 2) or words[9] != 0
                        or words[10] != NODE_COUNT or any(words[11:])):
                    raise RuntimeError('invalid parser graph terminal envelope')
                self.closed = True
                self.terminal = words[7:11]
                return 2
            if (result != 1 or not 1 <= words[2] <= 17 or words[1] == 0
                    or any(words[6:])):
                raise RuntimeError('invalid parser graph effect envelope')
            self.pending = words[1:6]
            return 1
        except BaseException:
            self._fence()
            raise
        finally:
            self.busy = False

    def observe(self):
        if self.closed or self.unknown or self.busy or self.pending is None:
            raise RuntimeError('parser context has no unique pending permission')
        self.busy = True
        sequence, operation, destination, a, b = self.pending
        try:
            payload = bytes(self.output.raw[128:128+b]) if operation == 7 else b''
            result, words = self._entry(self._packet(2, sequence, operation))
            if result != 3 or words[1:6] != self.pending:
                raise RuntimeError('parser context claim was not acknowledged')
            self.claimed = True
            observation = self.objects.effect(operation, destination, a, b, payload)
            if observation is None:
                observation = 0
            if type(observation) is not int or observation not in (0, 1):
                raise RuntimeError('invalid parser primitive observation')
            self.packet = self._packet(1, sequence, operation, observation)
            self.pending = None
            self.claimed = False
        except BaseException:
            self._fence()
            raise
        finally:
            self.busy = False

    def run(self):
        while self.step() != 2:
            self.observe()
        kind, action, root, message = self.terminal
        if kind == 0:
            return 0, None, None, None
        text = self.objects.take(message)
        if kind == 1:
            return 1, None, None, text
        return 2, self.objects.take(root), self.objects.take(action), text


class NativeParserContext(NativeHiaJsonImage):
    def materialize(self, parent, message):
        frame = ParserContext(self, parent, message)
        return frame.run()

    def raise_error(self, parent, first, second):
        # The graph's actual root/action stay in this traceback frame.  The
        # ordinary ArgumentError constructor receives the original layout,
        # and CPython establishes the real handled-exception context itself.
        kind, parser, action, message = self.materialize(parent, second)
        if kind:
            try:
                raise argparse.ArgumentError(action, message)
            except argparse.ArgumentError:
                _print_parser_message(first, sys.stderr)
                _print_parser_message(second, sys.stderr)
                raise SystemExit(parent.exit_code)
        _print_parser_message(first, sys.stderr)
        _print_parser_message(second, sys.stderr)
        raise SystemExit(parent.exit_code)


@lru_cache(maxsize=3)
def load_context_manifest(path, raw, source_sha):
    """Independent immutable mapping custody; do not evict other CLI images."""
    value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    keys = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))
            or value['source_sha256'] != source_sha
            or type(value['image_path']) is not str or not value['image_path']
            or Path(value['image_path']).name != value['image_path']
            or value['image_path'] in ('.', '..')):
        raise ValueError('invalid or stale parser context manifest')
    with (Path(path).parent / value['image_path']).open('rb') as stream:
        image = stream.read((1 << 20) + 1)
    owner = NativeParserContext(image, value['image_sha256'])
    owner._bind_manifest_source(source_sha)
    return owner
