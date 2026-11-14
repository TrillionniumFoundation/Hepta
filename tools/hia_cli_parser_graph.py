"""Author structural argparse facts; this module is never a runtime parser.

The retained construction prefix is an authoring oracle.  Its actual graph is
converted to typed allocation/link records, including cycles and shared module
constants.  No retained Python body, bytecode payload or prebuilt exception is
placed in the generated runtime image.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import inspect
import json
import re
import struct
import sys
import types
from unittest.mock import patch

from hepta import cli, hia_schema
from tools.generate_hia_cli_control import ACTIONS, FIELDS


def captured_parser():
    class Captured(BaseException):
        def __init__(self, parser):
            self.parser = parser

    def capture(parser, *_args, **_kwargs):
        raise Captured(parser)

    with patch.object(argparse.ArgumentParser, 'parse_args', capture):
        try:
            cli._reference_hia_main(['capabilities'])
        except Captured as observation:
            return observation.parser
    raise AssertionError('authoring oracle did not stop at the original parse boundary')


class Shared:
    def __init__(self):
        self.paths = []
        self.values = []
        self.by_id = {}
        self.walked = set()

    def add(self, value, path):
        if type(value) in (str, bytes, tuple, types.CodeType, types.FunctionType, type):
            if id(value) not in self.by_id:
                self.by_id[id(value)] = len(self.values)
                self.values.append(value)
                self.paths.append(path)

    def walk(self, value, path):
        self.add(value, path)
        if id(value) in self.walked:
            return
        self.walked.add(id(value))
        if type(value) is tuple:
            for index, item in enumerate(value):
                self.walk(item, path + [('item', index)])
        elif type(value) is types.CodeType:
            self.walk(value.co_consts, path + [('code-consts', None)])
        elif type(value) is types.FunctionType:
            self.walk(value.__code__, path + [('function-code', None)])
            self.walk(value.__defaults__, path + [('function-defaults', None)])
        elif type(value) is type:
            for key, item in sorted(vars(value).items()):
                if type(item) in (types.FunctionType, type, str, bytes, tuple):
                    self.walk(item, path + [('class-item', key)])


def shared_facts():
    shared = Shared()
    modules = [('argparse', argparse), ('cli', cli), ('schema', hia_schema)]
    colorize = sys.modules.get('_colorize')
    if colorize is not None:
        modules.append(('_colorize', colorize))
    for name, module in modules:
        for key, value in sorted(vars(module).items()):
            if type(value) in (types.FunctionType, type, str, bytes, tuple):
                shared.walk(value, [('module-item', (name, key))])
    if colorize is not None:
        namespace = vars(colorize)
        for name in ('theme_no_color', '_theme'):
            theme = namespace[name]
            if type(theme) is not namespace['Theme']:
                raise ValueError('authoring theme is not the exact standard Theme')
            value = vars(theme)['argparse']
            if type(value) is not namespace['Argparse']:
                raise ValueError('authoring palette is not the exact standard Argparse')
            if id(value) not in shared.by_id:
                shared.by_id[id(value)] = len(shared.values)
                shared.values.append(value)
                shared.paths.append([('module-item', ('_colorize', name)), ('theme-item', 'argparse')])
    # MappingProxyType cannot be reconstituted or coerced at runtime.  These
    # are the original ordered key objects used by tuple(PRIMITIVE_PROFILES).
    for index, value in enumerate(hia_schema.PRIMITIVE_PROFILES):
        shared.walk(value, [('schema-key', index)])
    return shared


def compress_lz(raw):
    """Fixed literal/back-reference wire, decoded by the companion HIA code."""
    positions = {}
    output = bytearray()
    literals = bytearray()

    def flush():
        if literals:
            output.append(len(literals) - 1)
            output.extend(literals)
            literals.clear()

    at = 0
    while at < len(raw):
        key = raw[at:at + 4]
        best = (0, 0)
        for previous in reversed(positions.get(key, ())[-128:]):
            distance = at - previous
            if not 0 < distance <= 65535:
                continue
            size = 0
            while size < 130 and at + size < len(raw) and raw[previous + size] == raw[at + size]:
                size += 1
            if size > best[0]:
                best = size, distance
                if size == 130:
                    break
        if best[0] >= 4:
            flush()
            output.append(128 + best[0] - 3)
            output.extend(struct.pack('<H', best[1]))
            consumed = best[0]
        else:
            literals.append(raw[at])
            if len(literals) == 128:
                flush()
            consumed = 1
        for index in range(at, at + consumed):
            positions.setdefault(raw[index:index + 4], []).append(index)
        at += consumed
    flush()
    return bytes(output)


def decompress_lz(raw):
    output = bytearray()
    at = 0
    while at < len(raw):
        token = raw[at]; at += 1
        if token < 128:
            output.extend(raw[at:at + token + 1]); at += token + 1
        else:
            distance = struct.unpack_from('<H', raw, at)[0]; at += 2
            for _ in range(token - 128 + 3):
                output.append(output[-distance])
    return bytes(output)


def graph_facts():
    parser = captured_parser()
    shared = shared_facts()
    objects = []
    nodes = []
    by_id = {}
    version = next(action.version for action in parser._actions
                   if type(action) is argparse._VersionAction)
    subparsers = next(action for action in parser._actions if type(action) is argparse._SubParsersAction)
    parsers = [parser] + [subparsers.choices[name] for name in ACTIONS]
    formatter_dicts = {}
    formatter_choices = {}
    if sys.version_info[:2] == (3, 14):
        colorize = sys.modules['_colorize']
        formatter_choices = {
            '_theme': [shared.by_id[id(vars(vars(colorize)[name])['argparse'])]
                       for name in ('theme_no_color', '_theme')],
            '_decolor': [shared.by_id[id(argparse._identity)], shared.by_id[id(colorize.decolor)]],
        }
        for original in parsers:
            formatter = original._cached_formatter
            if type(formatter) is not argparse.HelpFormatter:
                raise ValueError('authoring parser has an unexpected cached formatter')
            formatter_dicts[id(vars(formatter))] = formatter

    def formatter_value(key, value):
        # Each width subtraction creates a new result at runtime.  CPython
        # itself decides whether that integer aliases a small-integer cache;
        # the authoring-time value must not freeze the alias graph.
        index = len(nodes)
        objects.append(value)
        if key == '_width':
            nodes.append(['formatter-width'])
        elif key == '_max_help_position':
            nodes.append(['formatter-help-position'])
        else:
            nodes.append(['formatter-choice', *formatter_choices[key]])
        return index

    def visit(value):
        identity = id(value)
        if identity in by_id:
            return by_id[identity]
        index = len(nodes)
        by_id[identity] = index
        objects.append(value)
        nodes.append(None)
        t = type(value)
        if value is version:
            row = ['version']
        elif identity in shared.by_id:
            row = ['shared', shared.by_id[identity]]
        elif t is type(None):
            row = ['none']
        elif t is bool:
            row = ['bool', int(value)]
        elif t is int:
            if not -(1 << 63) <= value < 1 << 64:
                raise ValueError('authoring graph integer outside the fixed scalar port')
            row = ['int', value]
        elif t is str:
            row = ['str', value]
        elif t is bytes:
            row = ['bytes', value.hex()]
        elif t is list:
            row = ['list', [visit(item) for item in value]]
        elif t is set and not value:
            row = ['empty-set']
        elif t is dict:
            row = ['dict', [[visit(key), formatter_value(key, item)
                            if identity in formatter_dicts and key in
                            ('_width', '_max_help_position', '_theme', '_decolor')
                            else visit(item)] for key, item in value.items()]]
        elif t is tuple:
            row = ['tuple', [visit(item) for item in value]]
        elif t is types.FunctionType:
            if (value.__qualname__ != 'ArgumentParser.__init__.<locals>.identity'
                    or value.__globals__ is not vars(argparse)
                    or value.__closure__ is not None or value.__defaults__ is not None
                    or id(value.__code__) not in shared.by_id):
                raise ValueError('unknown authoring graph function')
            row = ['identity-function', shared.by_id[id(value.__code__)]]
        elif t is re.Pattern:
            row = ['pattern', visit(value.pattern), visit(value.flags)]
        elif isinstance(value, tuple):
            if id(t) not in shared.by_id:
                raise ValueError('unknown named tuple type in authoring graph')
            row = ['tuple-subclass', shared.by_id[id(t)], [visit(item) for item in value]]
        elif t.__module__ in ('argparse', '_colorize') and id(t) in shared.by_id:
            row = ['object', shared.by_id[id(t)], visit(vars(value))]
        else:
            raise ValueError('unsupported authoring graph value: ' + t.__module__ + '.' + t.__qualname__)
        nodes[index] = row
        return index

    root = visit(parser)
    action_map = []
    for value in parsers:
        by_dest = {action.dest: by_id[id(action)] for action in value._actions}
        action_map.append([by_dest.get(name, 65535) for name in FIELDS])
    # Only shared objects actually reached by this graph enter its fixed ABI.
    used = sorted({row[1] for row in nodes if row[0] in ('shared', 'object', 'identity-function', 'tuple-subclass')}
                  | {index for row in nodes if row[0] == 'formatter-choice' for index in row[1:]})
    remap = {old: new for new, old in enumerate(used)}
    for row in nodes:
        if row[0] in ('shared', 'object', 'identity-function', 'tuple-subclass'):
            row[1] = remap[row[1]]
        elif row[0] == 'formatter-choice':
            row[1:] = [remap[index] for index in row[1:]]
    return {'profile': tuple(sys.version_info[:3]), 'root': root, 'nodes': nodes,
            'has_formatters': bool(formatter_dicts),
            'shared_paths': [shared.paths[index] for index in used],
            'action_map': action_map,
            'reference_sha256': sha256(inspect.getsource(cli._reference_hia_main).encode()).hexdigest(),
            'argparse_sha256': sha256(inspect.getsource(argparse).encode()).hexdigest()}, objects, [shared.values[index] for index in used]


def instruction_plan(facts):
    """Plan only primitive allocations and links; graph order lives in HIA."""
    rows = []
    payload = bytearray()
    ready = set()
    nodes = facts['nodes']
    # Instruction: opcode, destination/object, argument, argument (four u16).
    # Literals use a separate typed payload and cannot contain Python code.
    for index, row in enumerate(nodes):
        kind = row[0]
        if kind in ('list', 'dict'):
            rows.append((1 if kind == 'dict' else 2, index, 0, 0)); ready.add(index)
        elif kind == 'object':
            rows.append((3, index, row[1], 0)); ready.add(index)
        elif kind == 'shared':
            rows.append((4, index, row[1], 0)); ready.add(index)
        elif kind == 'identity-function':
            rows.append((5, index, row[1], 0)); ready.add(index)
        elif kind == 'version':
            rows.append((6, index, 0, 0)); ready.add(index)
        elif kind == 'formatter-width':
            rows.append((17, index, len(nodes) + 1, 2)); ready.add(index)
        elif kind == 'formatter-choice':
            rows.append((18, index, row[1], row[2])); ready.add(index)
        elif kind == 'formatter-help-position':
            rows.append((19, index, 0, 0)); ready.add(index)
        elif kind in ('none', 'bool', 'int', 'str', 'bytes', 'empty-set'):
            tag = ('none', 'bool', 'int', 'str', 'bytes', 'empty-set').index(kind)
            data = (b'' if kind in ('none', 'empty-set') else bytes([row[1]]) if kind == 'bool'
                    else struct.pack('<Q', row[1] & ((1 << 64) - 1)) if kind == 'int'
                    else row[1].encode('utf-8', 'surrogatepass') if kind == 'str'
                    else bytes.fromhex(row[1]))
            at = len(payload); payload.extend(bytes([tag]) + struct.pack('<H', len(data)) + data)
            rows.append((7, index, at, len(data) + 3)); ready.add(index)
    waiting = {i for i in range(len(nodes)) if i not in ready}
    while waiting:
        advanced = False
        for index in sorted(waiting):
            row = nodes[index]; kind = row[0]
            dependencies = row[1] if kind == 'tuple' else row[2] if kind == 'tuple-subclass' else row[1:]
            if not all(item in ready for item in dependencies):
                continue
            if kind in ('tuple', 'tuple-subclass'):
                rows.append((2, index, 0, 0))
                rows.extend((8, index, item, 0) for item in dependencies)
                rows.append((9, index, 65535 if kind == 'tuple' else row[1], 0))
            elif kind == 'pattern':
                rows.append((10, index, row[1], row[2]))
            else:
                raise ValueError('unknown immutable graph node')
            ready.add(index); waiting.remove(index); advanced = True
        if not advanced:
            raise ValueError('immutable authoring graph cycle')
    for index, row in enumerate(nodes):
        if row[0] == 'list':
            rows.extend((8, index, item, 0) for item in row[1])
        elif row[0] == 'dict':
            rows.extend((11, index, key, value) for key, value in row[1])
        elif row[0] == 'object':
            rows.append((12, index, row[2], 0))
    raw = b''.join(struct.pack('<4H', *row) for row in rows)
    return rows, bytes(payload), raw


def delta_plan(rows):
    previous = [0, 0, 0, 0]
    output = bytearray()
    for row in rows:
        for column, value in enumerate(row):
            delta = value - previous[column]
            previous[column] = value
            zigzag = delta * 2 if delta >= 0 else -delta * 2 - 1
            while zigzag >= 128:
                output.append(128 | (zigzag & 127)); zigzag >>= 7
            output.append(zigzag)
    return bytes(output)


if __name__ == '__main__':
    facts, _objects, _shared = graph_facts()
    rows, payload, raw = instruction_plan(facts)
    deltas = delta_plan(rows)
    compressed = compress_lz(deltas)
    assert decompress_lz(compressed) == deltas
    print(json.dumps({'nodes': len(facts['nodes']), 'shared': len(facts['shared_paths']),
                      'instructions': len(rows), 'raw_bytes': len(raw), 'literal_bytes': len(payload),
                      'lz_bytes': len(compressed), 'profile': facts['profile'],
                      'kinds': {kind: sum(row[0] == kind for row in facts['nodes'])
                                for kind in sorted({row[0] for row in facts['nodes']})}}, sort_keys=True))
