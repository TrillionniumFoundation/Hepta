"""Author a separate HIA v9 word profile for the Bootstrap f0 ABI.

The original author and source remain exact reference inputs. Complete eight-byte
fields are lowered only after the original f0 128/96/192-byte length refusal.
The three independently callable word helpers retain their original byte-wise
fallback, including wrapped indices and partial writes before a bounds trap.
This module grants no runtime, cold-build, or delivery qualification.
"""
from __future__ import annotations

import ast
import copy
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_service_bootstrap as reference
from tools.generate_hia_cold_document import BulkWordBuilder, document as word_document
from tools.generate_hia_service_context import ContextBuilder

SOURCE_NAME = 'examples/hia_bootstrap/service_bootstrap_word.hepta'
REFERENCE_AUTHOR = 'tools/generate_hia_service_bootstrap.py'
REFERENCE_AUTHOR_SHA256 = '1619a4f38c98bf0cc3039d5b19541b4e8c7010794d285ad2966aaac635488061'
REFERENCE_SOURCE = 'examples/hia_bootstrap/service_bootstrap.hepta'
REFERENCE_SOURCE_SHA256 = '3628657b80d30c8b8f67e445dc47117f55ef52380e3efbdd0ee005646b49c4fd'
PROTOCOL = 'hepta/hia_service_bootstrap_protocol.py'
PROTOCOL_SHA256 = 'd471621a9e5ea160a74b6c0ea7c209df0b2d92aab17be592f01f0b0287332aec'
HELPERS = ('read_word', 'get', 'set')
EXTENTS = {'s': 128, 'o': 96, 'w': 192}


def _shape(node):
    return ast.dump(node, include_attributes=False)


def _statements(source):
    return ast.parse(source).body


def _refuse(message):
    raise ValueError('Bootstrap word author: ' + message)


def _replace_pair(node, expected, replacement):
    expected = [_shape(item) for item in _statements(expected)]
    found = [index for index in range(len(node.body) - 1)
             if [_shape(item) for item in node.body[index:index + 2]] == expected]
    if len(found) != 1:
        _refuse('fixed loop shape differs in ' + node.name)
    at = found[0]
    node.body[at:at + 2] = replacement


class _Index(ast.NodeTransformer):
    def __init__(self, value):
        self.value = value

    def visit_Name(self, node):
        if node.id == 'index':
            if not isinstance(node.ctx, ast.Load):
                _refuse('fixed loop has an unexpected index assignment')
            return ast.copy_location(ast.Constant(self.value), node)
        return node


def _expanded(body, values):
    return [_Index(value).visit(copy.deepcopy(statement))
            for value in values for statement in body]


class _Fields(ast.NodeTransformer):
    def __init__(self, function):
        self.function = function
        self.replacements = []

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name) or node.func.id not in ('read_word', 'get', 'set'):
            return self.generic_visit(node)
        kind = node.func.id
        if kind == 'set':
            _refuse('a field store return value is consumed in ' + self.function)
        if len(node.args) != 2 or node.keywords:
            _refuse('field load signature differs')
        view, index = node.args
        if (not isinstance(view, ast.Name) or view.id not in EXTENTS
                or not isinstance(index, ast.Constant) or type(index.value) is not int):
            _refuse('field load offset is not a fixed original field')
        offset = index.value if kind == 'read_word' else index.value * 8
        if not 0 <= offset <= EXTENTS[view.id] - 8:
            _refuse('field load exceeds the f0-admitted view')
        self.replacements.append((kind, view.id, offset))
        return ast.copy_location(ast.Call(ast.Name('word_load', ast.Load()),
                                          [view, ast.Constant(offset)], []), node)

    def visit_Expr(self, node):
        value = node.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == 'set'):
            return self.generic_visit(node)
        if len(value.args) != 3 or value.keywords:
            _refuse('field store signature differs')
        view, index, stored = value.args
        if (not isinstance(view, ast.Name) or view.id not in ('o', 'w')
                or not isinstance(index, ast.Constant) or type(index.value) is not int):
            _refuse('field store offset is not a fixed original field')
        offset = index.value * 8
        if not 0 <= offset <= EXTENTS[view.id] - 8:
            _refuse('field store exceeds the f0-admitted view')
        self.replacements.append(('set', view.id, offset))
        return ast.copy_location(ast.Expr(ast.Call(ast.Name('word_store', ast.Load()),
            [view, ast.Constant(offset), self.visit(stored)], [])), node)


def transformed_source():
    captured = {}
    for name, expected in ((REFERENCE_AUTHOR, REFERENCE_AUTHOR_SHA256),
                           (REFERENCE_SOURCE, REFERENCE_SOURCE_SHA256),
                           (PROTOCOL, PROTOCOL_SHA256)):
        raw = (ROOT / name).read_bytes()
        if sha256(raw).hexdigest() != expected:
            _refuse('complete reference input differs: ' + name)
        captured[name] = raw
    old_source = reference.source_program()
    if render_assembly(reference.document()).encode() != captured[REFERENCE_SOURCE]:
        _refuse('original author no longer reproduces the complete original HIA source')
    tree = ast.parse(old_source)
    nodes = {node.name: node for node in tree.body}
    if len(nodes) != len(tree.body) or next(iter(nodes)) != 'service_bootstrap':
        _refuse('original graph function inventory differs')
    first = _statements('if length(s) != 128 or length(o) != 96 or length(w) != 192:\n'
                        '    return 4294967293\n')[0]
    if _shape(nodes['service_bootstrap'].body[0]) != _shape(first):
        _refuse('original f0 length refusal is not the first operation')

    reserved = ('index = 64\nwhile index < 128:\n'
                '    if read_word(s, index) != 0:\n        return 4294967293\n'
                '    index = index + 8\n')
    _replace_pair(nodes['service_bootstrap'], reserved,
                  _expanded(_statements(reserved)[1].body[:-1], range(64, 128, 8)))
    zero = ('index = 0\nwhile index < 192:\n'
            '    if byte(w, index) != 0:\n        return 4294967293\n'
            '    index = index + 1\n')
    # No writes occur in this original zero-admission loop. A little-endian
    # word is zero exactly when all of the same eight bytes are zero.
    zero_body = _statements('if word_load(w, index) != 0:\n    return 4294967293\n')
    _replace_pair(nodes['initialize'], zero, _expanded(zero_body, range(0, 192, 8)))
    state = ('index = 13\nwhile index < 24:\n'
             '    if get(w, index) != 0:\n        return 0\n'
             '    index = index + 1\n')
    _replace_pair(nodes['valid_state'], state,
                  _expanded(_statements(state)[1].body[:-1], range(13, 24)))
    checksum = ('index = 0\nwhile index < 24:\n'
                '    if index != 10:\n'
                '        value = ((value << 7) | (value >> 57)) ^ get(w, index)\n'
                '    index = index + 1\n')
    _replace_pair(nodes['checksum'], checksum,
                  _expanded(_statements(checksum)[1].body[0].body,
                            (index for index in range(24) if index != 10)))

    replacements = {}
    for name, node in nodes.items():
        if name in HELPERS:
            continue
        transform = _Fields(name)
        transform.visit(node)
        if any(isinstance(item, ast.Name) and item.id == 'index' for item in ast.walk(node)):
            _refuse('a fixed loop variable escaped its original scope')
        replacements[name] = transform.replacements

    helper_prefixes = {
        'read_word': ('if index <= length(s) and 8 <= length(s) - index:\n'
                      '    return word_load(s, index)\n'),
        'get': ('at = index * 8\n'
                'if at <= length(w) and 8 <= length(w) - at:\n'
                '    return word_load(w, at)\n'),
        'set': ('at = index * 8\n'
                'if at <= length(w) and 8 <= length(w) - at:\n'
                '    word_store(w, at, value)\n'
                '    return value\n'),
    }
    original_nodes = {node.name: node for node in ast.parse(old_source).body}
    for name in HELPERS:
        original_body = copy.deepcopy(nodes[name].body)
        prefix = _statements(helper_prefixes[name])
        nodes[name].body = prefix + original_body
        if [_shape(item) for item in nodes[name].body[len(prefix):]] != [
                _shape(item) for item in original_nodes[name].body]:
            _refuse('original partial-trap fallback was not retained')

    field_sites = []
    for name, node in nodes.items():
        if name in HELPERS:
            continue
        for item in ast.walk(node):
            if not (isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                    and item.func.id in ('word_load', 'word_store')):
                continue
            view, offset = item.args[:2]
            if (not isinstance(view, ast.Name) or view.id not in EXTENTS
                    or not isinstance(offset, ast.Constant) or type(offset.value) is not int
                    or not 0 <= offset.value <= EXTENTS[view.id] - 8):
                _refuse('a direct field lacks an admitted fixed complete range')
            field_sites.append({'function': name, 'operation': item.func.id,
                                'view': view.id, 'offset': offset.value,
                                'f0_exact_extent': EXTENTS[view.id]})
    ast.fix_missing_locations(tree)
    for name, raw in captured.items():
        if (ROOT / name).read_bytes() != raw:
            _refuse('reference source changed while authoring')
    proof = {'schema': 'hepta.hia.bootstrap-word-author.v1',
        'reference_sources': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                              for name, raw in captured.items()},
        'function_order': list(nodes), 'f0_exact_extents': dict(EXTENTS),
        'original_first_length_refusal_preserved': True,
        'unrolled_exact_loops': {'request_reserved': 8, 'initial_zero_words': 24,
                                'state_reserved': 11, 'checksum_nonself_words': 23},
        'complete_range_sites': field_sites,
        'retained_original_partial_trap_helpers': list(HELPERS),
        'runtime_qualified': False, 'matching_source_cold_qualified': False}
    return ast.unparse(tree) + '\n', proof


def source_program():
    return transformed_source()[0]


class WordContextBuilder(ContextBuilder, BulkWordBuilder):
    """Use existing resource-26 operations and literal usize field offsets."""
    def expr(self, expression):
        if (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                and expression.func.id in ('word_load', 'word_store')
                and len(expression.args) in (2, 3)
                and isinstance(expression.args[1], ast.Constant)
                and type(expression.args[1].value) is int
                and 0 <= expression.args[1].value < 1 << 64):
            operation = expression.func.id
            if expression.keywords or len(expression.args) != (2 if operation == 'word_load' else 3):
                _refuse('literal word operation signature differs')
            view = self.expr(expression.args[0])
            if view[1] not in ('readbuf', 'mutbuf') or (operation == 'word_store' and view[1] != 'mutbuf'):
                _refuse('literal word operation view type differs')
            arguments = [view, self.c(expression.args[1].value, 'usize')]
            if operation == 'word_store':
                arguments.append(self.cast(self.expr(expression.args[2]), 'u64'))
            return self.op('buffer.load.u64.le' if operation == 'word_load'
                           else 'buffer.store.u64.le', arguments,
                           'u64' if operation == 'word_load' else None)
        return super().expr(expression)


def document():
    return word_document(source_program(), 'service_bootstrap', builder_type=WordContextBuilder)


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
