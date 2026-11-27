"""Specialize private codec loops in the fixed 4 MiB cold actors.

The public codec and general copy helpers keep their original domains. These
two actors admit exactly 4 MiB before calling their private codec functions.
Every original encoded-size, token, output-size and distance check remains.
The codec's encoded buffer is 800000..865536 and its decoded buffer is
940000..1005504, so their admitted copies are disjoint. Reading an entire word
for a two/three-byte token field remains inside the same admitted workspace;
only the originally checked low bytes affect the result.
"""
import ast
from hashlib import sha256
import json


# The range proof applies to these exact original functions. A future codec
# change must renew the proof instead of silently inheriting this rewrite.
ORIGINAL_FUNCTIONS = {
    'pack_chunk_rle': '97a1bac8ae3c1a3b7b89f1b8cd5c6bd733ee679671b71613422ebf9f1a1c4d59',
    'chunk_equal': '077229d0ad706381b240f674225d78d1bd0fab4ebc2c7d8e41f407b1409a892b',
    'pack_lz': 'ae4fd4078231e6b692911ca66edda74cef40d79b8636c94e803d628714c33362',
    'pack_chunk': '8db9209609991ac06b5eb12bc68b8acd27946481bcee7a0239a3d5a3398c1e6d',
    'unpack_chunk': '5fe200535403feeecbfdca2253679ad36a7b61e0f655fd4f48ecbc78936ffb9d',
    'copy_forward': '28ae43c7f69c9405e595a33f599d3c5fd97556febd884e6e18314be13242d224',
}


def function_shape(node):
    """Stable across Python AST dump formatting and empty type fields."""
    if isinstance(node, ast.AST):
        fields = []
        for name, value in ast.iter_fields(node):
            if name in ('type_params', 'type_comment'):
                if value is not None and value != []:
                    raise ValueError('unexpected codec generic/type-comment field')
                continue
            fields.append([name, function_shape(value)])
        return [type(node).__name__, fields]
    if isinstance(node, list):
        return [function_shape(value) for value in node]
    return node


class DisjointCopies(ast.NodeTransformer):
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id == 'copyw':
            if len(node.args) != 4 or node.keywords:
                raise ValueError('private codec copy shape differs')
            node.func.id = 'move_within'
        return self.generic_visit(node)


def decoder_words(function):
    text = ast.unparse(function)
    before = '''        token = byte(w, pos)
        amount = byte(w, pos + 1) | byte(w, pos + 2) << 8'''
    after = '''        token_word = word_load(w, pos)
        token = token_word & 255
        amount = (token_word >> 8) & 65535'''
    distance = '            distance = byte(w, pos) | byte(w, pos + 1) << 8'
    if text.count(before) != 1 or text.count(distance) != 1:
        raise ValueError('private LZ token shape differs')
    text = text.replace(before, after).replace(
        distance, '            distance = word_load(w, pos) & 65535')
    return ast.parse(text).body[0]


def repeat_groups(function):
    """Group only long RLE runs; the first mismatch and old tail stay exact."""
    text = ast.unparse(function)
    before = '''            while pos + count * 8 + 8 <= size and word_load(w, 700000 + pos + count * 8) == value:
                count = count + 1'''
    # Driver word loads are already inlined by its original author.
    if text.count(before) != 1:
        raise ValueError('private RLE run scan differs')
    grouped = '            while pos + count * 8 + 64 <= size'
    grouped += ''.join(
        f' and word_load(w, 700000 + pos + (count + {i}) * 8) == value'
        for i in range(8))
    grouped += ':\n                count = count + 8\n'
    return ast.parse(text.replace(before, grouped + before)).body[0]


def equality_groups(function):
    """Compare every original word in the original order, then the old tail."""
    text = ast.unparse(function)
    before = '''    while i + 8 <= size:
        if word_load(w, 700000 + i) != word_load(w, 940000 + i):
            return 0
        i = i + 8'''
    if text.count(before) != 1:
        raise ValueError('private raw-chunk comparison differs')
    grouped = '    while i + 64 <= size:\n        if '
    grouped += ' or '.join(
        f'word_load(w, 700000 + i + {i * 8}) != word_load(w, 940000 + i + {i * 8})'
        for i in range(8))
    grouped += ':\n            return 0\n        i = i + 64\n'
    return ast.parse(text.replace(before, grouped + before)).body[0]


def specialize(source, *, packing=False):
    tree = ast.parse(source)
    entry = tree.body[0]
    if (not isinstance(entry, ast.FunctionDef) or entry.name != 'advance'
            or not isinstance(entry.body[0], ast.If)
            or ast.unparse(entry.body[0].test)
            != 'length(o) != 128 or length(w) != 4194304'
            or ast.dump(ast.Module(body=entry.body[0].body, type_ignores=[]))
            != ast.dump(ast.parse('return 0'))):
        raise ValueError('private cold codec requires the original 4 MiB entry guard')
    changed = set()
    for index, function in enumerate(tree.body):
        if not isinstance(function, ast.FunctionDef):
            raise ValueError('unexpected cold author top-level statement')
        name = function.name
        if name in ORIGINAL_FUNCTIONS:
            digest = sha256(json.dumps(function_shape(function), separators=(',', ':'),
                                      ensure_ascii=True).encode()).hexdigest()
            if digest != ORIGINAL_FUNCTIONS[name]:
                raise ValueError('original private codec function changed: ' + name)
        if name == 'unpack_chunk':
            # RLE decoding remains unchanged. LZ literal ranges are disjoint.
            function = decoder_words(function)
            DisjointCopies().visit(function)
            changed.add(name)
        elif name == 'copy_forward':
            guarded = function.body[0]
            expected = ('distance != 0 and to >= source and to - source == distance '
                        'and to <= length(w) and size <= length(w) - to')
            if (not isinstance(guarded, ast.If)
                    or ast.dump(guarded.test) != ast.dump(ast.parse(expected, mode='eval').body)):
                raise ValueError('private forward-copy range guard differs')
            # first <= distance and every doubled copy <= written: each
            # individual copy is disjoint. Keep the old fallback untouched.
            DisjointCopies().visit(guarded)
            changed.add(name)
        elif packing and name == 'pack_chunk_rle':
            function = repeat_groups(function)
            DisjointCopies().visit(function)
            changed.add(name)
        elif packing and name in ('pack_lz', 'pack_chunk'):
            # Raw source 700000..765504, RLE 800000..865544, and LZ
            # 880000..945504 are mutually disjoint for these copy pairs.
            DisjointCopies().visit(function)
            changed.add(name)
        elif packing and name == 'chunk_equal':
            function = equality_groups(function)
            changed.add(name)
        tree.body[index] = function
    expected = {'unpack_chunk', 'copy_forward'}
    if packing:
        expected.update(('pack_chunk_rle', 'pack_lz', 'pack_chunk', 'chunk_equal'))
    if changed != expected:
        raise ValueError('private cold codec function set differs')
    return ast.unparse(ast.fix_missing_locations(tree)) + '\n'
