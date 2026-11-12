"""Isolated development registration understood by the actual wheel hook.

This changes one original literal tuple, never appends an AugAssign which the
actual setup.py resource reader does not consume. Product activation is owned
by a separately reviewed integration; this helper grants no cold authority.
"""
from __future__ import annotations
import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path


def extend_development_tuple(root, relative, name, additions):
    path = Path(root) / relative
    before = path.read_bytes()
    tree = ast.parse(before)
    declarations = [node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(declarations) != 1 or any(isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name) and node.target.id == name for node in tree.body):
        raise ValueError('one original literal development tuple required: ' + name)
    declaration = declarations[0]
    original = ast.literal_eval(declaration.value)
    if (type(original) is not tuple or any(type(item) is not str or not item for item in original)
            or len(original) != len(set(original)) or type(additions) is not tuple
            or any(type(item) is not str or not item for item in additions)
            or len(additions) != len(set(additions))):
        raise ValueError('development resource names must be unique exact strings')
    added = tuple(item for item in additions if item not in original)
    lines = before.splitlines(keepends=True)
    end = sum(map(len, lines[:declaration.value.end_lineno - 1])) + declaration.value.end_col_offset
    last = declaration.value.elts[-1] if declaration.value.elts else None
    if last is not None:
        last_end = sum(map(len, lines[:last.end_lineno - 1])) + last.end_col_offset
        if not before[last_end:end - 1].lstrip().startswith(b','):
            raise ValueError('original development tuple needs its explicit trailing comma')
    if before[end - 1:end] != b')':
        raise ValueError('development declaration is not a parenthesized literal tuple')
    insertion = b'' if not added else (b'' if before[end - 2:end - 1] == b'\n' else b'\n') + b''.join(
        b'    ' + repr(item).encode('utf-8') + b',\n' for item in added)
    after = before[:end - 1] + insertion + before[end - 1:]
    observed_tree = ast.parse(after)
    observed = [node for node in observed_tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)][0]
    if ast.literal_eval(observed.value) != original + added:
        raise ValueError('development literal tuple differs from its exact union')
    projected = deepcopy(observed_tree)
    projected_declaration = [node for node in projected.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)][0]
    projected_declaration.value = deepcopy(declaration.value)
    if ast.dump(projected, include_attributes=False) != ast.dump(tree, include_attributes=False):
        raise ValueError('development registry changed code outside its literal declaration')
    path.write_bytes(after)
    if path.read_bytes() != after:
        raise ValueError('development literal registry publication readback differs')
    return {'path': relative, 'symbol': name,
        'before_sha256': sha256(before).hexdigest(), 'after_sha256': sha256(after).hexdigest(),
        'original_count': len(original), 'added': list(added), 'scope': 'DEVELOPMENT_ONLY'}
