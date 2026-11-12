"""Exact fixed-eight-byte authoring transform; no interpreter change.

The original three helper definitions must match byte-for-byte. Every other
source byte and every function signature/order is retained. This changes the
authored HIA instruction count, not Core semantics or evaluator limits.
No all-fuel/step-count equivalence is claimed.
"""
from __future__ import annotations
import ast
import hashlib
from tools.generate_hia_selfhost import total_scalar_functions
OLD = r'''
def read64(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0
'''
NEW = r'''
def read64(s:readbuf, index:u64) -> u64:
    value = 0
    value = value | (byte(s, index + 0) << 0)
    value = value | (byte(s, index + 1) << 8)
    value = value | (byte(s, index + 2) << 16)
    value = value | (byte(s, index + 3) << 24)
    value = value | (byte(s, index + 4) << 32)
    value = value | (byte(s, index + 5) << 40)
    value = value | (byte(s, index + 6) << 48)
    value = value | (byte(s, index + 7) << 56)
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    value = value | (byte(w, index + 0) << 0)
    value = value | (byte(w, index + 1) << 8)
    value = value | (byte(w, index + 2) << 16)
    value = value | (byte(w, index + 3) << 24)
    value = value | (byte(w, index + 4) << 32)
    value = value | (byte(w, index + 5) << 40)
    value = value | (byte(w, index + 6) << 48)
    value = value | (byte(w, index + 7) << 56)
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    store(w, index + 0, value & 255)
    value = value >> 8
    store(w, index + 1, value & 255)
    value = value >> 8
    store(w, index + 2, value & 255)
    value = value >> 8
    store(w, index + 3, value & 255)
    value = value >> 8
    store(w, index + 4, value & 255)
    value = value >> 8
    store(w, index + 5, value & 255)
    value = value >> 8
    store(w, index + 6, value & 255)
    value = value >> 8
    store(w, index + 7, value & 255)
    value = value >> 8
    return 0
'''
OLD_SHA256 = "ce28fa53dae1e10cf3328a535e6911a5f72afe99e18783393b0b20ef539b3708"
NEW_SHA256 = "94fdc970665a613c1b441806815dae784e37a3f53235bc5dd56aeed0712c90f7"
NAMES = ("read64", "get", "put")
def sha(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
def shape(node):
    return ast.dump(node, annotate_fields=True, include_attributes=False)
def transform(source):
    if type(source) is not str:
        raise ValueError("exact-byte source must be a string")
    if sha(OLD) != OLD_SHA256 or sha(NEW) != NEW_SHA256:
        raise ValueError("exact-byte helper source identity differs")
    if source.count(OLD) != 1 or source.count(NEW) != 0:
        raise ValueError("exact-byte transform requires the unique original helper definitions")
    changed=source.replace(OLD,NEW,1)
    if changed.count(NEW)!=1 or changed.replace(NEW,OLD,1)!=source:
        raise ValueError("exact-byte reverse source equality failed")
    before=ast.parse(source).body;after=ast.parse(changed).body
    if any(not isinstance(n,ast.FunctionDef) for n in before+after):
        raise ValueError("exact-byte authoring source must contain only functions")
    if len({n.name for n in before})!=len(before) or [n.name for n in before]!=[n.name for n in after]:
        raise ValueError("exact-byte function inventory differs")
    old_defs={n.name:n for n in ast.parse(OLD).body}
    new_defs={n.name:n for n in ast.parse(NEW).body}
    seen=[]
    for left,right in zip(before,after,strict=True):
        if left.name in NAMES:
            if shape(left)!=shape(old_defs[left.name]) or shape(right)!=shape(new_defs[left.name]):
                raise ValueError("exact-byte helper AST differs")
            if shape(left.args)!=shape(right.args) or shape(left.returns)!=shape(right.returns):
                raise ValueError("exact-byte helper signature differs")
            seen.append(left.name)
        elif shape(left)!=shape(right):
            raise ValueError("exact-byte non-helper function changed")
    if tuple(seen)!=NAMES:
        raise ValueError("exact-byte helper inventory differs")
    if total_scalar_functions(before)!=total_scalar_functions(after):
        raise ValueError("exact-byte original total-scalar classification differs")
    return changed
def nodes(source):
    return ast.parse(transform(source)).body
