"""Data-only helpers for the explicitly bounded stored-borrow profile.

Rust remains the mandatory lifetime/alias checker. These helpers classify
syntax and preserve identities; they do not infer or prove region relations.
"""
from dataclasses import fields, is_dataclass

from .ast import Type


REFERENCE_TYPES = {"ref_read", "ref_mut"}


def substitute_lifetimes(typ, mapping):
    return Type(typ.name, tuple(substitute_lifetimes(arg, mapping) for arg in typ.args),
                typ.length, tuple(mapping.get(name, name) for name in typ.lifetimes))


def infer_lifetimes(typ):
    """An expression does not import a callee's bound lifetime identifiers."""
    return Type(typ.name, tuple(infer_lifetimes(arg) for arg in typ.args), typ.length,
                tuple("_" for _ in typ.lifetimes))


def value_type(typ):
    return typ.args[0] if typ.name in REFERENCE_TYPES else typ


def contains_storage(typ, structs, enums=None):
    pending, seen = [typ], set()
    while pending:
        current = pending.pop()
        if current.name in REFERENCE_TYPES or current.lifetimes:
            return True
        pending.extend(current.args)
        if current.name in seen:
            continue
        seen.add(current.name)
        decl = structs.get(current.name) or (enums or {}).get(current.name)
        if decl is not None:
            if getattr(decl, "lifetime_params", ()):
                return True
            pending.extend([f.type for f in decl.fields] if hasattr(decl, "fields") else
                           [t for variant in decl.variants for t in variant.fields])
    return False


def has_borrowed_storage(program):
    """Reject an entire unsupported backend profile, including unused bodies."""
    pending = [program]
    while pending:
        item = pending.pop()
        if isinstance(item, Type):
            if item.name in REFERENCE_TYPES or item.lifetimes:
                return True
            pending.extend(item.args)
        elif is_dataclass(item):
            if getattr(item, "lifetime_params", ()) or getattr(item, "lifetime", None) or getattr(item, "return_lifetime", None):
                return True
            pending.extend(getattr(item, f.name) for f in fields(item))
        elif isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (tuple, list)):
            pending.extend(item)
    return False
