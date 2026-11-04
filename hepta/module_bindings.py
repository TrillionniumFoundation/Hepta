"""Keep source-local bindings distinct from unrelated flattened functions."""
from __future__ import annotations

from dataclasses import fields, is_dataclass

from .ast import Expr, Param, Pattern, Span, Stmt, Type


def _nodes(roots):
    pending = list(roots)
    while pending:
        value = pending.pop()
        if isinstance(value, (Span, Type)):
            continue
        yield value
        if is_dataclass(value):
            pending.extend(getattr(value, field.name) for field in fields(value))
        elif isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, (list, tuple)):
            pending.extend(value)


def isolate_local_bindings(function, collisions, namespace, function_symbols):
    """Rename only bindings that would collide with another source module.

    Calls, type/field/lifetime names and C boundary parameter spellings are
    untouched. This runs before module reference resolution, so a local cannot
    be mistaken for an undeclared reference to an unrelated flat function.
    """
    if function.extern_c or function.body is None or not collisions:
        return
    roots = [*function.params, *function.body]
    bindings = set()
    for value in _nodes(roots):
        if isinstance(value, Param):
            bindings.add(value.name)
        elif isinstance(value, Stmt) and value.kind in {"let", "for"}:
            bindings.add(value.data["name"])
        elif isinstance(value, Pattern):
            bindings.update(name for name in value.bindings if name != "_")
    # C parameter identifiers are validated in their original spelling. Also
    # protect that spelling in nested binders, preserving duplicate rejection.
    protected = {param.name for param in function.params} if function.export_c else set()
    candidates = sorted((bindings & collisions) - protected)
    if not candidates:
        return
    renames = {}
    occupied = bindings | function_symbols
    for name in candidates:
        counter = 0
        while True:
            # A digit after the reserved module prefix cannot start a source
            # declaration name. Avoid raw C symbols after C's local h_ prefix
            # too; those symbols need not themselves start with reserved M.
            candidate = namespace + str(counter) + "_" + name
            if candidate not in occupied and "h_" + candidate not in function_symbols:
                break
            counter += 1
        renames[name] = candidate
        occupied.add(candidate)
    for value in _nodes(roots):
        if isinstance(value, Param):
            value.name = renames.get(value.name, value.name)
        elif isinstance(value, Stmt) and value.kind in {"let", "for"}:
            value.data["name"] = renames.get(value.data["name"], value.data["name"])
        elif isinstance(value, Pattern):
            value.bindings = ["_" if name == "_" else renames.get(name, name)
                              for name in value.bindings]
        elif isinstance(value, Expr) and value.kind == "name" and isinstance(value.value, str):
            value.value = renames.get(value.value, value.value)
    function.return_origin = renames.get(function.return_origin, function.return_origin)
