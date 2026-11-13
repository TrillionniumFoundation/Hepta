"""Lower a straight-line prefix of initialized read-pointer aliases.

The declarations and their first assignments must precede every other body
statement. They can only name already contracted read parameters; no pointer
arithmetic, path-sensitive initialization, mutation, or reinterpretation is
inferred. Aliases share the same safe slice expression.
"""
from __future__ import annotations

import re

from .c_migrate import MigrationRejected


def lower_read_alias_prefix(translator, fn: dict) -> list[dict]:
    body = fn["body"].get("inner", [])
    pending, aliases = {}, []
    offset = 0
    for statement in body:
        declarations = statement.get("inner", [])
        if statement.get("kind") != "DeclStmt" or not declarations or not all(
            child.get("kind") == "VarDecl" and "*" in child.get("type", {}).get("qualType", "")
            for child in declarations
        ):
            break
        for child in declarations:
            raw = child.get("type", {}).get("qualType", "")
            pointer = re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", raw)
            if pointer is None or child.get("storageClass") or child.get("inner"):
                raise MigrationRejected("E_C_POINTER_ALIAS", "Read-alias prefix requires simple automatic pointer declarations followed by direct initialization")
            elem = translator.typ(pointer[2].strip())
            if elem not in {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "usize", "isize", "f32", "f64"}:
                raise MigrationRejected("E_C_POINTER_ALIAS", "Read-alias element must be a modeled primitive")
            pending[child["id"]] = (child["name"], elem)
        offset += 1
    while pending:
        if offset >= len(body):
            raise MigrationRejected("E_C_POINTER_ALIAS", "Uninitialized read-pointer alias")
        statement = body[offset]
        children = statement.get("inner", [])
        if statement.get("kind") != "BinaryOperator" or statement.get("opcode") != "=" or len(children) != 2 or children[0].get("kind") != "DeclRefExpr":
            raise MigrationRejected("E_C_POINTER_ALIAS", "Read aliases must be initialized in an unconditional straight-line prefix")
        ident = children[0].get("referencedDecl", {}).get("id")
        if ident not in pending:
            raise MigrationRejected("E_C_POINTER_ALIAS", "Duplicate or unrelated pointer initialization")
        name, elem = pending.pop(ident)
        value = translator.expr(children[1])
        parameter = next((p for p in fn["params"] if p["pointer"] and value.text == "p_" + p["name"]), None)
        if parameter is None or value.typ != "slice:" + elem or translator.binding_modes.get(value.text) != "read":
            raise MigrationRejected("E_C_POINTER_ALIAS", "Alias must retain the exact contracted read-pointer element type")
        translator.bindings[ident] = value
        aliases.append({"name": name, "parameter": parameter["name"], "element": elem,
                        "lowering": "same_read_slice_no_runtime_pointer"})
        offset += 1
    if aliases:
        fn["read_pointer_aliases"] = aliases
    return body[offset:]
