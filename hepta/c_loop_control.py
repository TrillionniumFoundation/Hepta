"""Structure C loop jumps without adding jumps to the safe source language.

The input remains the retained Clang AST. This pass builds a separate lowering
tree for one loop, using initialized unsigned scalar flags and ordinary
conditionals. A jump only affects its nearest loop; nested loops are lowered
independently. Switch/goto remain unsupported; each source profile retains its
existing condition and expression admission rules.
"""
from __future__ import annotations

from .c_migrate import MigrationRejected


def _jumps_here(node: dict) -> bool:
    pending = [node]
    while pending:
        current = pending.pop()
        kind = current.get("kind")
        if kind in {"BreakStmt", "ContinueStmt"}:
            return True
        children = current.get("inner", [])
        if kind == "CompoundStmt":
            pending.extend(children)
        elif kind == "IfStmt":
            pending.extend(children[1:])
        # Nested loops own their jumps. Other control forms remain unsupported;
        # in particular a switch's break must never become a loop break.
    return False


def lower_loop_jumps(node: dict, serial: int) -> dict | None:
    """Return a distinct structured lowering, or None for an unchanged loop."""
    kind, children = node.get("kind"), node.get("inner", [])
    if kind not in {"WhileStmt", "DoStmt", "ForStmt"}:
        return None
    if kind == "ForStmt":
        if len(children) != 5 or children[1] or not all(children[i] for i in (2, 3, 4)):
            raise MigrationRejected("E_C_FOR", "C for loops require an explicit condition and increment")
        body, predicate = children[4], children[2]
    else:
        if len(children) != 2:
            raise MigrationRejected("E_C_CONTROL", "Unexpected loop AST")
        body, predicate = (children[1], children[0]) if kind == "WhileStmt" else children
    if not _jumps_here(body):
        return None

    scalar = {"qualType": "unsigned int"}
    prefix = "migration_loop_" + str(serial)

    def reference(name):
        return {"kind": "DeclRefExpr", "type": scalar,
                "referencedDecl": {"kind": "VarDecl", "id": prefix + ":" + name,
                                   "name": prefix + "_" + name}}

    def number(value):
        return {"kind": "IntegerLiteral", "type": scalar, "value": str(value)}

    def declaration(name):
        return {"kind": "DeclStmt", "inner": [
            {"kind": "VarDecl", "id": prefix + ":" + name,
             "name": prefix + "_" + name, "type": scalar, "inner": [number(1)]}]}

    def assign(name):
        return {"kind": "BinaryOperator", "opcode": "=", "type": scalar,
                "inner": [reference(name), number(0)]}

    def compound(statements):
        return {"kind": "CompoundStmt", "inner": statements}

    def conditional(name, statements):
        return {"kind": "IfStmt", "inner": [reference(name), compound(statements)]}

    def sequence(statements):
        reversed_result = []
        for statement in reversed(statements):
            lowered = rewrite(statement)
            if _jumps_here(statement) and reversed_result:
                # Guard the *whole suffix*, preserving the lexical scope of
                # declarations used by later statements in that suffix. Build
                # it iteratively so a wide input cannot exhaust Python's call
                # stack before the source emission depth budget checks it.
                guard = conditional("body", list(reversed(reversed_result)))
                reversed_result = [guard, lowered]
            else:
                reversed_result.append(lowered)
        return list(reversed(reversed_result))

    def rewrite(statement):
        statement_kind = statement.get("kind")
        inner = statement.get("inner", [])
        if statement_kind == "BreakStmt":
            return compound([assign("alive"), assign("body")])
        if statement_kind == "ContinueStmt":
            return assign("body")
        if statement_kind == "CompoundStmt":
            return {**statement, "inner": sequence(inner)}
        if statement_kind == "IfStmt":
            return {**statement, "inner": inner[:1] + [rewrite(child) for child in inner[1:]]}
        return statement

    guarded_predicate = {"kind": "BinaryOperator", "opcode": "&&",
                         "type": {"qualType": "int"},
                         "inner": [reference("alive"), predicate]}
    lowered_body = compound([declaration("body"), rewrite(body)])
    if kind == "WhileStmt":
        lowered_children = [guarded_predicate, lowered_body]
    elif kind == "DoStmt":
        lowered_children = [lowered_body, guarded_predicate]
    else:
        # C continue reaches the for increment; break does not. The existing
        # source lowerer accepts a structured statement in its increment slot.
        increment = conditional("alive", [children[3]])
        lowered_children = [children[0], children[1], guarded_predicate, increment, lowered_body]
    return compound([declaration("alive"), {**node, "inner": lowered_children}])

