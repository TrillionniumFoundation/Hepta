"""Conservative definite assignment for the structured C migration subset.

This is a precondition for giving an otherwise uninitialized scalar local an
unobservable zero initializer in safe Hepta. It is not C undefined-behavior
inference: every possible structured path must assign before a read. While/for
loops may execute zero times; a do body runs before its first condition. A
terminating branch does not reach its successor. Unknown
control flow rejects. The ordinary expression lowerer still admits or rejects
the operations themselves.
"""
from __future__ import annotations

from .c_migrate import MigrationRejected


def _nodes(node):
    yield node
    for child in node.get("inner", []):
        if isinstance(child, dict):
            yield from _nodes(child)


def check_definite_assignment(function, is_scalar):
    body = function["body"]
    locals_ = {node["id"]: node for node in _nodes(body)
               if node.get("kind") == "VarDecl" and isinstance(node.get("id"), str)}
    deferred = []
    for node in locals_.values():
        if node.get("inner"):
            continue
        try:
            scalar = is_scalar(node["type"])
        except MigrationRejected:
            # Pointer/aggregate profiles keep their existing entry checks.
            # This pass grants zero initialization to scalar locals only.
            continue
        if scalar:
            deferred.append(node)
    if not deferred:
        return {"deferred_scalar_initializers": 0, "checked": False}

    def reads(node, assigned):
        for part in _nodes(node):
            reference = part.get("referencedDecl", {})
            key = reference.get("id")
            if part.get("kind") == "DeclRefExpr" and key in locals_ and key not in assigned:
                raise MigrationRejected("E_C_UNINITIALIZED",
                    "Local may be read before assignment on a structured path: " + locals_[key]["name"])

    def target(node, assigned, *, read):
        if node.get("kind") == "DeclRefExpr":
            key = node.get("referencedDecl", {}).get("id")
            if read:
                reads(node, assigned)
            return key
        reads(node, assigned)
        return None

    def stmt(node, assigned):
        assigned = set(assigned)
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "CompoundStmt":
            reachable = True
            for child in children:
                state = stmt(child, assigned)
                if state is None:
                    reachable = False
                else:
                    assigned = state
            return assigned if reachable else None
        if kind == "NullStmt":
            return assigned
        if kind == "DeclStmt":
            for child in children:
                if child.get("kind") != "VarDecl" or child.get("storageClass") or len(child.get("inner", [])) > 1:
                    raise MigrationRejected("E_C_LOCAL", "Require ordinary local declarations with at most one initializer")
                if child.get("inner"):
                    reads(child["inner"][0], assigned)
                    assigned.add(child["id"])
            return assigned
        if kind == "ReturnStmt":
            reads(node, assigned)
            return None
        if kind == "IfStmt" and len(children) in {2, 3}:
            reads(children[0], assigned)
            yes = stmt(children[1], assigned)
            no = stmt(children[2], assigned) if len(children) == 3 else assigned
            live = [state for state in (yes, no) if state is not None]
            return set.intersection(*live) if live else None
        if kind == "WhileStmt" and len(children) == 2:
            reads(children[0], assigned)
            stmt(children[1], assigned)
            return assigned
        if kind == "DoStmt" and len(children) == 2 and children[0].get("kind") == "CompoundStmt":
            # No path reaching the condition can skip the first body. Check
            # reads inside that body using the incoming state, and only then
            # credit its definitely assigned values at the condition/exit.
            after_body = stmt(children[0], assigned)
            if after_body is None:
                return None
            reads(children[1], after_body)
            return after_body
        if kind == "ForStmt" and len(children) == 5 and not children[1] and all(children[i] for i in (2, 3, 4)):
            if children[0]:
                assigned = stmt(children[0], assigned)
                if assigned is None:
                    raise MigrationRejected("E_C_UNINITIALIZED", "Terminating for initializer is unsupported")
            reads(children[2], assigned)
            after_body = stmt(children[4], assigned)
            if after_body is not None:
                stmt(children[3], after_body)
            return assigned
        if kind in {"BinaryOperator", "CompoundAssignOperator"} and len(children) == 2:
            operation = node.get("opcode")
            if kind == "BinaryOperator" and operation == ",":
                left = stmt(children[0], assigned)
                if left is None:
                    raise MigrationRejected("E_C_UNINITIALIZED", "Terminating comma operand is unsupported")
                return stmt(children[1], left)
            if operation == "=" or kind == "CompoundAssignOperator":
                key = target(children[0], assigned, read=kind == "CompoundAssignOperator")
                reads(children[1], assigned)
                if key in locals_:
                    assigned.add(key)
                return assigned
        if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"} and len(children) == 1:
            reads(children[0], assigned)
            return assigned
        if kind == "CallExpr":
            reads(node, assigned)
            return assigned
        raise MigrationRejected("E_C_UNINITIALIZED_CONTROL",
            "Deferred initialization requires supported structured control flow: " + str(kind))

    stmt(body, {parameter["id"] for parameter in function["params"]})
    return {"deferred_scalar_initializers": len(deferred), "checked": True,
            "policy": "all_structured_paths_assign_before_read; while_for_may_execute_zero_times; do_executes_body_before_condition"}
