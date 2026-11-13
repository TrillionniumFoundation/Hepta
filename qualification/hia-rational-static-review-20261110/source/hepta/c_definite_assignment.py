"""Conservative definite assignment for the structured C migration subset.

This is a precondition for giving an otherwise uninitialized scalar local an
unobservable zero initializer in safe Hepta. It is not C undefined-behavior
inference: every possible structured path must assign before a read. Pre-test
loops may execute zero times; a do-loop executes its body before its condition.
Normal, break and continue exits are tracked separately. A terminating branch
does not reach its successor. Unknown control flow rejects. The ordinary
expression lowerer still admits or rejects the operations themselves.
"""
from __future__ import annotations

from dataclasses import dataclass, field

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

    @dataclass
    class Flow:
        normal: set | None
        breaks: list[set] = field(default_factory=list)
        continues: list[set] = field(default_factory=list)

    def merge(states):
        live = [state for state in states if state is not None]
        return set.intersection(*live) if live else None

    def stmt(node, assigned, loop_depth=0):
        assigned = set(assigned)
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "CompoundStmt":
            result = Flow(assigned)
            for child in children:
                if result.normal is None:
                    # Subsequent nodes cannot contribute initialized values
                    # or exits. Their language support is still checked by
                    # the ordinary lowerer, which traverses the entire AST.
                    break
                state = stmt(child, result.normal, loop_depth)
                result.normal = state.normal
                result.breaks.extend(state.breaks)
                result.continues.extend(state.continues)
            return result
        if kind == "NullStmt":
            return Flow(assigned)
        if kind == "DeclStmt":
            for child in children:
                if child.get("kind") != "VarDecl" or child.get("storageClass") or len(child.get("inner", [])) > 1:
                    raise MigrationRejected("E_C_LOCAL", "Require ordinary local declarations with at most one initializer")
                if child.get("inner"):
                    reads(child["inner"][0], assigned)
                    assigned.add(child["id"])
                else:
                    # A loop-local declaration starts a new object on every
                    # entry; a preceding lifetime cannot initialize it.
                    assigned.discard(child["id"])
            return Flow(assigned)
        if kind == "ReturnStmt":
            reads(node, assigned)
            return Flow(None)
        if kind in {"BreakStmt", "ContinueStmt"} and loop_depth:
            return Flow(None, breaks=[assigned]) if kind == "BreakStmt" else Flow(None, continues=[assigned])
        if kind == "IfStmt" and len(children) in {2, 3}:
            reads(children[0], assigned)
            yes = stmt(children[1], assigned, loop_depth)
            no = stmt(children[2], assigned, loop_depth) if len(children) == 3 else Flow(assigned)
            return Flow(merge([yes.normal, no.normal]), yes.breaks + no.breaks,
                        yes.continues + no.continues)
        if kind == "WhileStmt" and len(children) == 2:
            reads(children[0], assigned)
            body_flow = stmt(children[1], assigned, loop_depth + 1)
            for state in [body_flow.normal, *body_flow.continues]:
                if state is not None:
                    reads(children[0], state)
            # The zero-iteration path is always retained conservatively.
            return Flow(merge([assigned, *body_flow.breaks]))
        if kind == "DoStmt" and len(children) == 2:
            body_flow = stmt(children[0], assigned, loop_depth + 1)
            tested = [state for state in [body_flow.normal, *body_flow.continues]
                      if state is not None]
            for state in tested:
                reads(children[1], state)
            # Break bypasses the postcondition and may bypass an assignment.
            # Continue reaches the postcondition, but skips the body suffix.
            return Flow(merge(tested + body_flow.breaks))
        if kind == "ForStmt" and len(children) == 5 and not children[1] and all(children[i] for i in (2, 3, 4)):
            if children[0]:
                initial = stmt(children[0], assigned, loop_depth)
                if initial.normal is None or initial.breaks or initial.continues:
                    raise MigrationRejected("E_C_UNINITIALIZED", "Terminating for initializer is unsupported")
                assigned = initial.normal
            reads(children[2], assigned)
            body_flow = stmt(children[4], assigned, loop_depth + 1)
            for state in [body_flow.normal, *body_flow.continues]:
                if state is not None:
                    increment = stmt(children[3], state, loop_depth + 1)
                    if increment.normal is not None:
                        reads(children[2], increment.normal)
            return Flow(merge([assigned, *body_flow.breaks]))
        if kind in {"BinaryOperator", "CompoundAssignOperator"} and len(children) == 2:
            operation = node.get("opcode")
            if kind == "BinaryOperator" and operation == ",":
                left = stmt(children[0], assigned, loop_depth)
                if left.normal is None or left.breaks or left.continues:
                    raise MigrationRejected("E_C_UNINITIALIZED", "Terminating comma operand is unsupported")
                return stmt(children[1], left.normal, loop_depth)
            if operation == "=" or kind == "CompoundAssignOperator":
                key = target(children[0], assigned, read=kind == "CompoundAssignOperator")
                reads(children[1], assigned)
                if key in locals_:
                    assigned.add(key)
                return Flow(assigned)
        if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"} and len(children) == 1:
            reads(children[0], assigned)
            return Flow(assigned)
        if kind == "CallExpr":
            reads(node, assigned)
            return Flow(assigned)
        raise MigrationRejected("E_C_UNINITIALIZED_CONTROL",
            "Deferred initialization requires supported structured control flow: " + str(kind))

    stmt(body, {parameter["id"] for parameter in function["params"]})
    return {"deferred_scalar_initializers": len(deferred), "checked": True,
            "policy": "all_structured_paths_assign_before_read; pretest_loops_may_execute_zero_times; "
                      "do_body_precedes_test; break_exits_loop; continue_reaches_increment_or_test"}
