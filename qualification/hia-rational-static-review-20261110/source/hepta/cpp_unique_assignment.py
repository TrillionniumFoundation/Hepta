"""Sequenced move assignment for the separately checked unique-array profile.

This adapter only handles complete, statically distinct local owners (or one
literal self move). Defaulted C++ member assignment releases destination fields
in declaration order, unlike the reverse order of ordinary destruction. The
generated HIA consumes old ownership and introduces a fresh binding; it never
overwrites a live linear Core value or adopts an escaped pointer.
"""
from __future__ import annotations

from .cpp_composed_migrate import _children, _qual, _reject
from .cpp_composed_project import _ProjectTranslator


class UniqueAssignmentTranslator(_ProjectTranslator):
    def __init__(self, *args):
        super().__init__(*args)
        self.move_assignment = None
        self.stats.update(owner_move_assignments=0, owner_self_move_assignments=0)

    def assignment_specials(self, assignments):
        copy_signature = f"{self.class_name} &(const {self.class_name} &)"
        move_signature = f"{self.class_name} &({self.class_name} &&) noexcept"
        copies = [node for node in assignments if _qual(node) == copy_signature]
        moves = [node for node in assignments if _qual(node) == move_signature]
        if len(copies) != 1 or len(moves) != 1 or len(assignments) != 2:
            _reject("Need deleted copy and defaulted noexcept move assignment", "E_CPP_UNIQUE_ASSIGNMENT")
        node = moves[0]
        self.guard(node)
        params = [child for child in _children(node) if child.get("kind") == "ParmVarDecl"]
        bodies = [child for child in _children(node) if child.get("kind") == "CompoundStmt"]
        if (node.get("explicitlyDefaulted") != "default" or node.get("explicitlyDeleted")
                or len(params) != 1 or _qual(params[0]) != self.class_name + " &&"
                or _children(params[0]) or len(bodies) > 1
                or len(_children(node)) != 1 + len(bodies)):
            _reject("Move assignment must be the complete defaulted member", "E_CPP_UNIQUE_ASSIGNMENT")
        self.guard(params[0])
        self.mark(node, "defaulted_forward_field_move_assignment")
        self.mark(params[0], "exclusive_move_assignment_parameter")
        self.move_assignment = node
        return [(copies[0], copy_signature, "deleted_assignment")]

    def additional_helpers(self):
        if self.move_assignment is None:
            _reject("Missing bound move-assignment member", "E_CPP_UNIQUE_ASSIGNMENT")
        # C++ defaulted assignment visits members from first to last. Moving
        # the source unique_ptr between releases has no external effect in the
        # exact default-deleter contract. Its owner identity is kept intact.
        drops = "\n".join("    HeptaLeaf_drop(move destination." + field["emitted"] + ");"
                          for field in self.fields.values())
        return ("pub fn HeptaComposite_assign(destination: take HeptaComposite, "
                "source: take HeptaComposite) -> HeptaComposite effects {alloc, block} {\n"
                + drops + "\n    return move source;\n}\n\n")

    def extension_statement(self, node, env, *, context, const, nested, scope_depth):
        node = self._unwrapped(node, {"ExprWithCleanups", "ParenExpr"})
        if node.get("kind") != "CXXOperatorCallExpr":
            return None
        if context != "lifecycle" or const or nested or scope_depth:
            _reject("Move assignment needs a complete top-level lifecycle statement",
                    "E_CPP_UNIQUE_ASSIGNMENT_SEQUENCE")
        children = _children(node)
        if (len(children) != 3 or _qual(node) != self.class_name
                or node.get("valueCategory") != "lvalue" or self.move_assignment is None):
            _reject("Only complete bound owner move-assignment statements are admitted",
                    "E_CPP_UNIQUE_ASSIGNMENT")
        callee = children[0]
        if (callee.get("kind") != "ImplicitCastExpr" or callee.get("castKind") != "FunctionToPointerDecay"
                or len(_children(callee)) != 1):
            _reject("Move assignment lacks its captured member reference", "E_CPP_UNIQUE_ASSIGNMENT")
        callee = _children(callee)[0]
        ref = callee.get("referencedDecl", {})
        if (callee.get("kind") != "DeclRefExpr" or _children(callee)
                or ref.get("kind") != "CXXMethodDecl" or ref.get("name") != "operator="
                or ref.get("id") != self.move_assignment["id"] or _qual(ref) != _qual(self.move_assignment)):
            _reject("Assignment does not bind to the captured defaulted member", "E_CPP_UNIQUE_ASSIGNMENT")
        destination = self._unwrapped(children[1], {"ParenExpr"})
        cast = children[2]
        if (cast.get("kind") != "CXXStaticCastExpr" or cast.get("castKind") != "NoOp"
                or cast.get("valueCategory") != "xvalue" or _qual(cast) != self.class_name
                or len(_children(cast)) != 1):
            _reject("Assignment requires an explicit complete-owner rvalue conversion",
                    "E_CPP_UNIQUE_ASSIGNMENT")
        source = self._unwrapped(_children(cast)[0], {"ParenExpr"})
        target_place, target_type, _ = self.place(destination, env, context=context, const=False)
        source_place, source_type, _ = self.place(source, env, context=context, const=False)
        target_id = destination.get("referencedDecl", {}).get("id")
        source_id = source.get("referencedDecl", {}).get("id")
        if (target_type != self.class_name or source_type != self.class_name
                or target_id not in env or source_id not in env):
            _reject("Assignment operands must be complete live local/by-value owners",
                    "E_CPP_UNIQUE_ASSIGNMENT")
        if target_id == source_id:
            # The exact leaf contract guards this == &other before touching
            # its unique_ptr or size. Every defaulted field self move is inert.
            self.stats["owner_self_move_assignments"] += 1
            return []
        replacement = self.fresh("assigned")
        env[source_id]["alive"] = False
        env[target_id]["emitted"] = replacement
        self.stats["owner_move_assignments"] += 1
        return [f"let mut {replacement} = HeptaComposite_assign(move {target_place}, move {source_place});"]
