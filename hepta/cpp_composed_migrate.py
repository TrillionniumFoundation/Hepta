"""Translate bounded C++ resource composition from actual declaration-bound AST.

The byte-owner leaf has a checked complete protocol. Composite initialization,
algorithms and lifecycle control flow are lowered structurally, never selected
by matching one fixed composite body. Unsupported input rejects as a whole.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .c_migrate import MigrationRejected, _load_bounded_clang_ast, _run
from .cpp2hepta import _model
from .cpp_owned_migrate import _CPP_PROTOCOL, _HEPTA_PROTOCOL, _canonical, _nodes, _normalized, _sha
from .pipeline import analyze, compiler_hash
from .resource_lowering import lower_resource_ir
from .resource_ir import ResourceIRError, verify_resource_ir
from .artifact_publication import (PublicationRejected, publish_verified,
                                   verify_published, withdraw_own_link)

PROFILE = "cpp20-composed-exclusive-byte-owners-semantic-v1"
SCHEMA = "hepta.cpp-composed-migration.v1"
TYPES = {"bool": "bool", "unsigned char": "u8", "unsigned int": "u32", "int": "i32",
         "unsigned long": "usize", "unsigned long long": "u64"}
LIMITS = {"whole_cpp_raii_supported": False, "source_equivalence_proved": False,
          "cpp_class_abi_preserved": False, "whole_language_memory_safety_proved": False,
          "foreign_cpp_implementation_retained": False}
EFFECTS = "effects {alloc, block, panic, write}"
LEAF_CPP = _CPP_PROTOCOL.split("\nunsigned long long run_owned")[0]
LEAF_HEPTA = _HEPTA_PROTOCOL.split("\npub fn run_owned")[0].replace("OwnedBytes", "HeptaLeaf")


def _reject(message, code="E_CPP_COMPOSED_PROFILE"):
    raise MigrationRejected(code, message)


def _children(node):
    result = node.get("inner", [])
    if not isinstance(result, list) or any(not isinstance(child, dict) for child in result):
        _reject("Malformed Clang children", "E_CPP_COMPOSED_AST")
    return result


def _qual(node):
    return node.get("type", {}).get("qualType", "")


def _scalar(node):
    qual = _qual(node).removeprefix("const ")
    if qual not in TYPES:
        _reject("Unsupported scalar representation: " + qual, "E_CPP_COMPOSED_TYPE")
    return TYPES[qual]


def _name(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z][A-Za-z_0-9]{0,127}", value) is None:
        _reject("Unsupported source identifier")
    return value


def _without_usage(value):
    if isinstance(value, list):
        return [_without_usage(item) for item in value]
    if isinstance(value, dict):
        return {key: _without_usage(item) for key, item in value.items() if key not in {"isUsed", "isReferenced"}}
    return value


class _Translator:
    def __init__(self, tree, leaf, composite, operation):
        self.tree, self.leaf, self.composite, self.operation = tree, leaf, composite, operation
        self.leaf_name, self.class_name = _name(leaf.get("name")), _name(composite.get("name"))
        _name(operation.get("name"))
        self.roles, self.fields, self.methods = {}, {}, {}
        self.serial = 0
        self.stats = {"scalar_expressions": 0, "if_statements": 0, "scalar_locals": 0,
                      "owner_constructions": 0, "owner_moves": 0, "source_returns": 0}
        self.mark(composite, "composite_resource_class")
        self.mark(operation, "translated_lifecycle")
        for node, _ in _nodes(leaf):
            if str(node.get("kind", "")).endswith("Decl"):
                self.mark(node, "exact_leaf_protocol")
        methods = [n for n in _children(leaf) if n.get("kind") == "CXXMethodDecl" and n.get("name") != "operator="]
        rules = [("size", "usize", [], True), ("data", "slice", [], True), ("fill", "Unit", ["u8"], False),
                 ("get", "u8", ["usize"], True), ("set", "Unit", ["usize", "u8"], False)]
        if len(methods) != len(rules):
            _reject("Leaf method inventory differs")
        for node, (role, returns, params, const) in zip(methods, rules):
            self.methods[node["id"]] = {"owner": self.leaf_name, "emitted": "HeptaLeaf_" + role,
                "returns": returns, "parameters": params, "const": const, "name": node.get("name")}

    def fresh(self, prefix):
        self.serial += 1
        return prefix + str(self.serial)

    def mark(self, node, role):
        ident = node.get("id")
        if not isinstance(ident, str) or ident in self.roles:
            _reject("Missing or repeated declaration identity", "E_CPP_COMPOSED_INVENTORY")
        self.roles[ident] = role

    def guard(self, node):
        if any(node.get(flag) for flag in ("storageClass", "virtual", "pure", "variadic", "constexpr",
                "consteval", "inline", "mutable", "isMutable", "isBitfield", "hasInClassInitializer", "isInvalid")):
            _reject("Unmodeled declaration qualifier or storage")
        if any(child.get("kind", "").endswith("Attr") for child in _children(node)):
            _reject("Source attributes require separate rules")

    def params(self, node):
        result = {}
        for index, param in enumerate(child for child in _children(node) if child.get("kind") == "ParmVarDecl"):
            self.guard(param)
            if index >= 12 or _children(param) or param.get("init"):
                _reject("Only bounded scalar parameters without defaults are admitted")
            _name(param.get("name")); self.mark(param, "scalar_parameter")
            result[param["id"]] = {"emitted": "arg" + str(index), "type": _scalar(param),
                "cpp_type": _qual(param), "source_name": param["name"], "alive": True}
        return result

    def signature(self, node, *, constructor=False):
        self.guard(node)
        params = self.params(node)
        sig = re.fullmatch(r"(.+) \(([^()]*)\)( const)?( noexcept)?", _qual(node))
        if sig is None or sig[2] != ", ".join(p["cpp_type"] for p in params.values()) or (not constructor and not sig[4]):
            _reject("Unmodeled callable signature or exception specification")
        returns = "Unit" if sig[1] == "void" else TYPES.get(sig[1])
        if returns is None or (constructor and (returns != "Unit" or sig[3] or sig[4])):
            _reject("Fallible constructors and noexcept scalar/Unit methods only")
        if not constructor and not sig[3] and node["kind"] == "CXXMethodDecl" and returns != "Unit":
            _reject("Value-returning methods must be const; expression order must be side-effect-free")
        bodies = [c for c in _children(node) if c.get("kind") == "CompoundStmt"]
        allowed = {"ParmVarDecl", "CompoundStmt"} | ({"CXXCtorInitializer"} if constructor else set())
        if len(bodies) != 1 or any(c.get("kind") not in allowed for c in _children(node)):
            _reject("Callable must have one complete inventoried body")
        return returns, bool(sig[3]), params, bodies[0]

    def place(self, node, env, *, context, const):
        kind, children = node.get("kind"), _children(node)
        if kind in {"ParenExpr", "ImplicitCastExpr"}:
            if len(children) != 1 or (kind == "ImplicitCastExpr" and node.get("castKind") != "NoOp"):
                _reject("Only qualification-preserving owner references are admitted")
            return self.place(children[0], env, context=context, const=const)
        if kind == "MemberExpr" and context == "method":
            field = self.fields.get(node.get("referencedMemberDecl"))
            if (field is None or node.get("isArrow") is not True or len(children) != 1
                    or children[0].get("kind") != "CXXThisExpr" or _children(children[0])
                    or _qual(children[0]) != ("const " if const else "") + self.class_name + " *"
                    or _qual(node) != ("const " if const else "") + self.leaf_name
                    or node.get("name") != field["name"]):
                _reject("Member place must be this class's own inventoried leaf field")
            return "receiver." + field["emitted"], self.leaf_name, const
        if kind == "DeclRefExpr" and not children:
            decl = node.get("referencedDecl", {}); value = env.get(decl.get("id"))
            if (value is None or value["type"] != "owner" or not value["alive"]
                    or decl.get("kind") != "VarDecl" or decl.get("name") != value["source_name"]
                    or _qual(node) != self.class_name or _qual(decl) != self.class_name):
                _reject("Owner is not a live local; moved-from access rejects", "E_CPP_COMPOSED_MOVE")
            return value["emitted"], self.class_name, False
        _reject("Unsupported owner place or pointer escape", "E_CPP_COMPOSED_REFERENCE")

    def call(self, node, env, *, context, const, allow_effect=False):
        children = _children(node)
        if node.get("kind") != "CXXMemberCallExpr" or not children:
            _reject("Only selected member calls are admitted")
        member = children[0]; info = self.methods.get(member.get("referencedMemberDecl"))
        if (member.get("kind") != "MemberExpr" or member.get("isArrow") is not False or info is None
                or member.get("name") != info["name"] or len(_children(member)) != 1
                or len(children) - 1 != len(info["parameters"])):
            _reject("Call does not bind to an inventoried exact member", "E_CPP_COMPOSED_CALL")
        place, owner, readonly = self.place(_children(member)[0], env, context=context, const=const)
        if owner != info["owner"] or (not info["const"] and (readonly or not allow_effect)):
            _reject("Mutating calls require standalone sequenced statements on mutable owners")
        args = []
        for argument, typ in zip(children[1:], info["parameters"]):
            value, actual = self.expr(argument, env, context=context, const=const)
            if actual != typ:
                _reject("Member argument's promoted type differs")
            args.append(value)
        actual = "slice" if _qual(node) == "const unsigned char *" else "Unit" if _qual(node) == "void" else _scalar(node)
        if actual != info["returns"]:
            _reject("Member result representation differs")
        mode = "read" if info["const"] else "mut"
        return info["emitted"] + "(" + ", ".join([mode + " " + place, *args]) + ")", actual

    def expr(self, node, env, *, context, const=False):
        self.stats["scalar_expressions"] += 1
        kind, children = node.get("kind"), _children(node)
        if kind == "CXXMemberCallExpr":
            result = self.call(node, env, context=context, const=const)
            if result[1] in {"Unit", "slice"}:
                _reject("A pointer view may only be consumed immediately by checked indexing")
            return result
        typ = _scalar(node)
        if kind in {"ImplicitCastExpr", "CXXStaticCastExpr", "ParenExpr"}:
            cast = node.get("castKind")
            if len(children) != 1 or (kind != "ParenExpr" and cast not in {"NoOp", "LValueToRValue", "IntegralCast", "IntegralToBoolean"}):
                _reject("Unmodeled scalar conversion")
            value, original = self.expr(children[0], env, context=context, const=const)
            if typ == original:
                return value, typ
            if cast == "IntegralToBoolean" and typ == "bool" and original != "bool":
                return f"({value} != 0)", typ
            if cast != "IntegralCast" or typ == "bool" or original == "bool":
                _reject("Only actual Clang integer conversions are lowered")
            return f"({value} as {typ})", typ
        if kind in {"IntegerLiteral", "CXXBoolLiteralExpr"} and not children:
            if typ == "bool":
                if type(node.get("value")) is not bool:
                    _reject("Invalid Boolean literal")
                return str(node["value"]).lower(), typ
            value = int(node.get("value", "invalid"))
            width = {"u8": 8, "u32": 32, "i32": 32, "u64": 64, "usize": 64}[typ]
            lower, upper = (-(2**31), 2**31 - 1) if typ == "i32" else (0, 2**width - 1)
            if not lower <= value <= upper:
                _reject("Out-of-representation literal")
            return f"({value} as {typ})", typ
        if kind == "DeclRefExpr" and not children:
            decl = node.get("referencedDecl", {}); value = env.get(decl.get("id"))
            if (value is None or not value["alive"] or value["type"] != typ
                    or value["source_name"] != decl.get("name") or _qual(decl) != value["cpp_type"]
                    or decl.get("kind") not in {"ParmVarDecl", "VarDecl"}):
                _reject("Scalar reference does not bind to a live local/parameter")
            return value["emitted"], typ
        if kind == "ArraySubscriptExpr" and len(children) == 2 and typ == "u8":
            view, returned = self.call(children[0], env, context=context, const=const)
            index, index_type = self.expr(children[1], env, context=context, const=const)
            if returned != "slice" or index_type != "usize":
                _reject("Only immediate byte-view indexing with usize index is admitted")
            return f"{view}[{index}]", "u8"
        if kind == "BinaryOperator" and len(children) == 2:
            left, lt = self.expr(children[0], env, context=context, const=const)
            right, rt = self.expr(children[1], env, context=context, const=const)
            op = node.get("opcode")
            if op in {"&&", "||"} and (typ, lt, rt) == ("bool", "bool", "bool"):
                return f"({left} {op} {right})", typ
            if op in {"==", "!=", "<", "<=", ">", ">="} and lt == rt and typ == "bool":
                return f"({left} {op} {right})", typ
            if lt != rt or lt != typ or typ == "bool":
                _reject("Binary operators require actual Clang-converted scalar types")
            if op in {"+", "-", "*"}:
                if typ.startswith("u"):
                    builtin = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
                    return f"{builtin}({left}, {right})", typ
                return f"({left} {op} {right})", typ
            if op in {"^", "&", "|"} and typ.startswith("u"):
                return f"({left} {op} {right})", typ
            _reject("Unsupported binary operator or signed bitwise semantics")
        if kind == "UnaryOperator" and len(children) == 1 and node.get("opcode") == "!" and typ == "bool":
            value, actual = self.expr(children[0], env, context=context, const=const)
            if actual == "bool":
                return f"(!{value})", typ
        _reject("Unsupported expression: " + str(kind), "E_CPP_COMPOSED_EXPRESSION")

    def cleanup(self, env):
        return ["HeptaComposite_drop(move " + value["emitted"] + ");"
                for value in reversed(list(env.values())) if value["type"] == "owner" and value["alive"]]

    def statements(self, statements, env, *, context, returns, const=False, depth=1,
                   constructor_fields=(), catch=None, nested=False,
                   scope_ids=None, scope_depth=0):
        # Allocation success arms recurse over the rest of this same C++ scope.
        # Their generated match blocks do not create a new source lifetime.
        # Branches and explicit compound statements do create a source scope:
        # only owners introduced there are consumed on ordinary fallthrough.
        if scope_ids is None:
            scope_ids = frozenset(env)
        if scope_depth > 16:
            _reject("Lexical ownership nesting exceeds sixteen scopes", "E_CPP_COMPOSED_SCOPE")
        lines, indent = [], "    " * depth
        for offset, node in enumerate(statements):
            kind, children = node.get("kind"), _children(node)
            if kind == "IfStmt" and len(children) in {2, 3} and all(k not in node for k in ("hasInit", "hasVar", "isConstexpr")):
                self.stats["if_statements"] += 1
                predicate, typ = self.expr(children[0], env, context=context, const=const)
                if typ != "bool" or any(c.get("kind") != "CompoundStmt" for c in children[1:]):
                    _reject("Conditions must be Boolean and branches explicit compound statements")
                states, terminated = [], []
                lines.append(indent + "if " + predicate + " {")
                for index, branch in enumerate(children[1:]):
                    if index:
                        lines.append(indent + "else {")
                    branch_env = copy.deepcopy(env)
                    branch_lines, done = self.statements(_children(branch), branch_env, context=context, returns=returns,
                        const=const, depth=depth + 1, constructor_fields=constructor_fields, catch=catch,
                        nested=True, scope_depth=scope_depth + 1)
                    lines += branch_lines + [indent + "}"]; states.append(branch_env); terminated.append(done)
                if len(states) == 1:
                    states.append(copy.deepcopy(env)); terminated.append(False)
                continuations = [state for state, done in zip(states, terminated) if not done]
                if not continuations:
                    if offset != len(statements) - 1:
                        _reject("Unreachable statements are not silently skipped")
                    return lines, True
                for ident in env:
                    live = [state[ident]["alive"] for state in continuations]
                    if len(set(live)) != 1:
                        _reject("Conditional ownership changes need matching continuation states")
                    env[ident]["alive"] = live[0]
            elif kind == "CompoundStmt":
                scoped = copy.deepcopy(env)
                block_lines, done = self.statements(children, scoped, context=context, returns=returns,
                    const=const, depth=depth, constructor_fields=constructor_fields, catch=catch,
                    nested=True, scope_depth=scope_depth + 1)
                # All generated identifiers are fresh. Flattening a source block
                # is safe after its explicit exits and cleanup are emitted; its
                # declarations never enter the enclosing source environment.
                lines += block_lines
                if done:
                    if offset != len(statements) - 1:
                        _reject("Unreachable statements after a terminating scope")
                    return lines, True
                for ident in env:
                    env[ident]["alive"] = scoped[ident]["alive"]
            elif kind == "ReturnStmt" and context != "constructor":
                self.stats["source_returns"] += 1
                if returns == "Unit" and not children:
                    lines += [indent + line for line in self.cleanup(env)] + [indent + "return;"]
                elif len(children) == 1:
                    value, typ = self.expr(children[0], env, context=context, const=const)
                    if typ != returns:
                        _reject("Return type differs from actual scalar result")
                    result = self.fresh("result")
                    lines += [indent + f"let {result}: {typ} = {value};"]
                    lines += [indent + line for line in self.cleanup(env)] + [indent + "return " + result + ";"]
                else:
                    _reject("Return needs one scalar value")
                if offset != len(statements) - 1:
                    _reject("Unreachable statements after return")
                return lines, True
            elif kind == "CXXThrowExpr" and context == "constructor" and len(children) == 1:
                literal = children[0]
                if literal.get("kind") != "IntegerLiteral" or _qual(literal) != "int" or not 3 <= int(literal.get("value", -1)) <= 255:
                    _reject("Composite constructor may throw only a literal error code from 3 through 255")
                lines += [indent + f"HeptaLeaf_drop(move {field});" for field in reversed(constructor_fields)]
                lines.append(indent + "return Result::Err(" + literal["value"] + ");")
                if offset != len(statements) - 1:
                    _reject("Unreachable statements after throw")
                return lines, True
            elif kind == "CXXMemberCallExpr" and context != "constructor":
                value, typ = self.call(node, env, context=context, const=const, allow_effect=True)
                if typ != "Unit":
                    _reject("Discarding non-Unit member results is outside this profile")
                lines.append(indent + value + ";")
            elif kind == "DeclStmt" and len(children) == 1 and children[0].get("kind") == "VarDecl":
                variable = children[0]; self.guard(variable); name = _name(variable.get("name"))
                if len(_children(variable)) != 1 or not variable.get("init"):
                    _reject("Every local must have exactly one checked initializer")
                initializer = _children(variable)[0]
                self.mark(variable, "owner_local" if _qual(variable) == self.class_name else "scalar_local")
                emitted = self.fresh("local")
                if _qual(variable) == self.class_name:
                    if context != "lifecycle" or initializer.get("kind") != "CXXConstructExpr":
                        _reject("Owner construction/moves require the checked lifecycle body")
                    if _qual(initializer) != self.class_name or initializer.get("constructionKind") != "complete":
                        _reject("Unsupported owner construction kind")
                    arguments = _children(initializer)
                    entry = {"type": "owner", "cpp_type": self.class_name, "source_name": name,
                             "emitted": emitted, "alive": True}
                    if initializer.get("ctorType", {}).get("qualType") == f"void ({self.class_name} &&) noexcept":
                        if (len(arguments) != 1 or arguments[0].get("kind") != "CXXStaticCastExpr"
                                or arguments[0].get("valueCategory") != "xvalue" or arguments[0].get("castKind") != "NoOp"
                                or _qual(arguments[0]) != self.class_name or len(_children(arguments[0])) != 1):
                            _reject("Owner move requires an explicit checked rvalue conversion")
                        origin = _children(arguments[0])[0]
                        place, _, _ = self.place(origin, env, context=context, const=const)
                        ident = origin.get("referencedDecl", {}).get("id")
                        if ident not in env:
                            _reject("Move source must be a complete live owner local")
                        env[ident]["alive"] = False
                        lines.append(indent + f"let mut {emitted} = HeptaComposite_move(move {place});")
                        env[variable["id"]] = entry; self.stats["owner_moves"] += 1
                    else:
                        if initializer.get("ctorType", {}).get("qualType") != self.ctor_signature or len(arguments) != len(self.ctor_params):
                            _reject("Owner initializer does not bind to selected fallible constructor")
                        values = []
                        for argument, param in zip(arguments, self.ctor_params.values()):
                            value, typ = self.expr(argument, env, context=context)
                            if typ != param["type"]:
                                _reject("Constructor argument representation differs")
                            values.append(value)
                        self.stats["owner_constructions"] += 1; error = self.fresh("error")
                        lines += [indent + "match HeptaComposite_new(" + ", ".join(values) + ") {", indent + "    Result::Err(" + error + ") => {"]
                        lines += [indent + "        " + line for line in self.cleanup(env)]
                        lines += [indent + "        " + line for line in self.catch_lines(error, catch)]
                        lines += [indent + "    },", indent + "    Result::Ok(" + emitted + "value) => {",
                                  indent + "        let mut " + emitted + " = move " + emitted + "value;"]
                        env[variable["id"]] = entry
                        rest, done = self.statements(statements[offset + 1:], env, context=context,
                            returns=returns, const=const, depth=depth + 2, catch=catch,
                            nested=nested, scope_ids=scope_ids, scope_depth=scope_depth)
                        if not done and not nested:
                            _reject("Lifecycle must return and consume all live owners")
                        return lines + rest + [indent + "    },", indent + "}"], done
                else:
                    typ = _scalar(variable); value, actual = self.expr(initializer, env, context=context, const=const)
                    if typ != actual:
                        _reject("Scalar local initialization changes representation")
                    env[variable["id"]] = {"type": typ, "cpp_type": _qual(variable), "source_name": name, "emitted": emitted, "alive": True}
                    lines.append(indent + f"let {emitted}: {typ} = {value};"); self.stats["scalar_locals"] += 1
            else:
                _reject("Unsupported statement: " + str(kind), "E_CPP_COMPOSED_STATEMENT")
        if nested:
            locals_ = {ident: value for ident, value in env.items() if ident not in scope_ids}
            lines += [indent + line for line in self.cleanup(locals_)]
            for value in locals_.values():
                if value["type"] == "owner":
                    value["alive"] = False
        return lines, False

    def catch_lines(self, error, catch):
        if catch is None:
            _reject("Fallible construction must have inventoried handlers")
        return [f"if {error} == 1 {{ return {catch['allocation']}; }}", f"let caughtcode: i32 = {error} as i32;",
                "return " + catch["integer"] + ";"]

    def translate(self):
        cls = self.composite
        if (cls.get("tagUsed") not in {"class", "struct"} or not cls.get("completeDefinition") or cls.get("bases")
                or cls.get("definitionData", {}).get("isPolymorphic")):
            _reject("Only complete non-polymorphic composition without inheritance is admitted")
        self.guard(cls)
        constructors, moves, copies, assignments, destructors, ordinary = [], [], [], [], [], []
        for node in _children(cls):
            kind = node.get("kind")
            if node.get("isImplicit"):
                if kind != "CXXRecordDecl" or node.get("name") != self.class_name or _children(node):
                    _reject("Unmodeled implicit composite member")
                self.mark(node, "injected_class_name")
            elif kind == "AccessSpecDecl" and node.get("access") in {"public", "private"} and not _children(node):
                self.mark(node, "visibility_replaced_by_closed_free_functions")
            elif kind == "FieldDecl":
                self.guard(node)
                if _qual(node) != self.leaf_name or _children(node):
                    _reject("Composite fields must be complete selected leaf owners")
                self.mark(node, "owned_leaf_field")
                self.fields[node["id"]] = {"name": _name(node.get("name")), "emitted": "resource" + str(len(self.fields))}
            elif kind == "CXXConstructorDecl":
                if node.get("explicitlyDeleted"):
                    copies.append(node)
                elif _qual(node) == f"void ({self.class_name} &&) noexcept":
                    moves.append(node)
                else:
                    constructors.append(node)
            elif kind == "CXXDestructorDecl":
                destructors.append(node)
            elif kind == "CXXMethodDecl" and node.get("name") == "operator=":
                assignments.append(node)
            elif kind == "CXXMethodDecl":
                ordinary.append(node)
            else:
                _reject("Unconverted class member: " + str(kind), "E_CPP_COMPOSED_INVENTORY")
        if not 2 <= len(self.fields) <= 4 or (len(constructors), len(moves), len(copies), len(assignments), len(destructors)) != (1, 1, 1, 2, 1) or not 1 <= len(ordinary) <= 16:
            _reject("Need 2..4 fields, one fallible/move constructor, deleted copy/assignments and default destructor")
        if {_qual(n) for n in assignments} != {f"{self.class_name} &(const {self.class_name} &)", f"{self.class_name} &({self.class_name} &&)"}:
            _reject("Both copy and move assignment must be explicitly deleted")
        special = [(copies[0], f"void (const {self.class_name} &)", "deleted_copy")]
        special += [(node, _qual(node), "deleted_assignment") for node in assignments]
        for node, signature, role in special:
            self.guard(node)
            if (node.get("explicitlyDeleted") is not True or _qual(node) != signature or len(_children(node)) != 1
                    or _children(node)[0].get("kind") != "ParmVarDecl" or _children(_children(node)[0])):
                _reject("Unsupported deleted special member")
            self.mark(node, role); self.mark(_children(node)[0], "deleted_special_parameter")
        dtor = destructors[0]; self.guard(dtor)
        if (dtor.get("explicitlyDefaulted") != "default" or _qual(dtor) != "void () noexcept"
                or any(n.get("kind") != "CompoundStmt" or _children(n) for n in _children(dtor))):
            _reject("Only default nontrivial member destruction is admitted; custom destruction rejects")
        self.mark(dtor, "reverse_field_destruction"); self.move(moves[0])
        ctor = constructors[0]; self.mark(ctor, "ordered_fallible_member_constructor")
        _, _, self.ctor_params, ctor_body = self.signature(ctor, constructor=True)
        self.ctor_signature = _qual(ctor)
        methods = []
        for index, method in enumerate(ordinary):
            self.mark(method, "translated_scalar_or_mutating_method")
            returns, const, params, body = self.signature(method); _name(method.get("name"))
            info = {"owner": self.class_name, "emitted": "HeptaComposite_method" + str(index), "returns": returns,
                    "const": const, "parameters": [p["type"] for p in params.values()], "name": method["name"]}
            self.methods[method["id"]] = info; methods.append((info, params, body))
        rendered = LEAF_HEPTA.replace("module cpp_owned_migrated;", "module cpp_composed_migrated;") + "\n"
        rendered += "pub struct HeptaComposite { " + ", ".join(f["emitted"] + ": HeptaLeaf" for f in self.fields.values()) + " }\n\n"
        rendered += "pub fn HeptaComposite_move(owner: take HeptaComposite) -> HeptaComposite effects {} { return move owner; }\n\n"
        rendered += "pub fn HeptaComposite_drop(owner: take HeptaComposite) -> Unit effects {alloc, block} {\n"
        rendered += "\n".join("    HeptaLeaf_drop(move owner." + f["emitted"] + ");" for f in reversed(list(self.fields.values()))) + "\n}\n\n"
        signature = ", ".join(p["emitted"] + ": " + p["type"] for p in self.ctor_params.values())
        rendered += f"pub fn HeptaComposite_new({signature}) -> Result<HeptaComposite, u8> {EFFECTS} {{\n"
        rendered += "\n".join(self.constructor(ctor, ctor_body)) + "\n}\n\n"
        for info, params, body in methods:
            signature = ", ".join(["receiver: " + ("read" if info["const"] else "mut") + " HeptaComposite",
                                   *[p["emitted"] + ": " + p["type"] for p in params.values()]])
            body_lines, done = self.statements(_children(body), copy.deepcopy(params), context="method", returns=info["returns"], const=info["const"])
            if info["returns"] != "Unit" and not done:
                _reject("Value method has a falling-through source path")
            rendered += f"pub fn {info['emitted']}({signature}) -> {info['returns']} {EFFECTS} {{\n" + "\n".join(body_lines) + "\n}\n\n"
        rendered += self.lifecycle()
        inventory = []
        for top in (self.leaf, self.composite, self.operation):
            for node, path in _nodes(top):
                if str(node.get("kind", "")).endswith("Decl"):
                    role = self.roles.get(node.get("id"))
                    if role is None:
                        _reject("Declaration has no explained disposition", "E_CPP_COMPOSED_INVENTORY")
                    inventory.append({"kind": node["kind"], "name": node.get("name"), "owner": top.get("name"), "path": list(path), "role": role})
        return rendered, {"declaration_inventory": inventory, "active_declarations": len(inventory),
            "resource_fields": list(self.fields.values()), "resource_count": len(self.fields),
            "source_class": self.class_name, "source_leaf": self.leaf_name, "lifecycle_function": self.operation["name"],
            "methods": [{k: info[k] for k in ("name", "emitted", "returns", "parameters", "const")} for info, _, _ in methods],
            "translation_statistics": self.stats, "unconverted_declarations": [], "foreign_cpp_calls": 0}

    def move(self, node):
        self.guard(node); self.mark(node, "memberwise_exclusive_move")
        params = [n for n in _children(node) if n.get("kind") == "ParmVarDecl"]
        initializers = [n for n in _children(node) if n.get("kind") == "CXXCtorInitializer"]
        bodies = [n for n in _children(node) if n.get("kind") == "CompoundStmt"]
        if (len(params) != 1 or _qual(params[0]) != self.class_name + " &&" or _children(params[0])
                or len(bodies) != 1 or _children(bodies[0]) or len(initializers) != len(self.fields)
                or len(_children(node)) != len(initializers) + 2):
            _reject("Move must initialize every field and have an empty body")
        self.mark(params[0], "exclusive_move_parameter")
        for init, (ident, field) in zip(initializers, self.fields.items()):
            children = _children(init)
            if init.get("anyInit", {}).get("id") != ident or len(children) != 1:
                _reject("Move initialization order/field identity differs")
            construct = children[0]; casts = _children(construct)
            if (construct.get("kind") != "CXXConstructExpr" or _qual(construct) != self.leaf_name
                    or construct.get("ctorType", {}).get("qualType") != f"void ({self.leaf_name} &&) noexcept"
                    or construct.get("constructionKind") != "complete" or len(casts) != 1
                    or casts[0].get("kind") != "CXXStaticCastExpr" or casts[0].get("castKind") != "NoOp"
                    or casts[0].get("valueCategory") != "xvalue" or _qual(casts[0]) != self.leaf_name
                    or len(_children(casts[0])) != 1):
                _reject("Each moved field requires the selected leaf move constructor")
            member = _children(casts[0])[0]; refs = _children(member)
            if (member.get("kind") != "MemberExpr" or member.get("referencedMemberDecl") != ident
                    or member.get("isArrow") is not False or len(refs) != 1 or refs[0].get("kind") != "DeclRefExpr"
                    or refs[0].get("referencedDecl", {}).get("id") != params[0]["id"] or _children(refs[0])):
                _reject("Member move may neither swap fields nor inspect another source")

    def constructor(self, node, body):
        initializers = [n for n in _children(node) if n.get("kind") == "CXXCtorInitializer"]
        if len(initializers) != len(self.fields):
            _reject("Constructor must explicitly initialize every resource")
        lines, held = [], []
        for index, (initializer, (ident, field)) in enumerate(zip(initializers, self.fields.items())):
            children = _children(initializer)
            if initializer.get("anyInit", {}).get("id") != ident or len(children) != 1:
                _reject("Constructor identity/order differs from actual Clang initialization order")
            call = children[0]
            if (call.get("kind") != "CXXConstructExpr" or _qual(call) != self.leaf_name
                    or call.get("ctorType", {}).get("qualType") != "void (unsigned long, bool)"
                    or call.get("constructionKind") != "complete" or len(_children(call)) != 2):
                _reject("Each field must invoke the selected leaf allocation constructor")
            arguments = [self.expr(a, self.ctor_params, context="constructor") for a in _children(call)]
            if [typ for _, typ in arguments] != ["usize", "bool"]:
                _reject("Leaf construction arguments have unmodeled conversions")
            indent = "    " * (1 + 2 * index); value = "created" + str(index)
            lines += [indent + "match HeptaLeaf_new(" + ", ".join(v for v, _ in arguments) + ") {", indent + "    Result::Err(code) => {"]
            lines += [indent + "        HeptaLeaf_drop(move " + previous + ");" for previous in reversed(held)]
            lines += [indent + "        return Result::Err(code);", indent + "    },", indent + "    Result::Ok(" + value + ") => {"]
            held.append(value)
        depth = 1 + 2 * len(held)
        body_lines, done = self.statements(_children(body), copy.deepcopy(self.ctor_params), context="constructor", returns="Unit", depth=depth, constructor_fields=held)
        if done:
            _reject("An always-throwing constructor is outside the admitted profile")
        lines += body_lines
        fields = [f["emitted"] + ": move " + value for f, value in zip(self.fields.values(), held)]
        lines.append("    " * depth + "return Result::Ok(HeptaComposite {" + ", ".join(fields) + "});")
        for index in reversed(range(len(held))):
            indent = "    " * (1 + 2 * index); lines += [indent + "    },", indent + "}"]
        return lines

    def lifecycle(self):
        returns, const, params, body = self.signature(self.operation)
        if returns != "u64" or const or len(_children(body)) != 1 or _children(body)[0].get("kind") != "CXXTryStmt":
            _reject("Lifecycle requires one complete try body returning u64")
        parts = _children(_children(body)[0])
        if len(parts) != 3 or parts[0].get("kind") != "CompoundStmt" or any(n.get("kind") != "CXXCatchStmt" for n in parts[1:]):
            _reject("Need explicit int and catch-all handlers")
        ints, alls = _children(parts[1]), _children(parts[2])
        if (len(ints) != 2 or ints[0].get("kind") != "VarDecl" or _qual(ints[0]) != "int" or _children(ints[0])
                or len(alls) != 2 or alls[0] not in ({}, {"id": "0x0"})
                or any(p.get("kind") != "CompoundStmt" or len(_children(p)) != 1
                       or _children(p)[0].get("kind") != "ReturnStmt" or len(_children(_children(p)[0])) != 1 for p in (ints[1], alls[1]))):
            _reject("Handlers may only return checked scalar expressions")
        self.guard(ints[0]); self.mark(ints[0], "integer_exception_parameter")
        handler_env = copy.deepcopy(params)
        handler_env[ints[0]["id"]] = {"emitted": "caughtcode", "cpp_type": "int", "type": "i32", "source_name": ints[0].get("name"), "alive": True}
        integer, typ = self.expr(_children(_children(ints[1])[0])[0], handler_env, context="handler")
        allocation, other = self.expr(_children(_children(alls[1])[0])[0], params, context="handler")
        if typ != returns or other != returns:
            _reject("Exception handler type mismatch")
        lines, done = self.statements(_children(parts[0]), copy.deepcopy(params), context="lifecycle", returns=returns, catch={"integer": integer, "allocation": allocation})
        if not done or self.stats["owner_constructions"] == 0:
            _reject("Complete lifecycle must construct and consume an owned composite")
        signature = ", ".join(p["emitted"] + ": " + p["type"] for p in params.values())
        return f"pub fn translated_run({signature}) -> u64 {EFFECTS} {{\n" + "\n".join(lines) + "\n}\n"


def translate_cpp_composed(source_file, *, clangxx="clang++"):
    """Fresh actual C++ frontend + lowering; no publication or receipt AST input."""
    source = Path(source_file).resolve(); original = source.read_bytes()
    if source.suffix not in {".cpp", ".cc", ".cxx"} or len(original) > 256000:
        _reject("Need a bounded complete C++ source file")
    text = original.decode("utf-8")
    if "#" in text or "%:" in text or re.search(r"\\\r?\n", text):
        _reject("Preprocessing requires a separate complete-project inventory", "E_CPP_COMPOSED_PREPROCESSOR")
    selected = shutil.which(clangxx)
    if selected is None:
        _reject("Clang C++ compiler unavailable", "E_CPP_COMPOSED_TOOLCHAIN")
    compiler = Path(selected).resolve(strict=True)
    native_hash, hepta_hash = _sha(compiler.read_bytes()), compiler_hash(); model = _model(str(compiler))
    version = re.search(r"clang version (\d+)\.", model["clang_version"])
    if version is None or int(version[1]) < 20 or model["sizeof_long"] != 8 or model["sizeof_pointer"] != 8:
        _reject("Requires Clang20+ on the checked native LP64 model", "E_CPP_COMPOSED_TOOLCHAIN")
    command = [str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    tree = _load_bounded_clang_ast(_run([*command, str(source)]))
    declarations = [n for n in _children(tree) if n.get("isImplicit") is not True]
    if len(declarations) != 3 or [n.get("kind") for n in declarations] != ["CXXRecordDecl", "CXXRecordDecl", "FunctionDecl"]:
        _reject("Exactly a leaf, composed owner and lifecycle function must account for the source")
    leaf, composite, operation = declarations
    for node in declarations:
        begin = node.get("range", {}).get("begin", {}).get("offset"); end = node.get("range", {}).get("end", {}).get("offset")
        if type(begin) is not int or type(end) is not int or not 0 <= begin <= end < len(original):
            _reject("Declaration lacks an exact source position")
    leaf_source = re.sub(r"\bOwnedBytes\b", _name(leaf.get("name")), LEAF_CPP)
    rules = _load_bounded_clang_ast(_run([*command, "-"], input_text=leaf_source))
    expected = next(n for n in _children(rules) if n.get("kind") == "CXXRecordDecl" and n.get("name") == leaf["name"])
    actual_leaf = _without_usage(_normalized(leaf, leaf["name"])); expected = _without_usage(_normalized(expected, leaf["name"]))
    if actual_leaf != expected:
        _reject("Complete leaf AST differs from allocation/move/borrow/destructor rules", "E_CPP_COMPOSED_LEAF")
    implicit = {"kind": "TranslationUnitDecl", "inner": [n for n in _children(tree) if n.get("isImplicit") is True]}
    expected_implicit = {"kind": "TranslationUnitDecl", "inner": [n for n in _children(rules) if n.get("isImplicit") is True]}
    if _without_usage(_normalized(implicit, leaf["name"])) != _without_usage(_normalized(expected_implicit, leaf["name"])):
        _reject("Unmodeled compiler-generated declarations", "E_CPP_COMPOSED_INVENTORY")
    rendered, ledger = _Translator(tree, leaf, composite, operation).translate()
    checks = {}
    for backend in ("rust", "c"):
        checked = analyze(rendered, "composed.hepta", backend=backend, native=False, crate_type="obj"); checks[backend] = checked.report
        if checked.report["ok"] is not True or checked.report["assumptions"]:
            _reject("Generated implementation failed checked lowering: " + json.dumps(checked.report), "E_CPP_COMPOSED_HEPTA")
    graph = lower_resource_ir(checked.program, checked.checked); verification = verify_resource_ir(graph)
    if verification["ok"] is not True or graph["obligations"]:
        _reject("Generated ownership graph failed independent verification")
    traits = "\n".join(f"static_assert({test});" for name in (leaf["name"], composite["name"]) for test in
        (f"!__is_constructible({name}, const {name}&)", f"__is_nothrow_constructible({name}, {name}&&)",
         f"__is_nothrow_destructible({name})", f"!__is_trivially_destructible({name})"))
    _run([str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only", "-"], input_text=text + "\n" + traits)
    if source.read_bytes() != original or _sha(compiler.read_bytes()) != native_hash or compiler_hash() != hepta_hash:
        _reject("Source/compiler changed during translation", "E_CPP_COMPOSED_RACE")
    return rendered, {"schema": SCHEMA, "profile": PROFILE, "ok": True, "status": "composed_implementation_translated",
        **LIMITS, **ledger, "source": str(source), "source_sha256": _sha(original), "output_sha256": _sha(rendered.encode()),
        "hepta_compiler_sha256": hepta_hash, "target_model": {**model, "compiler": str(compiler), "compiler_sha256": native_hash},
        "source_declarations": 3, "converted_source_declarations": 3,
        "implicit_declarations": sum(1 for top in implicit["inner"] for n, _ in _nodes(top) if str(n.get("kind", "")).endswith("Decl")),
        "complete_ast_nodes": sum(1 for _ in _nodes(tree)), "complete_ast_sha256": _sha(_canonical(_normalized(tree, leaf["name"]))),
        "leaf_protocol_ast_sha256": _sha(_canonical(actual_leaf)), "composite_lowering": "declaration_bound_expression_and_control_flow_translation",
        "hepta_checks": checks, "resource_ir": graph, "resource_verification": verification,
        "native_traits": {"copy_constructible": False, "nothrow_move_constructible": True, "nothrow_destructible": True, "trivially_destructible": False},
        "moved_from_policy": "consumed_source_cannot_be_observed", "destruction_order": "reverse_field_initialization",
        "native_execution": "not_run", "diagnostics": []}


def migrate_cpp_composed(source_file, destination_file, *, clangxx="clang++"):
    output = Path(os.path.abspath(destination_file))
    rejected = {"schema": SCHEMA, "profile": PROFILE, "ok": False, "status": "rejected", **LIMITS,
                "source": str(Path(source_file).resolve()), "output": str(output), "diagnostics": []}
    try:
        if output.suffix != ".hepta" or output.is_symlink() or output.exists() or not output.parent.is_dir():
            _reject("Output must be a distinct new ordinary .hepta file", "E_CPP_COMPOSED_PATH")
        rendered, report = translate_cpp_composed(source_file, clangxx=clangxx)
        staged = None
        try:
            payload = rendered.encode("utf-8")
            with tempfile.NamedTemporaryFile("wb", dir=output.parent, prefix=".cpp-composed-", delete=False) as handle:
                staged = Path(handle.name); handle.write(payload); handle.flush(); os.fsync(handle.fileno())
            def unchanged():
                return (Path(source_file).resolve() == Path(report["source"])
                    and _sha(Path(source_file).read_bytes()) == report["source_sha256"]
                    and compiler_hash() == report["hepta_compiler_sha256"]
                    and _sha(Path(report["target_model"]["compiler"]).read_bytes()) == report["target_model"]["compiler_sha256"])
            if not unchanged():
                _reject("Source/compiler changed before publication", "E_CPP_COMPOSED_RACE")
            try:
                receipt = publish_verified(staged, output, payload)
                if not unchanged():
                    _reject("Source/compiler changed during publication", "E_CPP_COMPOSED_RACE")
                final = verify_published(staged, output, payload)
                if receipt != final or final["sha256"] != report["output_sha256"]:
                    raise PublicationRejected("Published migration bytes no longer match the checked output")
            except (MigrationRejected, PublicationRejected, OSError):
                withdraw_own_link(staged, output)
                raise
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        return {**report, "output": str(output)}
    except (MigrationRejected, ResourceIRError, OSError, ValueError, UnicodeError) as error:
        rejected["diagnostics"].append({"code": getattr(error, "code", "E_CPP_COMPOSED_INPUT"), "message": str(error)})
        return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clangxx", default="clang++"); args = parser.parse_args()
    report = migrate_cpp_composed(args.source, args.output, clangxx=args.clangxx)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
