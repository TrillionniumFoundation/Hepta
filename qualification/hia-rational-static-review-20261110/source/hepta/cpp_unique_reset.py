"""Direct, declaration-bound unique_ptr release/reset migration.

The complete actual Clang TU is inventoried. The project algorithm is lowered
structurally; a compiler-owned probe binds only the trusted standard-library
operations, never the project algorithm. A released pointer must be the direct
argument of reset. It has no generated raw-pointer representation or escape.

This sequential LP64 profile has immutable scalar bindings, explicit capacity
guards, proved syntactic subscript guards, and complete-owner local state.
Arbitrary C++, custom deleters, a retained C++ ABI, and proofs of the standard
library implementation are deliberately not claimed.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import re
import time

from .c_project import capture_project, verify_capture
from .cpp_composed_migrate import (_Translator, _children, _qual, _scalar,
                                   _name, _reject, EFFECTS)
from .cpp_owned_migrate import _nodes
from .cpp_unique_project import _large_ast, _reference_config, _standard_snapshot
from .hia_program_source import lower_source, source_report
from .pipeline import analyze, compiler_hash


PROFILE = "cpp20-direct-unique-byte-array-closed-reset-v1"
REUSABLE_PROFILE = "cpp20-direct-unique-byte-array-reusable-reset-v2"
SWAP_PROFILE = "cpp20-direct-unique-byte-array-reusable-swap-v3"
UNIQUE = "std::unique_ptr<unsigned char[]>"
MAX_ALLOCATION = 65536
_REFERENCE = r'''#include <memory>
unsigned char hepta_library_contract(unsigned long size, unsigned long index) {
    std::unique_ptr<unsigned char[]> a(size == 0 ? nullptr : new unsigned char[size]{});
    std::unique_ptr<unsigned char[]> b(size == 0 ? nullptr : new unsigned char[size]{});
    a.reset(b.release());
    a.reset();
    a.reset(nullptr);
    return a[index];
}
'''
_REFERENCE_SWAP = _REFERENCE.replace("    a.reset(b.release());",
    "    a.swap(b);\n    b.swap(b);\n    a.reset(b.release());")


def _only(node, kind=None):
    children = _children(node)
    if len(children) != 1 or (kind is not None and node.get("kind") != kind):
        _reject("Expected one complete expression", "E_CPP_RESET_AST")
    return children[0]


def _unwrap(node, kinds=("ParenExpr",)):
    while node.get("kind") in kinds:
        node = _only(node)
    return node


def _literal(node):
    node = _unwrap(node, ("ParenExpr", "ImplicitCastExpr"))
    if node.get("kind") != "IntegerLiteral" or _children(node):
        return None
    return int(node.get("value", "invalid"))


def _nullptr(node):
    while node.get("kind") in {"ParenExpr", "ImplicitCastExpr", "CXXDefaultArgExpr"}:
        if (node.get("kind") == "ImplicitCastExpr"
                and node.get("castKind") not in {"NullToPointer", "NoOp"}):
            return False
        node = _only(node)
    return (node.get("kind") == "CXXNullPtrLiteralExpr" and not _children(node)
            and _qual(node) == "std::nullptr_t")


def _contracts(probe, external, *, owner_swaps=False):
    selected = {name: set() for name in ("reset", "release", "operator[]", "new", "delete")}
    if owner_swaps:
        selected["swap"] = set()
    for node, _ in _nodes(probe):
        if node.get("kind") == "MemberExpr" and node.get("name") in ({"reset", "release", "swap"} if owner_swaps else {"reset", "release"}):
            selected[node["name"]].add(external[node["referencedMemberDecl"]])
        if node.get("kind") == "DeclRefExpr" and node.get("referencedDecl", {}).get("name") == "operator[]":
            selected["operator[]"].add(external[node["referencedDecl"]["id"]])
        if node.get("kind") == "CXXNewExpr":
            selected["new"].add(external[node["operatorNewDecl"]["id"]])
            selected["delete"].add(external[node["operatorDeleteDecl"]["id"]])
    if any(not signatures for signatures in selected.values()):
        _reject("Incomplete compiler-owned library contract probe", "E_CPP_RESET_CONTRACT")
    return selected


class _ResetTranslator(_Translator):
    """Reuse scalar typing, with a separate complete local ownership machine."""

    def __init__(self, operation, external, contracts, *, reusable_released_owners=False,
                 owner_swaps=False):
        self.operation, self.external, self.contracts = operation, external, contracts
        self.reusable_released_owners = reusable_released_owners
        self.owner_swaps = owner_swaps
        self.roles, self.fields, self.methods, self.serial = {}, {}, {}, 0
        self.stats = {"scalar_expressions": 0, "if_statements": 0, "scalar_locals": 0,
                      "owner_constructions": 0, "source_returns": 0,
                      "distinct_release_reset": 0, "self_release_reset": 0,
                      "explicit_reset_null": 0, "guarded_subscripts": 0,
                      "throw_cleanup_paths": 0, "distinct_owner_swaps": 0,
                      "self_owner_swaps": 0}
        self.mark(operation, "structurally_translated_direct_unique_function")

    def bound(self, ident, role):
        if self.external.get(ident) not in self.contracts[role]:
            _reject("Operation does not bind to the captured default-deleter contract: " + role,
                    "E_CPP_RESET_BINDING")

    def owner(self, node, env, *, empty=False):
        while node.get("kind") in {"ParenExpr", "ImplicitCastExpr"}:
            if node.get("kind") == "ImplicitCastExpr" and node.get("castKind") != "NoOp":
                _reject("Only qualification-preserving owner references are admitted", "E_CPP_RESET_OWNER")
            node = _only(node)
        ref = node.get("referencedDecl", {})
        value = env.get(ref.get("id"))
        if (node.get("kind") != "DeclRefExpr" or _children(node) or not isinstance(value, dict)
                or value.get("type") != "owner" or ref.get("kind") != "VarDecl"
                or _qual(node) != UNIQUE or _qual(ref) != UNIQUE
                or ref.get("name") != value["source_name"] or value.get("consumed")
                or (not empty and not value["alive"])):
            _reject("Expected a complete live unique owner; released/escaped source use rejects",
                    "E_CPP_RESET_OWNER")
        return ref["id"], value

    def member(self, node, env, role, *, empty=False):
        children = _children(node)
        if node.get("kind") != "CXXMemberCallExpr" or not children:
            _reject("Expected one bound unique_ptr member call", "E_CPP_RESET_CALL")
        member = children[0]
        if (member.get("kind") != "MemberExpr" or member.get("name") != role
                or member.get("isArrow") is not False):
            _reject("Only the selected unique_ptr operation is admitted", "E_CPP_RESET_CALL")
        self.bound(member.get("referencedMemberDecl"), role)
        ident, owner = self.owner(_only(member), env, empty=empty)
        return ident, owner, children[1:]

    def subscript(self, node, env):
        children = _children(node)
        if (node.get("kind") != "CXXOperatorCallExpr" or len(children) != 3
                or _qual(node) != "unsigned char" or node.get("valueCategory") != "lvalue"):
            _reject("Expected bound byte-array subscript", "E_CPP_RESET_INDEX")
        callee = children[0]
        if callee.get("kind") != "ImplicitCastExpr" or callee.get("castKind") != "FunctionToPointerDecay":
            _reject("Subscript lacks its actual member binding", "E_CPP_RESET_BINDING")
        refnode = _only(callee)
        ref = refnode.get("referencedDecl", {})
        if refnode.get("kind") != "DeclRefExpr" or _children(refnode) or ref.get("name") != "operator[]":
            _reject("Unmodeled subscript reference", "E_CPP_RESET_BINDING")
        self.bound(ref.get("id"), "operator[]")
        _, owner = self.owner(children[1], env)
        index, typ = self.expr(children[2], env, context="lifecycle")
        if typ != "usize" or (index, owner["length"]) not in env.get("__bounds__", set()):
            _reject("Subscript needs a dominating index < current owner length guard",
                    "E_CPP_RESET_BOUNDS")
        self.stats["guarded_subscripts"] += 1
        return f"{owner['emitted']}[{index}]"

    def expr(self, node, env, *, context, const=False):
        if node.get("kind") == "CXXOperatorCallExpr":
            return self.subscript(node, env), "u8"
        if (node.get("kind") == "BinaryOperator" and _qual(node) == "int"
                and node.get("opcode") in {"+", "-", "*"}):
            _reject("Signed arithmetic needs a separate overflow proof", "E_CPP_RESET_SCALAR")
        return super().expr(node, env, context=context, const=const)

    def call(self, *args, **kwargs):
        _reject("Member effects must be complete release/reset statements; pointers cannot escape",
                "E_CPP_RESET_ESCAPE")

    def cleanup(self, env):
        return ["drop(move " + value["emitted"] + ");" for value in reversed(list(env.values()))
                if isinstance(value, dict) and value.get("type") == "owner" and value["alive"]]

    def guard_facts(self, node, env, truth):
        """Syntactic unsigned guards over immutable, side-effect-free scalars."""
        node = _unwrap(node)
        children = _children(node)
        if node.get("kind") != "BinaryOperator" or len(children) != 2:
            return
        left, lt = self.expr(children[0], env, context="lifecycle")
        right, rt = self.expr(children[1], env, context="lifecycle")
        if (lt, rt) != ("usize", "usize"):
            return
        op = node.get("opcode")
        if (op == "<" and truth) or (op == ">=" and not truth):
            env.setdefault("__bounds__", set()).add((left, right))
        constant = _literal(children[1])
        if constant is not None and 0 <= constant <= MAX_ALLOCATION:
            limit = constant if (op == "<=" and truth) or (op == ">" and not truth) else (
                constant - 1 if (op == "<" and truth) or (op == ">=" and not truth) else None)
            if limit is not None and limit >= 0:
                limits = env.setdefault("__limits__", {})
                limits[left] = min(limit, limits.get(left, limit))

    def allocation(self, node, env):
        if (node.get("kind") != "CXXConstructExpr" or _qual(node) != UNIQUE
                or node.get("ctorType", {}).get("qualType") != "void (unsigned char *) noexcept"
                or node.get("constructionKind") != "complete"):
            _reject("Owner must use the captured byte-array pointer constructor", "E_CPP_RESET_NEW")
        conditional = _only(node)
        parts = _children(conditional)
        if (conditional.get("kind") != "ConditionalOperator" or _qual(conditional) != "unsigned char *"
                or len(parts) != 3 or not _nullptr(parts[1])):
            _reject("Allocation must explicitly map zero length to nullptr", "E_CPP_RESET_NEW")
        predicate = parts[0]; condition = _children(predicate)
        if predicate.get("kind") != "BinaryOperator" or predicate.get("opcode") != "==" or len(condition) != 2:
            _reject("Zero-allocation condition differs", "E_CPP_RESET_NEW")
        length, typ = self.expr(condition[0], env, context="lifecycle")
        if typ != "usize" or _literal(condition[1]) != 0:
            _reject("Allocation length must be usize and test equality with zero", "E_CPP_RESET_NEW")
        if env.get("__limits__", {}).get(length, MAX_ALLOCATION + 1) > MAX_ALLOCATION:
            _reject("Allocation needs a dominating finite unsigned capacity guard <= 65536",
                    "E_CPP_RESET_CAPACITY")
        new = parts[2]; arguments = _children(new)
        allowed = {"id", "kind", "range", "type", "valueCategory", "isArray", "initStyle",
                   "operatorNewDecl", "operatorDeleteDecl", "inner"}
        if (new.get("kind") != "CXXNewExpr" or set(new) - allowed
                or new.get("isArray") is not True or new.get("initStyle") != "list"
                or _qual(new) != "unsigned char *" or len(arguments) != 2):
            _reject("Only ordinary zero-initialized byte-array new is admitted", "E_CPP_RESET_NEW")
        self.bound(new.get("operatorNewDecl", {}).get("id"), "new")
        self.bound(new.get("operatorDeleteDecl", {}).get("id"), "delete")
        if self.expr(arguments[0], env, context="lifecycle") != (length, "usize"):
            _reject("Allocated size differs from the tested size", "E_CPP_RESET_NEW")
        init = arguments[1]; fillers = init.get("array_filler", [])
        if (init.get("kind") != "InitListExpr" or _children(init) or _qual(init) != "unsigned char[0]"
                or len(fillers) != 1 or fillers[0].get("kind") != "ImplicitValueInitExpr"
                or _children(fillers[0]) or _qual(fillers[0]) != "unsigned char"):
            _reject("Byte initialization must be complete value initialization", "E_CPP_RESET_NEW")
        return length

    def reset(self, node, env):
        target_id, target, args = self.member(node, env, "reset", empty=True)
        if _qual(node) != "void" or len(args) != 1:
            _reject("Reset must be a complete one-argument operation", "E_CPP_RESET_CALL")
        if _nullptr(args[0]):
            lines = ["drop(move " + target["emitted"] + ");"] if target["alive"] else []
            target.update(alive=False, length="(0 as usize)")
            self.stats["explicit_reset_null"] += 1
            return lines
        source_id, source, inner = self.member(args[0], env, "release", empty=True)
        if inner or args[0].get("type", {}).get("desugaredQualType", _qual(args[0])) != "unsigned char *":
            _reject("Reset must directly adopt exactly one no-argument release", "E_CPP_RESET_ESCAPE")
        if target_id == source_id:
            # reset(p.release()) first makes p null: the reset deletes nullptr.
            # Unlike reset(p.get()), this self transfer is resource preserving.
            self.stats["self_release_reset"] += 1
            return []
        lines = ["drop(move " + target["emitted"] + ");"] if target["alive"] else []
        if source["alive"]:
            replacement = self.fresh("reset")
            lines.append(f"let mut {replacement} = move {source['emitted']};")
            target.update(alive=True, emitted=replacement, length=source["length"])
        else:
            target.update(alive=False, length="(0 as usize)")
        # C++ release() consumes the allocation, not the unique_ptr object.
        # The v2 profile retains an empty source slot that can later adopt a
        # different live owner. Every adoption gets a fresh Hepta binding;
        # no moved linear value or raw pointer is reused. The v1 admission
        # boundary remains unchanged for callers that did not select v2.
        source.update(alive=False, consumed=not self.reusable_released_owners,
                      length="(0 as usize)")
        self.stats["distinct_release_reset"] += 1
        return lines

    def swap(self, node, env):
        if not self.owner_swaps:
            _reject("Member swap requires the explicit v3 ownership profile", "E_CPP_RESET_SWAP_PROFILE")
        left_id, left, arguments = self.member(node, env, "swap", empty=True)
        if _qual(node) != "void" or len(arguments) != 1:
            _reject("Swap requires exactly one complete owner argument", "E_CPP_RESET_SWAP")
        right_id, right = self.owner(arguments[0], env, empty=True)
        if left_id == right_id:
            self.stats["self_owner_swaps"] += 1
            return []
        # An owner slot and an allocation are different identities. The C++
        # objects keep declaration order and source names; only the allocation
        # identity, initialization/length fact, and corresponding linear value
        # change slots. No raw pointer or second live Hepta binding is created.
        for field in ("alive", "length", "emitted"):
            left[field], right[field] = right[field], left[field]
        self.stats["distinct_owner_swaps"] += 1
        return []

    def statements(self, statements, env, *, context, returns, depth=1, catch=None,
                   nested=False, scope_depth=0, **kwargs):
        if scope_depth > 16 or len(statements) > 256:
            _reject("Direct ownership statement/depth budget exceeded", "E_CPP_RESET_BUDGET")
        lines, indent = [], "    " * depth
        for offset, raw in enumerate(statements):
            node = _unwrap(raw, ("ExprWithCleanups", "ParenExpr"))
            kind, children = node.get("kind"), _children(node)
            if kind == "IfStmt" and len(children) in {2, 3} and not any(
                    key in node for key in ("hasInit", "hasVar", "isConstexpr")):
                predicate, typ = self.expr(children[0], env, context=context)
                if typ != "bool" or any(c.get("kind") != "CompoundStmt" for c in children[1:]):
                    _reject("Branches require Boolean conditions and explicit blocks", "E_CPP_RESET_IF")
                self.stats["if_statements"] += 1
                states, done = [], []
                lines.append(indent + "if " + predicate + " {")
                for index, branch in enumerate(children[1:]):
                    if index:
                        lines.append(indent + "else {")
                    branch_env = copy.deepcopy(env)
                    self.guard_facts(children[0], branch_env, index == 0)
                    rendered, terminated = self.statements(_children(branch), branch_env,
                        context=context, returns=returns, depth=depth + 1, catch=catch,
                        nested=True, scope_depth=scope_depth + 1)
                    lines += rendered + [indent + "}"]
                    states.append(branch_env); done.append(terminated)
                if len(states) == 1:
                    other = copy.deepcopy(env); self.guard_facts(children[0], other, False)
                    states.append(other); done.append(False)
                continuing = [state for state, terminated in zip(states, done) if not terminated]
                if not continuing:
                    if offset != len(statements) - 1:
                        _reject("Unreachable source statements are not discarded", "E_CPP_RESET_UNREACHABLE")
                    return lines, True
                # New owner bindings inside a branch have block scope. This
                # profile accepts changes only on paths that leave the function.
                for key, value in env.items():
                    if isinstance(value, dict) and value.get("type") == "owner":
                        if any(state[key] != value for state in continuing):
                            _reject("Continuing branches may not change ownership bindings", "E_CPP_RESET_JOIN")
                env["__bounds__"] = set.intersection(*(state.get("__bounds__", set()) for state in continuing))
                limit_keys = set.intersection(*(set(state.get("__limits__", {})) for state in continuing))
                env["__limits__"] = {key: max(state["__limits__"][key] for state in continuing) for key in limit_keys}
            elif kind == "DeclStmt" and len(children) == 1 and children[0].get("kind") == "VarDecl":
                variable = children[0]; self.guard(variable); _name(variable.get("name"))
                if len(_children(variable)) != 1 or not variable.get("init"):
                    _reject("Every local requires one complete initializer", "E_CPP_RESET_LOCAL")
                if _qual(variable) != UNIQUE:
                    typ = _scalar(variable)
                    value, actual = self.expr(_only(variable), env, context=context)
                    if typ != actual:
                        _reject("Scalar local changes representation", "E_CPP_RESET_SCALAR")
                    emitted = self.fresh("scalar")
                    self.mark(variable, "immutable_scalar_local"); self.stats["scalar_locals"] += 1
                    env[variable["id"]] = {"type": typ, "cpp_type": _qual(variable), "alive": True,
                        "source_name": variable["name"], "emitted": emitted}
                    lines.append(indent + f"let {emitted}: {typ} = {value};")
                    continue
                if nested or context != "lifecycle":
                    _reject("New owners require a complete outer lifecycle scope", "E_CPP_RESET_SCOPE")
                length = self.allocation(_only(variable), env)
                self.mark(variable, "captured_direct_unique_array_owner")
                self.stats["owner_constructions"] += 1
                emitted = self.fresh("owner")
                lines += [indent + f"match try_buffer({length}) {{",
                          indent + "    Result::Err(allocationcode) => {"]
                lines += [indent + "        " + line for line in self.cleanup(env)]
                lines += [indent + "        return " + catch["allocation"] + ";", indent + "    },",
                          indent + f"    Result::Ok({emitted}value) => {{",
                          indent + f"        let mut {emitted} = move {emitted}value;"]
                env[variable["id"]] = {"type": "owner", "cpp_type": UNIQUE, "source_name": variable["name"],
                    "alive": True, "consumed": False, "length": length, "emitted": emitted}
                rest, done = self.statements(statements[offset + 1:], env, context=context,
                    returns=returns, depth=depth + 2, catch=catch, nested=nested, scope_depth=scope_depth)
                return lines + rest + [indent + "    },", indent + "}"], done
            elif kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
                place = self.subscript(children[0], env)
                value, typ = self.expr(children[1], env, context=context)
                if typ != "u8" or _qual(node) != "unsigned char":
                    _reject("Only checked byte stores are admitted", "E_CPP_RESET_STORE")
                lines.append(indent + place + " = " + value + ";")
            elif kind == "CXXMemberCallExpr":
                if children and children[0].get("name") == "swap":
                    rendered = self.swap(node, env)
                else:
                    rendered = self.reset(node, env)
                lines += [indent + line for line in rendered]
            elif kind in {"ReturnStmt", "CXXThrowExpr"} and len(children) == 1:
                if kind == "ReturnStmt":
                    value, typ = self.expr(children[0], env, context=context)
                    if typ != returns:
                        _reject("Return representation differs", "E_CPP_RESET_RETURN")
                    result = self.fresh("result")
                    lines.append(indent + f"let {result}: {typ} = {value};")
                    self.stats["source_returns"] += 1
                else:
                    value = _literal(children[0])
                    if _qual(children[0]) != "int" or value is None or not 2 <= value <= 255:
                        _reject("Only literal int exceptions in 2..255 are admitted", "E_CPP_RESET_THROW")
                    result = catch["integer"]
                    lines.append(indent + f"let caughtcode: i32 = {value};")
                    self.stats["throw_cleanup_paths"] += 1
                lines += [indent + line for line in self.cleanup(env)]
                lines.append(indent + "return " + result + ";")
                if offset != len(statements) - 1:
                    _reject("Unreachable source statements are not discarded", "E_CPP_RESET_UNREACHABLE")
                return lines, True
            else:
                _reject("Unmodeled direct unique-array statement: " + str(kind), "E_CPP_RESET_STATEMENT")
        return lines, False

    def translate(self):
        source = "module cpp_unique_reset_migrated;\n\n" + self.lifecycle()
        if not self.stats["distinct_release_reset"]:
            _reject("Profile requires an actual distinct-owner release/reset", "E_CPP_RESET_PROFILE")
        if self.owner_swaps and not self.stats["distinct_owner_swaps"]:
            _reject("The v3 profile requires an actual distinct-owner swap", "E_CPP_RESET_PROFILE")
        inventory = []
        for node, path in _nodes(self.operation):
            if str(node.get("kind", "")).endswith("Decl"):
                if node.get("id") not in self.roles:
                    _reject("Unaccounted active project declaration", "E_CPP_RESET_INVENTORY")
                inventory.append({"kind": node["kind"], "name": node.get("name"), "path": list(path),
                                  "role": self.roles[node["id"]]})
        return source, inventory


def lower_unique_reset_project(database, *, clangxx="clang++", reusable_released_owners=False,
                               owner_swaps=False):
    """Capture one real source TU, bind its library, and emit checked Core."""
    if type(reusable_released_owners) is not bool:
        raise ValueError("reusable_released_owners must be an explicit Boolean profile selection")
    if type(owner_swaps) is not bool:
        raise ValueError("owner_swaps must be an explicit Boolean profile selection")
    if owner_swaps and not reusable_released_owners:
        raise ValueError("owner_swaps requires reusable_released_owners=True")
    started = time.perf_counter_ns()
    before = compiler_hash()
    stage = time.perf_counter_ns()
    capture = capture_project(database, clang=clangxx, language="c++")
    costs = {"build_configuration_capture_wall_ns": time.perf_counter_ns() - stage}
    stage = time.perf_counter_ns()
    if len(capture["configurations"]) != 1:
        _reject("Direct reset profile requires one complete listed translation unit", "E_CPP_RESET_SCOPE")
    if not re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", capture["compiler"]["version"]):
        _reject("Clang20+ is required for direct reset capture", "E_CPP_RESET_TOOLCHAIN")
    config = capture["configurations"][0]
    if config["model"]["long_bits"] != 64 or config["model"]["pointer_bits"] != 64:
        _reject("Direct reset profile requires LP64", "E_CPP_RESET_ABI")
    compiler = capture["compiler"]["path"]
    active, ast, external, library, implicit = _large_ast(compiler, config)
    if len(active) != 1 or active[0][0].get("kind") != "FunctionDecl":
        _reject("Expected exactly one defined project function and no custom library declarations",
                "E_CPP_RESET_INVENTORY")
    reference_config = _reference_config(config)
    actual_standard = _standard_snapshot(compiler, config)
    reference_source = _REFERENCE_SWAP if owner_swaps else _REFERENCE
    reference_standard = _standard_snapshot(compiler, reference_config, source=reference_source)
    if not actual_standard or actual_standard != reference_standard:
        _reject("Project changes the expanded default standard-library contract", "E_CPP_RESET_STDLIB")
    reference, reference_ast, reference_external, _, _ = _large_ast(compiler, reference_config, source=reference_source)
    if len(reference) != 1 or reference[0][0].get("name") != "hepta_library_contract":
        _reject("Incomplete trusted operation probe", "E_CPP_RESET_CONTRACT")
    contracts = _contracts(reference[0][0], reference_external, owner_swaps=owner_swaps)
    costs["ast_and_library_contract_capture_wall_ns"] = time.perf_counter_ns() - stage
    stage = time.perf_counter_ns()
    translator = _ResetTranslator(active[0][0], external, contracts,
                                  reusable_released_owners=reusable_released_owners,
                                  owner_swaps=owner_swaps)
    source, inventory = translator.translate()
    costs["source_generation_wall_ns"] = time.perf_counter_ns() - stage
    stage = time.perf_counter_ns()
    checked = analyze(source, "captured-unique-reset.hepta", backend="c", native=False, crate_type="obj")
    if not checked.report["ok"] or checked.report["assumptions"]:
        _reject("Direct unique owner failed checked source lowering: " + json.dumps(checked.report), "E_CPP_RESET_CORE")
    program = lower_source(source, path="<captured-unique-reset>")
    source_summary = source_report(source)
    costs["source_and_core_verification_wall_ns"] = time.perf_counter_ns() - stage
    stage = time.perf_counter_ns()
    verify_capture(capture)
    if compiler_hash() != before:
        _reject("Compiler changed during direct reset capture", "E_CPP_RESET_CHANGED")
    costs["source_toolchain_revalidation_wall_ns"] = time.perf_counter_ns() - stage
    costs["total_migration_wall_ns"] = time.perf_counter_ns() - started
    costs["human_engineering_seconds"] = None
    return {"schema": ("hepta.cpp-unique-reset-migration.v3" if owner_swaps else
                       "hepta.cpp-unique-reset-migration.v2" if reusable_released_owners else "hepta.cpp-unique-reset-migration.v1"),
            "profile": SWAP_PROFILE if owner_swaps else REUSABLE_PROFILE if reusable_released_owners else PROFILE, "ok": True,
            "source": source, "program": program, "capture": capture, "compiler_sha256": before,
            "source_lowering": source_summary, "translation_statistics": translator.stats, "costs": costs,
            "project_function": active[0][0]["name"], "declarations": inventory,
            "unconverted_declarations": [], "compiler_implicit_declarations": implicit,
            "standard_library_declarations": library, "ast_capture": ast,
            "reference_ast_capture": reference_ast,
            "standard_library_expansion": {"reference_equal": True, "headers": actual_standard,
                "reference_source_sha256": sha256(reference_source.encode()).hexdigest()},
            "library_operation_contracts": {key: sorted(value) for key, value in contracts.items()},
            "claims": {"actual_project_algorithm_structurally_translated": True,
                "standalone_core_resource_check": "passed", "original_cpp_objects_in_target": False,
                "standard_library_contract_is_trusted": True, "standard_library_bodies_translated": 0,
                "standard_library_implementation_migrated": False, "source_equivalence_formally_proved": False,
                "whole_cpp_supported": False, "scalar_abi_requires_native_qualification": True,
                "cpp_class_abi_preserved": False, "pointer_escape_supported": False,
                "released_source_reuse_supported": reusable_released_owners, "custom_deleters_supported": False,
                "bound_member_swap_supported": owner_swaps, "std_swap_supported": False,
                "loops_or_concurrency_supported": False, "maximum_guarded_allocation_bytes": MAX_ALLOCATION,
                "allocator_contract": "zeroed byte allocation and default delete; replaceable allocator behavior outside contract is unsupported",
                "abort_or_process_crash_recovery_qualified": False}}

