"""Source-derived, closed Microsoft GSL final_action specialization.

Only the selected genuine upstream class instantiation and the captured scalar
callback body are translated. The frontend consumes real Clang JSON ASTs and
rejects every unmodeled statement in those bodies. std::move and std::exchange
remain explicit trusted library contracts; the complete preprocessor dependency
closure and compiler identity are retained. The authored client models C++
unwinding as explicit status paths and is not counted as automatic migration.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from .native_tool_identity import update_stable_regular_hash

PROFILE = "cpp20-real-gsl-final-action-closed-scalar-callback-v1"
MAX_AST_BYTES = 32 * 1024 * 1024
MAX_NODES = 100_000
VERSIONS = {
    "3.1.0": ("0f6dbc9e2915ef5c16830f3fa3565738de2a9230", "gsl/gsl_util"),
    "4.0.0": ("a3534567187d2edc428efd3f13466ff75fe5805c", "gsl/util"),
}

# The probe is compiler owned: user-supplied extra standard-library overloads,
# specializations or preprocessing flags cannot self-certify the std contracts.
PROBE = '''#include "selected_gsl.hpp"
#include "callback.hpp"
#include <climits>
#include <type_traits>
#include <utility>

using GslGuard = gsl::final_action<GslCallback>;
static_assert(CHAR_BIT == 8 && sizeof(unsigned long long) == 8);
static_assert(std::is_aggregate<GslCallback>::value);
static_assert(std::is_aggregate<GslState>::value);
static_assert(std::is_trivially_copy_constructible<GslCallback>::value);
static_assert(std::is_trivially_move_constructible<GslCallback>::value);
static_assert(std::is_trivially_destructible<GslCallback>::value);
static_assert(std::is_standard_layout<GslCallback>::value);
static_assert(std::is_same<decltype(&GslCallback::operator()),
                          void (GslCallback::*)() noexcept>::value);
static_assert(!std::is_copy_constructible<GslGuard>::value);
static_assert(!std::is_copy_assignable<GslGuard>::value);
static_assert(!std::is_move_assignable<GslGuard>::value);
static_assert(std::is_nothrow_move_constructible<GslGuard>::value);
static_assert(std::is_nothrow_destructible<GslGuard>::value);

// This instantiates all three upstream implementation bodies. Its source is
// a compiler probe and is not counted as an upstream implementation.
void gsl_capture(GslState* state, unsigned long long tag) noexcept {
    GslGuard first(GslCallback{state, tag});
    GslGuard second(static_cast<GslGuard&&>(first));
}
void gsl_factory_capture(GslState* state, unsigned long long tag) noexcept {
    auto guard = gsl::finally(GslCallback{state, tag});
}
#if HEPTA_GSL_LVALUE
void gsl_lvalue_factory_capture(GslState* state, unsigned long long tag) noexcept {
    GslCallback callback{state, tag};
    auto guard = gsl::finally(callback);
}
#endif
'''


class MigrationError(ValueError):
    """Fail closed on a source, type, dependency or unsupported AST mismatch."""


def need(value, message):
    if not value:
        raise MigrationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def children(node):
    return node.get("inner", [])


def qual(node):
    value = node.get("type", {})
    return value.get("desugaredQualType", value.get("qualType", ""))


def _without_locations(value):
    if isinstance(value, dict):
        return {key: _without_locations(item) for key, item in value.items()
                if key not in {"id", "loc", "range"}}
    if isinstance(value, list):
        return [_without_locations(item) for item in value]
    return value


def walk(node):
    pending = [node]
    visited = 0
    while pending:
        item = pending.pop()
        visited += 1
        need(visited <= MAX_NODES and isinstance(item, dict), "AST node budget/shape")
        yield item
        pending.extend(reversed(children(item)))


def documents(raw):
    need(len(raw.encode()) <= MAX_AST_BYTES, "AST exceeds byte budget")
    decoder = json.JSONDecoder()
    result, cursor = [], 0
    while cursor < len(raw):
        while cursor < len(raw) and raw[cursor].isspace():
            cursor += 1
        if cursor == len(raw):
            break
        value, cursor = decoder.raw_decode(raw, cursor)
        need(isinstance(value, dict), "AST document is not an object")
        result.append(value)
        need(len(result) <= 128, "AST document budget")
    need(bool(result), "Empty AST capture")
    return result


def unwrap(node):
    for _ in range(16):
        kind = node.get("kind")
        if kind == "ParenExpr":
            need(len(children(node)) == 1, "Malformed parentheses")
        elif kind == "ImplicitCastExpr":
            need(node.get("castKind") in {"NoOp", "LValueToRValue", "FunctionToPointerDecay", "BuiltinFnToFnPtr"},
                 "Unsupported implicit cast: " + str(node.get("castKind")))
            need(len(children(node)) == 1, "Malformed implicit cast")
        elif kind in {"MaterializeTemporaryExpr", "ExprWithCleanups"}:
            need(len(children(node)) == 1, "Malformed temporary wrapper")
        else:
            return node
        node = children(node)[0]
    raise MigrationError("Expression wrapper depth")


class Translator:
    """Translate operations, never infer semantics from only the class name."""

    def __init__(self, upstream, callback, factory=None):
        roots = documents(upstream) if isinstance(upstream, str) else upstream
        callbacks = documents(callback) if isinstance(callback, str) else callback
        specs = [n for root in roots for n in walk(root)
                 if n.get("kind") == "ClassTemplateSpecializationDecl"
                 and n.get("name") == "final_action" and n.get("completeDefinition")
                 and any(c.get("kind") == "TemplateArgument" and qual(c) == "GslCallback"
                         for c in children(n))]
        need(len(specs) == 1, "Exactly one complete final_action<GslCallback> instantiation is required")
        self.owner = specs[0]
        need(not self.owner.get("bases"), "Inheritance is outside this profile")
        self.fields = {c.get("name"): c for c in children(self.owner) if c.get("kind") == "FieldDecl"}
        need(set(self.fields) == {"f_", "invoke_"} and qual(self.fields["f_"]) == "GslCallback"
             and qual(self.fields["invoke_"]) == "bool", "Upstream owner field contract changed")
        need(all(not f.get("isBitfield") for f in self.fields.values()), "Bitfield owner state")
        self.callback_roots = callbacks
        self.factory_roots = documents(factory) if isinstance(factory, str) else factory
        self.callback_nodes = [n for root in callbacks for n in walk(root)]
        self._callback_layout()
        self.stats = {"upstream_method_bodies_translated": 0,
                      "upstream_factory_instantiations_translated": 0,
                      "authored_callback_bodies_translated": 0,
                      "callback_assignments_translated": 0}
        self.trace = []

    def _callback_layout(self):
        records = {}
        for n in self.callback_nodes:
            if n.get("kind") == "CXXRecordDecl" and n.get("completeDefinition"):
                need(n.get("name") in {"GslState", "GslCallback"}, "Unexpected callback-side record")
                need(n.get("name") not in records, "Duplicate callback record")
                records[n["name"]] = n
        need(set(records) == {"GslState", "GslCallback"}, "Callback/state definitions missing")
        for name, expected in {
            "GslState": [("trace", "unsigned long long"), ("calls", "unsigned long long")],
            "GslCallback": [("state", "GslState *"), ("tag", "unsigned long long")],
        }.items():
            record = records[name]
            fields = [n for n in children(record) if n.get("kind") == "FieldDecl"]
            need(not record.get("bases") and [(f.get("name"), qual(f)) for f in fields] == expected,
                 "Callback/state type layout differs: " + name)
            need(all(not f.get("isBitfield") and not children(f) for f in fields),
                 "Callback fields cannot hide initialization or bitfields")
            need(record.get("definitionData", {}).get("isTriviallyCopyable") is True,
                 "Callback/state must remain trivially copyable")
            for item in children(record):
                if item.get("isImplicit") or item.get("kind") == "FieldDecl":
                    continue
                need(name == "GslCallback" and item.get("kind") == "CXXMethodDecl"
                     and item.get("name") == "operator()" and qual(item) == "void () noexcept"
                     and not children(item), "Unmodeled callback record declaration")
        self.callback_record = records["GslCallback"]
        self.callback_fields = {n["id"]: n["name"] for n in children(self.callback_record)
                                if n.get("kind") == "FieldDecl"}
        self.state_fields = {n["id"]: n["name"] for n in children(records["GslState"])
                            if n.get("kind") == "FieldDecl"}
        # This source has no standard headers. Reject all active top-level
        # declarations except the two records and the one callback definition;
        # global initialization must not disappear behind AST filtering.
        for root in self.callback_roots:
            top = children(root) if root.get("kind") == "TranslationUnitDecl" else [root]
            for node in top:
                if node.get("isImplicit"):
                    continue
                need(node.get("kind") in {"CXXRecordDecl", "CXXMethodDecl"},
                     "Unmodeled active callback translation-unit declaration")
                if node.get("kind") == "CXXMethodDecl":
                    need(node.get("name") == "operator()", "Extra callback-side method definition")

    @staticmethod
    def _body(method):
        bodies = [n for n in children(method) if n.get("kind") == "CompoundStmt"]
        need(len(bodies) == 1, "Method must have one complete source body")
        need(qual(method).endswith("noexcept"), "Throwing method is outside this profile")
        return bodies[0]

    def _member(self, node, *, base=None, field=None):
        node = unwrap(node)
        need(node.get("kind") == "MemberExpr" and len(children(node)) == 1,
             "Expected one declaration-bound member access")
        name = node.get("name")
        if field is not None:
            need(name == field and node.get("referencedMemberDecl") == self.fields[field]["id"],
                 "Owner member does not reference captured declaration")
        origin = unwrap(children(node)[0])
        if base == "this":
            need(origin.get("kind") == "CXXThisExpr", "Member does not belong to this owner")
        elif base is not None:
            need(origin.get("kind") == "DeclRefExpr"
                 and origin.get("referencedDecl", {}).get("id") == base,
                 "Member does not belong to captured other owner")
        return node

    @staticmethod
    def _call(node, name, arity):
        node = unwrap(node)
        need(node.get("kind") == "CallExpr" and len(children(node)) == arity + 1,
             "Expected trusted std::" + name + " call")
        callee = unwrap(children(node)[0])
        need(callee.get("kind") == "DeclRefExpr"
             and callee.get("referencedDecl", {}).get("kind") == "FunctionDecl"
             and callee.get("referencedDecl", {}).get("name") == name,
             "Trusted standard function binding differs: " + name)
        return children(node)[1:]

    def _callback_move(self, node):
        node = unwrap(node)
        need(node.get("kind") == "CXXConstructExpr" and qual(node) == "GslCallback"
             and len(children(node)) == 1, "Callback must use its trivial move constructor")
        need(node.get("ctorType", {}).get("qualType") == "void (GslCallback &&) noexcept",
             "Nontrivial/unknown callback constructor")
        return self._call(children(node)[0], "move", 1)[0]

    def _initializers(self, method):
        body = self._body(method)
        need(not children(body), "Unexpected constructor body side effect")
        need(all(c.get("kind") in {"ParmVarDecl", "CXXCtorInitializer", "CompoundStmt"}
                 for c in children(method)), "Unknown constructor declaration child")
        init = [n for n in children(method) if n.get("kind") == "CXXCtorInitializer"]
        need(len(init) == 2 and [n.get("anyInit", {}).get("id") for n in init]
             == [self.fields["f_"]["id"], self.fields["invoke_"]["id"]],
             "Owner initializers must initialize both captured fields in declaration order")
        need(all(len(children(n)) == 1 for n in init), "Unexpected initializer argument count")
        return [children(n)[0] for n in init]

    def constructor(self, method):
        parameters = [n for n in children(method) if n.get("kind") == "ParmVarDecl"]
        need(len(parameters) == 1 and qual(parameters[0]) == "GslCallback", "Constructor callable type")
        f, invoke = self._initializers(method)
        moved = unwrap(self._callback_move(f))
        need(moved.get("kind") == "DeclRefExpr" and
             moved.get("referencedDecl", {}).get("id") == parameters[0]["id"],
             "Constructor must move its captured by-value callback")
        invoke = unwrap(invoke)
        if invoke.get("kind") == "CXXDefaultInitExpr":
            defaults = children(self.fields["invoke_"])
            need(len(defaults) == 1 and len(children(invoke)) <= 1,
                 "Unknown default activation initializer")
            if children(invoke):
                need(invoke.get("hasRewrittenInit") is True
                     and _without_locations(children(invoke)[0]) == _without_locations(defaults[0]),
                     "Default activation rewrite differs")
            invoke = unwrap(defaults[0])
        if invoke.get("kind") == "InitListExpr":
            need(qual(invoke) == "bool" and len(children(invoke)) == 1,
                 "Unsupported activation aggregate initializer")
            invoke = unwrap(children(invoke)[0])
        need(invoke.get("kind") == "CXXBoolLiteralExpr" and type(invoke.get("value")) is bool,
             "Activation must be a captured Boolean literal")
        self.stats["upstream_method_bodies_translated"] += 1
        self.trace.append({"operation": "construct", "callback": "trivial_move_from_value",
                           "active": invoke["value"], "source_range": method.get("range")})
        return invoke["value"]

    def move_constructor(self, method):
        parameters = [n for n in children(method) if n.get("kind") == "ParmVarDecl"]
        need(len(parameters) == 1 and "final_action" in qual(parameters[0])
             and qual(parameters[0]).endswith("&&"), "Move constructor owner type")
        other = parameters[0]["id"]
        f, invoke = self._initializers(method)
        self._member(self._callback_move(f), base=other, field="f_")
        target, reset = self._call(invoke, "exchange", 2)
        self._member(target, base=other, field="invoke_")
        reset = unwrap(reset)
        need(reset.get("kind") == "CXXBoolLiteralExpr" and reset.get("value") is False,
             "Moved-from guard must become inactive")
        self.stats["upstream_method_bodies_translated"] += 1
        self.trace.append({"operation": "move", "callback": "trivial_move_from_other",
                           "active": "exchange_other_with_false",
                           "source_range": method.get("range")})

    def destructor(self, method):
        body = self._body(method)
        need(all(n.get("kind") in {"CompoundStmt", "SuppressAttr"} for n in children(method))
             and len(children(body)) == 1,
             "Unexpected destructor side effect")
        branch = children(body)[0]
        need(branch.get("kind") == "IfStmt" and not branch.get("hasElse")
             and len(children(branch)) == 2, "Destructor must conditionally invoke the callback once")
        self._member(children(branch)[0], base="this", field="invoke_")
        call = unwrap(children(branch)[1])
        need(call.get("kind") == "CXXOperatorCallExpr" and qual(call) == "void"
             and len(children(call)) == 2, "Destructor must make one nullary callback call")
        callee = unwrap(children(call)[0])
        decl = callee.get("referencedDecl", {})
        need(callee.get("kind") == "DeclRefExpr" and decl.get("kind") == "CXXMethodDecl"
             and decl.get("name") == "operator()" and qual(decl) == "void () noexcept",
             "Destructor callback signature differs")
        self._member(children(call)[1], base="this", field="f_")
        self.stats["upstream_method_bodies_translated"] += 1
        self.trace.append({"operation": "destroy", "condition": "active", "callback_count": 1,
                           "source_range": method.get("range")})

    def place(self, node):
        node = unwrap(node)
        need(node.get("kind") == "MemberExpr" and len(children(node)) == 1,
             "Callback may access only captured scalar fields")
        member = node.get("referencedMemberDecl")
        base = unwrap(children(node)[0])
        if member in self.callback_fields:
            need(base.get("kind") == "CXXThisExpr", "Callback field must belong to this")
            name = self.callback_fields[member]
            need(node.get("name") == name, "Callback member identity mismatch")
            return "owner.tag" if name == "tag" else "state"
        need(member in self.state_fields and self.place(base) == "state",
             "State field must use the captured synchronous state pointer")
        name = self.state_fields[member]
        need(node.get("name") == name and qual(node) == "unsigned long long",
             "State field identity/type mismatch")
        return "state." + name

    def scalar(self, node, depth=0):
        need(depth <= 32, "Scalar expression depth")
        node = unwrap(node)
        need(qual(node) == "unsigned long long", "Only unsigned 64-bit callback arithmetic is supported")
        if node.get("kind") == "IntegerLiteral":
            value = int(node.get("value", "-1"))
            need(not children(node) and 0 <= value < 1 << 64, "Invalid scalar literal")
            return str(value)
        if node.get("kind") == "MemberExpr":
            place = self.place(node)
            need(place != "state", "A pointer cannot become a scalar")
            return place
        need(node.get("kind") == "BinaryOperator" and len(children(node)) == 2
             and node.get("opcode") in {"+", "-", "*"}, "Unsupported callback scalar operation")
        operation = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[node["opcode"]]
        left, right = (self.scalar(child, depth + 1) for child in children(node))
        return operation + "(" + left + ", " + right + ")"

    def callback(self):
        methods = [n for n in self.callback_nodes if n.get("kind") == "CXXMethodDecl"
                   and n.get("name") == "operator()"
                   and any(c.get("kind") == "CompoundStmt" for c in children(n))]
        need(len(methods) == 1, "Exactly one captured callback definition is required")
        method = methods[0]
        need(method.get("parentDeclContextId") == self.callback_record["id"]
             and qual(method) == "void () noexcept", "Callback definition owner/signature differs")
        body = self._body(method)
        need(len(children(method)) == 1 and 1 <= len(children(body)) <= 16,
             "Callback body statement budget/signature")
        result = []
        for statement in children(body):
            statement = unwrap(statement)
            need(statement.get("kind") == "BinaryOperator" and statement.get("opcode") == "="
                 and len(children(statement)) == 2, "Callback statements must be scalar assignments")
            destination = self.place(children(statement)[0])
            need(destination in {"state.trace", "state.calls"}, "Callback cannot alter/store its pointer or tag")
            result.append(destination + " = " + self.scalar(children(statement)[1]) + ";")
        self.stats["authored_callback_bodies_translated"] += 1
        self.stats["callback_assignments_translated"] = len(result)
        self.trace.append({"operation": "callback", "assignments": result,
                           "source_range": method.get("range")})
        return result

    def factories(self):
        if self.factory_roots is None:
            return "", []
        selected = [n for root in self.factory_roots for n in walk(root)
                    if n.get("kind") == "FunctionDecl" and n.get("name") == "finally"
                    and n.get("isUsed") and any(c.get("kind") == "TemplateArgument" for c in children(n))]
        need(1 <= len(selected) <= 2, "Expected the captured rvalue and optional nonconst-lvalue factories")
        emitted, categories = [], []
        for method in selected:
            need(all(n.get("kind") in {"TemplateArgument", "ParmVarDecl", "CompoundStmt", "WarnUnusedResultAttr"}
                     for n in children(method)), "Unmodeled factory declaration child")
            parameters = [n for n in children(method) if n.get("kind") == "ParmVarDecl"]
            arguments = [n for n in children(method) if n.get("kind") == "TemplateArgument"]
            need(len(parameters) == len(arguments) == 1, "Factory template/parameter arity")
            category = {"GslCallback &&": "rvalue", "GslCallback &": "nonconst_lvalue"}.get(qual(parameters[0]))
            need(category is not None and category not in categories, "Unknown or repeated factory category")
            need(qual(arguments[0]) == ("GslCallback" if category == "rvalue" else "GslCallback &"),
                 "Factory template argument differs from reference category")
            body = self._body(method)
            need(len(children(body)) == 1 and children(body)[0].get("kind") == "ReturnStmt"
                 and len(children(children(body)[0])) == 1, "Factory must directly return one owner")
            cast = unwrap(children(children(body)[0])[0])
            need(cast.get("kind") == "CXXFunctionalCastExpr" and cast.get("castKind") == "ConstructorConversion"
                 and qual(cast) == "gsl::final_action<GslCallback>" and len(children(cast)) == 1
                 and cast.get("conversionFunc", {}).get("name") == "final_action"
                 and qual(cast.get("conversionFunc", {})) == "void (GslCallback) noexcept",
                 "Factory must construct the captured owner value")
            temporary = children(cast)[0]
            need(temporary.get("kind") == "CXXBindTemporaryExpr" and len(children(temporary)) == 1
                 and qual(temporary) == "gsl::final_action<GslCallback>"
                 and temporary.get("dtor", {}).get("name") == "~final_action"
                 and qual(temporary.get("dtor", {})) == "void () noexcept", "Factory temporary owner contract")
            owner = children(temporary)[0]
            need(owner.get("kind") == "CXXConstructExpr" and len(children(owner)) == 1
                 and qual(owner) == "gsl::final_action<GslCallback>"
                 and owner.get("ctorType", {}).get("qualType") == "void (GslCallback) noexcept",
                 "Factory owner constructor contract")
            callback = children(owner)[0]
            expected_constructor = ("void (GslCallback &&) noexcept" if category == "rvalue"
                                    else "void (const GslCallback &) noexcept")
            need(callback.get("kind") == "CXXConstructExpr" and len(children(callback)) == 1
                 and qual(callback) == "GslCallback"
                 and callback.get("ctorType", {}).get("qualType") == expected_constructor,
                 "Factory must use the captured trivial callback move/copy")
            forwarded = self._call(children(callback)[0], "forward", 1)[0]
            forwarded = unwrap(forwarded)
            need(forwarded.get("kind") == "DeclRefExpr"
                 and forwarded.get("referencedDecl", {}).get("id") == parameters[0]["id"],
                 "Factory must forward its captured parameter")
            name = "GslFinallyRvalue" if category == "rvalue" else "GslFinallyLvalue"
            emitted.append("fn " + name + "(tag: u64) -> GslFinalAction effects {alloc, block, panic} {\n"
                           "    return GslConstruct(tag);\n}\n")
            categories.append(category)
            self.stats["upstream_factory_instantiations_translated"] += 1
            self.trace.append({"operation": "factory", "category": category,
                               "callback_transfer": "trivial_move" if category == "rvalue" else "trivial_copy",
                               "return": "construct_owner_prvalue", "source_range": method.get("range")})
        need("rvalue" in categories, "Rvalue factory is required")
        return "\n".join(emitted), sorted(categories)

    def translate(self):
        constructors = [n for n in children(self.owner) if n.get("kind") == "CXXConstructorDecl"
                        and not n.get("explicitlyDeleted") and not n.get("isImplicit")]
        need(len(constructors) == 2, "Unexpected owner constructor set")
        value = [n for n in constructors if any(c.get("kind") == "ParmVarDecl" and qual(c) == "GslCallback"
                                                for c in children(n))]
        move = [n for n in constructors if n not in value]
        need(len(value) == len(move) == 1, "Value/move constructor distinction")
        active = self.constructor(value[0])
        self.move_constructor(move[0])
        destructors = [n for n in children(self.owner) if n.get("kind") == "CXXDestructorDecl"]
        need(len(destructors) == 1, "Unexpected destructor set")
        self.destructor(destructors[0])
        callback = self.callback()
        factories, categories = self.factories()
        # The moved-from C++ destructor is effect-free because the captured
        # exchange sets false and the captured destructor tests that flag. A
        # consumed Core owner therefore represents the same cleanup obligation.
        source = """module gsl_final_action_migrated;
// Generated from real captured upstream method and callback bodies.
// This zero-length linear token does not allocate a payload on the C backend.
struct GslState { trace: u64, calls: u64 }
struct GslFinalAction { token: Buffer<u8>, tag: u64, active: bool }
fn GslConstruct(tag: u64) -> GslFinalAction effects {alloc, block, panic} {
    let token = buffer(0);
    return GslFinalAction {token: move token, tag: tag, active: ACTIVE};
}
fn GslMove(owner: take GslFinalAction) -> GslFinalAction effects {} {
    return move owner;
}
fn GslDestroy(owner: take GslFinalAction, state: mut GslState) -> Unit effects {alloc, block, write} {
    if owner.active {
CALLBACK
    }
    drop(move owner);
}
""".replace("ACTIVE", str(active).lower()).replace("CALLBACK", "\n".join("        " + row for row in callback))
        return source + factories, {"profile": PROFILE, "statistics": dict(self.stats),
                                    "factory_categories": categories, "lowered_operations": self.trace}


def translate_captured(upstream_ast, callback_ast, factory_ast=None):
    """Pure, fail-closed AST lowering; public callers must bind capture inputs."""
    return Translator(upstream_ast, callback_ast, factory_ast).translate()


def _identity(path):
    path = Path(path).resolve(strict=True)
    digest = sha256()
    update_stable_regular_hash(digest, path, allow_empty=False)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def _run(argv, *, output=None):
    started = time.monotonic()
    result = subprocess.run([str(a) for a in argv], capture_output=True, timeout=60)
    need(result.returncode == 0, "Capture compiler failed: " + result.stderr.decode(errors="replace")[:4000])
    if output is not None:
        Path(output).write_bytes(result.stdout)
    return result.stdout.decode(), {"argv": [str(a) for a in argv], "returncode": result.returncode,
        "stderr": result.stderr.decode(errors="replace"), "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stdout_bytes": len(result.stdout), "elapsed_seconds": time.monotonic() - started}


def capture_and_lower(root, version, output, *, clang, examples=None):
    root, output = Path(root).resolve(), Path(output).resolve()
    need(version in VERSIONS, "Unsupported pinned upstream release")
    output.mkdir(parents=True, exist_ok=True)
    examples = Path(examples).resolve() if examples is not None else root / "examples/cpp/gsl_final_action"
    upstream = root / "tests/fixtures/gsl_final_action"
    lock = json.loads((upstream / "lock.json").read_text())
    entry = [item for item in lock["versions"] if item["version"] == version]
    need(len(entry) == 1 and entry[0]["commit"] == VERSIONS[version][0], "Upstream commit differs")
    locked = entry[0]
    for file in locked["files"]:
        actual = _identity(upstream / version / file["path"])
        need(actual["sha256"] == file["sha256"] and actual["bytes"] == file["bytes"], "Upstream file lock mismatch")
    executable = Path(shutil.which(str(clang)) or str(clang)).resolve(strict=True)
    compiler = _identity(executable)
    version_text, compiler_version = _run([executable, "--version"])
    need(re.search(r"clang version 20\.", version_text) is not None,
         "This AST profile is qualified only for Clang 20")
    selected = output / "selected_gsl.hpp"
    selected.write_text("#include <" + VERSIONS[version][1] + ">\n")
    need((examples / "contract.cpp").read_text() == PROBE,
         "Type contract must match the compiler-owned probe exactly")
    probe = output / "capture_contract.cpp"
    probe.write_text(PROBE)
    flags = ["-std=c++20", "-Werror", "-DHEPTA_GSL_LVALUE=" + str(int(version == "4.0.0")),
             "-I" + str(output), "-I" + str(examples),
             "-I" + str(upstream / version / "include")]
    commands, captured, before = [compiler_version], {}, {}
    for label, source, selected_filter in (("upstream", probe, "gsl::final_action"),
                                           ("factory", probe, "gsl::finally"),
                                           ("callback", examples / "callback.cpp", None)):
        dependency_text, receipt = _run([executable, *flags, "-M", "-MT", "capture", source],
                                       output=output / (label + ".d"))
        commands.append(receipt)
        # -M includes system dependencies; retain all of them, not just the two
        # vendored upstream headers. A changed host standard library is a new
        # capture identity and therefore cannot reuse the old receipt.
        names = shlex.split(dependency_text.replace("\\\n", " ").split(":", 1)[1])
        for filename in names:
            path = Path(filename).resolve(strict=True)
            identity = _identity(path)
            if str(path) in before:
                need(identity == before[str(path)], "Dependency changed between captures")
            else:
                before[str(path)] = identity
        argv = [executable, *flags, "-fsyntax-only", "-Xclang", "-ast-dump=json"]
        if selected_filter is not None:
            argv += ["-Xclang", "-ast-dump-filter=" + selected_filter]
        raw, receipt = _run([*argv, source], output=output / (label + ".ast.json"))
        need(len(raw.encode()) <= MAX_AST_BYTES, "Captured AST byte budget exceeded")
        captured[label] = raw
        commands.append(receipt)
    component, lowering = translate_captured(captured["upstream"], captured["callback"], captured["factory"])
    need(lowering["factory_categories"] == (["nonconst_lvalue", "rvalue"] if version == "4.0.0" else ["rvalue"]),
         "Captured factory categories differ from this release's type contract")
    client_path = examples / "client.hepta"
    before[str(client_path)] = _identity(client_path)
    source = component + "\n" + client_path.read_text()
    for filename, identity in before.items():
        need(_identity(filename) == identity, "Input dependency changed during translation")
    need(_identity(probe)["sha256"] == sha256(PROBE.encode()).hexdigest(), "Compiler-owned probe changed")
    for file in locked["files"]:
        actual = _identity(upstream / version / file["path"])
        need(actual["sha256"] == file["sha256"] and actual["bytes"] == file["bytes"], "Upstream file lock changed")
    need(_identity(executable) == compiler, "Compiler executable changed during translation")
    report = {"schema": "hepta.gsl-final-action-migration.v1", "profile": PROFILE,
              "upstream": locked, "compiler": compiler, "compiler_version": version_text,
              "commands": commands, "dependencies": list(before.values()),
              "dependency_closure_sha256": sha256(canonical(before)).hexdigest(),
              "ast_sha256": {name: sha256(raw.encode()).hexdigest() for name, raw in captured.items()},
              "importer_sha256": _identity(__file__)["sha256"],
              "type_contract_sha256": sha256(PROBE.encode()).hexdigest(),
              **lowering, "generated_component_sha256": sha256(component.encode()).hexdigest(),
              "generated_source_sha256": sha256(source.encode()).hexdigest(),
              "trusted_contracts": ["Clang 20 C++20 parsing and type instantiation",
                  "captured host standard-library std::move, std::forward and std::exchange semantics",
                  "trivial GslCallback move/copy/destruction, 8-bit bytes and 64-bit unsigned long long",
                  "one synchronous callback state binding in the authored closed client"],
              "scope": {"upstream": "gsl::final_action<GslCallback> value/move constructors and destructor",
                        "authored_translated": "GslCallback::operator() scalar body",
                        "authored_not_translated": "C++ test clients and explicit-status Hepta integration client",
                        "factory": "actual rvalue instantiation; 4.0 also captures and lowers nonconst-lvalue instantiation",
                        "general_templates_or_exceptions_supported": False,
                        "standard_library_implementation_migrated": False,
                        "general_callable_lifetime_inference": False}}
    (output / "component.hepta").write_text(component)
    (output / "migration.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    return {"component_source": component, "source": source, "report": report}
