"""Captured, synchronous borrowed C++ callback implementation migration.

The closed profile binds one actual function-pointer argument to one captured
callback definition. It specializes that argument to a direct checked HIA call;
it neither calls a C++ bridge nor introduces general indirect calls into Core.
All callback statements and scalar expressions use the existing structural
translator. References cannot be stored, returned, mutated, or escape.
"""
from __future__ import annotations

from collections import Counter
import copy
from hashlib import sha256
import json
import re

from .c_project import capture_project, verify_capture
from .c_project_matrix import capture_project_matrix, verify_project_matrix
from .cpp_composed_migrate import (
    _Translator, _children, _qual, _name, _reject, _scalar, EFFECTS, LIMITS,
)
from .cpp_composed_project import _ProjectTranslator, _decls
from .cpp_owned_migrate import _nodes
from .cpp_unique_project import (
    UNIQUE_LEAF, _large_ast, _unique_shape, _reference_config, _standard_snapshot,
)
from .hia_program_source import lower_source, source_report
from .pipeline import analyze, compiler_hash

PROFILE = "cpp20-captured-unique-owner-synchronous-borrowed-callback-v1"


class _CallbackTranslator(_ProjectTranslator):
    """A finite, declaration-bound callback specialization, not a pointer cast."""

    def __init__(self, tree, leaf, composite, operation, helpers, callbacks):
        if len(helpers) != 1 or len(callbacks) != 1:
            _reject("Exactly one consuming helper and one captured callback are required",
                    "E_CPP_CALLBACK_CLOSED")
        super().__init__(tree, leaf, composite, operation, helpers)
        self.callback = callbacks[0]
        self.callback_type = f"unsigned long long (*)(const {self.class_name} &, unsigned long, bool) noexcept"
        self.callback_signature = f"unsigned long long (const {self.class_name} &, unsigned long, bool) noexcept"
        if _qual(self.callback) != self.callback_signature:
            _reject("Callback must synchronously borrow const owner and return u64 noexcept",
                    "E_CPP_CALLBACK_SIGNATURE")
        self.mark(self.callback, "translated_synchronous_borrowed_callback")
        self.callback_parameters = {}
        self.stats.update(borrowed_callback_calls=0, closed_callback_bindings=0)
        for info in self.helpers.values():
            params = [n for n in _children(info["node"]) if n.get("kind") == "ParmVarDecl"]
            if len(params) < 2 or _qual(params[1]) != self.callback_type:
                _reject("Owner consumer requires its explicit second function-pointer parameter",
                        "E_CPP_CALLBACK_SIGNATURE")
            self.callback_parameters[params[1]["id"]] = params[1]
        # Binding is verified at the sole entry's actual call, before emitting
        # a specialized body. No uninspected function pointer is trusted.
        sites = []
        for node, _ in _nodes(operation):
            if node.get("kind") != "CallExpr":
                continue
            children = _children(node)
            if not children:
                _reject("Missing callback consumer reference")
            callee = self._unwrapped(children[0], {"ImplicitCastExpr", "ParenExpr"})
            if callee.get("referencedDecl", {}).get("id") in self.helpers:
                self._binding(children)
                sites.append(node)
        if len(sites) != 1:
            _reject("Closed callback profile requires exactly one captured binding site",
                    "E_CPP_CALLBACK_CLOSED")

    def _binding(self, children):
        if len(children) < 3:
            _reject("Callback binding is missing", "E_CPP_CALLBACK_BINDING")
        callback = children[2]
        if (callback.get("kind") != "ImplicitCastExpr"
                or callback.get("castKind") != "FunctionToPointerDecay"
                or _qual(callback) != self.callback_type or len(_children(callback)) != 1):
            _reject("Callback must be the captured function itself, without cast or null",
                    "E_CPP_CALLBACK_BINDING")
        reference = _children(callback)[0]
        ref = reference.get("referencedDecl", {})
        if (reference.get("kind") != "DeclRefExpr" or _children(reference)
                or ref.get("kind") != "FunctionDecl" or ref.get("id") != self.callback["id"]
                or ref.get("name") != self.callback["name"] or _qual(ref) != self.callback_signature):
            _reject("Callback does not bind to the complete captured definition",
                    "E_CPP_CALLBACK_BINDING")

    def params(self, node):
        if node.get("id") not in self.helpers and node.get("id") != self.callback["id"]:
            return super().params(node)
        result = {}
        parameters = [n for n in _children(node) if n.get("kind") == "ParmVarDecl"]
        if not 1 <= len(parameters) <= 12:
            _reject("Callback/consumer parameter budget exceeded")
        for index, param in enumerate(parameters):
            self.guard(param)
            if _children(param) or param.get("init"):
                _reject("Callback parameters cannot hide defaults or attributes")
            _name(param.get("name"))
            if index == 0:
                borrowed = node["id"] == self.callback["id"]
                expected = "const " + self.class_name + " &" if borrowed else self.class_name
                if _qual(param) != expected:
                    _reject("Callback owner parameter differs from its captured contract")
                typ = "borrowed_owner" if borrowed else "owner"
            elif param["id"] in self.callback_parameters:
                if _qual(param) != self.callback_type:
                    _reject("Callback pointer signature changed")
                typ = "closed_callback"
            else:
                typ = _scalar(param)
            self.mark(param, {"borrowed_owner": "non_escaping_read_borrow_parameter",
                              "owner": "consumed_by_value_owner_parameter",
                              "closed_callback": "statically_bound_callback_parameter"}.get(typ, "scalar_parameter"))
            result[param["id"]] = {"emitted": "arg" + str(index), "type": typ,
                "cpp_type": _qual(param), "source_name": param["name"], "alive": True}
        return result

    def signature(self, node, *, constructor=False):
        if node.get("id") not in self.helpers:
            return super().signature(node, constructor=constructor)
        self.guard(node)
        params = self.params(node)
        expected = "unsigned long long (" + ", ".join(p["cpp_type"] for p in params.values()) + ") noexcept"
        bodies = [n for n in _children(node) if n.get("kind") == "CompoundStmt"]
        if (_qual(node) != expected or len(bodies) != 1
                or any(n.get("kind") not in {"ParmVarDecl", "CompoundStmt"} for n in _children(node))):
            _reject("Consumer must have one complete noexcept body", "E_CPP_CALLBACK_SIGNATURE")
        return "u64", False, params, bodies[0]

    def place(self, node, env, *, context, const):
        plain = self._unwrapped(node, {"ParenExpr"})
        if plain.get("kind") == "ImplicitCastExpr" and plain.get("castKind") == "NoOp":
            children = _children(plain)
            if len(children) != 1:
                _reject("Invalid qualification of callback borrow")
            return self.place(children[0], env, context=context, const=const)
        if plain.get("kind") == "DeclRefExpr" and not _children(plain):
            ref = plain.get("referencedDecl", {})
            value = env.get(ref.get("id"))
            if value is not None and value["type"] == "borrowed_owner":
                if (not value["alive"] or ref.get("kind") != "ParmVarDecl"
                        or ref.get("name") != value["source_name"]
                        or _qual(ref) != "const " + self.class_name + " &"
                        or _qual(plain) != "const " + self.class_name):
                    _reject("Borrowed owner does not match its captured parameter")
                return value["emitted"], self.class_name, True
        return super().place(node, env, context=context, const=const)

    def transfer_call(self, node, env, *, context, const):
        children = _children(node)
        self._binding(children)
        callee = self._unwrapped(children[0], {"ImplicitCastExpr", "ParenExpr"})
        info = self.helpers.get(callee.get("referencedDecl", {}).get("id"))
        if info is None:
            _reject("Only the captured consuming helper may receive the callback")
        # The base transfer rule checks exact owner move, argument sequencing,
        # arity and scalar semantics. Give it a local view with the proved
        # callback slot erased; never mutate the original captured AST.
        projected = copy.deepcopy(node)
        projected["inner"].pop(2)
        original_info = info["node"]
        projected_function = copy.deepcopy(original_info)
        projected_function["inner"] = [n for n in projected_function["inner"]
                                       if not (n.get("kind") == "ParmVarDecl"
                                               and n.get("id") in self.callback_parameters)]
        # _ProjectTranslator consults only the helper's captured parameter list
        # and signature identity here. A temporary per-instance view is safe:
        # translation is synchronous and recursive transfer is disallowed.
        info["node"] = projected_function
        try:
            result = super().transfer_call(projected, env, context=context, const=const)
        finally:
            info["node"] = original_info
        self.stats["closed_callback_bindings"] += 1
        return result

    def expr(self, node, env, *, context, const=False):
        if node.get("kind") == "CallExpr":
            children = _children(node)
            callee = self._unwrapped(children[0], {"ImplicitCastExpr", "ParenExpr"}) if children else {}
            ref = callee.get("referencedDecl", {})
            if ref.get("id") in self.callback_parameters:
                if self._expression_depth or context != "lifecycle":
                    _reject("Callback requires one sequenced synchronous value expression",
                            "E_CPP_CALLBACK_SEQUENCE")
                if (callee.get("kind") != "DeclRefExpr" or _children(callee)
                        or ref.get("kind") != "ParmVarDecl" or _qual(ref) != self.callback_type
                        or env.get(ref.get("id"), {}).get("type") != "closed_callback"
                        or len(children) != 4 or _qual(node) != "unsigned long long"):
                    _reject("Indirect call differs from the captured closed callback",
                            "E_CPP_CALLBACK_CALL")
                place, typ, _ = self.place(children[1], env, context=context, const=const)
                if typ != self.class_name:
                    _reject("Callback must borrow one whole live owner")
                values = []
                for child, expected in zip(children[2:], ("usize", "bool")):
                    if any(n.get("kind") in {"CallExpr", "CXXMemberCallExpr"} for n, _ in _nodes(child)):
                        _reject("Callback arguments cannot add hidden calls")
                    value, actual = self.expr(child, env, context=context, const=const)
                    if actual != expected:
                        _reject("Callback scalar representation differs")
                    values.append(value)
                self.stats["borrowed_callback_calls"] += 1
                return "HeptaBorrowedCallback_0(" + ", ".join(["read " + place, *values]) + ")", "u64"
        return super().expr(node, env, context=context, const=const)

    def lifecycle(self):
        rendered = []
        ordered = [(self.callback, "HeptaBorrowedCallback_0"),
                   *[(info["node"], info["emitted"]) for info in self.helpers.values()]]
        for node, emitted in ordered:
            returns, const, params, body = self.signature(node)
            if returns != "u64" or const:
                _reject("Callback/consumer must return u64 noexcept")
            lines, done = self.statements(_children(body), copy.deepcopy(params),
                                          context="lifecycle", returns=returns)
            if not done:
                _reject("Callback/consumer has an unhandled fallthrough")
            arguments = []
            for param in params.values():
                typ = param["type"]
                if typ == "closed_callback":
                    continue
                spelling = {"owner": "take HeptaComposite", "borrowed_owner": "read HeptaComposite"}.get(typ, typ)
                arguments.append(param["emitted"] + ": " + spelling)
            rendered.append(f"pub fn {emitted}({', '.join(arguments)}) -> u64 {EFFECTS} {{\n"
                            + "\n".join(lines) + "\n}\n")
        rendered.append(_Translator.lifecycle(self))
        if self.stats["borrowed_callback_calls"] != 1 or self.stats["closed_callback_bindings"] != 1:
            _reject("Profile requires one bound and one actual callback instruction",
                    "E_CPP_CALLBACK_CLOSED")
        return "\n".join(rendered)


def _capture_lower(capture):
    before = compiler_hash()
    compiler = capture["compiler"]["path"]
    if not re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", capture["compiler"]["version"]):
        _reject("Clang20+ is required for the captured unique-array profile")
    units, inventory, library, ast_receipts, standard_receipts = [], [], [], [], []
    definitions, declaration_symbols = {}, {}
    shape = None
    expected_leaf_shape = None
    for config in capture["configurations"]:
        if config["model"]["long_bits"] != 64 or config["model"]["pointer_bits"] != 64:
            _reject("The unique-array native profile requires LP64")
        active, receipt, external, system_declarations, implicit = _large_ast(compiler, config)
        library.extend(system_declarations); inventory.extend(implicit)
        ast_receipts.append({"unit": config["index"], **receipt})
        records = [node for node, _ in active if node["kind"] == "CXXRecordDecl"]
        if len(records) != 2 or any(not node.get("completeDefinition") for node in records):
            _reject("Every unit requires one complete unique-array leaf and one composite")
        leaf, composite = records
        actual_leaf_shape = _unique_shape(leaf, external)
        current_shape = _unique_shape({"kind": "TranslationUnitDecl", "name": leaf["name"],
                                       "inner": [leaf, composite]}, external)
        if shape is None:
            shape = current_shape
        elif shape != current_shape:
            _reject("Owner definition differs between translation units", "E_CPP_UNIQUE_ODR")
        source = UNIQUE_LEAF.replace("OwnedBytes", leaf["name"])
        reference_config = _reference_config(config)
        actual_standard = _standard_snapshot(compiler, config)
        reference_standard = _standard_snapshot(compiler, reference_config, source=source)
        if actual_standard != reference_standard or not actual_standard:
            _reject("Project changes the expanded standard-library contract", "E_CPP_UNIQUE_STDLIB")
        standard_receipts.append({"unit": config["index"], "headers": actual_standard,
                                  "reference_equal": True,
                                  "reference_frontend_arguments": reference_config["frontend_arguments"],
                                  "reference_source_sha256": sha256(source.encode()).hexdigest()})
        if expected_leaf_shape is None:
            expected_active, expected_ast, expected_external, _, _ = _large_ast(compiler, reference_config, source=source)
            expected_leaf = next((node for node, _ in expected_active
                                  if node.get("kind") == "CXXRecordDecl" and node.get("name") == leaf["name"]), None)
            if expected_leaf is None:
                _reject("Compiler-owned reference owner was not captured")
            expected_leaf_shape = _unique_shape(expected_leaf, expected_external)
            del expected_active, expected_external
        if actual_leaf_shape != expected_leaf_shape:
            _reject("Complete unique-array wrapper differs from the checked default-deleter contract", "E_CPP_UNIQUE_LEAF")
        for node, file in active:
            if node["kind"] != "FunctionDecl":
                continue
            _name(node.get("name"))
            symbol = node.get("mangledName")
            if not isinstance(symbol, str):
                _reject("Free functions need captured mangled identities")
            key = (node["name"], _qual(node), symbol)
            if declaration_symbols.setdefault(node["name"], key) != key:
                _reject("Conflicting or overloaded free-function declarations")
            if any(child.get("kind") == "CompoundStmt" for child in _children(node)):
                if key in definitions:
                    _reject("Multiple function definitions", "E_CPP_UNIQUE_ODR")
                definitions[key] = (config["index"], node, file)
        units.append((config, active, leaf, composite))
    if not units or len(definitions) < 2 or set(definitions) != set(declaration_symbols.values()):
        _reject("Complete cross-unit lifecycle and consumer definitions are required", "E_CPP_UNIQUE_UNDEFINED")
    first, mappings = units[0], {}
    for config, active, leaf, composite in units:
        mapping = {}
        for record, canonical in zip((leaf, composite), first[2:4]):
            original_decls, canonical_decls = _decls(record), _decls(canonical)
            if [p for _, p in original_decls] != [p for _, p in canonical_decls]:
                _reject("Header declaration identities do not align")
            mapping.update({n["id"]: "unit" + str(first[0]["index"]) + ":" + selected["id"]
                            for (n, _), (selected, _) in zip(original_decls, canonical_decls)})
        for node, _ in active:
            if node["kind"] == "FunctionDecl":
                unit, definition, _ = definitions[declaration_symbols[node["name"]]]
                mapping[node["id"]] = "unit" + str(unit) + ":" + definition["id"]
        mappings[config["index"]] = mapping

    def rewritten(value, unit):
        if isinstance(value, list):
            return [rewritten(child, unit) for child in value]
        if not isinstance(value, dict):
            return value
        return {key: (child if child == "0x0" else mappings[unit].get(child, "unit" + str(unit) + ":" + child))
                if key in {"id", "referencedMemberDecl", "previousDecl"} and isinstance(child, str)
                else rewritten(child, unit) for key, child in value.items()}

    leaf, composite = [rewritten(node, first[0]["index"]) for node in first[2:4]]
    functions = [rewritten(node, unit) for unit, node, _ in definitions.values()]
    helpers, callbacks, entries = [], [], []
    for function in functions:
        parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
        if parameters and _qual(parameters[0]) == composite["name"]:
            helpers.append(function)
        elif parameters and _qual(parameters[0]) == "const " + composite["name"] + " &":
            callbacks.append(function)
        else:
            entries.append(function)
    if len(entries) != 1 or len(helpers) != 1 or len(callbacks) != 1 or len({unit for unit, _, _ in definitions.values()}) < 2:
        _reject("One scalar entry, one separately defined consumer and one borrowed callback are required")
    translator = _CallbackTranslator({"kind": "TranslationUnitDecl", "inner": [leaf, composite, *functions]},
                                  leaf, composite, entries[0], helpers, callbacks)
    source, translated = translator.translate()
    if translator.stats["cross_unit_owner_transfers"] == 0:
        _reject("Project contains no actual owner transfer")
    for config, active, _, _ in units:
        for top, file in active:
            definition = top["kind"] != "FunctionDecl" or any(child.get("kind") == "CompoundStmt" for child in _children(top))
            for node, path in _decls(top):
                identity = mappings[config["index"]].get(node["id"], "unit" + str(config["index"]) + ":" + node["id"])
                role = translator.roles.get(identity)
                if not definition:
                    if node["kind"] not in {"FunctionDecl", "ParmVarDecl"}:
                        _reject("Unaccounted forward-declaration children")
                    translator.guard(node)
                    if ((node["kind"] == "FunctionDecl" and any(c.get("kind") != "ParmVarDecl" for c in _children(node)))
                            or node["kind"] == "ParmVarDecl" and (_children(node) or node.get("init"))):
                        _reject("Forward declarations cannot hide attributes or defaults")
                    role = "forward_signature_bound_to_captured_definition"
                if role is None:
                    _reject("Active declaration has no disposition", "E_CPP_UNIQUE_INVENTORY")
                if role == "exact_leaf_protocol":
                    role = "exact_unique_array_default_deleter_contract"
                inventory.append({"unit": config["index"], "file": file, "kind": node["kind"],
                                  "name": node.get("name"), "path": list(path), "status": role,
                                  "canonical_id": identity})
    checked = analyze(source, "captured-callback-owners.hepta", backend="c", native=False, crate_type="obj")
    if not checked.report["ok"] or checked.report["assumptions"]:
        _reject("Unique owner failed checked lowering: " + json.dumps(checked.report))
    program = lower_source(source, path="<captured-callback-owner-project>")
    verify_capture(capture)
    if compiler_hash() != before:
        _reject("Compiler changed during unique-array capture")
    return {"schema": "hepta.cpp-callback-project-migration.v1",
            "profile": PROFILE, "ok": True,
            "program": program, "source": source, "capture": capture, "declarations": inventory,
            "standard_library_declarations": library, "standard_library_expansion": standard_receipts,
            "ast_capture": ast_receipts, "reference_ast_capture": expected_ast,
            "source_lowering": source_report(source), "translation_statistics": translator.stats,
            "active_declaration_count": sum(r["status"] != "compiler_implicit_declaration" for r in inventory),
            "standard_library_declaration_count": len(library), "unconverted_declarations": [],
            "disposition_counts": dict(Counter(r["status"] for r in [*inventory, *library])),
            "migration_accounting": {"project_functions_implemented": len(definitions),
                                     "foreign_bridge_functions": 0,
                                     "standard_library_contracts_used": ["unique_ptr<unsigned char[], default_delete<unsigned char[]>>"],
                                     "standard_library_bodies_translated": 0,
                                     "project_source_equivalence_proofs": 0,
                                     "standalone_core_resource_check": "passed",
                                     "performance_comparison": "not_run"},
            "functions": [{"name": node["name"], "unit": unit, "file": file} for unit, node, file in definitions.values()],
            "compiler_sha256": before,
            "claims": {**LIMITS, "standalone_hia_verified": True,
                       "actual_cross_unit_owner_value_transfer": True,
                       "all_captured_active_declarations_accounted_for": True,
                       "standard_library_contract_is_trusted": True,
                       "standard_library_implementation_migrated": False,
                       "custom_deleters_supported": False, "pointer_escape_supported": False,
                       "closed_synchronous_callback_specialized": True,
                       "callback_pointer_escape_supported": False,
                       "general_indirect_callbacks_supported": False,
                       "reset_or_release_supported": False,
                       "native_execution_qualified": False, "unlisted_builds_qualified": False}}



def lower_callback_project(database, *, clangxx="clang++"):
    return _capture_lower(capture_project(database, clang=clangxx, language="c++"))


def lower_callback_matrix(manifest, *, clangxx="clang++"):
    capture = capture_project_matrix(manifest, clang=clangxx, language="c++")
    variants = [{"name": row["name"], **_capture_lower(row["capture"])} for row in capture["variants"]]
    verify_project_matrix(capture)
    return {"schema": "hepta.cpp-callback-project-matrix.v1", "profile": PROFILE,
            "ok": True, "capture": capture, "variants": variants,
            "all_declared_variants_translated_separately": True,
            "original_cpp_objects_in_translated_targets": False,
            "unlisted_builds_qualified": False, "native_execution_qualified": False}
