"""Captured multi-TU C++ ownership transfer into standalone HIA.

The existing complete leaf/composite protocol remains the authority for class
semantics. This adapter additionally resolves real by-value owner calls across
translation units. Each configuration is translated separately and every
active declaration receives an explicit disposition. No source object enters
the translated target; C++ class/mangled ABI preservation is not claimed.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re

from .c_project import capture_project, invoke, verify_capture
from .c_project_matrix import capture_project_matrix, verify_project_matrix
from .c_migrate import _load_bounded_clang_ast
from .c_translation import CTranslator
from .cpp_composed_migrate import (_Translator, _children, _qual, _scalar, _name, _reject,
                                   _without_usage, LEAF_CPP, EFFECTS, LIMITS)
from .cpp_owned_migrate import _nodes, _normalized, _canonical, _sha
from .hia_program_source import lower_source, source_report
from .pipeline import analyze, compiler_hash

PROFILE = "cpp20-captured-composed-owner-value-transfer-v1"


def _decls(node):
    return [(item, path) for item, path in _nodes(node) if str(item.get("kind", "")).endswith("Decl")]


def _shape(leaf, composite):
    return _without_usage(_normalized({"kind": "TranslationUnitDecl", "inner": [leaf, composite]}, leaf["name"]))


class _ProjectTranslator(_Translator):
    def __init__(self, tree, leaf, composite, operation, helpers):
        super().__init__(tree, leaf, composite, operation)
        self.helpers = {node["id"]: {"node": node, "emitted": "HeptaTransferred_" + str(index)}
                        for index, node in enumerate(helpers)}
        self._expression_depth = 0
        for node in helpers:
            self.mark(node, "translated_cross_unit_by_value_owner_consumer")
        self.stats["cross_unit_owner_transfers"] = 0

    def params(self, node):
        if node.get("id") not in self.helpers:
            return super().params(node)
        result = {}
        params = [child for child in _children(node) if child.get("kind") == "ParmVarDecl"]
        if not 1 <= len(params) <= 12 or _qual(params[0]) != self.class_name:
            _reject("Transfer helper must consume one first by-value composite parameter", "E_CPP_PROJECT_OWNER")
        for index, param in enumerate(params):
            self.guard(param)
            if _children(param) or param.get("init"):
                _reject("Owner transfer parameters cannot have defaults")
            _name(param.get("name"))
            owner = index == 0
            self.mark(param, "consumed_by_value_owner_parameter" if owner else "scalar_parameter")
            result[param["id"]] = {"emitted": "arg" + str(index), "type": "owner" if owner else _scalar(param),
                                    "cpp_type": _qual(param), "source_name": param["name"], "alive": True}
        return result

    def place(self, node, env, *, context, const):
        if (node.get("kind") == "DeclRefExpr" and node.get("referencedDecl", {}).get("kind") == "ParmVarDecl"
                and env.get(node["referencedDecl"]["id"], {}).get("type") == "owner"):
            # By-value class parameters own their object and are destroyed at
            # function exit. The underlying checked place rule then applies.
            node = copy.deepcopy(node)
            node["referencedDecl"]["kind"] = "VarDecl"
        return super().place(node, env, context=context, const=const)

    @staticmethod
    def _unwrapped(node, kinds):
        while node.get("kind") in kinds:
            children = _children(node)
            if len(children) != 1:
                _reject("An ownership wrapper contains unaccounted operations")
            node = children[0]
        return node

    def transfer_call(self, node, env, *, context, const):
        children = _children(node)
        if not children:
            _reject("Missing resolved function reference")
        callee = self._unwrapped(children[0], {"ImplicitCastExpr", "ParenExpr"})
        ref = callee.get("referencedDecl", {})
        info = self.helpers.get(ref.get("id"))
        if (callee.get("kind") != "DeclRefExpr" or ref.get("kind") != "FunctionDecl" or info is None
                or ref.get("name") != info["node"]["name"] or _qual(ref) != _qual(info["node"])):
            _reject("Free call must bind to a captured by-value owner definition", "E_CPP_PROJECT_CALL")
        params = [p for p in _children(info["node"]) if p.get("kind") == "ParmVarDecl"]
        if len(children) != len(params) + 1 or _qual(node) != "unsigned long long":
            _reject("Owner call arity/result differs from captured definition")
        argument = self._unwrapped(children[1], {"CXXBindTemporaryExpr", "MaterializeTemporaryExpr", "ExprWithCleanups"})
        if (argument.get("kind") != "CXXConstructExpr" or _qual(argument) != self.class_name
                or argument.get("ctorType", {}).get("qualType") != f"void ({self.class_name} &&) noexcept"
                or argument.get("constructionKind") != "complete" or len(_children(argument)) != 1):
            _reject("Cross-unit argument must invoke the complete checked owner move", "E_CPP_PROJECT_MOVE")
        cast = _children(argument)[0]
        if (cast.get("kind") != "CXXStaticCastExpr" or cast.get("castKind") != "NoOp"
                or cast.get("valueCategory") != "xvalue" or len(_children(cast)) != 1):
            _reject("Owner transfer requires the explicit rvalue cast")
        origin = self._unwrapped(_children(cast)[0], {"ParenExpr"})
        place, _, _ = self.place(origin, env, context=context, const=const)
        identity = origin.get("referencedDecl", {}).get("id")
        if identity not in env:
            _reject("Transfer source must be one complete live owner")
        # C++ does not impose left-to-right argument evaluation. Other
        # arguments cannot inspect the owner being moved or contain another
        # effectful transfer; no guessed sequencing is introduced.
        for expression in children[2:]:
            for child, _ in _nodes(expression):
                if (child.get("kind") == "CallExpr" or child.get("referencedDecl", {}).get("id") == identity):
                    _reject("Unsequenced owner observation/transfer in call arguments", "E_CPP_PROJECT_SEQUENCE")
        arguments = ["move " + place]
        for expression, param in zip(children[2:], params[1:]):
            value, typ = self.expr(expression, env, context=context, const=const)
            if typ != _scalar(param):
                _reject("Cross-unit scalar argument representation differs")
            arguments.append(value)
        env[identity]["alive"] = False
        self.stats["cross_unit_owner_transfers"] += 1
        return info["emitted"] + "(" + ", ".join(arguments) + ")", "u64"

    def expr(self, node, env, *, context, const=False):
        if node.get("kind") == "ExprWithCleanups":
            node = self._unwrapped(node, {"ExprWithCleanups"})
        if node.get("kind") == "CallExpr":
            if self._expression_depth:
                _reject("Effectful ownership calls require a complete sequenced value expression", "E_CPP_PROJECT_SEQUENCE")
            return self.transfer_call(node, env, context=context, const=const)
        self._expression_depth += 1
        try:
            return super().expr(node, env, context=context, const=const)
        finally:
            self._expression_depth -= 1

    def lifecycle(self):
        rendered = []
        for info in self.helpers.values():
            node = info["node"]
            returns, const, params, body = self.signature(node)
            if returns != "u64" or const:
                _reject("Cross-unit owner consumer must return u64 noexcept")
            lines, done = self.statements(_children(body), copy.deepcopy(params), context="lifecycle", returns=returns)
            if not done:
                _reject("Owner consumer has an unhandled fallthrough path")
            arguments = [p["emitted"] + ": " + ("take HeptaComposite" if p["type"] == "owner" else p["type"])
                         for p in params.values()]
            rendered.append(f"pub fn {info['emitted']}({', '.join(arguments)}) -> u64 {EFFECTS} {{\n"
                            + "\n".join(lines) + "\n}\n")
        rendered.append(super().lifecycle())
        return "\n".join(rendered)


def _capture_lower(capture):
    before = compiler_hash()
    compiler = capture["compiler"]["path"]
    if not re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", capture["compiler"]["version"]):
        _reject("Clang20+ is required for the captured owner protocol")
    units = []
    canonical_shape = None
    definitions = {}
    declaration_symbols = {}
    inventory = []
    for config in capture["configurations"]:
        if config["model"]["long_bits"] != 64 or config["model"]["pointer_bits"] != 64:
            _reject("This native owner profile requires Linux LP64")
        tree = _load_bounded_clang_ast(invoke([compiler, *config["frontend_arguments"], "-Werror",
                                             "-fsyntax-only", "-Xclang", "-ast-dump=json", config["source"]],
                                            Path(config["directory"])))
        active = []
        current_file = None
        for node in _children(tree):
            position = CTranslator._position(node)
            if position.get("file"):
                current_file = str((Path(config["directory"]) / position["file"]).resolve())
            if node.get("isImplicit"):
                for implicit, path in _decls(node):
                    inventory.append({"unit": config["index"], "file": current_file,
                                      "kind": implicit["kind"], "name": implicit.get("name"), "path": list(path),
                                      "status": "compiler_implicit_declaration", "canonical_id": None})
                continue
            if current_file not in config["local_dependencies"] or type(position.get("offset")) is not int:
                _reject("No system or locationless declaration can be silently omitted", "E_CPP_PROJECT_INVENTORY")
            if node.get("kind") not in {"CXXRecordDecl", "FunctionDecl"}:
                _reject("Unmodeled active project declaration: " + str(node.get("kind")), "E_CPP_PROJECT_INVENTORY")
            active.append((node, current_file))
        records = [node for node, _ in active if node["kind"] == "CXXRecordDecl"]
        if len(records) != 2 or any(not node.get("completeDefinition") for node in records):
            _reject("Each translation unit must capture the same complete leaf and composite declarations")
        leaf, composite = records
        shape = _shape(leaf, composite)
        if canonical_shape is None:
            canonical_shape = shape
        elif shape != canonical_shape:
            _reject("Class definition or inline algorithm differs between translation units", "E_CPP_PROJECT_ODR")
        for node, file in active:
            if node["kind"] != "FunctionDecl":
                continue
            _name(node.get("name"))
            symbol = node.get("mangledName")
            if type(symbol) is not str:
                _reject("Every free function needs its actual captured mangled identity")
            key = (node["name"], _qual(node), symbol)
            previous = declaration_symbols.setdefault(node["name"], key)
            if previous != key:
                _reject("Overloaded/conflicting free-function symbols are outside the transfer profile")
            if any(child.get("kind") == "CompoundStmt" for child in _children(node)):
                if key in definitions:
                    _reject("A cross-unit function has multiple implementation definitions", "E_CPP_PROJECT_ODR")
                definitions[key] = (config["index"], node, file)
        units.append((config, tree, active, leaf, composite))
    if not units or len(definitions) < 2:
        _reject("A complete project needs a lifecycle and an actual separately defined owner consumer")
    if set(definitions) != set(declaration_symbols.values()):
        _reject("A declared function has no captured implementation", "E_CPP_PROJECT_UNDEFINED")
    first = units[0]
    mappings = {}
    canonical_records = first[3:5]
    for config, tree, active, leaf, composite in units:
        mapping = {}
        for record, canonical in zip((leaf, composite), canonical_records):
            original_decls, canonical_decls = _decls(record), _decls(canonical)
            if [path for _, path in original_decls] != [path for _, path in canonical_decls]:
                _reject("Duplicate-header declaration identities do not align")
            for (node, _), (selected, _) in zip(original_decls, canonical_decls):
                mapping[node["id"]] = "unit" + str(first[0]["index"]) + ":" + selected["id"]
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
        result = {}
        for key, child in value.items():
            if key == "id" and child == "0x0":
                result[key] = child  # Clang's absent catch-all exception binding.
            elif key in {"id", "referencedMemberDecl", "previousDecl"} and type(child) is str:
                result[key] = mappings[unit].get(child, "unit" + str(unit) + ":" + child)
            else:
                result[key] = rewritten(child, unit)
        return result

    leaf = rewritten(first[3], first[0]["index"])
    composite = rewritten(first[4], first[0]["index"])
    functions = [rewritten(node, unit) for unit, node, _ in definitions.values()]
    owner_type = composite["name"]
    helpers, entries = [], []
    for function in functions:
        parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
        (helpers if parameters and _qual(parameters[0]) == owner_type else entries).append(function)
    if len(entries) != 1 or not helpers or len(helpers) > 8:
        _reject("One scalar lifecycle and one to eight complete by-value consumers are required")
    if len({unit for unit, _, _ in definitions.values()}) < 2:
        _reject("This project profile requires implementations in distinct translation units")
    # The complete known leaf protocol is checked afresh with the same native
    # compiler. Class ASTs cannot gain custom destructors or hidden allocators.
    expected_tree = _load_bounded_clang_ast(invoke([compiler, "-x", "c++", "-std=c++20", "-Werror",
                                                    "-fsyntax-only", "-Xclang", "-ast-dump=json", "-"],
                                                   Path(capture["database"]["path"]).parent,
                                                   stdin=LEAF_CPP.replace("OwnedBytes", leaf["name"])))
    expected = next(node for node in _children(expected_tree) if node.get("kind") == "CXXRecordDecl" and node.get("name") == leaf["name"])
    if _without_usage(_normalized(leaf, leaf["name"])) != _without_usage(_normalized(expected, leaf["name"])):
        _reject("Captured complete leaf differs from the checked ownership protocol", "E_CPP_PROJECT_LEAF")
    canonical_tree = {"kind": "TranslationUnitDecl", "inner": [leaf, composite, *functions]}
    translator = _ProjectTranslator(canonical_tree, leaf, composite, entries[0], helpers)
    source, translated = translator.translate()
    if translator.stats["cross_unit_owner_transfers"] == 0:
        _reject("Project contains no translated ownership transfer call")
    for config, tree, active, _, _ in units:
        for top, file in active:
            definition = top["kind"] != "FunctionDecl" or any(child.get("kind") == "CompoundStmt" for child in _children(top))
            for node, path in _decls(top):
                identity = mappings[config["index"]].get(node["id"], "unit" + str(config["index"]) + ":" + node["id"])
                role = translator.roles.get(identity)
                if not definition:
                    if node["kind"] not in {"FunctionDecl", "ParmVarDecl"}:
                        _reject("A forward declaration contains unaccounted children")
                    translator.guard(node)
                    if (node["kind"] == "FunctionDecl" and any(child.get("kind") != "ParmVarDecl" for child in _children(node))
                            or node["kind"] == "ParmVarDecl" and (_children(node) or node.get("init"))):
                        _reject("Forward declarations cannot hide attributes, defaults or unmodeled operations")
                    role = "forward_signature_bound_to_captured_definition"
                if role is None:
                    _reject("Active declaration has no disposition: " + str(node.get("name")), "E_CPP_PROJECT_INVENTORY")
                inventory.append({"unit": config["index"], "file": file, "kind": node["kind"],
                                  "name": node.get("name"), "path": list(path), "status": role,
                                  "canonical_id": identity})
    checked = analyze(source, "captured-owners.hepta", backend="c", native=False, crate_type="obj")
    if not checked.report["ok"] or checked.report["assumptions"]:
        _reject("Transferred owner implementation failed source checking: " + json.dumps(checked.report))
    program = lower_source(source, path="<captured-cross-unit-owners>")
    verify_capture(capture)
    if compiler_hash() != before:
        _reject("Compiler changed while translating captured owners")
    return {"schema": "hepta.cpp-composed-project-migration.v1", "profile": PROFILE, "ok": True,
            "program": program, "source": source, "capture": capture, "declarations": inventory,
            "source_lowering": source_report(source), "translation_statistics": translator.stats,
            "active_declaration_count": sum(row["status"] != "compiler_implicit_declaration" for row in inventory),
            "unconverted_declarations": [], "functions": [{"name": node["name"], "unit": unit, "file": file}
                                                           for unit, node, file in definitions.values()],
            "compiler_sha256": before,
            "claims": {**LIMITS, "standalone_hia_verified": True,
                       "actual_cross_unit_owner_value_transfer": True,
                       "all_captured_active_declarations_accounted_for": True,
                       "native_execution_qualified": False, "unlisted_builds_qualified": False}}


def lower_composed_project(database, *, clangxx="clang++"):
    return _capture_lower(capture_project(database, clang=clangxx, language="c++"))


def lower_composed_matrix(manifest, *, clangxx="clang++"):
    capture = capture_project_matrix(manifest, clang=clangxx, language="c++")
    variants = [{"name": row["name"], **_capture_lower(row["capture"])} for row in capture["variants"]]
    verify_project_matrix(capture)
    return {"schema": "hepta.cpp-composed-project-matrix.v1", "profile": PROFILE,
            "ok": True, "capture": capture, "variants": variants,
            "all_declared_variants_translated_separately": True,
            "original_cpp_objects_in_translated_targets": False,
            "unlisted_builds_qualified": False, "native_execution_qualified": False}
