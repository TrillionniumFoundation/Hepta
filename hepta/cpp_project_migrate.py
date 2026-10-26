"""Captured C++20 concrete function implementations to standalone HIA.

Clang performs overload resolution and template instantiation.  This pass
translates the resulting *bodies*, using the same scalar expression/control
lowerer as C project migration.  No original C++ implementation is called by
the output.  Only the finite instances present in the captured build qualify;
this is not an implementation of arbitrary C++ templates, class ABI or STL.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .c_migrate import MigrationRejected
from .c_project import capture_project, invoke, verify_capture
from .c_translation import CTranslator, Expression, INTEGER, ident
from .hia_program_source import lower_source


def _reject(message, code="E_CPP_PROJECT_PROFILE"):
    raise MigrationRejected(code, message)


def _nodes(node):
    yield node
    for child in node.get("inner", []):
        if isinstance(child, dict):
            yield from _nodes(child)


class _ConcreteTranslator(CTranslator):
    def __init__(self, capture):
        super().__init__(capture)
        self.function_rows = []
        self.reference_symbols = {}
        self.symbol_names = {}
        self.templates = {}
        self.ast_observations = []

    def typ(self, data, *, model=None):
        qual = data if isinstance(data, str) else data.get("qualType", "")
        if qual == "bool":
            return "bool"
        typ = super().typ(data, model=model)
        if typ not in INTEGER | {"bool", "Unit"}:
            _reject("Only closed integer/Boolean value types are translated", "E_CPP_PROJECT_TYPE")
        return typ

    def _item(self, config, node, file, namespace, **metadata):
        loc = self._position(node)
        item = {"unit": config["index"], "kind": node.get("kind", "unknown"),
                "name": node.get("name", "<anonymous>"), "namespace": list(namespace),
                "file": file, "offset": loc.get("offset"), "status": "pending",
                "reason": None, **metadata}
        self.inventory.append(item)
        if len(self.inventory) > 8192:
            _reject("Declaration inventory exceeds 8192 entries", "E_CPP_PROJECT_SIZE")
        return item

    def _template(self, config, node, file, namespace, item):
        name = ident(node.get("name", ""))
        parameters, patterns, instances = [], [], []
        for child in node.get("inner", []):
            kind = child.get("kind")
            if kind in {"TemplateTypeParmDecl", "NonTypeTemplateParmDecl"}:
                row = self._item(config, child, file, namespace, template=name)
                if (child.get("isParameterPack") or child.get("defaultArg")
                        or child.get("inner") or child.get("depth") != 0):
                    _reject("Template parameter packs/defaults/nesting are unsupported")
                ident(child.get("name", ""))
                if kind == "NonTypeTemplateParmDecl" and self.typ(child.get("type", {})) not in INTEGER:
                    _reject("Only integer non-type template parameters are supported")
                parameters.append({"kind": kind, "name": child["name"],
                                   "type": child.get("type", {}).get("qualType")})
                row.update(status="template_parameter_bound_in_concrete_instances")
            elif kind == "FunctionDecl":
                (instances if any(x.get("kind") == "TemplateArgument" for x in child.get("inner", []))
                 else patterns).append(child)
            elif kind != "FullComment":
                _reject("Unaccounted function-template child: " + str(kind))
        if not parameters or len(patterns) != 1:
            _reject("Require one complete function-template pattern with explicit parameters")
        pattern = patterns[0]
        if sum(x.get("kind") == "CompoundStmt" for x in pattern.get("inner", [])) != 1:
            _reject("Forward-only function templates are unsupported")
        key = json.dumps([file, item["offset"], list(namespace), name,
                          pattern.get("type"), parameters], sort_keys=True)
        template = self.templates.setdefault(key, {"name": "::".join((*namespace, name)),
                                                   "parameters": parameters, "instances": set(), "rows": []})
        template["rows"].append(item)
        pattern_row = self._item(config, pattern, file, namespace, template=name)
        pattern_row.update(status="template_pattern_pending")
        template["rows"].append(pattern_row)
        for instance in instances:
            arguments = []
            for argument in instance.get("inner", []):
                if argument.get("kind") != "TemplateArgument":
                    continue
                if argument.get("isPack"):
                    _reject("Template argument packs are unsupported")
                if "type" in argument:
                    arguments.append({"type": self.typ(argument["type"])})
                elif type(argument.get("value")) is int:
                    arguments.append({"value": argument["value"]})
                else:
                    _reject("Template arguments must be concrete scalar types or integer values")
            if len(arguments) != len(parameters):
                _reject("Template specialization arguments differ from parameter count")
            row = self._item(config, instance, file, namespace, template=name,
                             template_arguments=arguments)
            self._function(config, instance, file, namespace, row, template=key)

    def _function(self, config, node, file, namespace, item, *, template=None):
        name = ident(node.get("name", ""))
        raw = node.get("type", {}).get("qualType", "")
        if (not raw.endswith(" noexcept") or node.get("variadic") or node.get("constexpr")
                or node.get("consteval") or node.get("isDeleted") or node.get("explicitlyDeleted")
                or node.get("isDefaulted") or node.get("isImplicit")):
            _reject("Only explicit noexcept scalar functions with ordinary bodies are translated")
        if node.get("storageClass") not in {None, "static", "extern"}:
            _reject("Unsupported function storage")
        for child in node.get("inner", []):
            if child.get("kind") not in {"ParmVarDecl", "CompoundStmt", "FullComment", "TemplateArgument"}:
                _reject("Unaccounted function child/attribute: " + str(child.get("kind")))
            if child.get("kind") == "ParmVarDecl" and (child.get("init") or child.get("inner")):
                _reject("Default arguments and parameter attributes are unsupported")
        mangled = node.get("mangledName")
        if not isinstance(mangled, str) or not mangled:
            _reject("Concrete function has no Clang symbol identity", "E_CPP_PROJECT_SYMBOL")
        symbol = (f"unit{config['index']}:" if node.get("storageClass") == "static" else "") + mangled
        identity = (config["index"], node.get("id"))
        if not isinstance(identity[1], str):
            _reject("Concrete function lacks a Clang declaration identity")
        if identity in self.reference_symbols and self.reference_symbols[identity] != symbol:
            _reject("Conflicting Clang declaration identities")
        self.reference_symbols[identity] = symbol
        c_linkage = mangled == name
        generated = name if c_linkage else "cpp_" + hashlib.sha256(symbol.encode()).hexdigest()[:24]
        if symbol in self.symbol_names and self.symbol_names[symbol] != generated:
            _reject("Conflicting output symbol identity")
        if generated in self.symbol_names.values() and self.symbol_names.get(symbol) != generated:
            _reject("Generated symbol collision", "E_CPP_PROJECT_SYMBOL")
        self.symbol_names[symbol] = generated
        self.function_rows.append((config, node, item, symbol, template))
        item.update(source_symbol=mangled, hia_function=generated, c_linkage=c_linkage,
                    qualified_name="::".join((*namespace, name)), status="function_pending")
        if template:
            self.templates[template]["instances"].add(symbol)

    def _walk(self, config, children, file=None, namespace=()):
        for node in children:
            loc = self._position(node)
            if loc.get("file"):
                file = str((Path(config["directory"]) / loc["file"]).resolve())
            item = self._item(config, node, file, namespace)
            if file not in config["local_dependencies"] or node.get("isImplicit"):
                item.update(status="system_or_compiler_declaration",
                            reason="outside_project_declarations")
                continue
            if type(loc.get("offset")) is not int:
                _reject("Project declaration has no traceable source location", "E_CPP_PROJECT_LOCATION")
            kind = node.get("kind")
            if kind == "NamespaceDecl":
                if node.get("isInline") or not node.get("name"):
                    _reject("Inline/anonymous namespaces are outside this finite identity profile")
                name = ident(node["name"])
                self._walk(config, node.get("inner", []), file, (*namespace, name))
                item.update(status="namespace_inventory_expanded")
            elif kind == "LinkageSpecDecl":
                if node.get("language") not in {"C", "C++"}:
                    _reject("Unmodeled language linkage")
                self._walk(config, node.get("inner", []), file, namespace)
                item.update(status="language_linkage_inventory_expanded", language=node["language"])
            elif kind == "FunctionTemplateDecl":
                self._template(config, node, file, namespace, item)
            elif kind == "FunctionDecl":
                self._function(config, node, file, namespace, item)
            else:
                item.update(status="rejected", reason="unsupported_project_declaration")
                _reject("Untranslated project declaration: " + str(kind), "E_CPP_PROJECT_DECLARATION")

    def _rewrite(self, node, unit):
        output = deepcopy(node)
        for part in _nodes(output):
            reference = part.get("referencedDecl")
            if isinstance(reference, dict) and reference.get("kind") == "FunctionDecl":
                symbol = self.reference_symbols.get((unit, reference.get("id")))
                if symbol is None:
                    _reject("Call/reference to an uncaptured implementation", "E_CPP_PROJECT_EXTERNAL")
                reference["name"] = self.symbol_names[symbol]
        return output

    @staticmethod
    def _body_identity(node):
        """Remove addresses/source positions while retaining binding identity.

        Repeated template/inline definitions from headers may merge only when
        their instantiated semantics match, including macro-selected constants
        and resolved overload names.  Parameter/local shadowing remains distinct.
        """
        bindings = {part["id"]: "binding" + str(i)
                    for i, part in enumerate(part for part in _nodes(node)
                                             if part.get("kind") in {"ParmVarDecl", "VarDecl"}
                                             and "id" in part)}
        ignored = {"id", "loc", "range", "previousDecl", "isUsed", "isReferenced", "mangledName",
                   "foundReferencedDecl", "parentDeclContextId"}
        def normalize(value, key=None):
            if isinstance(value, list):
                return [normalize(x) for x in value]
            if isinstance(value, dict):
                result = {k: normalize(v, k) for k, v in value.items() if k not in ignored}
                if key == "referencedDecl" and value.get("kind") in {"ParmVarDecl", "VarDecl"}:
                    result["binding"] = bindings.get(value.get("id"), "unbound")
                return result
            return value
        # Inline/header usage metadata is irrelevant to executable semantics.
        return hashlib.sha256(json.dumps(normalize(node), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def collect(self):
        if self.capture.get("schema") not in {"hepta.cpp-build.v1", "hepta.cpp-build-selection.v1"}:
            _reject("C++ migration requires a replayed C++ capture")
        verify_capture(self.capture)
        models = [config["model"] for config in self.capture["configurations"]]
        if any(model != models[0] for model in models):
            _reject("All captured C++ units must use the same actual scalar model")
        for config in self.capture["configurations"]:
            raw = invoke([self.capture["compiler"]["path"], *config["frontend_arguments"],
                          "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json", config["source"]],
                         Path(config["directory"]))
            tree = json.loads(raw)
            if tree.get("kind") != "TranslationUnitDecl":
                _reject("Clang AST root is not a translation unit")
            self.ast_observations.append({"unit": config["index"],
                                          "raw_ast_sha256": hashlib.sha256(raw.encode()).hexdigest()})
            self._walk(config, tree.get("inner", []))
        for template in self.templates.values():
            if not template["instances"]:
                _reject("Uninstantiated template has no executable destination: " + template["name"],
                        "E_CPP_PROJECT_UNINSTANTIATED")
            for row in template["rows"]:
                row.update(status="template_pattern_specialized", instances=sorted(self.symbol_names[s] for s in template["instances"]))
        if not self.function_rows or len(self.symbol_names) > 120:
            _reject("Require 1–120 concrete functions", "E_CPP_PROJECT_SIZE")
        for config, node, item, symbol, template in self.function_rows:
            rewritten = self._rewrite(node, config["index"])
            generated = self.symbol_names[symbol]
            rewritten["name"] = generated
            rewritten["inner"] = [x for x in rewritten.get("inner", []) if x.get("kind") != "TemplateArgument"]
            signature = self.signature(rewritten, generated, config["index"], config["model"])
            if any(p["pointer"] for p in signature["params"]):
                _reject("Pointers/references require a separate resource contract")
            signature["hepta_name"] = generated
            body = next((x for x in rewritten.get("inner", []) if x.get("kind") == "CompoundStmt"), None)
            signature.update(body=body, node=rewritten, inventory=item,
                             source_symbol=node["mangledName"], c_linkage=item["c_linkage"],
                             body_identity=self._body_identity(rewritten) if body else None,
                             mergeable_definition=bool(template or node.get("inline")))
            previous = self.functions.get(generated)
            if previous is not None:
                if previous["shape"] != signature["shape"]:
                    _reject("Conflicting scalar signatures across captured units")
                if body is None:
                    item.update(status="prototype_resolved")
                    continue
                if previous["body"] is not None:
                    if (not signature["mergeable_definition"] or not previous["mergeable_definition"]
                            or signature["body_identity"] != previous["body_identity"]):
                        _reject("Conflicting/duplicate concrete definition across captured units", "E_CPP_PROJECT_ODR")
                    item.update(status="identical_inline_or_template_definition_resolved")
                    continue
                previous["inventory"].update(status="prototype_resolved")
            self.functions[generated] = signature
        for function in self.functions.values():
            if function["body"] is None:
                _reject("No captured implementation for " + function["source_symbol"], "E_CPP_PROJECT_EXTERNAL")
        self.inventory_complete = True

    def expr(self, node):
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "CXXStaticCastExpr" and len(children) == 1:
            return super().expr({**node, "kind": "CStyleCastExpr"})
        if kind == "CXXBoolLiteralExpr" and type(node.get("value")) is bool:
            return Expression("true" if node["value"] else "false", "bool")
        if kind == "SubstNonTypeTemplateParmExpr":
            if (len(children) != 2 or children[0].get("kind") != "NonTypeTemplateParmDecl"
                    or children[1].get("kind") != "IntegerLiteral"):
                _reject("Unmodeled non-type template substitution")
            result = self.expr(children[1])
            if result.typ != self.typ(node["type"]):
                _reject("Non-type template substitution has inconsistent type")
            return result
        if kind == "ConstantExpr" and len(children) == 1:
            return self.expr(children[0])
        return super().expr(node)

    def stmt(self, node, depth=1):
        if node.get("kind") == "IfStmt" and (node.get("isConstexpr") or node.get("isConsteval")):
            _reject("Compile-time discarded statement semantics are outside this profile")
        return super().stmt(node, depth)

    def bridge(self):
        # All translated bodies are in HIA.  No Rust/C++ bridge is generated.
        return ""


def lower_cpp_project(database, *, clangxx="clang++", command_indices=None):
    """Capture, structurally translate and independently verify a C++ build.

    Returns a VerifiedProgram and reviewable generated Hepta source.  No files
    are published and no native equivalence/ABI qualification is implied here.
    The qualifier separately compiles and observes originals and HIA outputs.
    """
    capture = capture_project(database, clang=clangxx, language="c++", command_indices=command_indices)
    return _lower_cpp_capture(capture)


def _lower_cpp_capture(capture):
    translator = _ConcreteTranslator(capture)
    source, _, functions = translator.emit()
    source = source.replace("module c_project_migrated;", "module cpp_project_migrated;", 1)
    source = source.replace("// Safe Hepta core. C ABI bridges carry separate caller obligations.",
                            "// Captured C++ concrete bodies; direct HIA implementations, no foreign calls.", 1)
    verified = lower_source(source, path="<captured-cpp-concrete-project>")
    verify_capture(capture)
    unresolved = [row for row in translator.inventory if row["status"].endswith("pending")]
    if unresolved:
        _reject("Declaration inventory has unresolved entries", "E_CPP_PROJECT_INVENTORY")
    return {"program": verified, "source": source, "functions": functions,
            "capture": capture, "declarations": translator.inventory,
            "declaration_scope": capture["scope"],
            "ast_observations": translator.ast_observations,
            "declaration_inventory_complete": translator.inventory_complete,
            "active_project_declarations": sum(row["status"] != "system_or_compiler_declaration"
                                                for row in translator.inventory),
            "template_instances": [{"name": item["name"], "parameters": item["parameters"],
                                     "instances": sorted(translator.symbol_names[s] for s in item["instances"])}
                                    for item in translator.templates.values()],
            "claims": {"structural_instantiated_ast_translation": True,
                       "same_c_scalar_lowering_authority": True,
                       "standalone_hia_verified": True,
                       "original_cpp_implementation_linked_into_target": False,
                       "all_declarations_accounted_for_captured_build": True,
                       "all_possible_template_instantiations_proved": False,
                       "cpp_mangled_or_class_abi_preserved": False,
                       "source_equivalence_proved": False,
                       "arbitrary_cpp_stl_raii_exceptions_supported": False},
            "defined_input_domain": "C++ defined scalar executions; signed overflow, invalid shifts and division are not source equivalence claims"}


def lower_cpp_project_matrix(manifest, *, clangxx="clang++"):
    """Migrate all explicitly partitioned builds to separate verified programs.

    No configuration is picked by a heuristic, merged with another, or silently
    dropped. All command selections remain bound to the original database.
    Native execution and behavioral equivalence require separate qualification.
    """
    from .c_project_matrix import capture_project_matrix, verify_project_matrix
    captured = capture_project_matrix(manifest, clang=clangxx, language="c++")
    variants = []
    for variant in captured["variants"]:
        lowered = _lower_cpp_capture(variant["capture"])
        variants.append({"name": variant["name"], "command_indices": variant["command_indices"],
                         **lowered})
    verify_project_matrix(captured)
    return {"schema": "hepta.cpp-project-matrix-migration.v1", "ok": True,
            "status": "all_declared_variants_frontend_verified_not_native_qualified",
            "matrix_capture": captured, "variants": variants,
            "claims": {"every_listed_command_assigned_exactly_once": True,
                       "same_complete_source_unit_set_per_variant": True,
                       "variant_bodies_never_merged": True,
                       "all_listed_variants_standalone_hia_verified": True,
                       "unlisted_configurations_qualified": False,
                       "native_equivalence_qualified": False,
                       "arbitrary_cpp_migration_supported": False}}
