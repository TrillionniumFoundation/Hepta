"""Captured default-deleter std::unique_ptr<byte[]> into standalone HIA.

This is a distinct, bounded implementation-migration profile. It captures the
whole actual translation unit, accounts for standard-library declarations as
dependencies of an explicit trusted contract, and checks the complete project
wrapper against compiler-owned source. Composite algorithms and cross-unit
owner calls use the existing structural translator. Neither arbitrary templates
nor the implementation of the C++ standard library are claimed to be proved.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re

from .c_project import capture_project, invoke, verify_capture
from .c_project_matrix import capture_project_matrix, verify_project_matrix
from .c_translation import CTranslator
from .cpp_unique_capture import stream_ast
from .cpp_unique_assignment import UniqueAssignmentTranslator
from .cpp_composed_migrate import _children, _qual, _name, _reject, _without_usage, LIMITS
from .cpp_composed_project import _ProjectTranslator, _decls
from .cpp_owned_migrate import _nodes, _normalized
from .hia_program_source import lower_source, source_report
from .pipeline import analyze, compiler_hash


PROFILE = "cpp20-captured-unique-byte-array-default-deleter-v1"
ASSIGNMENT_PROFILE = "cpp20-captured-unique-byte-array-move-assignment-v1"
MAX_DECLARATIONS = 120_000
UNIQUE_LEAF = r'''#include <memory>
class OwnedBytes {
    std::unique_ptr<unsigned char[]> data_;
    unsigned long size_;
public:
    OwnedBytes(unsigned long size, bool reject)
        : data_(size == 0 ? nullptr : new unsigned char[size]{}), size_(size) {
        if (reject) { throw 2; }
    }
    OwnedBytes(OwnedBytes&& other) noexcept
        : data_(static_cast<std::unique_ptr<unsigned char[]>&&>(other.data_)), size_(other.size_) {
        other.size_ = 0;
    }
    OwnedBytes(const OwnedBytes&) = delete;
    OwnedBytes& operator=(const OwnedBytes&) = delete;
    OwnedBytes& operator=(OwnedBytes&&) = delete;
    ~OwnedBytes() noexcept = default;
    unsigned long size() const noexcept { return size_; }
    const unsigned char* data() const noexcept { return data_.get(); }
    void fill(unsigned char value) noexcept {
        for (unsigned long i = 0; i < size_; ++i) { data_[i] = value; }
    }
    unsigned char get(unsigned long index) const noexcept { return data_[index]; }
    void set(unsigned long index, unsigned char value) noexcept { data_[index] = value; }
};
unsigned long long hepta_contract_use(unsigned long size, unsigned char value, unsigned long index, bool reject) noexcept {
    try {
        OwnedBytes first(size, reject);
        first.fill(value);
        first.set(index, value);
        OwnedBytes second(static_cast<OwnedBytes&&>(first));
        return second.size() + second.data()[index] + second.get(index);
    } catch (...) { return 0; }
}
'''

UNIQUE_ASSIGNMENT_LEAF = UNIQUE_LEAF.replace(
    "    OwnedBytes& operator=(OwnedBytes&&) = delete;",
    """    OwnedBytes& operator=(OwnedBytes&& other) noexcept {
        if (this != &other) {
            data_ = static_cast<std::unique_ptr<unsigned char[]>&&>(other.data_);
            size_ = other.size_;
            other.size_ = 0;
        }
        return *this;
    }""").replace(
    "        return second.size() + second.data()[index] + second.get(index);",
    """        OwnedBytes destination(size, reject);
        destination = static_cast<OwnedBytes&&>(second);
        destination = static_cast<OwnedBytes&&>(destination);
        return destination.size() + destination.data()[index] + destination.get(index);""")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _reference_config(config):
    """The trusted standard contract comes from default toolchain headers.

    Project include paths and -D/-U options must not redefine the library used
    to validate their own implementation. Their actual effects are retained in
    the source capture and rejected when expanded library text differs.
    """
    arguments, skip = [], False
    for argument in config["frontend_arguments"]:
        if skip:
            skip = False
        elif argument in {"-I", "-isystem", "-iquote", "-D", "-U"}:
            skip = True
        elif any(argument.startswith(prefix) for prefix in ("-I", "-isystem", "-iquote", "-D", "-U")):
            continue
        else:
            arguments.append(argument)
    if skip:
        _reject("Missing captured preprocessing argument")
    return {**config, "frontend_arguments": arguments}


def _large_ast(compiler, config, *, source=None):
    """Project the whole stream only after every declaration is accounted for."""
    arguments = [compiler, *config["frontend_arguments"], "-Werror", "-fsyntax-only",
                 "-Xclang", "-ast-dump=json", *([] if source is None else ["-x", "c++"]),
                 config["source"] if source is None else "-"]
    receipt, external, library, implicit, active = {}, {}, [], [], []
    current_file = None
    dependencies = set(config["all_dependencies"])
    local = set(config["local_dependencies"])
    if source is not None:
        local.add(str((Path(config["directory"]) / "<stdin>").resolve()))
    for top_index, node in enumerate(stream_ast(arguments, cwd=config["directory"], source=source, receipt=receipt)):
        position = CTranslator._position(node)
        if position.get("file"):
            current_file = str((Path(config["directory"]) / position["file"]).resolve())
        if node.get("isImplicit") and current_file is None:
            target, status = implicit, "compiler_implicit_declaration"
        elif current_file in local:
            if type(position.get("offset")) is not int or node.get("kind") not in {"CXXRecordDecl", "FunctionDecl"}:
                _reject("Unmodeled active project declaration: " + str(node.get("kind")), "E_CPP_UNIQUE_INVENTORY")
            active.append((node, current_file))
            continue
        elif current_file in dependencies - local:
            target, status = library, "standard_library_dependency_not_migrated"
        else:
            _reject("Declaration lacks a captured project/system disposition", "E_CPP_UNIQUE_INVENTORY")
        external.update(_external_bindings({"kind": "TranslationUnitDecl", "inner": [node]}, set()))
        for child, path in _decls(node):
            child_position = CTranslator._position(child)
            if (status == "standard_library_dependency_not_migrated" and child_position.get("file")
                    and str((Path(config["directory"]) / child_position["file"]).resolve()) in local):
                _reject("Project declaration is nested inside a library dependency", "E_CPP_UNIQUE_INVENTORY")
            target.append({"unit": config["index"], "top_level_file": current_file,
                           "kind": child["kind"], "name": child.get("name"),
                           "path": [top_index, *path], "status": status})
            if len(library) + len(implicit) > MAX_DECLARATIONS:
                _reject("Library declaration census exceeds its budget", "E_CPP_UNIQUE_INVENTORY")
    return active, receipt, external, library, implicit


def _standard_snapshot(compiler, config, *, source=None):
    """Compare expanded system headers, including project macro effects.

    Dependency hashes alone do not identify a header's macro-dependent meaning.
    Actual and compiler-owned reference units must have exactly the same
    preprocessed external text. Line markers are interpreted as data; no shell
    or source-provided path is executed.
    """
    raw = invoke([compiler, *config["frontend_arguments"], "-E", *([] if source is None else ["-x", "c++"]),
                  config["source"] if source is None else "-"],
                 Path(config["directory"]), stdin=source)
    dependencies = set(config["all_dependencies"])
    local = set(config["local_dependencies"])
    current = None
    regions = {}
    for line in raw.splitlines(keepends=True):
        marker = re.fullmatch(r'#\s+\d+\s+("(?:[^"\\]|\\.)*")(?:\s+\d+)*\s*\n?', line)
        if marker:
            filename = json.loads(marker[1])
            if filename.startswith("<") and filename.endswith(">"):
                current = None
            else:
                current = str((Path(config["directory"]) / filename).resolve())
                if current not in dependencies and current != config["source"]:
                    _reject("Preprocessor named an uncaptured input", "E_CPP_UNIQUE_DEPENDENCY")
            continue
        if line.startswith("#") and not line.startswith("#pragma "):
            _reject("Unmodeled preprocessor output directive", "E_CPP_UNIQUE_DEPENDENCY")
        if current in dependencies - local:
            regions.setdefault(current, []).append(line)
    return {name: {"sha256": sha256("".join(lines).encode()).hexdigest(),
                   "bytes": len("".join(lines).encode())}
            for name, lines in sorted(regions.items())}


def _external_bindings(tree, project_files):
    """Stable semantic signatures for referenced library declarations.

    Their semantics are an explicit trusted standard-library contract, bound to
    captured dependency bytes and independently expanded reference headers.
    Internal project declaration identities are still checked by tree position.
    """
    bindings = {}
    current_file = None

    def representation(value):
        if isinstance(value, dict):
            # Clang's alias address is process-local. Spelled/desugared types,
            # declaration kind/name and specialization ancestry remain bound.
            return {key: representation(child) for key, child in value.items() if key != "typeAliasDeclId"}
        if isinstance(value, list):
            return [representation(child) for child in value]
        return value

    for top in _children(tree):
        position = CTranslator._position(top)
        if position.get("file"):
            current_file = str(Path(position["file"]).resolve())
        if current_file in project_files:
            continue
        stack = [(top, ())]
        while stack:
            node, ancestry = stack.pop()
            kind = node.get("kind", "")
            context = ancestry
            if kind.endswith("Decl") and isinstance(node.get("id"), str):
                signature = {"kind": kind, "name": node.get("name"), "type": representation(node.get("type")),
                             "context": ancestry,
                             "arguments": [representation(child.get("type", child.get("value")))
                                           for child in _children(node) if child.get("kind") == "TemplateArgument"]}
                bindings[node["id"]] = "standard:" + sha256(_canonical(signature)).hexdigest()
                if kind in {"NamespaceDecl", "ClassTemplateDecl", "ClassTemplateSpecializationDecl",
                            "ClassTemplatePartialSpecializationDecl", "CXXRecordDecl"}:
                    context = (*ancestry, (kind, node.get("name"), tuple(
                        _canonical(representation(c.get("type", c.get("value")))).decode()
                        for c in _children(node) if c.get("kind") == "TemplateArgument")))
            stack.extend((child, context) for child in reversed(_children(node)))
    return bindings


def _unique_shape(leaf, external):
    # Add stable external reference declarations solely for normalization.
    # No external implementation is presented to the structural translator.
    local = {node.get("id") for node, _ in _nodes(leaf)
             if str(node.get("kind", "")).endswith("Decl")}
    referenced = set()

    def discover(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"referencedMemberDecl", "typeAliasDeclId"} and child not in local:
                    if child not in external:
                        _reject("Unique owner references an uncaptured library member", "E_CPP_UNIQUE_MEMBER")
                    referenced.add(child)
                discover(child)
        elif isinstance(value, list):
            for child in value:
                discover(child)

    discover(leaf)
    # Equal semantic external signatures intentionally share one identifier.
    symbols = sorted({external[ident] for ident in referenced})
    remap = {ident: "library:" + str(symbols.index(external[ident])) for ident in referenced}

    def rewrite(value):
        if isinstance(value, dict):
            return {key: remap.get(child, child) if key == "referencedMemberDecl"
                    else external.get(child, child) if key == "typeAliasDeclId" else rewrite(child)
                    for key, child in value.items()}
        if isinstance(value, list):
            return [rewrite(child) for child in value]
        return value

    synthetic = [{"id": "library:" + str(i), "kind": "CXXMethodDecl", "name": symbol}
                 for i, symbol in enumerate(symbols)]
    normalized = _normalized({"kind": "TranslationUnitDecl", "inner": [*synthetic, rewrite(leaf)]}, leaf["name"])
    return {"external_signatures": symbols, "leaf": _without_usage(normalized)}


def _capture_lower(capture, *, move_assignment=False):
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
        source = (UNIQUE_ASSIGNMENT_LEAF if move_assignment else UNIQUE_LEAF).replace("OwnedBytes", leaf["name"])
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
    helpers, entries = [], []
    for function in functions:
        parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
        (helpers if parameters and _qual(parameters[0]) == composite["name"] else entries).append(function)
    if len(entries) != 1 or not 1 <= len(helpers) <= 8 or len({unit for unit, _, _ in definitions.values()}) < 2:
        _reject("One scalar entry and actual separately defined owner consumers are required")
    translator_class = UniqueAssignmentTranslator if move_assignment else _ProjectTranslator
    translator = translator_class({"kind": "TranslationUnitDecl", "inner": [leaf, composite, *functions]},
                                  leaf, composite, entries[0], helpers)
    source, translated = translator.translate()
    if translator.stats["cross_unit_owner_transfers"] == 0:
        _reject("Project contains no actual owner transfer")
    if move_assignment and translator.stats["owner_move_assignments"] == 0:
        _reject("Move-assignment profile requires an actual distinct-owner replacement", "E_CPP_UNIQUE_ASSIGNMENT")
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
                    role = ("exact_unique_array_guarded_move_assignment_contract" if move_assignment
                            else "exact_unique_array_default_deleter_contract")
                inventory.append({"unit": config["index"], "file": file, "kind": node["kind"],
                                  "name": node.get("name"), "path": list(path), "status": role,
                                  "canonical_id": identity})
    checked = analyze(source, "captured-unique-owners.hepta", backend="c", native=False, crate_type="obj")
    if not checked.report["ok"] or checked.report["assumptions"]:
        _reject("Unique owner failed checked lowering: " + json.dumps(checked.report))
    program = lower_source(source, path="<captured-unique-array-project>")
    verify_capture(capture)
    if compiler_hash() != before:
        _reject("Compiler changed during unique-array capture")
    return {"schema": "hepta.cpp-unique-project-migration.v1",
            "profile": ASSIGNMENT_PROFILE if move_assignment else PROFILE, "ok": True,
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
                       "sequenced_complete_owner_move_assignment": move_assignment,
                       "self_move_preserves_owner": move_assignment,
                       "reset_or_release_supported": False,
                       "native_execution_qualified": False, "unlisted_builds_qualified": False}}


def lower_unique_project(database, *, clangxx="clang++"):
    return _capture_lower(capture_project(database, clang=clangxx, language="c++"))


def lower_unique_matrix(manifest, *, clangxx="clang++"):
    capture = capture_project_matrix(manifest, clang=clangxx, language="c++")
    variants = [{"name": row["name"], **_capture_lower(row["capture"])} for row in capture["variants"]]
    verify_project_matrix(capture)
    return {"schema": "hepta.cpp-unique-project-matrix.v1", "profile": PROFILE,
            "ok": True, "capture": capture, "variants": variants,
            "all_declared_variants_translated_separately": True,
            "original_cpp_objects_in_translated_targets": False,
            "unlisted_builds_qualified": False, "native_execution_qualified": False}


def lower_unique_assignment_project(database, *, clangxx="clang++"):
    return _capture_lower(capture_project(database, clang=clangxx, language="c++"), move_assignment=True)


def lower_unique_assignment_matrix(manifest, *, clangxx="clang++"):
    capture = capture_project_matrix(manifest, clang=clangxx, language="c++")
    variants = [{"name": row["name"], **_capture_lower(row["capture"], move_assignment=True)}
                for row in capture["variants"]]
    verify_project_matrix(capture)
    return {"schema": "hepta.cpp-unique-project-matrix.v1", "profile": ASSIGNMENT_PROFILE,
            "ok": True, "capture": capture, "variants": variants,
            "all_declared_variants_translated_separately": True,
            "original_cpp_objects_in_translated_targets": False,
            "unlisted_builds_qualified": False, "native_execution_qualified": False}
