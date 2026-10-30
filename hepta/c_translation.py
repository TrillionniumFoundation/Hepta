"""Bounded Clang C AST lowering to safe Hepta plus an explicit unsafe ABI edge.

This module accepts no raw-pointer operations in generated Hepta. Pointer
parameters require caller-supplied slice contracts. Those contracts can narrow
the source program's input domain and are NOT inferred equivalence proofs.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from .c_migrate import MigrationRejected, reject_function_type_attributes, _load_bounded_clang_ast
from .c_contracts import snapshot_contracts
from .c_project import _read_dependency, captured_source_argument, digest, invoke


INTEGER = {f"{s}{w}" for s in ("u", "i") for w in (8, 16, 32, 64)} | {"usize", "isize"}
NUMBER = INTEGER | {"f32", "f64"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def ident(name: str) -> str:
    if not IDENTIFIER.fullmatch(name) or name.startswith("__"):
        raise MigrationRejected("E_C_IDENTIFIER", "Unsupported C identifier: " + repr(name))
    return name


def _physical_source_files(tree: dict, directory: Path) -> dict[int, str | None]:
    """Resolve the actual Clang dump's globally elided physical filenames.

    JSONNodeDumper writes locations in JSON order and shares LastLocFilename
    across loc/range and macro spelling/expansion locations. includedFrom and
    presumedFile are diagnostic information, not physical filename updates.
    Keep an out-of-band map: do not rewrite or add claims to the captured AST.
    """
    current = None
    result = {}
    pending = [tree]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "offset" in value and "tokLen" in value:
                if "file" in value:
                    filename = value["file"]
                    if type(filename) is not str or not filename or "\0" in filename:
                        raise MigrationRejected("E_C_SOURCE_LOCATION", "Invalid physical source filename")
                    current = str((directory / filename).resolve())
                result[id(value)] = current
            pending.extend(reversed(list(value.values())))
        elif isinstance(value, list):
            pending.extend(reversed(value))
    return result


def _parameter_source_form(node: dict, source: bytes) -> str:
    """Classify finite physical spelling; this alone does not admit an array."""
    loc, span = node.get("loc"), node.get("range")
    begin = span.get("begin") if isinstance(span, dict) else None
    end = span.get("end") if isinstance(span, dict) else None
    if (not isinstance(loc, dict) or not isinstance(begin, dict)
            or not isinstance(end, dict) or type(source) is not bytes):
        raise MigrationRejected("E_C_PARAMETER_DECLARATOR", "Parameter source location is not available")
    for position in (begin, loc, end):
        if ("spellingLoc" in position or "expansionLoc" in position
                or type(position.get("offset")) is not int or position["offset"] < 0
                or type(position.get("tokLen")) is not int or position["tokLen"] <= 0):
            raise MigrationRejected("E_C_PARAMETER_DECLARATOR", "Ambiguous or expanded parameter declarator")
    start, name_start, finish = begin["offset"], loc["offset"], end["offset"] + end["tokLen"]
    name = node.get("name")
    if (type(name) is not str or not IDENTIFIER.fullmatch(name)
            or not 0 <= start < name_start < name_start + loc["tokLen"] <= finish <= len(source)
            or source[name_start:name_start + loc["tokLen"]] != name.encode("ascii")):
        raise MigrationRejected("E_C_PARAMETER_DECLARATOR", "Parameter location does not identify its captured source spelling")

    def clean(value):
        value = value.replace(b"\\\r\n", b"").replace(b"\\\n", b"")
        if b"\\" in value or b"??" in value:
            raise MigrationRejected("E_C_PARAMETER_DECLARATOR", "Unqualified parameter source escape")
        return re.sub(rb"/\*.*?\*/|//[^\r\n]*(?:\r?\n|$)", b" ", value, flags=re.S)

    prefix = clean(source[start:name_start])
    names = rb"[A-Za-z_][A-Za-z_0-9]*(?:\s+[A-Za-z_][A-Za-z_0-9]*)*"
    if (loc["offset"], loc["tokLen"]) == (end["offset"], end["tokLen"]):
        if re.fullmatch(rb"\s*" + names + rb"\s*\*\s*", prefix):
            return "pointer"
    else:
        suffix = clean(source[name_start + loc["tokLen"]:finish])
        if (re.fullmatch(rb"\s*" + names + rb"\s+", prefix)
                and re.fullmatch(rb"\s*\[[A-Za-z_0-9\s()+*/%<>&|^~?:!\-]*\]\s*", suffix)
                and not re.search(rb"\b(?:static|const|volatile|restrict|_Atomic|typeof|__typeof__)\b", suffix)):
            return "array"
    raise MigrationRejected("E_C_PARAMETER_DECLARATOR",
                            "Parameter needs direct pointer or qualified fixed/incomplete array spelling; computed types are unsupported")


def reject_adjusted_pointer_parameter(node: dict, source: bytes, original_type: dict | None = None) -> None:
    """Admit array decay only with independently bound original-type evidence.

    Direct physical type-name/pointer spelling preserves the previous finite
    guard. Fixed/incomplete array spelling additionally needs a verified original
    array shape; VLA, typeof, macro-ambiguous and cross-file declarators do not
    acquire admission through an adjusted pointer type or a caller contract.
    """
    form = _parameter_source_form(node, source)
    if form == "array" and (type(original_type) is not dict
            or original_type.get("name") != node.get("name")
            or original_type.get("state") != "fixed"
            or original_type.get("shape", {}).get("kind") not in {"ConstantArray", "IncompleteArray"}):
        raise MigrationRejected("E_C_PARAMETER_DECLARATOR", "Array parameter requires bound fixed original array type")


def width(typ: str) -> int:
    return 64 if typ in {"usize", "isize"} else int(typ[1:])


def integer_range(typ: str) -> tuple[int, int]:
    bits = width(typ)
    return (0, (1 << bits) - 1) if typ.startswith("u") else (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)


@dataclass(frozen=True)
class Expression:
    text: str
    typ: str
    side_effect: bool = False


def cast(expr: Expression, target: str, *, c_conversion: bool = False) -> Expression:
    if expr.typ == target:
        return expr
    if expr.typ == "bool" and target in INTEGER:
        return Expression(f"(c_bool_to_int({expr.text}) as {target})", target, expr.side_effect)
    if expr.typ in INTEGER and target in INTEGER:
        # Unsigned conversions have modulo semantics in C and Rust. Signed
        # narrowing is implementation-defined in C: reject instead of silently
        # claiming portable semantics. Same-width size aliases are harmless.
        low, high = integer_range(expr.typ)
        t_low, t_high = integer_range(target)
        if c_conversion and target.startswith("i") and not (t_low <= low and high <= t_high):
            raise MigrationRejected("E_C_SIGNED_CONVERSION", f"Unqualified signed narrowing: {expr.typ} -> {target}")
    elif not (expr.typ in NUMBER and target in NUMBER):
        raise MigrationRejected("E_C_CONVERSION", f"Unsupported conversion: {expr.typ} -> {target}")
    elif expr.typ in {"f32", "f64"} and target in INTEGER:
        raise MigrationRejected("E_C_FLOAT_CONVERSION", "Float-to-integer conversion is not in this profile")
    return Expression(f"({expr.text} as {target})", target, expr.side_effect)


def truth(expr: Expression) -> Expression:
    if expr.typ == "bool":
        return expr
    if expr.typ not in NUMBER:
        raise MigrationRejected("E_C_POINTER_CONTROL", "Pointer truthiness is not a slice operation")
    zero = "0.0" if expr.typ in {"f32", "f64"} else "0"
    return Expression(f"({expr.text} != ({zero} as {expr.typ}))", "bool", expr.side_effect)


def _signature_shape(return_type: str, parameters: list[dict]) -> tuple:
    """Compare validated contracts by ABI argument position, never spelling.

    Parameter names may differ between compatible C declarations. A named
    extent or initializer source must nevertheless denote the same argument
    in every declaration. Keep the original names in the parameters/contracts
    for emission and diagnostics, and use this resolved identity only when
    coalescing declarations. Both value and record-view profiles call this
    after their existing contract validation has completed.
    """
    ordinals = {parameter["name"]: index for index, parameter in enumerate(parameters)}
    shape = []
    for parameter in parameters:
        length = None
        if parameter["pointer"] and not parameter.get("record"):
            extent = parameter["length"]
            length = ("fixed", extent) if type(extent) is int else ("parameter", ordinals[extent])
        initialize = parameter.get("initialize")
        sources = (None if initialize is None else
                   tuple(sorted((field, ordinals[source]) for field, source in initialize.items())))
        shape.append((parameter["type"], parameter["pointer"], parameter["mode"],
                      parameter.get("c_const"), parameter.get("c_void"), length, sources))
    return return_type, shape


class CTranslator:
    def __init__(self, capture: dict, contracts: dict | None = None):
        self.capture = capture
        self.contracts = snapshot_contracts(contracts)
        if self.contracts.get("schema") != "hepta.c-contracts.v1" or set(self.contracts) != {"schema", "functions"} or not isinstance(self.contracts["functions"], dict):
            raise MigrationRejected("E_C_CONTRACT", "Expected hepta.c-contracts.v1 with functions")
        self.inventory: list[dict] = []
        self.inventory_complete = False
        self.record_nodes: dict[str, dict] = {}
        self.records: dict[str, list[tuple[str, str]]] = {}
        self.aliases: dict[str, str] = {}
        self.functions: dict[str, dict] = {}
        self.declarations: list[tuple[int, dict, dict]] = []
        self.current: dict = {}
        self.bindings: dict[str, Expression] = {}
        self.binding_modes: dict[str, str] = {}
        self.counter = 0
        self.expression_helpers: list[str] = []
        self.conditional_count = 0
        self.loop_control_count = 0
        self.original_type_receipts: list[dict] = []
        self.parameter_sources: dict[str, bytes] = {}
        self.physical_source_files: dict[int, str | None] = {}
        # Optional evidence retention for the direct HIA project adapter. The
        # exact text consumed by this translator is retained, not a second
        # compiler invocation whose AST could describe different source bytes.
        self.retained_asts: dict[int, str] | None = None

    def check_parameter_sources(self, node: dict, item: dict) -> None:
        """Bind finite spelling before any type adaptation or array admission."""
        pointers = [child for child in node.get("inner", [])
                    if child.get("kind") == "ParmVarDecl"
                    and re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", child.get("type", {}).get("qualType", ""))]
        if not pointers:
            return
        path = item["file"]
        for parameter in pointers:
            span = parameter.get("range")
            positions = [parameter.get("loc"),
                         span.get("begin") if isinstance(span, dict) else None,
                         span.get("end") if isinstance(span, dict) else None]
            if any(not isinstance(position, dict)
                   or self.physical_source_files.get(id(position)) != path
                   for position in positions):
                raise MigrationRejected("E_C_PARAMETER_DECLARATOR",
                                        "Parameter spelling crosses physical files or lacks a bound physical source")
        if path not in self.parameter_sources:
            dependency = next((part for part in self.capture["dependencies"] if part["path"] == path), None)
            source = _read_dependency(Path(path))
            if dependency is None or digest(source) != dependency["sha256"]:
                raise MigrationRejected("E_C_BUILD_CHANGED", "Parameter spelling differs from captured dependency")
            self.parameter_sources[path] = source
        for parameter in pointers:
            _parameter_source_form(parameter, self.parameter_sources[path])

    def capture_original_types(self):
        from .c_parameter_types import original_parameter_types

        for config in self.capture["configurations"]:
            declarations = [(node, item) for unit, node, item in self.declarations
                            if unit == config["index"] and node["kind"] == "FunctionDecl"]
            if declarations:
                self.original_type_receipts.append(original_parameter_types(
                    self.capture, config, declarations, self.physical_source_files))

    def check_parameter_declarators(self, node: dict, item: dict, unit: int) -> None:
        receipts = [receipt for receipt in self.original_type_receipts if receipt["unit"] == unit]
        rows = [row for receipt in receipts for row in receipt["functions"]
                if (row["declaration"]["file"], row["declaration"]["offset"], row["declaration"]["name"])
                == (item["file"], item["offset"], node["name"])]
        if len(rows) != 1:
            raise MigrationRejected("E_C_ORIGINAL_TYPE", "Missing or ambiguous original function type binding")
        row = rows[0]
        for original in [row["result"], *row["parameters"]]:
            if original["state"] != "fixed":
                code = "E_C_VLA_PARAMETER" if original["state"] == "variable" else "E_C_ORIGINAL_TYPE"
                raise MigrationRejected(code, "Unmodeled original type for " + node["name"]
                                        + ": " + original["spelling"])
        parameters = [child for child in node.get("inner", []) if child.get("kind") == "ParmVarDecl"]
        for parameter, original in zip(parameters, row["parameters"]):
            if re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", parameter.get("type", {}).get("qualType", "")):
                reject_adjusted_pointer_parameter(parameter, self.parameter_sources[item["file"]], original)

    def typ(self, data: dict | str, *, model: dict | None = None) -> str:
        qual = data if isinstance(data, str) else data.get("qualType", "")
        if any(token in qual for token in ("volatile", "restrict", "_Atomic", "[", "(", "*")):
            raise MigrationRejected("E_C_TYPE", "Unsupported value type: " + qual)
        qual = re.sub(r"\bconst\b", "", qual).strip()
        model = model or self.current.get("model") or self.capture["configurations"][0]["model"]
        types = {"void": "Unit", "_Bool": "bool", "char": "u8" if model["char_unsigned"] else "i8",
                 "signed char": "i8", "unsigned char": "u8", "short": "i16", "unsigned short": "u16",
                 "int": "i32", "unsigned int": "u32", "long": "i" + str(model["long_bits"]),
                 "unsigned long": "u" + str(model["long_bits"]), "long long": "i64", "unsigned long long": "u64",
                 "size_t": "usize", "ptrdiff_t": "isize", "float": "f32", "double": "f64"}
        types.update({f"{s}int{w}_t": f"{'u' if s else 'i'}{w}" for s in ("", "u") for w in (8, 16, 32, 64)})
        if qual in self.aliases:
            return self.aliases[qual]
        if qual in types:
            return types[qual]
        if qual.startswith("struct ") and qual[7:] in self.record_nodes:
            return "C_" + ident(qual[7:])
        if isinstance(data, dict) and data.get("desugaredQualType") and data["desugaredQualType"] != qual:
            return self.typ(data["desugaredQualType"], model=model)
        raise MigrationRejected("E_C_TYPE", "Unmodeled value type: " + qual)

    @staticmethod
    def _position(node: dict) -> dict:
        loc = node.get("loc") or node.get("range", {}).get("begin", {})
        return loc.get("expansionLoc", loc.get("spellingLoc", loc))

    def field_type(self, record: str, field: dict) -> str:
        return self.typ(field["type"])

    def repeated_definition(self, previous: dict, node: dict, item: dict) -> bool:
        """Only a separately qualified profile may coalesce header definitions."""
        return False

    def check_pointer_alias_profile(self, pointers: list[dict]) -> None:
        if len(pointers) > 1 and any(p["mode"] == "mut" for p in pointers):
            raise MigrationRejected("E_C_ALIAS_CONTRACT", "Multiple buffers with mutation need a separate alias-preserving model")

    def collect(self) -> None:
        deferred_errors = []
        retained_bytes = 0
        for config in self.capture["configurations"]:
            directory = Path(config["directory"])
            raw_ast = invoke([self.capture["compiler"]["path"], *config["frontend_arguments"],
                              "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json",
                              captured_source_argument(config)], directory)
            tree = _load_bounded_clang_ast(raw_ast)
            if self.retained_asts is not None:
                retained_bytes += len(raw_ast.encode("utf-8"))
                if retained_bytes > 64_000_000:
                    raise MigrationRejected("E_C_AST_RETENTION", "Retained project AST text exceeds 64 MB")
                self.retained_asts[config["index"]] = raw_ast
            if tree.get("kind") != "TranslationUnitDecl":
                raise MigrationRejected("E_C_AST", "Clang did not produce a translation unit")
            source_files = _physical_source_files(tree, directory)
            self.physical_source_files.update(source_files)
            for node in tree.get("inner", []):
                loc = self._position(node)
                active_file = source_files.get(id(loc))
                kind, name = node.get("kind", "unknown"), node.get("name", "<anonymous>")
                user = active_file in config["local_dependencies"] and not node.get("isImplicit")
                item = {"unit": config["index"], "kind": kind, "name": name,
                        "file": active_file, "offset": loc.get("offset"),
                        "status": "pending" if user else "system_or_compiler_declaration",
                        "reason": None if user else "recorded_dependency_outside_translated_project_declarations"}
                self.inventory.append(item)
                if active_file is None and not node.get("isImplicit"):
                    item.update(status="rejected", reason="untraceable_physical_source")
                    deferred_errors.append(("E_C_SOURCE_LOCATION", "Declaration has no bound physical source file"))
                    continue
                if not user:
                    continue
                if loc.get("offset") is None:
                    item.update(status="rejected", reason="untraceable_source_location")
                    deferred_errors.append(("E_C_SOURCE_LOCATION", "Project declaration has no traceable source location"))
                    continue
                self.declarations.append((config["index"], node, item))
                if kind == "RecordDecl":
                    if not node.get("completeDefinition") and node.get("tagUsed") == "struct" and name != "<anonymous>" and getattr(self, "allow_record_views", False):
                        item.update(status="record_forward_pending", reason=None)
                    elif not node.get("completeDefinition") or node.get("tagUsed") != "struct" or name == "<anonymous>":
                        item.update(status="rejected", reason="unsupported_record")
                        deferred_errors.append(("E_C_RECORD", "Only complete named ordinary structs are supported"))
                    else:
                        self.record_nodes.setdefault(ident(name), node)
                elif kind not in {"TypedefDecl", "FunctionDecl"}:
                    item.update(status="rejected", reason="unsupported_top_level_declaration")
                    deferred_errors.append(("E_C_TOPLEVEL", f"Unsupported project declaration: {kind} {name}"))
        self.inventory_complete = True
        models = [config["model"] for config in self.capture["configurations"]]
        if any(model != models[0] for model in models[1:]):
            raise MigrationRejected("E_C_PROJECT_MODEL", "All translation units in one bundle must use the same captured C data model, including plain-char signedness")
        if deferred_errors:
            code, message = deferred_errors[0]
            raise MigrationRejected(code, message)
        # Preserve the physical source guard before the independent original-type
        # probe or the record-view adapter can reinterpret adjusted parameters.
        for _, node, item in self.declarations:
            if node["kind"] == "FunctionDecl":
                try:
                    self.check_parameter_sources(node, item)
                except MigrationRejected as error:
                    item.update(status="rejected", reason=error.code)
                    raise
        # Register aliases before field types, including typedef struct aliases.
        unresolved = [(node, item) for _, node, item in self.declarations if node["kind"] == "TypedefDecl"]
        for _ in range(len(unresolved) + 1):
            left = []
            for node, item in unresolved:
                try:
                    value = self.typ(node["type"])
                except MigrationRejected:
                    left.append((node, item))
                    continue
                name = ident(node["name"])
                if name in self.aliases and self.aliases[name] != value:
                    raise MigrationRejected("E_C_ALIAS", "Conflicting typedef across project configurations")
                self.aliases[name] = value
                item.update(status="type_alias_resolved", reason=None)
            if not left:
                break
            if len(left) == len(unresolved):
                raise MigrationRejected("E_C_TYPEDEF", "Unresolved typedefs: " + ", ".join(node["name"] for node, _ in left))
            unresolved = left
        for _, node, item in self.declarations:
            if node["kind"] != "RecordDecl":
                continue
            if item["status"] == "record_forward_pending":
                if node["name"] not in self.record_nodes:
                    raise MigrationRejected("E_C_RECORD", "Forward record has no captured complete definition")
                item.update(status="record_forward_resolved", reason=None)
                continue
            fields = []
            for field in node.get("inner", []):
                if field.get("kind") == "FullComment":
                    continue
                if field.get("kind") != "FieldDecl" or field.get("isBitfield") or any(child.get("kind") != "FullComment" for child in field.get("inner", [])):
                    raise MigrationRejected("E_C_RECORD", "Packed, attributed, anonymous and bitfield records are unsupported")
                fields.append(("f_" + ident(field["name"]), self.field_type(node["name"], field)))
            if not fields:
                raise MigrationRejected("E_C_RECORD", "Empty C record unsupported")
            name = "C_" + node["name"]
            if name in self.records and self.records[name] != fields:
                raise MigrationRejected("E_C_RECORD", "Conflicting struct layout in listed configurations")
            self.records[name] = fields
            item.update(status="record_converted", reason=None)
        self.capture_original_types()
        models_by_unit = {config["index"]: config["model"] for config in self.capture["configurations"]}
        for unit, node, item in self.declarations:
            if node["kind"] != "FunctionDecl":
                continue
            # Explicit matrix selections retain their original database
            # indices; a unit identity is not a position in this subset.
            model = models_by_unit[unit]
            name = ident(node["name"])
            key = f"local_{unit}_{name}" if node.get("storageClass") == "static" else name
            try:
                self.check_parameter_declarators(node, item, unit)
                signature = self.signature(node, key, unit, model)
            except MigrationRejected as exc:
                item.update(status="rejected", reason=exc.code)
                raise
            body = next((child for child in node.get("inner", []) if child.get("kind") == "CompoundStmt"), None)
            if key in self.functions:
                previous = self.functions[key]
                if previous["shape"] != signature["shape"]:
                    raise MigrationRejected("E_C_FUNCTION", "Incompatible project declarations: " + name)
                if body is not None and previous.get("body") is not None:
                    if self.repeated_definition(previous, node, item):
                        item.update(status="repeated_inline_definition_resolved", reason=None)
                        continue
                    raise MigrationRejected("E_C_FUNCTION", "Duplicate function definition: " + name)
                if body is None:
                    item.update(status="prototype_resolved", reason=None)
                    continue
            signature.update(body=body, node=node, inventory=item)
            self.functions[key] = signature
            item.update(status="function_pending" if body is not None else "prototype_pending", reason=None)
        for fn in self.functions.values():
            if fn["body"] is None:
                fn["inventory"].update(status="rejected", reason="unresolved_project_prototype")
                raise MigrationRejected("E_C_EXTERNAL", "Project declaration has no captured implementation: " + fn["name"])
        known_names = {fn["name"] for fn in self.functions.values()}
        if set(self.contracts["functions"]) - known_names:
            raise MigrationRejected("E_C_CONTRACT", "Contracts name functions outside this captured project")
        # Earlier prototypes also receive an explicit result, never disappear.
        for _, node, item in self.declarations:
            if item["status"] == "prototype_pending":
                item.update(status="prototype_resolved", reason=None)

    def signature(self, node: dict, key: str, unit: int, model: dict) -> dict:
        reject_function_type_attributes(node)
        name = ident(node["name"])
        if name == "main" or node.get("variadic") or "..." in node["type"]["qualType"] or node["type"]["qualType"].endswith(" ()"):
            raise MigrationRejected("E_C_FUNCTION", "main, varargs and unprototyped functions are unsupported")
        if any(child.get("kind") not in {"ParmVarDecl", "CompoundStmt", "FullComment"} for child in node.get("inner", [])):
            raise MigrationRejected("E_C_ATTRIBUTE", "Function attributes need separate ABI qualification")
        ret = self.typ(node["type"]["qualType"].split("(", 1)[0].strip(), model=model)
        contract = self.contracts["functions"].get(name, {"slices": {}})
        if not isinstance(contract, dict) or set(contract) != {"slices"} or not isinstance(contract["slices"], dict):
            raise MigrationRejected("E_C_CONTRACT", "Each function contract contains only slices")
        params = []
        used_contract_keys = set()
        for child in node.get("inner", []):
            if child.get("kind") != "ParmVarDecl":
                continue
            pname = ident(child.get("name", ""))
            raw = child["type"]["qualType"]
            pointer = re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", raw)
            if pointer:
                # C prototypes may legally use different parameter names from
                # their implementation. Ordinal selectors remain unambiguous.
                selectors = [key for key in (pname, str(len(params))) if key in contract["slices"]]
                if len(selectors) != 1:
                    raise MigrationRejected("E_C_POINTER_CONTRACT", f"{name}.{pname} requires exactly one name or ordinal slice contract")
                selector = selectors[0]
                used_contract_keys.add(selector)
                specification = contract["slices"][selector]
                c_void = pointer[2].strip() == "void"
                keys = {"length", "access", "element"} if c_void else {"length", "access"}
                if not isinstance(specification, dict) or set(specification) != keys or specification["access"] not in {"read", "mut"}:
                    raise MigrationRejected("E_C_POINTER_CONTRACT", f"{name}.{pname} requires an explicit length/access slice contract")
                if specification["access"] == "mut" and pointer[1]:
                    raise MigrationRejected("E_C_POINTER_CONTRACT", "A const C pointer cannot become a mutable slice")
                if c_void and not isinstance(specification["element"], str):
                    raise MigrationRejected("E_C_POINTER_CONTRACT", "void pointers require a concrete C element type")
                elem = self.typ(specification["element"] if c_void else pointer[2].strip(), model=model)
                if elem not in NUMBER:
                    raise MigrationRejected("E_C_POINTER_CONTRACT", "Only primitive element slices are supported")
                params.append({"name": pname, "id": child["id"], "type": elem, "pointer": True,
                               "mode": specification["access"], "length": specification["length"], "c_const": bool(pointer[1]),
                               "c_void": c_void, "contract_selector": selector})
            else:
                params.append({"name": pname, "id": child["id"], "type": self.typ(child["type"], model=model), "pointer": False, "mode": "value"})
        pointers = [p for p in params if p["pointer"]]
        if set(contract["slices"]) != used_contract_keys:
            raise MigrationRejected("E_C_CONTRACT", "Slice contract does not exactly match pointer parameters")
        self.check_pointer_alias_profile(pointers)
        values = {p["name"]: p for p in params if not p["pointer"]}
        for pointer in pointers:
            if type(pointer["length"]) is int:
                if pointer["length"] != 1:
                    raise MigrationRejected("E_C_POINTER_CONTRACT", "The fixed-size profile supports exactly one element")
                continue
            if not isinstance(pointer["length"], str):
                raise MigrationRejected("E_C_POINTER_CONTRACT", "Length must name an unsigned parameter or be the integer 1")
            length = values.get(pointer["length"])
            if length is None or length["type"] not in {"usize", "u32", "u64"}:
                raise MigrationRejected("E_C_POINTER_CONTRACT", "Slice length must name an unsigned scalar parameter")
        shape = _signature_shape(ret, params)
        return {"key": key, "name": name, "hepta_name": "c_" + key, "unit": unit, "model": model,
                "return": ret, "params": params, "shape": shape,
                "nonsemantic_documentation_comments": sum(child.get("kind") == "FullComment" for child in node.get("inner", [])),
                "external_symbol": node.get("storageClass") != "static"}

    def _numeric(self, text: str, typ: str) -> Expression:
        if typ in {"u64", "usize"} and text.isdigit() and int(text) > (1 << 63) - 1:
            value = int(text)
            return Expression(f"(((1 as {typ}) << (63 as {typ})) | ({value - (1 << 63)} as {typ}))", typ)
        return Expression(f"({text} as {typ})", typ)

    def expr(self, node: dict) -> Expression:
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "ConditionalOperator":
            return self.scalar_conditional(node)
        if kind == "ParenExpr" and len(children) == 1:
            return self.expr(children[0])
        if kind in {"ImplicitCastExpr", "CStyleCastExpr"} and len(children) == 1:
            value = self.expr(children[0])
            conversion = node.get("castKind")
            if conversion in {"LValueToRValue", "NoOp"}:
                return value
            if conversion == "BitCast" and value.typ.startswith("slice:"):
                raw = node.get("type", {}).get("qualType", "")
                pointer = re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", raw)
                if pointer is not None and (pointer[2].strip() == "void" or self.typ(pointer[2].strip()) == value.typ[6:]):
                    return value
                raise MigrationRejected("E_C_POINTER_CAST", "Pointer cast differs from its explicit typed slice contract")
            if conversion in {"IntegralCast", "IntegralToFloating", "FloatingCast"}:
                return cast(value, self.typ(node["type"]), c_conversion=True)
            if conversion == "IntegralToBoolean":
                return truth(value)
            raise MigrationRejected("E_C_CAST", "Unsupported C conversion: " + str(conversion))
        if kind == "IntegerLiteral":
            typ, value = self.typ(node["type"]), int(node["value"])
            low, high = integer_range(typ)
            if not low <= value <= high:
                raise MigrationRejected("E_C_INTEGER", "Integer outside its typed range")
            return self._numeric(str(value), typ)
        if kind == "FloatingLiteral":
            return self._numeric(repr(float(node["value"])), self.typ(node["type"]))
        if kind == "DeclRefExpr":
            ref = node.get("referencedDecl", {})
            value = self.bindings.get(ref.get("id"))
            if value is None:
                raise MigrationRejected("E_C_REFERENCE", "Untranslated/global reference: " + ref.get("name", "?"))
            return value
        if kind == "MemberExpr" and not node.get("isArrow") and len(children) == 1:
            base = self.expr(children[0])
            field = "f_" + ident(node["name"])
            fields = dict(self.records.get(base.typ, []))
            if field not in fields:
                raise MigrationRejected("E_C_RECORD", "Unknown field")
            return Expression(f"({base.text}).{field}", fields[field], base.side_effect)
        if kind == "ArraySubscriptExpr" and len(children) == 2:
            base, index = self.expr(children[0]), self.expr(children[1])
            if not base.typ.startswith("slice:") or index.typ not in INTEGER or index.side_effect:
                raise MigrationRejected("E_C_SUBSCRIPT", "Only pure indices into contracted slices are supported")
            return Expression(f"{base.text}[{cast(index, 'usize').text}]", base.typ[6:], base.side_effect)
        if kind == "UnaryOperator" and len(children) == 1:
            value, op = self.expr(children[0]), node.get("opcode")
            if op == "*" and value.typ.startswith("slice:"):
                return Expression(f"{value.text}[(0 as usize)]", value.typ[6:], value.side_effect)
            if op == "!":
                return Expression(f"(!{truth(value).text})", "bool", value.side_effect)
            if op == "+":
                return value
            if op == "~" and value.typ in INTEGER:
                return Expression(f"(!{value.text})", value.typ, value.side_effect)
            if op == "-" and value.typ in NUMBER:
                if value.typ.startswith("u"):
                    return Expression(f"wrapping_sub((0 as {value.typ}), {value.text})", value.typ, value.side_effect)
                return Expression(f"(-{value.text})", value.typ, value.side_effect)
            raise MigrationRejected("E_C_UNARY", "Pointer arithmetic and expression increments are unsupported")
        if kind == "BinaryOperator" and len(children) == 2:
            lhs, rhs = self.expr(children[0]), self.expr(children[1])
            op = node.get("opcode")
            if lhs.side_effect or rhs.side_effect:
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Side-effectful calls inside expressions require sequencing")
            if op in {"&&", "||"}:
                return Expression(f"({truth(lhs).text} {op} {truth(rhs).text})", "bool")
            if op in {"==", "!=", "<", "<=", ">", ">="}:
                rhs = cast(rhs, lhs.typ)
                return Expression(f"({lhs.text} {op} {rhs.text})", "bool")
            typ = self.typ(node["type"])
            return self.arithmetic(lhs, rhs, op, typ)
        if kind == "InitListExpr":
            typ = self.typ(node["type"])
            fields = self.records.get(typ)
            if fields is None or len(children) != len(fields):
                raise MigrationRejected("E_C_INITIALIZER", "Only complete scalar-field struct initialization is supported")
            values = [cast(self.expr(child), field_type).text for child, (_, field_type) in zip(children, fields)]
            return Expression(typ + " { " + ", ".join(f"{field}: {value}" for (field, _), value in zip(fields, values)) + " }", typ)
        if kind == "ImplicitValueInitExpr":
            typ = self.typ(node["type"])
            if typ in NUMBER:
                return self._numeric("0.0" if typ in {"f32", "f64"} else "0", typ)
            raise MigrationRejected("E_C_INITIALIZER", "Nested aggregate zero initialization is unsupported")
        if kind == "CallExpr" and children:
            callee = children[0]
            while callee.get("kind") in {"ImplicitCastExpr", "ParenExpr"} and len(callee.get("inner", [])) == 1:
                callee = callee["inner"][0]
            ref = callee.get("referencedDecl", {})
            name = ref.get("name", "")
            if name in {"malloc", "calloc", "realloc", "free", "aligned_alloc"}:
                raise MigrationRejected("E_C_ALLOCATOR", "C allocation/failure/escape semantics are not inferred; rewrite with explicit ownership")
            key = f"local_{self.current['unit']}_{name}"
            target = self.functions.get(key) or self.functions.get(name)
            if target is None or ref.get("kind") != "FunctionDecl" or len(children) - 1 != len(target["params"]):
                raise MigrationRejected("E_C_CALL", "Only direct calls to captured project implementations are supported")
            args = []
            for child, parameter in zip(children[1:], target["params"]):
                value = self.expr(child)
                if value.side_effect:
                    raise MigrationRejected("E_C_EVALUATION_ORDER", "Nested mutating calls are unsupported")
                if parameter["pointer"]:
                    if value.typ != "slice:" + parameter["type"] or value.text not in self.binding_modes:
                        raise MigrationRejected("E_C_CALL", "Slice argument must be an unchanged contracted parameter")
                    if parameter["mode"] == "mut" and self.binding_modes[value.text] != "mut":
                        raise MigrationRejected("E_C_READ_ONLY", "Cannot call a mutating callee with a read slice")
                    args.append(parameter["mode"] + " " + value.text)
                else:
                    args.append(cast(value, parameter["type"]).text)
            side = any(p["mode"] == "mut" for p in target["params"]) or target.get("allocates", False)
            return Expression(target["hepta_name"] + "(" + ", ".join(args) + ")", target["return"], side)
        raise MigrationRejected("E_C_EXPRESSION", "Unsupported C expression: " + str(kind))

    def scalar_conditional(self, node: dict) -> Expression:
        """A pure scalar value conditional remains lazy inside a helper body.

        Only existing scalar values are passed eagerly. Branch expressions,
        including checked division and nested conditionals, execute inside the
        selected helper branch. Slice/record captures and mutating calls reject.
        This avoids an eager select that could evaluate an invalid unused arm.
        """
        children = node.get("inner", [])
        typ = self.typ(node.get("type", {}))
        if len(children) != 3 or typ not in NUMBER | {"bool"}:
            raise MigrationRejected("E_C_CONDITIONAL", "Require three operands and a scalar conditional result")
        from .c_allocation import nodes
        captured = {}
        for part in nodes(node):
            if part.get("kind") != "DeclRefExpr":
                continue
            reference = part.get("referencedDecl", {})
            if reference.get("kind") == "FunctionDecl":
                continue
            key = reference.get("id")
            value = self.bindings.get(key)
            if value is None or value.typ not in NUMBER | {"bool"} or value.side_effect:
                raise MigrationRejected("E_C_CONDITIONAL", "Value conditionals may capture initialized pure scalar locals only")
            captured.setdefault(key, value)
        self.conditional_count += 1
        name = "migration_conditional_" + str(self.conditional_count)
        while name in {function["hepta_name"] for function in self.functions.values()}:
            self.conditional_count += 1
            name = "migration_conditional_" + str(self.conditional_count)
        parameters, arguments = [], []
        previous = self.bindings
        self.bindings = dict(previous)
        try:
            for index, (key, value) in enumerate(captured.items()):
                parameter = "argument_" + str(index)
                parameters.append(parameter + ": " + value.typ)
                arguments.append(value.text)
                self.bindings[key] = Expression(parameter, value.typ)
            condition = truth(self.expr(children[0]))
            yes, no = (cast(self.expr(child), typ) for child in children[1:])
            if any(value.side_effect for value in (condition, yes, no)):
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating value conditionals require a separate sequencing model")
        finally:
            self.bindings = previous
        self.expression_helpers.append(
            f"fn {name}({', '.join(parameters)}) -> {typ} effects {{panic, write}} {{\n"
            f"    if {condition.text} {{ return {yes.text}; }} else {{ return {no.text}; }}\n}}")
        return Expression(name + "(" + ", ".join(arguments) + ")", typ)

    def arithmetic(self, lhs: Expression, rhs: Expression, op: str, typ: str) -> Expression:
        if op not in {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"} or typ not in NUMBER:
            raise MigrationRejected("E_C_OPERATOR", "Unsupported arithmetic operator/type: " + str(op))
        lhs, rhs = cast(lhs, typ), cast(rhs, typ)
        if op in {"<<", ">>"} and not typ.startswith("u"):
            raise MigrationRejected("E_C_SHIFT", "Signed C shifts require a separate implementation-defined model")
        if op in {"+", "-", "*"} and typ.startswith("u"):
            operation = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
            return Expression(f"{operation}({lhs.text}, {rhs.text})", typ)
        return Expression(f"({lhs.text} {op} {rhs.text})", typ)

    def lvalue(self, node: dict) -> Expression:
        dereference = node.get("kind") == "UnaryOperator" and node.get("opcode") == "*"
        if node.get("kind") not in {"DeclRefExpr", "MemberExpr", "ArraySubscriptExpr"} and not dereference:
            raise MigrationRejected("E_C_LVALUE", "Unsupported assignment destination")
        if node.get("kind") == "ArraySubscriptExpr" or dereference:
            base = self.expr(node["inner"][0])
            if self.binding_modes.get(base.text) != "mut":
                raise MigrationRejected("E_C_READ_ONLY", "Contracted read slice cannot be written")
        result = self.expr(node)
        if result.side_effect or result.typ.startswith("slice:"):
            raise MigrationRejected("E_C_LVALUE", "Pointer reassignment and effectful lvalues are unsupported")
        return result

    def loop_control(self, node: dict, depth: int) -> dict | None:
        # Structuring a wide sequence of possible jumps adds guarded suffixes.
        # Bound that expansion before the recursive source/IR walkers consume
        # it, independently of the depth of the original captured Clang AST.
        if depth > 64:
            raise MigrationRejected("E_C_CONTROL_LIMIT", "Structured source lowering exceeds 64 statement levels")
        from .c_loop_control import lower_loop_jumps
        lowered = lower_loop_jumps(node, self.loop_control_count)
        if lowered is not None:
            self.loop_control_count += 1
        return lowered

    def if_condition(self, node: dict, depth: int) -> tuple[list[str], Expression]:
        """Sequence one scalar postfix update at an if full-expression boundary.

        Only parentheses, logical negation and an implicit conversion to bool
        may enclose the update.  Saving its old value before the existing
        checked/wrapping statement update preserves both the condition value
        and the completed side effect before either branch begins.  This does
        not grant effectful arithmetic, short-circuit operands, loop tests or
        aggregate/pointer lvalues a general expression-sequencing model.
        The captured Clang AST is read without mutation.
        """
        current, wrappers = node, []
        while len(current.get("inner", [])) == 1:
            kind = current.get("kind")
            if kind == "ParenExpr":
                wrappers.append("paren")
            elif kind == "UnaryOperator" and current.get("opcode") == "!":
                wrappers.append("not")
            elif kind == "ImplicitCastExpr" and current.get("castKind") == "IntegralToBoolean":
                wrappers.append("bool")
            else:
                break
            current = current["inner"][0]
        if (current.get("kind") != "UnaryOperator"
                or current.get("opcode") not in {"++", "--"}
                or current.get("isPostfix") is not True
                or len(current.get("inner", [])) != 1):
            return [], truth(self.expr(node))
        target = current["inner"][0]
        while target.get("kind") == "ParenExpr" and len(target.get("inner", [])) == 1:
            target = target["inner"][0]
        reference = target.get("referencedDecl", {})
        if (target.get("kind") != "DeclRefExpr"
                or reference.get("kind") not in {"ParmVarDecl", "VarDecl"}
                or reference.get("id") not in self.bindings):
            raise MigrationRejected("E_C_IF_POSTFIX",
                                    "Postfix if conditions require an initialized scalar local or parameter")
        value = self.lvalue(target)
        if value.typ not in INTEGER:
            raise MigrationRejected("E_C_IF_POSTFIX",
                                    "Postfix if conditions require a non-Boolean integer local or parameter")
        # Reuse the existing promotion/narrowing and checked/wrapping rules.
        # In particular i8/i16 still reject and signed overflow still traps;
        # no claim is made about executions with undefined signed C overflow.
        update = self.stmt(dict(current, inner=[target]), depth)
        self.counter += 1
        old = "migration_if_old_" + str(self.counter)
        prefix = [f"{'    ' * depth}let {old}: {value.typ} = {value.text};", *update]
        condition = Expression(old, value.typ)
        for wrapper in reversed(wrappers):
            if wrapper == "not":
                condition = Expression(f"(!{truth(condition).text})", "bool")
            elif wrapper == "bool":
                condition = truth(condition)
        return prefix, truth(condition)

    def stmt(self, node: dict, depth: int = 1) -> list[str]:
        lowered = self.loop_control(node, depth)
        if lowered is not None:
            return self.stmt(lowered, depth)
        pad = "    " * depth
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "CompoundStmt":
            return [line for child in children for line in self.stmt(child, depth)]
        if kind == "NullStmt":
            return []
        if kind == "DeclStmt":
            output = []
            for child in children:
                if child.get("kind") != "VarDecl" or child.get("storageClass") or len(child.get("inner", [])) > 1:
                    raise MigrationRejected("E_C_LOCAL", "Locals require at most one initializer and ordinary automatic storage")
                typ = self.typ(child["type"])
                if child.get("inner"):
                    value = cast(self.expr(child["inner"][0]), typ)
                elif typ in NUMBER | {"bool"} and self.current.get("definite_assignment", {}).get("checked"):
                    value = Expression("false", "bool") if typ == "bool" else self._numeric("0.0" if typ in {"f32", "f64"} else "0", typ)
                else:
                    raise MigrationRejected("E_C_LOCAL", "Deferred initialization requires a checked scalar local")
                self.counter += 1
                name = "v_" + ident(child["name"]) + "_" + str(self.counter)
                self.bindings[child["id"]] = Expression(name, typ)
                output.append(f"{pad}let mut {name}: {typ} = {value.text};")
            return output
        if kind == "ReturnStmt":
            if not children and self.current["return"] == "Unit":
                return [pad + "return;"]
            if len(children) != 1:
                raise MigrationRejected("E_C_RETURN", "Unsupported return")
            # Return-position conditionals become control flow so only the
            # selected operand is evaluated (an empty slice must not be read).
            # Clang retains the conditional's common-type conversions on its
            # operands; do not strip cast nodes or eagerly evaluate both arms.
            returned = children[0]
            while returned.get("kind") == "ParenExpr" and len(returned.get("inner", [])) == 1:
                returned = returned["inner"][0]
            if returned.get("kind") == "ConditionalOperator":
                arms = returned.get("inner", [])
                if len(arms) != 3 or self.typ(returned["type"]) not in NUMBER | {"bool"}:
                    raise MigrationRejected("E_C_RETURN", "Only scalar return conditionals are supported")
                condition = truth(self.expr(arms[0]))
                if condition.side_effect:
                    raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating return conditions are unsupported")
                return [f"{pad}if {condition.text} {{",
                        *self.stmt({"kind": "ReturnStmt", "inner": [arms[1]]}, depth + 1),
                        pad + "} else {",
                        *self.stmt({"kind": "ReturnStmt", "inner": [arms[2]]}, depth + 1), pad + "}"]
            value = cast(self.expr(children[0]), self.current["return"])
            return [f"{pad}return {value.text};"]
        if kind in {"IfStmt", "WhileStmt"}:
            if len(children) not in ({2, 3} if kind == "IfStmt" else {2}):
                raise MigrationRejected("E_C_CONTROL", "Unexpected control-flow AST")
            prefix, condition = (self.if_condition(children[0], depth) if kind == "IfStmt"
                                 else ([], truth(self.expr(children[0]))))
            if condition.side_effect:
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating conditions are unsupported")
            keyword = "if" if kind == "IfStmt" else "while"
            out = prefix + [f"{pad}{keyword} {condition.text} {{", *self.stmt(children[1], depth + 1), pad + "}"]
            if len(children) == 3:
                out += [pad + "else {", *self.stmt(children[2], depth + 1), pad + "}"]
            return out
        if kind == "DoStmt":
            if len(children) != 2:
                raise MigrationRejected("E_C_CONTROL", "Unexpected post-test loop AST")
            body, predicate = children
            condition = truth(self.expr(predicate))
            if condition.side_effect:
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating post-test conditions are unsupported")
            # Generate the body once. Short-circuiting skips the first test;
            # subsequent header visits occur after the preceding body. This
            # keeps local declarations scoped to each iteration and a return
            # skips the postcondition, including a potentially trapping one.
            # Loop jumps have already been structured by loop_control; goto
            # and other unsupported control forms still reject.
            self.counter += 1
            first = "migration_do_first_" + str(self.counter)
            return [f"{pad}let mut {first}: bool = true;",
                    f"{pad}while {first} || {condition.text} {{",
                    f"{pad}    {first} = false;",
                    *self.stmt(body, depth + 1), pad + "}"]
        if kind == "ForStmt":
            if len(children) != 5 or children[1] or not all(children[i] for i in (2, 3, 4)):
                raise MigrationRejected("E_C_FOR", "C for loops require an explicit condition and increment")
            initial = self.stmt(children[0], depth) if children[0] else []
            condition = truth(self.expr(children[2]))
            if condition.side_effect:
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating loop conditions are unsupported")
            return initial + [f"{pad}while {condition.text} {{", *self.stmt(children[4], depth + 1),
                              *self.stmt(children[3], depth + 1), pad + "}"]
        if kind in {"BinaryOperator", "CompoundAssignOperator"} and len(children) == 2:
            if kind == "BinaryOperator" and node.get("opcode") == ",":
                # The C comma operator introduces a sequence point. Only
                # statement position is admitted; each operand must itself
                # be a supported statement, executed exactly left to right.
                return self.stmt(children[0], depth) + self.stmt(children[1], depth)
            lhs, rhs = self.lvalue(children[0]), self.expr(children[1])
            op = node.get("opcode", "")
            if kind == "BinaryOperator" and op != "=":
                raise MigrationRejected("E_C_STATEMENT", "Unused arithmetic expressions are unsupported")
            if rhs.side_effect and children[0].get("kind") != "DeclRefExpr":
                raise MigrationRejected("E_C_EVALUATION_ORDER", "Mutating call combined with aggregate assignment needs sequencing")
            if kind == "CompoundAssignOperator":
                result_type = self.typ(node.get("computeResultType", node["type"]))
                rhs = self.arithmetic(lhs, rhs, op[:-1], result_type)
            return [f"{pad}{lhs.text} = {cast(rhs, lhs.typ, c_conversion=True).text};"]
        if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"} and len(children) == 1:
            lhs = self.lvalue(children[0])
            # C promotes these operands to int for the arithmetic and then
            # converts back to the small signed destination.  Computing in
            # i8/i16 instead would trap where the captured compiler narrows.
            # This profile rejects unqualified signed narrowing elsewhere;
            # statement-form increments must obey the same admission rule.
            if lhs.typ in {"i8", "i16"}:
                raise MigrationRejected("E_C_SIGNED_CONVERSION",
                    "Small signed ++/-- requires integer promotion and unqualified signed narrowing")
            rhs = self.arithmetic(lhs, self._numeric("1", lhs.typ), "+" if node["opcode"] == "++" else "-", lhs.typ)
            return [f"{pad}{lhs.text} = {rhs.text};"]
        if kind == "CallExpr":
            return [pad + self.expr(node).text + ";"]
        raise MigrationRejected("E_C_STATEMENT", "Unsupported C statement: " + str(kind))

    def emit(self) -> tuple[str, str, list[dict]]:
        self.collect()
        from .c_allocation import allocation_names, call_name, lower_allocation, nodes
        # Conservative transitive allocation effects: this project profile is
        # hosted. Keeping the upper bound on every generated function avoids
        # hiding effects when a scalar helper calls an allocating function.
        for fn in self.functions.values():
            fn["allocates"] = any(name in {"malloc", "calloc", "realloc", "aligned_alloc"} for name in allocation_names(fn["body"]))
        changed = True
        while changed:
            changed = False
            for fn in self.functions.values():
                if fn["allocates"]:
                    continue
                for node in nodes(fn["body"]):
                    name = call_name(node)
                    target = self.functions.get(f"local_{fn['unit']}_{name}") or self.functions.get(name)
                    if target is not None and target["allocates"]:
                        fn["allocates"] = changed = True
                        break
        allocating_project = any(fn["allocates"] for fn in self.functions.values())
        effect_text = "alloc, block, panic, write" if allocating_project else "panic, write"
        pieces = ["module c_project_migrated;", "// Safe Hepta core. C ABI bridges carry separate caller obligations.",
                  "fn c_bool_to_int(value: bool) -> i32 effects {} { if value { return 1; } else { return 0; } }"]
        for name, fields in sorted(self.records.items()):
            pieces.append("repr(C) struct " + name + " { " + ", ".join(f"{field}: {typ}" for field, typ in fields) + ", }")
        reports = []
        for key, fn in sorted(self.functions.items()):
            self.current, self.bindings, self.binding_modes, self.counter = fn, {}, {}, 0
            from .c_definite_assignment import check_definite_assignment
            fn["definite_assignment"] = check_definite_assignment(fn, lambda data: self.typ(data) in NUMBER | {"bool"})
            parameters, entry = [], []
            for param in fn["params"]:
                pname = "p_" + param["name"]
                if param["pointer"]:
                    parameters.append(f"{pname}: {param['mode']} [{param['type']}]")
                    self.bindings[param["id"]] = Expression(pname, "slice:" + param["type"])
                    self.binding_modes[pname] = param["mode"]
                    length = "1" if type(param["length"]) is int else "p_" + param["length"]
                    entry.append(f"    assert(({length} as usize) <= len(read {pname}));")
                else:
                    parameters.append(f"{pname}: {param['type']}")
                    vname = "v_" + param["name"]
                    self.bindings[param["id"]] = Expression(vname, param["type"])
                    entry.append(f"    let mut {vname}: {param['type']} = {pname};")
            lines = lower_allocation(self, fn)
            if lines is None:
                from .c_aliases import lower_read_alias_prefix
                lines = self.stmt({**fn["body"], "inner": lower_read_alias_prefix(self, fn)})
            pieces.append(f"pub fn {fn['hepta_name']}({', '.join(parameters)}) -> {fn['return']} effects {{{effect_text}}} {{\n" + "\n".join(entry + lines) + "\n}")
            fn["inventory"].update(status="function_converted", reason=None)
            reports.append({k: v for k, v in fn.items() if k not in {"body", "node", "inventory", "model", "shape"}})
            reports[-1]["params"] = [{k: v for k, v in param.items() if k != "id"} for param in fn["params"]]
        source = "\n\n".join(pieces + self.expression_helpers) + "\n"
        return source, self.bridge(), reports

    @staticmethod
    def rust_type(typ: str) -> str:
        return "()" if typ == "Unit" else "H_" + typ if typ.startswith("C_") else typ

    def bridge(self) -> str:
        pieces = ["// Generated caller-unsafe C ABI bridge. NOT a proof of foreign pointer validity.",
                  "// SAFETY: nonempty buffers must be initialized, aligned, live within one allocation,",
                  "// stable throughout the call; a mutable slice additionally requires exclusive access.",
                  "// These are caller-supplied contracts and may narrow the original C input domain."]
        for index, fn in enumerate(sorted(self.functions.values(), key=lambda f: f["key"])):
            if not fn["external_symbol"]:
                continue
            params, body, args = [], [], []
            for param in fn["params"]:
                typ, name = self.rust_type(param["type"]), "b_" + param["name"]
                if not param["pointer"]:
                    params.append(f"{name}: {typ}")
                    args.append(name)
                    continue
                abi_type = "core::ffi::c_void" if param["c_void"] else typ
                params.append(f"{name}: *{'const' if param['c_const'] else 'mut'} {abi_type}")
                size = "1" if type(param["length"]) is int else "b_" + param["length"]
                body.append(f"    let n_{name} = {size} as usize;")
                body.append(f"    if n_{name} > (isize::MAX as usize) / core::mem::size_of::<{typ}>() {{ std::process::abort(); }}")
                body.append(f"    if n_{name} != 0 && ({name}.is_null() || ({name} as usize) % core::mem::align_of::<{typ}>() != 0) {{ std::process::abort(); }}")
                mutable = param["mode"] == "mut"
                method = "from_raw_parts_mut" if mutable else "from_raw_parts"
                empty = "&mut []" if mutable else "&[]"
                pointer = f"{name}.cast::<{typ}>()" if param["c_void"] else name
                body.append(f"    let s_{name} = if n_{name} == 0 {{ {empty} }} else {{ unsafe {{ core::slice::{method}({pointer}, n_{name}) }} }};")
                args.append("s_" + name)
            body.append(f"    h_{fn['hepta_name']}({', '.join(args)})")
            pieces.append(f"#[export_name = {json.dumps(fn['name'])}]\npub unsafe extern \"C\" fn __hepta_c_export_{index}({', '.join(params)}) -> {self.rust_type(fn['return'])} {{\n" + "\n".join(body) + "\n}")
        return "\n\n".join(pieces) + "\n"
