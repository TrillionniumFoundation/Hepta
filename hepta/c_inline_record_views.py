"""Explicit fixed inline byte arrays at a captured C ABI boundary.

This new profile leaves the existing pointer-record adapter and original C
admission gates intact. Its safe Hepta representation adds private constant
extent metadata; the original C ABI does not contain that metadata. The C
bridge passes byte storage without copying or initializing unused payload.
Foreign provenance, extent and concurrency remain caller obligations.
"""
from __future__ import annotations

import copy
import re

from .ast import Type
from .c_allocation import peel, literal
from .c_contracts import snapshot_contracts
from .c_migrate import MigrationRejected
from .c_record_views import CRecordViewTranslator
from .c_translation import CTranslator, NUMBER, _signature_shape, ident

SCHEMA = "hepta.c-inline-record-views.v1"


def snapshot_inline_contracts(value):
    # Reuse the bounded ordinary-JSON graph intake, then validate this separate
    # envelope. No shared schema or admission rule is changed by the extension.
    copied = snapshot_contracts({"schema": "hepta.c-contracts.v1", "functions": {"payload": value}})["functions"]["payload"]
    if (type(copied) is not dict or set(copied) != {"schema", "records", "functions"}
            or copied.get("schema") != SCHEMA or type(copied["records"]) is not dict
            or type(copied["functions"]) is not dict):
        raise MigrationRejected("E_C_INLINE_CONTRACT", "Expected exact inline-record contract envelope")
    return copied


class CInlineRecordViewTranslator(CRecordViewTranslator):
    """One inline byte array plus scalar state, with captured physical types."""

    def __init__(self, capture, contracts):
        original = snapshot_inline_contracts(contracts)
        converted = {"schema": "hepta.c-record-views.v1", "records": {}, "functions": {}}
        self.inline_arrays = {}
        self.function_options = {}
        for record, spec in original["records"].items():
            ident(record)
            if type(spec) is not dict or set(spec) != {"buffers"} or type(spec["buffers"]) is not dict or len(spec["buffers"]) != 1:
                raise MigrationRejected("E_C_INLINE_CONTRACT", "One explicitly sized inline buffer per record is required")
            self.inline_arrays[record] = {}
            converted["records"][record] = {"buffers": {}}
            for field, extent in spec["buffers"].items():
                ident(field)
                if (type(extent) is not dict or set(extent) != {"length"}
                        or type(extent["length"]) is not int or not 1 <= extent["length"] <= 65536):
                    raise MigrationRejected("E_C_INLINE_CONTRACT", "Inline byte-array length must be an explicit bounded positive integer")
                metadata = "hepta_inline_extent_" + field
                self.inline_arrays[record][field] = {"length": extent["length"], "metadata": metadata}
                converted["records"][record]["buffers"][field] = {"length_field": metadata, "add": 0}
        if not self.inline_arrays:
            raise MigrationRejected("E_C_INLINE_CONTRACT", "At least one captured inline record is required")
        for name, spec in original["functions"].items():
            ident(name)
            if (type(spec) is not dict or not {"records", "slices"} <= set(spec)
                    or set(spec) - {"records", "slices", "slice_extra", "scalar_initializer"}
                    or type(spec["records"]) is not dict or type(spec["slices"]) is not dict
                    or any(type(item) is not dict or set(item) != {"length", "access"}
                           for item in spec["slices"].values())):
                raise MigrationRejected("E_C_INLINE_CONTRACT", "Unsupported inline function contract fields")
            extras = spec.get("slice_extra", {})
            initializer = spec.get("scalar_initializer", False)
            if (type(extras) is not dict or any(type(v) is not int or v not in {0, 1} for v in extras.values())
                    or type(initializer) is not bool):
                raise MigrationRejected("E_C_INLINE_CONTRACT", "Slice extent increments and initializer flag must be explicit finite values")
            converted["functions"][name] = {"records": spec["records"], "slices": spec["slices"]}
            self.function_options[name] = {"slice_extra": extras, "scalar_initializer": initializer}
        super().__init__(capture, converted)
        self.inline_contracts = original
        self.abi_fields = {}
        self.c_field_spellings = {}

    def field_type(self, record, field):
        name = field.get("name")
        if name and name.startswith("hepta_inline_extent_"):
            raise MigrationRejected("E_C_INLINE_NAME", "Source field collides with private extent metadata")
        spec = self.inline_arrays.get(record, {}).get(name)
        if spec is None:
            return CTranslator.field_type(self, record, field)
        raw = field["type"].get("desugaredQualType", field["type"].get("qualType", ""))
        match = re.fullmatch(r"([^\[\]*]+?)\s*\[\s*([0-9]+)\s*\]", raw)
        if (not match or int(match[2]) != spec["length"]
                or re.search(r"\b(?:const|volatile|restrict|_Atomic)\b", raw)):
            raise MigrationRejected("E_C_INLINE_ARRAY", "Captured field must be the exact unqualified fixed inline array")
        element = self.typ(match[1].strip())
        if element not in {"i8", "u8"}:
            raise MigrationRejected("E_C_INLINE_ARRAY", "This profile supports inline byte elements only")
        spec.update(element=element, c_element=match[1].strip())
        self.views[record][name]["element"] = element
        return "view:" + element

    def signature(self, node, key, unit, model):
        # The shared capture/original-declarator gate still sees unmodified C.
        # Only the slice extent contract is adapted here to admit bounded u8/u16
        # lengths; their physical parameter types and arithmetic stay unchanged.
        name = node["name"]
        saved_contracts, saved_values = self.contracts, self.value_contracts
        contracts, values = copy.deepcopy(saved_contracts), copy.deepcopy(saved_values)
        contract = contracts["functions"].get(name)
        if contract is None:
            return super().signature(node, key, unit, model)
        params = {p.get("name"): p for p in node.get("inner", []) if p.get("kind") == "ParmVarDecl"}
        narrow = {}
        for selector, specification in contract["slices"].items():
            length = specification.get("length")
            if type(length) is str and length in params:
                typ = self.typ(params[length]["type"], model=model)
                if typ in {"u8", "u16"}:
                    narrow[selector] = length
                    contracts["functions"][name]["slices"][selector]["length"] = 1
                    values["functions"][name]["slices"][selector]["length"] = 1
        try:
            self.contracts, self.value_contracts = contracts, values
            result = super().signature(node, key, unit, model)
        finally:
            self.contracts, self.value_contracts = saved_contracts, saved_values
        options = self.function_options[name]
        used = set()
        for p in result["params"]:
            if p.get("pointer") and not p.get("record"):
                if p["contract_selector"] in narrow:
                    p["length"] = narrow[p["contract_selector"]]
                if p.get("c_void"):
                    raise MigrationRejected("E_C_INLINE_CONTRACT", "Inline profile does not admit void-pointer reinterpretation")
                selectors = [s for s in (p["name"], p["contract_selector"]) if s in options["slice_extra"]]
                selectors = list(dict.fromkeys(selectors))
                if len(selectors) > 1:
                    raise MigrationRejected("E_C_INLINE_CONTRACT", "Ambiguous extra extent selector")
                p["extent_add"] = options["slice_extra"].get(selectors[0], 0) if selectors else 0
                used.update(selectors)
                if p["extent_add"] and (p["mode"] != "mut" or type(p["length"]) is not str):
                    raise MigrationRejected("E_C_INLINE_CONTRACT", "Extra extent is only allowed for an explicit mutable length parameter")
        if used != set(options["slice_extra"]):
            raise MigrationRejected("E_C_INLINE_CONTRACT", "Extra extent names an absent slice")
        result["scalar_initializer"] = options["scalar_initializer"]
        result["shape"] = _signature_shape(result["return"], result["params"])
        return result

    def collect(self):
        CTranslator.collect(self)
        if set(self.record_nodes) != set(self.inline_arrays):
            raise MigrationRejected("E_C_INLINE_CONTRACT", "Every captured record must have an exact inline-array contract")
        for record, arrays in self.inline_arrays.items():
            key = "C_" + record
            fields = self.records[key]
            if any(not typ.startswith("view:") and typ not in NUMBER | {"bool"} for _, typ in fields):
                raise MigrationRejected("E_C_INLINE_FIELD", "Non-buffer record fields must be primitive scalar state")
            self.abi_fields[key] = list(fields)
            self.c_field_spellings[record] = {f["name"]:f["type"]["qualType"] for f in self.record_nodes[record]["inner"] if f.get("kind") == "FieldDecl"}
            for field, spec in arrays.items():
                if "element" not in spec or dict(fields).get("f_" + field) != "view:" + spec["element"]:
                    raise MigrationRejected("E_C_INLINE_ARRAY", "Contract did not bind a captured inline byte array")
                fields.append(("f_" + spec["metadata"], "usize"))
        for fn in self.functions.values():
            if fn.get("initializer"):
                raise MigrationRejected("E_C_INLINE_INITIALIZER", "Pointer-field initialization is not part of the inline profile")
            if fn["scalar_initializer"]:
                self._check_scalar_initializer(fn)

    def _check_scalar_initializer(self, fn):
        records = [p for p in fn["params"] if p.get("record")]
        if fn["return"] != "Unit" or len(fn["params"]) != 1 or len(records) != 1 or records[0]["mode"] != "mut":
            raise MigrationRejected("E_C_INLINE_INITIALIZER", "Scalar initialization requires one mutable record and void return")
        record = records[0]
        expected = {name[2:] for name, typ in self.abi_fields[record["type"]] if not typ.startswith("view:")}
        seen = set()
        for statement in fn["body"].get("inner", []):
            if statement.get("kind") != "BinaryOperator" or statement.get("opcode") != "=" or len(statement.get("inner", [])) != 2:
                raise MigrationRejected("E_C_INLINE_INITIALIZER", "Initializer must assign each scalar once without accessing payload")
            left, right = statement["inner"]
            base = peel(left.get("inner", [{}])[0])
            if (left.get("kind") != "MemberExpr" or not left.get("isArrow")
                    or base.get("referencedDecl", {}).get("id") != record["id"]
                    or left.get("name") not in expected or left["name"] in seen
                    or not literal(right, 0)):
                raise MigrationRejected("E_C_INLINE_INITIALIZER", "Initializer may only zero each scalar state field exactly once")
            seen.add(left["name"])
        if seen != expected:
            raise MigrationRejected("E_C_INLINE_INITIALIZER", "Initializer leaves scalar state undefined")

    def expr(self, node):
        if node.get("kind") == "ImplicitCastExpr" and node.get("castKind") == "ArrayToPointerDecay":
            inner = node.get("inner", [])
            if len(inner) != 1 or inner[0].get("kind") != "MemberExpr" or not inner[0].get("isArrow"):
                raise MigrationRejected("E_C_INLINE_DECAY", "Only a contracted inline record field may decay to a slice")
            result = super().expr(inner[0])
            if not result.typ.startswith("slice:"):
                raise MigrationRejected("E_C_INLINE_DECAY", "Array decay did not resolve to the contracted field")
            return result
        return super().expr(node)

    def bridge(self):
        # emit() retains the shared checked slice/body translation. A separate
        # backend-specific boundary is emitted only after frontend validation.
        return "// Inline-record bridge must be selected explicitly after checking.\n"

    def view_report(self):
        return {"schema": SCHEMA, "records": self.inline_arrays,
                "safe_representation": "scalar_state_plus_private_constant_extent_and_explicit_byte_slices",
                "original_abi": "unchanged_fixed_array_record_and_original_function_types",
                "unused_payload_initialized_or_copied": False,
                "caller_obligations": ["live record storage", "initialized scalar state after init", "initialized bytes actually read", "valid external slice extent including declared legacy extra write", "exclusive foreign mutation"],
                "runtime_checks": ["numeric pointer range/alignment", "mutable external overlap", "checked Hepta byte indices"],
                "not_inferred": ["allocation provenance", "actual foreign allocation size", "foreign concurrency"],
                "source_equivalence_proved": False, "whole_language_soundness_proved": False}

    def c_bridge(self, emitter, program):
        """A thin ABI projection; every ring algorithm remains in checked Hepta."""
        hepta_functions = {fn.name:fn for fn in program.functions}
        pieces = [r'''
/* Caller-unsafe C ABI; no byte payload is copied or initialized by this edge. */
typedef struct { uintptr_t lo, hi; } __hia_inline_range_t;
static __hia_inline_range_t __hia_inline_range(uintptr_t p, size_t n, size_t s, size_t a) {
    if ((n && (!p || p % a)) || n > (size_t)PTRDIFF_MAX / s || n > (UINTPTR_MAX - p) / s) abort();
    return (__hia_inline_range_t){p, p + n*s};
}
static void __hia_inline_disjoint(__hia_inline_range_t a, __hia_inline_range_t b) {
    if (a.lo < a.hi && b.lo < b.hi && a.lo < b.hi && b.lo < a.hi) abort();
}
''']
        for key, fields in sorted(self.abi_fields.items()):
            record = key[2:]
            declarations = []
            for field, typ in fields:
                original = field[2:]
                if typ.startswith("view:"):
                    spec = self.inline_arrays[record][original]
                    declarations.append(f"    {spec['c_element']} {original}[{spec['length']}];")
                else:
                    declarations.append(f"    {emitter.typ(Type(typ))} {original};")
            pieces.append(f"typedef struct {record} {{\n" + "\n".join(declarations) + f"\n}} {record};")
        declared = set(self.inline_arrays)
        for _, node, _ in self.declarations:
            if node.get("kind") == "TypedefDecl" and node["name"] not in declared:
                typ = self.aliases[node["name"]]
                if typ.startswith("C_"):
                    rhs = typ[2:]
                else:
                    rhs = emitter.typ(Type(typ))
                pieces.append(f"typedef {rhs} {ident(node['name'])};")
                declared.add(node["name"])
        for fn in sorted(self.functions.values(), key=lambda item:item["key"]):
            if not fn["external_symbol"]:
                continue
            target = hepta_functions[fn["hepta_name"]]
            original_params = [p for p in fn["node"]["inner"] if p.get("kind") == "ParmVarDecl"]
            parameters = [p["type"]["qualType"] + " b_" + ident(p["name"]) for p in original_params]
            result_type = fn["node"]["type"]["qualType"].split("(", 1)[0].strip()
            lines, arguments, finish, ranges = [], [], [], []
            for param in fn["params"]:
                name = "b_" + param["name"]
                if param.get("record"):
                    record = param["type"][2:]
                    lines.append(f"    __hia_inline_range_t r_{name} = __hia_inline_range((uintptr_t){name}, 1, sizeof({record}), _Alignof({record}));")
                    ranges.append(("r_" + name, param["mode"]))
                    values = []
                    for field, typ in self.abi_fields[param["type"]]:
                        if not typ.startswith("view:"):
                            value = "0" if fn["scalar_initializer"] else f"{name}->{field[2:]}"
                            values.append(f".h_{field} = {value}")
                            if param["mode"] == "mut":
                                finish.append(f"    {name}->{field[2:]} = s_{name}.h_{field};")
                    for field, spec in self.inline_arrays[record].items():
                        values.append(f".h_f_{spec['metadata']} = {spec['length']}")
                    lines.append(f"    {emitter.typ(Type(param['type']))} s_{name} = {{" + ", ".join(values) + "};")
                    arguments.append("&s_" + name)
                    for field, spec in self.inline_arrays[record].items():
                        slice_type = emitter.slice_type(Type("slice", (Type(spec["element"]),)), param["mode"])
                        element = emitter.typ(Type(spec["element"]))
                        arguments.append(f"({slice_type}){{({element} *){name}->{field}, {spec['length']}}}")
                elif param["pointer"]:
                    length = "1" if type(param["length"]) is int else f"(size_t)b_{param['length']}"
                    if param.get("extent_add"):
                        lines.append(f"    if ({length} == SIZE_MAX) abort();")
                        length = f"({length} + 1)"
                    lines.append(f"    size_t n_{name} = {length};")
                    element = emitter.typ(Type(param["type"]))
                    lines.append(f"    __hia_inline_range_t r_{name} = __hia_inline_range((uintptr_t){name}, n_{name}, sizeof({element}), _Alignof({element}));")
                    ranges.append(("r_" + name, param["mode"]))
                    slice_type = emitter.slice_type(Type("slice", (Type(param["type"]),)), param["mode"])
                    arguments.extend([f"({slice_type}){{({'const ' if param['mode']=='read' else ''}{element} *){name}, n_{name}}}", "0"])
                else:
                    arguments.append(name)
            for i, (left, left_mode) in enumerate(ranges):
                for right, right_mode in ranges[i + 1:]:
                    if "mut" in {left_mode, right_mode}:
                        lines.append(f"    __hia_inline_disjoint({left}, {right});")
            call = emitter.fn_name(target) + "(" + ", ".join(arguments) + ")"
            if fn["return"] == "Unit":
                lines.append("    (void)" + call + ";")
                lines.extend(finish); lines.append("    return;")
            else:
                lines.append(f"    {result_type} result = {call};")
                lines.extend(finish); lines.append("    return result;")
            pieces.append(result_type + " " + fn["name"] + "(" + ", ".join(parameters) + ") {\n" + "\n".join(lines) + "\n}")
        return "\n\n".join(pieces) + "\n"
