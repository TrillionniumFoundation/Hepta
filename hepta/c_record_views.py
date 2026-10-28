"""Checked decomposition of pointer-bearing C records into safe borrowed views.

The opt-in profile keeps the original C record ABI at an unsafe generated edge.
A safe Hepta function receives a scalar-only state record and explicit slices;
no raw pointer or stored reference enters the translated algorithm. Contracts
are caller obligations, not ownership/provenance inference. Unmodeled mutation,
pointer operations, attributes, globals and declarations still reject a bundle.
"""
from __future__ import annotations

import copy
import json
import re

from .c_allocation import peel, nodes
from .c_migrate import MigrationRejected
from .c_contracts import snapshot_contracts
from .c_translation import CTranslator, Expression, INTEGER, NUMBER, cast, ident, truth


class CRecordViewTranslator(CTranslator):
    allow_record_views = True

    def check_pointer_alias_profile(self, pointers):
        # This profile checks every mutable pair numerically before creating
        # any Rust references. Internal generated calls remain subject to the
        # ordinary Hepta borrow checker. The value-only C route retains its
        # stricter rejection, since it has no corresponding ABI range guards.
        pass

    def repeated_definition(self, previous, node, item):
        """Coalesce the same preprocessed inline header body across C units.

        Location identity alone is insufficient: different macro expansions
        at the same header offset can have different behavior. Require both
        source location and the complete AST after removing only Clang's
        per-invocation identities/positions and use-count annotations. Ordinary
        repeated external definitions, different headers and changed bodies
        still reject. Actual native export linkage is qualified separately.
        """
        old = previous["node"]
        if (not old.get("inline") or not node.get("inline")
                or old.get("storageClass") == "static" or node.get("storageClass") == "static"
                or previous["inventory"]["file"] != item["file"]
                or previous["inventory"]["offset"] != item["offset"]
                or previous["unit"] == item["unit"]):
            return False

        ignored = {"id", "loc", "range", "previousDecl", "typeAliasDeclId", "referencedMemberDecl",
                   "isUsed", "isReferenced"}

        def semantic(value):
            if isinstance(value, dict):
                return {key: semantic(child) for key, child in value.items()
                        if key not in ignored}
            if isinstance(value, list):
                return [semantic(child) for child in value]
            return value

        return semantic(old) == semantic(node)

    def __init__(self, capture: dict, contracts: dict):
        contracts = snapshot_contracts(contracts)
        if (set(contracts) != {"schema", "records", "functions"}
                or contracts.get("schema") != "hepta.c-record-views.v1"
                or not isinstance(contracts["records"], dict)
                or not isinstance(contracts["functions"], dict)):
            raise MigrationRejected("E_C_VIEW_CONTRACT", "Expected exact records/functions view contract")
        self.views = {}
        for name, specification in contracts["records"].items():
            ident(name)
            if not isinstance(specification, dict) or set(specification) != {"buffers"} or not isinstance(specification["buffers"], dict) or len(specification["buffers"]) != 1:
                raise MigrationRejected("E_C_VIEW_CONTRACT", "Each record view currently requires exactly one buffer field")
            fields = {}
            for field, extent in specification["buffers"].items():
                ident(field)
                if not isinstance(extent, dict) or set(extent) != {"length_field", "add"} or not isinstance(extent["length_field"], str) or type(extent["add"]) is not int or extent["add"] not in {0, 1}:
                    raise MigrationRejected("E_C_VIEW_CONTRACT", "Buffer extent must be an unsigned record field plus zero or one")
                ident(extent["length_field"])
                fields[field] = dict(extent)
            self.views[name] = fields
        if not self.views:
            raise MigrationRejected("E_C_VIEW_CONTRACT", "At least one record view is required")
        value_functions = {}
        for name, specification in contracts["functions"].items():
            ident(name)
            if not isinstance(specification, dict) or set(specification) != {"slices", "records"} or not isinstance(specification["records"], dict):
                raise MigrationRejected("E_C_VIEW_CONTRACT", "Each function requires exact slices/records maps")
            value_functions[name] = {"slices": specification["slices"]}
        self.value_contracts = {"schema": "hepta.c-contracts.v1", "functions": value_functions}
        super().__init__(capture, self.value_contracts)
        self.contracts = contracts
        self.slice_bindings = {}
        self.record_bindings = {}
        self.pending_locals = {}
        self.initialized_fields = set()
        self.initializer_pointer_fields = set()

    def field_type(self, record: str, field: dict) -> str:
        name = field.get("name")
        specification = self.views.get(record, {}).get(name)
        if specification is None:
            return super().field_type(record, field)
        raw = field["type"].get("desugaredQualType", field["type"].get("qualType", ""))
        pointer = re.fullmatch(r"([^*]+?)\s*\*", raw)
        if pointer is None or re.search(r"\b(?:const|volatile|restrict|_Atomic)\b", raw):
            raise MigrationRejected("E_C_VIEW_FIELD", "Record buffers require one unqualified primitive pointer")
        element = self.typ(pointer[1])
        if element not in NUMBER:
            raise MigrationRejected("E_C_VIEW_FIELD", "Record buffer elements must be primitive numeric values")
        specification["element"] = element
        return "view:" + element

    def collect(self):
        super().collect()
        if set(self.views) - set(self.record_nodes):
            raise MigrationRejected("E_C_VIEW_CONTRACT", "Record contract names an absent record")
        for record, buffers in self.views.items():
            fields = dict(self.records["C_" + record])
            if any(not typ.startswith("view:") and typ not in NUMBER | {"bool"} for typ in fields.values()):
                raise MigrationRejected("E_C_VIEW_FIELD", "Record-view state fields must be primitive scalars")
            for name, specification in buffers.items():
                if "element" not in specification or fields.get("f_" + specification["length_field"]) not in {"usize", "u64", "u32"}:
                    raise MigrationRejected("E_C_VIEW_FIELD", "Every buffer field and unsigned length field must exist in the captured record")
        if set(self.record_nodes) != set(self.views):
            raise MigrationRejected("E_C_VIEW_CONTRACT", "Every record declaration in a view-profile module needs an explicit view contract")
        for fn in self.functions.values():
            if fn["initializer"]:
                self._validate_initializer(fn)

    def signature(self, node, key, unit, model):
        name = node["name"]
        contract = self.contracts["functions"].get(name)
        if contract is None:
            raise MigrationRejected("E_C_VIEW_CONTRACT", "Every view-profile function needs an explicit complete contract")
        value_node = copy.deepcopy(node)
        record_parameters = {}
        used = set()
        ordinal = 0
        for child in value_node.get("inner", []):
            if child.get("kind") != "ParmVarDecl":
                continue
            raw = child["type"].get("qualType", "")
            pointer = re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", raw)
            record_type = None
            if pointer:
                try:
                    record_type = self.typ(pointer[2], model=model)
                except MigrationRejected:
                    pass
            if record_type and record_type.startswith("C_") and record_type[2:] in self.views:
                pname = child.get("name", "")
                selectors = [selector for selector in (pname, str(ordinal)) if selector in contract["records"]]
                if len(selectors) != 1:
                    raise MigrationRejected("E_C_VIEW_CONTRACT", "Record pointer needs exactly one name or ordinal contract")
                selector = selectors[0]
                used.add(selector)
                spec = contract["records"][selector]
                if not isinstance(spec, dict) or set(spec) not in ({"access"}, {"access", "initialize"}) or spec.get("access") not in {"read", "mut"}:
                    raise MigrationRejected("E_C_VIEW_CONTRACT", "Record contract requires read/mut access and optional initialize map")
                if pointer[1] and spec["access"] == "mut":
                    raise MigrationRejected("E_C_VIEW_CONTRACT", "const record cannot become mutable")
                init = spec.get("initialize")
                if init is not None and (spec["access"] != "mut" or not isinstance(init, dict) or set(init) != set(self.views[record_type[2:]]) or not all(isinstance(value, str) for value in init.values())):
                    raise MigrationRejected("E_C_VIEW_CONTRACT", "Initializer must map every pointer field to an explicit slice parameter")
                record_parameters[ordinal] = (record_type, spec, bool(pointer[1]))
                child["type"] = {"qualType": pointer[2]}
            ordinal += 1
        if set(contract["records"]) != used or len(record_parameters) > 1:
            raise MigrationRejected("E_C_VIEW_CONTRACT", "This profile supports at most one fully contracted record parameter per function")
        original_contract = self.contracts
        try:
            self.contracts = self.value_contracts
            result = super().signature(value_node, key, unit, model)
        finally:
            self.contracts = original_contract
        if result["return"].startswith("C_") or any(p["type"].startswith("C_") and index not in record_parameters for index, p in enumerate(result["params"])):
            raise MigrationRejected("E_C_VIEW_VALUE_ABI", "Pointer-bearing records cannot cross by-value ABI boundaries after view decomposition")
        result["initializer"] = False
        for index, (typ, spec, const) in record_parameters.items():
            param = result["params"][index]
            param.update(pointer=True, record=True, type=typ, mode=spec["access"], c_const=const,
                         initialize=spec.get("initialize"))
            if spec.get("initialize") is not None:
                result["initializer"] = True
                params_by_name = {p["name"]: p for p in result["params"]}
                for field, source in spec["initialize"].items():
                    source_param = params_by_name.get(source)
                    if source_param is None or not source_param["pointer"] or source_param.get("record") or source_param["mode"] != "mut" or source_param["type"] != self.views[typ[2:]][field].get("element"):
                        raise MigrationRejected("E_C_VIEW_INIT", "Initializer buffer source must be a compatible mutable slice parameter")
        result["shape"] = (result["return"], [(p["type"], p["pointer"], p["mode"], p.get("c_const"), p.get("c_void"), p.get("initialize")) for p in result["params"]])
        generated = []
        for param in result["params"]:
            name = "p_" + param["name"]
            generated.append(name)
            if param.get("record") and param.get("initialize") is None:
                generated.extend(name + "_f_" + field for field in self.views[param["type"][2:]])
            elif param["pointer"] and not param.get("record"):
                generated.append(name + "_offset")
        if len(generated) != len(set(generated)):
            raise MigrationRejected("E_C_VIEW_NAME", "C parameter names collide with generated record-view or cursor bindings")
        return result

    def _validate_initializer(self, fn):
        if fn["return"] != "Unit":
            raise MigrationRejected("E_C_VIEW_INIT", "Record initialization must have void return and complete straight-line writes")
        record = next(p for p in fn["params"] if p.get("initialize") is not None)
        assigned = set()
        fields = {name[2:] for name, _ in self.records[record["type"]]}
        for statement in fn["body"].get("inner", []):
            if self._void_noop(statement):
                continue
            if statement.get("kind") != "BinaryOperator" or statement.get("opcode") != "=" or len(statement.get("inner", [])) != 2:
                raise MigrationRejected("E_C_VIEW_INIT", "Initializer accepts only one assignment to every record field; assertions must remain in the captured build configuration")
            left, right = statement["inner"]
            base = peel(left.get("inner", [{}])[0])
            if left.get("kind") != "MemberExpr" or not left.get("isArrow") or base.get("referencedDecl", {}).get("id") != record["id"] or left.get("name") in assigned:
                raise MigrationRejected("E_C_VIEW_INIT", "Initializer must assign each target field exactly once")
            if any(n.get("referencedDecl", {}).get("id") == record["id"] for n in nodes(right)):
                raise MigrationRejected("E_C_VIEW_INIT", "Initializer cannot read possibly uninitialized record storage")
            field = left["name"]
            if field in record["initialize"]:
                source = peel(right).get("referencedDecl", {})
                expected = next(p for p in fn["params"] if p["name"] == record["initialize"][field])
                if source.get("id") != expected["id"]:
                    raise MigrationRejected("E_C_VIEW_INIT", "Pointer initialization differs from its declared unchanged slice parameter")
            assigned.add(field)
        if assigned != fields:
            raise MigrationRejected("E_C_VIEW_INIT", "Initializer does not fully initialize every declared field")

    @staticmethod
    def _void_noop(node):
        node = peel(node)
        return node.get("kind") == "CStyleCastExpr" and node.get("castKind") == "ToVoid" and len(node.get("inner", [])) == 1 and peel(node["inner"][0]).get("kind") == "IntegerLiteral"

    def _slice(self, value):
        info = self.slice_bindings.get(value.text)
        if not value.typ.startswith("slice:") or info is None:
            raise MigrationRejected("E_C_VIEW_CURSOR", "Pointer must be a tracked parameter, record buffer or local cursor")
        return info

    def _member(self, node):
        base = self.expr(node["inner"][0])
        parameter = self.record_bindings.get(base.text)
        if parameter is None:
            raise MigrationRejected("E_C_VIEW_RECORD", "Arrow operation needs a contracted record parameter")
        return base, parameter

    def expr(self, node):
        kind, children = node.get("kind"), node.get("inner", [])
        if kind == "MemberExpr" and node.get("isArrow") and len(children) == 1:
            base, param = self._member(node)
            field = "f_" + ident(node["name"])
            typ = dict(self.records[param["type"]]).get(field)
            if typ is None:
                raise MigrationRejected("E_C_VIEW_RECORD", "Unknown record field")
            if typ.startswith("view:"):
                if param.get("initialize") is not None:
                    raise MigrationRejected("E_C_VIEW_INIT", "Initializer cannot read its old buffer field")
                return Expression(base.text + "_" + field, "slice:" + typ[5:])
            return Expression(base.text + "." + field, typ)
        if kind == "ArraySubscriptExpr" and len(children) == 2:
            base, index = self.expr(children[0]), self.expr(children[1])
            info = self._slice(base)
            if index.typ not in INTEGER or index.side_effect:
                raise MigrationRejected("E_C_VIEW_CURSOR", "Cursor index must be a pure integer")
            # C indexes are relative to the cursor, and a negative signed
            # index can still identify a live earlier element in this view.
            # All accepted C integers are at most 64 bits. Widen *before*
            # adding, then check the absolute position before narrowing.
            return Expression(f"{info['base']}[c_view_index({info['offset']}, ({index.text} as i128), len(read {info['base']}))]", base.typ[6:])
        if kind == "UnaryOperator" and node.get("opcode") == "*" and len(children) == 1:
            value = self.expr(children[0])
            info = self._slice(value)
            return Expression(f"{info['base']}[{info['offset']}]", value.typ[6:])
        if kind == "BinaryOperator" and node.get("opcode") in {"&&", "||"} and len(children) == 2:
            lhs, rhs = truth(self.expr(children[0])), truth(self.expr(children[1]))
            return Expression(f"({lhs.text} {node['opcode']} {rhs.text})", "bool", lhs.side_effect or rhs.side_effect)
        if kind == "CallExpr" and children:
            ref = peel(children[0]).get("referencedDecl", {})
            target = self.functions.get(f"local_{self.current['unit']}_{ref.get('name')}") or self.functions.get(ref.get("name"))
            if ref.get("kind") != "FunctionDecl" or target is None or len(children) - 1 != len(target["params"]) or target["initializer"]:
                raise MigrationRejected("E_C_CALL", "Only captured non-initializing direct calls are allowed in view-profile bodies")
            arguments = []
            for child, parameter in zip(children[1:], target["params"]):
                value = self.expr(child)
                if value.side_effect:
                    raise MigrationRejected("E_C_EVALUATION_ORDER", "Nested mutating call arguments require explicit sequencing")
                if parameter.get("record"):
                    source = self.record_bindings.get(value.text)
                    if source is None or source["type"] != parameter["type"] or (parameter["mode"] == "mut" and source["mode"] != "mut"):
                        raise MigrationRejected("E_C_READ_ONLY", "Record call requires a compatible unchanged borrowed record")
                    arguments.append(parameter["mode"] + " " + value.text)
                    for field in self.views[parameter["type"][2:]]:
                        arguments.append(parameter["mode"] + " " + value.text + "_f_" + field)
                elif parameter["pointer"]:
                    info = self._slice(value)
                    if value.typ != "slice:" + parameter["type"] or parameter["mode"] == "mut" and info["mode"] != "mut":
                        raise MigrationRejected("E_C_READ_ONLY", "Cannot mutate or reinterpret a borrowed slice")
                    arguments.extend([parameter["mode"] + " " + info["base"], info["offset"]])
                else:
                    arguments.append(cast(value, parameter["type"]).text)
            side = any(p["mode"] == "mut" for p in target["params"])
            return Expression(target["hepta_name"] + "(" + ", ".join(arguments) + ")", target["return"], side)
        return super().expr(node)

    def lvalue(self, node):
        if node.get("kind") == "MemberExpr" and node.get("isArrow"):
            _, parameter = self._member(node)
            if parameter["mode"] != "mut":
                raise MigrationRejected("E_C_READ_ONLY", "Read-only record view cannot be written")
            if parameter.get("initialize") is None and node.get("name") in {spec["length_field"] for spec in self.views[parameter["type"][2:]].values()}:
                raise MigrationRejected("E_C_VIEW_EXTENT_WRITE", "Buffer extent fields are immutable outside complete initialization")
            result = self.expr(node)
            if result.typ.startswith("slice:"):
                raise MigrationRejected("E_C_VIEW_POINTER_WRITE", "Record pointer fields can only be written by their complete initializer")
            return result
        if node.get("kind") == "ArraySubscriptExpr" or node.get("kind") == "UnaryOperator" and node.get("opcode") == "*":
            info = self._slice(self.expr(node["inner"][0]))
            if info["mode"] != "mut":
                raise MigrationRejected("E_C_READ_ONLY", "Cannot write a read-only cursor")
            return self.expr(node)
        return super().lvalue(node)

    def stmt(self, node, depth=1):
        kind, children = node.get("kind"), node.get("inner", [])
        pad = "    " * depth
        if self._void_noop(node):
            return []
        if kind == "DeclStmt":
            lines = []
            for child in children:
                if child.get("kind") != "VarDecl" or child.get("storageClass"):
                    raise MigrationRejected("E_C_LOCAL", "Only ordinary automatic locals are supported")
                raw = child.get("type", {}).get("qualType", "")
                if "*" in raw:
                    if len(child.get("inner", [])) != 1:
                        raise MigrationRejected("E_C_VIEW_CURSOR", "A local cursor requires an unchanged slice initializer")
                    source = self.expr(child["inner"][0])
                    info = self._slice(source)
                    # Use the original cast/type checker to prevent element reinterpretation.
                    pointer = re.fullmatch(r"(const\s+)?([^*]+?)\s*\*", raw)
                    if pointer is None or self.typ(pointer[2]) != source.typ[6:]:
                        raise MigrationRejected("E_C_VIEW_CURSOR", "Cursor element type differs from its borrowed storage")
                    self.counter += 1
                    name = "cursor_" + ident(child["name"]) + "_" + str(self.counter)
                    offset = name + "_offset"
                    lines.append(f"{pad}let mut {offset}: usize = {info['offset']};")
                    self.bindings[child["id"]] = Expression(name, source.typ)
                    self.slice_bindings[name] = dict(info, offset=offset, local=True)
                elif not child.get("inner"):
                    self.pending_locals[child["id"]] = (child, depth)
                else:
                    lines.extend(super().stmt(dict(node, inner=[child]), depth))
            return lines
        if kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
            left, right = children
            ref = left.get("referencedDecl", {})
            if ref.get("id") in self.pending_locals:
                child, declared_depth = self.pending_locals.pop(ref["id"])
                if declared_depth != depth:
                    raise MigrationRejected("E_C_LOCAL", "Uninitialized scalar must receive its first assignment unconditionally in the same scope")
                return super().stmt({"kind": "DeclStmt", "inner": [dict(child, inner=[right])]}, depth)
            if self.current["initializer"] and left.get("kind") == "MemberExpr" and left.get("name") in next(p for p in self.current["params"] if p.get("initialize") is not None)["initialize"]:
                return []  # Fully checked structural initialization; the ABI edge stores the original pointer.
        if kind == "UnaryOperator" and node.get("opcode") == "++" and len(children) == 1:
            value = self.expr(children[0])
            if value.typ.startswith("slice:"):
                info = self._slice(value)
                if not info.get("local"):
                    raise MigrationRejected("E_C_VIEW_CURSOR", "Only explicit local slice cursors may advance")
                return [f"{pad}{info['offset']} = {info['offset']} + (1 as usize);",
                        f"{pad}assert({info['offset']} <= len(read {info['base']}));"]
        if kind in {"IfStmt", "WhileStmt"}:
            if len(children) not in ({2, 3} if kind == "IfStmt" else {2}):
                raise MigrationRejected("E_C_CONTROL", "Unexpected conditional AST")
            condition = truth(self.expr(children[0]))
            out = [f"{pad}{'if' if kind == 'IfStmt' else 'while'} {condition.text} {{", *self.stmt(children[1], depth + 1), pad + "}"]
            if len(children) == 3:
                out += [pad + "else {", *self.stmt(children[2], depth + 1), pad + "}"]
            return out
        return super().stmt(node, depth)

    def emit(self):
        self.collect()
        pieces = ["module c_record_views_migrated;",
                  "// Scalar state plus explicit slices; foreign record/storage contracts remain external.",
                  "fn c_bool_to_int(value: bool) -> i32 effects {} { if value { return 1; } else { return 0; } }",
                  "fn c_view_index(offset: usize, index: i128, length: usize) -> usize effects {panic} {\n"
                  "    let absolute: i128 = (offset as i128) + index;\n"
                  "    assert(absolute >= 0);\n"
                  "    assert(absolute < (length as i128));\n"
                  "    return absolute as usize;\n}"]
        for name, fields in sorted(self.records.items()):
            scalars = [(field, typ) for field, typ in fields if not typ.startswith("view:")]
            if not scalars:
                raise MigrationRejected("E_C_VIEW_RECORD", "A record view requires nonempty scalar state")
            pieces.append("pub struct " + name + " { " + ", ".join(f"{field}: {typ}" for field, typ in scalars) + ", }")
        reports = []
        for _, fn in sorted(self.functions.items()):
            self.current, self.bindings, self.binding_modes, self.counter = fn, {}, {}, 0
            self.slice_bindings, self.record_bindings, self.pending_locals = {}, {}, {}
            parameters, entry = [], []
            for param in fn["params"]:
                pname = "p_" + param["name"]
                if param.get("record"):
                    parameters.append(f"{pname}: {param['mode']} {param['type']}")
                    self.bindings[param["id"]] = Expression(pname, "record:" + param["type"])
                    self.record_bindings[pname] = param
                    if param.get("initialize") is None:
                        for field, specification in self.views[param["type"][2:]].items():
                            bname = pname + "_f_" + field
                            parameters.append(f"{bname}: {param['mode']} [{specification['element']}]")
                            self.slice_bindings[bname] = {"base": bname, "offset": "(0 as usize)", "mode": param["mode"]}
                            extent = f"({pname}.f_{specification['length_field']} as usize)"
                            if specification["add"]:
                                extent = "(" + extent + " + (1 as usize))"
                            entry.append(f"    assert({extent} <= len(read {bname}));")
                elif param["pointer"]:
                    parameters.extend([f"{pname}: {param['mode']} [{param['type']}]", f"{pname}_offset: usize"])
                    self.bindings[param["id"]] = Expression(pname, "slice:" + param["type"])
                    self.slice_bindings[pname] = {"base": pname, "offset": pname + "_offset", "mode": param["mode"]}
                    length = "(1 as usize)" if type(param["length"]) is int else "(p_" + param["length"] + " as usize)"
                    entry.extend([f"    assert({pname}_offset <= len(read {pname}));",
                                  f"    assert({length} <= (len(read {pname}) - {pname}_offset));"])
                else:
                    parameters.append(f"{pname}: {param['type']}")
                    vname = "v_" + param["name"]
                    self.bindings[param["id"]] = Expression(vname, param["type"])
                    entry.append(f"    let mut {vname}: {param['type']} = {pname};")
            lines = self.stmt(fn["body"])
            if fn["initializer"]:
                record = next(p for p in fn["params"] if p.get("initialize") is not None)
                for field, specification in self.views[record["type"][2:]].items():
                    source = "p_" + record["initialize"][field]
                    extent = f"(p_{record['name']}.f_{specification['length_field']} as usize)"
                    if specification["add"]:
                        extent = "(" + extent + " + (1 as usize))"
                    lines.append(f"    assert({extent} <= (len(read {source}) - {source}_offset));")
            pieces.append(f"pub fn {fn['hepta_name']}({', '.join(parameters)}) -> {fn['return']} effects {{panic, write}} {{\n" + "\n".join(entry + lines) + "\n}")
            fn["inventory"].update(status="function_converted", reason=None)
            reports.append({k: v for k, v in fn.items() if k not in {"body", "node", "inventory", "model", "shape"}})
            reports[-1]["params"] = [{k: v for k, v in p.items() if k != "id"} for p in fn["params"]]
        return "\n\n".join(pieces) + "\n", self.bridge(), reports

    def bridge(self):
        pieces = ["// Caller-unsafe original C ABI. Initialized live disjoint storage is an external obligation.",
                  "// Numeric interval checks reject overlap; they do not prove provenance or allocation extent.",
                  "fn __hepta_view_range(address: usize, count: usize, size: usize, align: usize) -> (usize, usize) {\n"
                  "    if count > (isize::MAX as usize) / size || count != 0 && (address == 0 || address % align != 0) { std::process::abort(); }\n"
                  "    let bytes = count.checked_mul(size).unwrap_or_else(|| std::process::abort());\n"
                  "    (address, address.checked_add(bytes).unwrap_or_else(|| std::process::abort()))\n}",
                  "fn __hepta_view_disjoint(a: (usize, usize), b: (usize, usize)) {\n"
                  "    if a.0 < a.1 && b.0 < b.1 && a.0 < b.1 && b.0 < a.1 { std::process::abort(); }\n}"]
        for name, fields in sorted(self.records.items()):
            lines = []
            for field, typ in fields:
                rt = "*mut " + typ[5:] if typ.startswith("view:") else self.rust_type(typ)
                lines.append(f"    {field}: {rt},")
            pieces.append("#[repr(C)]\n#[derive(Clone, Copy)]\npub struct __HeptaAbi_" + name + " {\n" + "\n".join(lines) + "\n}")
        for index, fn in enumerate(sorted(self.functions.values(), key=lambda f: f["key"])):
            if not fn["external_symbol"]:
                continue
            params, prelude, borrows, args, finish, ranges = [], [], [], [], [], []
            for param in fn["params"]:
                name, typ = "b_" + param["name"], self.rust_type(param["type"])
                if param.get("record"):
                    abi = "__HeptaAbi_" + param["type"]
                    params.append(f"{name}: *{'const' if param['c_const'] else 'mut'} {abi}")
                    prelude.append(f"    let r_{name} = __hepta_view_range({name} as usize, 1, core::mem::size_of::<{abi}>(), core::mem::align_of::<{abi}>());")
                    ranges.append(("r_" + name, param["mode"]))
                    initial = param.get("initialize") is not None
                    if not initial:
                        prelude.append(f"    let a_{name} = unsafe {{ {name}.read() }};")
                    scalars = [(f, t) for f, t in self.records[param["type"]] if not t.startswith("view:")]
                    values = ", ".join(f"h_{field}: " + (("false" if field_type == "bool" else "0.0" if field_type in {"f32", "f64"} else "0") if initial else f"a_{name}.{field}") for field, field_type in scalars)
                    prelude.append(f"    let mut s_{name} = {typ} {{ {values} }};")
                    args.append(("&mut " if param["mode"] == "mut" else "&") + "s_" + name)
                    pointer_values = {}
                    for field, spec in self.views[param["type"][2:]].items():
                        if initial:
                            pointer_values["f_" + field] = "b_" + param["initialize"][field]
                            continue
                        bname = name + "_f_" + field
                        expression = f"(a_{name}.f_{spec['length_field']} as usize)"
                        if spec["add"]:
                            expression += ".checked_add(1).unwrap_or_else(|| std::process::abort())"
                        prelude.append(f"    let n_{bname} = {expression};")
                        prelude.append(f"    let p_{bname} = a_{name}.f_{field};")
                        self._bridge_slice(bname, "p_" + bname, "n_" + bname, spec["element"], param["mode"], prelude, borrows, ranges)
                        args.append("s_" + bname)
                        pointer_values["f_" + field] = f"a_{name}.f_{field}"
                    if param["mode"] == "mut":
                        values = ", ".join(f"{field}: " + (pointer_values[field] if field in pointer_values else f"s_{name}.h_{field}") for field, _ in self.records[param["type"]])
                        finish.append(f"    unsafe {{ {name}.write({abi} {{ {values} }}); }}")
                elif param["pointer"]:
                    abi_type = "core::ffi::c_void" if param.get("c_void") else typ
                    params.append(f"{name}: *{'const' if param['c_const'] else 'mut'} {abi_type}")
                    size = "1" if type(param["length"]) is int else "b_" + param["length"] + " as usize"
                    prelude.append(f"    let n_{name} = {size};")
                    pointer = f"{name}.cast::<{typ}>()" if param.get("c_void") else name
                    self._bridge_slice(name, pointer, "n_" + name, typ, param["mode"], prelude, borrows, ranges)
                    args.extend(["s_" + name, "0"])
                else:
                    params.append(f"{name}: {typ}")
                    args.append(name)
            for i, (left, left_mode) in enumerate(ranges):
                for right, right_mode in ranges[i + 1:]:
                    if "mut" in {left_mode, right_mode}:
                        prelude.append(f"    __hepta_view_disjoint({left}, {right});")
            body = prelude + borrows + [f"    let result = h_{fn['hepta_name']}({', '.join(args)});"] + finish + ["    result"]
            pieces.append(f"#[export_name = {json.dumps(fn['name'])}]\npub unsafe extern \"C\" fn __hepta_c_view_export_{index}({', '.join(params)}) -> {self.rust_type(fn['return'])} {{\n" + "\n".join(body) + "\n}")
        return "\n\n".join(pieces) + "\n"

    @staticmethod
    def _bridge_slice(name, pointer, length, typ, mode, prelude, borrows, ranges):
        prelude.append(f"    let r_{name} = __hepta_view_range({pointer} as usize, {length}, core::mem::size_of::<{typ}>(), core::mem::align_of::<{typ}>());")
        ranges.append(("r_" + name, mode))
        method = "from_raw_parts_mut" if mode == "mut" else "from_raw_parts"
        empty = "&mut []" if mode == "mut" else "&[]"
        borrows.append(f"    let s_{name} = if {length} == 0 {{ {empty} }} else {{ unsafe {{ core::slice::{method}({pointer}, {length}) }} }};")

    def view_report(self):
        return {"schema": "hepta.c-record-view-report.v1", "records": self.views,
                "safe_core": "scalar_records_plus_explicit_borrowed_slices_no_raw_pointers",
                "original_record_abi": "generated_repr_C_caller_unsafe_bridge",
                "runtime_checks": ["non-null/alignment/representable length", "numeric mutable storage non-overlap", "cursor and element bounds"],
                "remaining_obligations": ["initialized live record and complete buffer storage", "pointer provenance and allocation extent", "foreign concurrency exclusion", "record extent field validity", "captured build configuration only"],
                "allocation_inference": False, "ownership_inference": False,
                "stored_references_added_to_language": False, "source_equivalence_proved": False}
