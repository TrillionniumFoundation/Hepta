"""Finite Drop composition decisions derived from independently verified Resource IR types.

No AST parser, borrow checker or new LLVM backend. The caller MUST pass the
exact type table of a successfully checked *source-derived* Resource IR graph.
A missing concrete generic instantiation is reported, never guessed by this
adapter. This is a partial Drop helper consumer, not executable owned SSA.
"""
from __future__ import annotations

from dataclasses import dataclass

from .resource_ir import _SCALARS


class DropPlanRejected(ValueError):
    """A reviewed Resource IR type table cannot describe this native Drop."""


def _validate_resource_shape(key: str, info: object) -> None:
    """Check exact known Resource IR type descriptors before native Drop use.

    This is defense in depth; it is not a substitute for the independent
    source-derived Resource IR verifier or a proof of native refinement.
    """
    if type(key) is not str or type(info) is not dict or type(info.get("kind")) is not str:
        raise DropPlanRejected("E_DROP_PLAN: malformed type descriptor")
    kind = info["kind"]
    if kind == "scalar":
        if set(info) != {"kind", "name"} or info["name"] != key or key not in _SCALARS:
            raise DropPlanRejected("E_DROP_PLAN: forged scalar type identity")
    elif kind == "buffer":
        if set(info) != {"kind", "element"} or key != "Buffer<u8>" or info["element"] != "u8":
            raise DropPlanRejected("E_DROP_PLAN: invalid owned buffer type")
    elif kind == "parameter":
        if (set(info) != {"kind", "function", "name", "bound"}
                or type(info["function"]) is not str or type(info["name"]) is not str
                or key != "@" + info["function"] + "::" + info["name"]
                or info["bound"] not in {"Copy", "Owned"}):
            raise DropPlanRejected("E_DROP_PLAN: generic resource identity mismatch")
    elif kind in {"array", "slice"}:
        expected = {"kind", "element"} | ({"length"} if kind == "array" else set())
        if set(info) != expected or type(info["element"]) is not str:
            raise DropPlanRejected("E_DROP_PLAN: malformed sequence type")
        if kind == "array":
            size = info["length"]
            if type(size) is not int or not 0 <= size <= 2**32 or key != f"[{info['element']}; {size}]":
                raise DropPlanRejected("E_DROP_PLAN: array type identity mismatch")
        elif key != f"[{info['element']}]":
            raise DropPlanRejected("E_DROP_PLAN: slice type identity mismatch")
    elif kind in {"struct", "enum"}:
        member_key = "fields" if kind == "struct" else "variants"
        if (set(info) != {"kind", "name", "args", member_key}
                or type(info["name"]) is not str or type(info["args"]) is not list
                or not all(type(arg) is str for arg in info["args"])
                or key != info["name"] + ("<" + ", ".join(info["args"]) + ">" if info["args"] else "")):
            raise DropPlanRejected("E_DROP_PLAN: nominal type identity mismatch")
        members = info[member_key]
        if type(members) is not list or len(members) > 128:
            raise DropPlanRejected("E_DROP_PLAN: aggregate exceeds finite layout")
        seen = set()
        for member in members:
            expected = {"name", "type"} if kind == "struct" else {"name", "fields"}
            if (type(member) is not dict or set(member) != expected
                    or type(member["name"]) is not str or not member["name"]
                    or member["name"] in seen):
                raise DropPlanRejected("E_DROP_PLAN: malformed/duplicate aggregate field")
            seen.add(member["name"])
            if kind == "struct":
                if type(member["type"]) is not str:
                    raise DropPlanRejected("E_DROP_PLAN: malformed struct type")
            elif (type(member["fields"]) is not list or len(member["fields"]) > 128
                  or not all(type(field) is str for field in member["fields"])):
                raise DropPlanRejected("E_DROP_PLAN: malformed enum payload")
    else:
        raise DropPlanRejected("E_DROP_PLAN: unsupported native resource kind " + kind)


@dataclass(frozen=True)
class DropPlan:
    kind: str
    fields: tuple[tuple[str, str, bool], ...] = ()
    variants: tuple[tuple[str, tuple[tuple[str, bool], ...]], ...] = ()


def derive_resource_drop_plan(types: dict, type_key: str) -> DropPlan | None:
    """Return typed child-drop decisions, or None for an absent instantiation.

    Every present Resource IR type is independently verified before this
    consumer is invoked. Locally rechecking the finite closed shape protects
    the helper from accidental invocation on a fabricated partial type table.
    """
    if type(types) is not dict or type(type_key) is not str or not type_key:
        raise DropPlanRejected("E_DROP_PLAN: invalid type inventory or identity")
    if len(types) > 4096:
        raise DropPlanRejected("E_DROP_PLAN: Resource IR type inventory exceeds budget")
    if type_key not in types:
        return None
    active: set[str] = set()
    cached: dict[str, bool] = {}

    def owns(key: str, depth: int = 0) -> bool:
        if type(key) is not str or key not in types or depth > 128:
            raise DropPlanRejected("E_DROP_PLAN: missing or overdeep dependent type")
        if key in cached:
            return cached[key]
        if key in active:
            raise DropPlanRejected("E_DROP_PLAN: recursive owned type")
        active.add(key)
        info = types[key]
        _validate_resource_shape(key, info)
        kind = info["kind"]
        if kind == "scalar":
            result = False
        elif kind == "buffer":
            if info.get("element") != "u8":
                raise DropPlanRejected("E_DROP_PLAN: unsupported buffer")
            result = True
        elif kind == "parameter":
            if info.get("bound") not in {"Owned", "Copy"}:
                raise DropPlanRejected("E_DROP_PLAN: unknown generic constraint")
            result = info["bound"] == "Owned"
        elif kind in {"array", "slice"}:
            if owns(info.get("element"), depth + 1):
                raise DropPlanRejected("E_DROP_PLAN: resource array/slice is not admitted")
            result = False
        elif kind == "struct":
            fields = info.get("fields")
            if type(fields) is not list:
                raise DropPlanRejected("E_DROP_PLAN: invalid struct field inventory")
            children = [owns(field.get("type"), depth + 1) for field in fields]
            result = any(children)
        elif kind == "enum":
            variants = info.get("variants")
            if type(variants) is not list:
                raise DropPlanRejected("E_DROP_PLAN: invalid enum variant inventory")
            children = [owns(field, depth + 1) for item in variants
                        for field in item.get("fields", [])]
            result = any(children)
        else:
            # In particular, stored borrowed records are not owned LLVM types.
            raise DropPlanRejected("E_DROP_PLAN: unsupported native resource kind " + kind)
        active.remove(key)
        cached[key] = result
        return result

    info = types[type_key]
    # Validate the root descriptor, not merely the dependent children:
    # an apparently owned struct may itself be a forged nominal layout.
    owns(type_key)
    kind = info["kind"]
    if kind == "buffer":
        owns(type_key)
        return DropPlan("buffer")
    if kind == "struct":
        fields = info.get("fields")
        if type(fields) is not list or len(fields) > 128:
            raise DropPlanRejected("E_DROP_PLAN: malformed struct shape")
        result = []
        for field in fields:
            if type(field) is not dict or type(field.get("name")) is not str:
                raise DropPlanRejected("E_DROP_PLAN: malformed struct member")
            child = field.get("type")
            result.append((field["name"], child, owns(child)))
        return DropPlan("struct", fields=tuple(result))
    if kind == "enum":
        variants = info.get("variants")
        if type(variants) is not list or len(variants) > 128:
            raise DropPlanRejected("E_DROP_PLAN: malformed enum shape")
        result = []
        for item in variants:
            if type(item) is not dict or type(item.get("name")) is not str or type(item.get("fields")) is not list:
                raise DropPlanRejected("E_DROP_PLAN: malformed enum variant")
            result.append((item["name"], tuple((child, owns(child)) for child in item["fields"])))
        return DropPlan("enum", variants=tuple(result))
    raise DropPlanRejected("E_DROP_PLAN: non-resource target cannot be lowered as Drop")
