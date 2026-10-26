"""Finite Drop composition decisions derived from independently verified Resource IR types.

No AST parser, borrow checker or new LLVM backend. The caller MUST pass the
exact type table of a successfully checked *source-derived* Resource IR graph.
A missing concrete generic instantiation is reported, never guessed by this
adapter. This is a partial Drop helper consumer, not executable owned SSA.
"""
from __future__ import annotations

from dataclasses import dataclass


class DropPlanRejected(ValueError):
    """A reviewed Resource IR type table cannot describe this native Drop."""


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
        if type(info) is not dict or type(info.get("kind")) is not str:
            raise DropPlanRejected("E_DROP_PLAN: invalid dependent type descriptor")
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
    if type(info) is not dict:
        raise DropPlanRejected("E_DROP_PLAN: invalid target type descriptor")
    kind = info.get("kind")
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
