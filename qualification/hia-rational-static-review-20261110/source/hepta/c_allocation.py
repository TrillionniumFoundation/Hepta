"""Recognize one conservative, non-escaping byte allocation/free idiom.

This is a structural rule with explicit rejection, not general ownership
inference. malloc bytes must be fully initialized before any source read.
Allocation failure remains an ordinary source return through try_buffer.
"""
from __future__ import annotations

from .c_migrate import MigrationRejected


def peel(node: dict) -> dict:
    while node.get("kind") in {"ParenExpr", "ImplicitCastExpr", "CStyleCastExpr"} and len(node.get("inner", [])) == 1:
        if node.get("kind") != "ParenExpr" and node.get("castKind") not in {"LValueToRValue", "NoOp", "FunctionToPointerDecay", "BitCast", "NullToPointer"}:
            break
        node = node["inner"][0]
    return node


def nodes(node: dict):
    yield node
    for child in node.get("inner", []):
        yield from nodes(child)


def call_name(node: dict) -> str | None:
    node = peel(node)
    if node.get("kind") != "CallExpr" or not node.get("inner"):
        return None
    ref = peel(node["inner"][0]).get("referencedDecl", {})
    return ref.get("name") if ref.get("kind") == "FunctionDecl" else None


def reference(node: dict, ident: str) -> bool:
    return peel(node).get("referencedDecl", {}).get("id") == ident


def literal(node: dict, value: int) -> bool:
    node = peel(node)
    # Zero and one retain their value under the integer promotions present in
    # these exact patterns; arbitrary casts of the length are not stripped.
    while node.get("kind") in {"ImplicitCastExpr", "CStyleCastExpr"} and node.get("castKind") == "IntegralCast" and len(node.get("inner", [])) == 1:
        node = peel(node["inner"][0])
    return node.get("kind") == "IntegerLiteral" and node.get("value") == str(value)


def one_statement(node: dict) -> dict:
    while node.get("kind") == "CompoundStmt" and len(node.get("inner", [])) == 1:
        node = node["inner"][0]
    return node


def _returns(node: dict) -> bool:
    return one_statement(node).get("kind") == "ReturnStmt"


def allocation_names(body: dict) -> list[str]:
    return [name for node in nodes(body) if node.get("kind") == "CallExpr"
            if (name := call_name(node)) in {"malloc", "calloc", "realloc", "free", "aligned_alloc"}]


def lower_allocation(translator, fn: dict) -> list[str] | None:
    names = allocation_names(fn["body"])
    if not names:
        return None
    if names.count("malloc") + names.count("calloc") != 1 or names.count("free") != 1 or any(name in {"realloc", "aligned_alloc"} for name in names):
        raise MigrationRejected("E_C_ALLOCATOR", "Requires exactly one malloc/calloc and one free; realloc/escape are not inferred")
    if any(param["pointer"] for param in fn["params"]):
        raise MigrationRejected("E_C_ALLOCATOR", "Allocated-owner profile currently takes scalar/value parameters only")
    body = fn["body"].get("inner", [])
    if len(body) < 5 or body[1].get("kind") != "DeclStmt" or len(body[1].get("inner", [])) != 1:
        raise MigrationRejected("E_C_ALLOCATOR", "Expected zero-length early return, allocation, failure guard, body, free, return")
    declaration = body[1]["inner"][0]
    if declaration.get("kind") != "VarDecl" or declaration.get("storageClass") or len(declaration.get("inner", [])) != 1:
        raise MigrationRejected("E_C_ALLOCATOR", "Owner must be a single initialized automatic local")
    if declaration.get("type", {}).get("qualType") not in {"unsigned char *", "uint8_t *"}:
        raise MigrationRejected("E_C_ALLOCATOR", "Allocation profile supports byte owners only")
    allocation = peel(declaration["inner"][0])
    allocation_kind = call_name(allocation)
    args = allocation.get("inner", [])[1:]
    if allocation_kind not in {"malloc", "calloc"} or len(args) != (1 if allocation_kind == "malloc" else 2):
        raise MigrationRejected("E_C_ALLOCATOR", "Expected malloc(length) or calloc(length, 1)")
    if allocation_kind == "calloc" and not literal(args[1], 1):
        raise MigrationRejected("E_C_ALLOCATOR", "Only calloc(length, 1) avoids unmodeled multiplication/element semantics")
    length_ref = peel(args[0]).get("referencedDecl", {})
    length = next((p for p in fn["params"] if p.get("id") == length_ref.get("id") and p["type"] == "usize"), None)
    if length is None:
        raise MigrationRejected("E_C_ALLOCATOR", "Allocation size must be an unchanged size_t parameter")
    guard = body[0]
    gc = guard.get("inner", [])
    if guard.get("kind") != "IfStmt" or len(gc) != 2 or not _returns(gc[1]):
        raise MigrationRejected("E_C_ALLOCATOR_ZERO", "An explicit size==0 early return is required")
    condition = peel(gc[0])
    parts = condition.get("inner", [])
    if condition.get("kind") != "BinaryOperator" or condition.get("opcode") != "==" or len(parts) != 2 or not (
        reference(parts[0], length["id"]) and literal(parts[1], 0)
        or reference(parts[1], length["id"]) and literal(parts[0], 0)
    ):
        raise MigrationRejected("E_C_ALLOCATOR_ZERO", "Zero-sized C allocator behavior must be handled before allocation")
    owner_id = declaration["id"]
    failure = body[2]
    fc = failure.get("inner", [])
    if failure.get("kind") != "IfStmt" or len(fc) != 2 or not _returns(fc[1]):
        raise MigrationRejected("E_C_ALLOCATOR_FAILURE", "Allocation failure must return explicitly before any buffer use")
    condition = peel(fc[0])
    parts = condition.get("inner", [])
    null_guard = (condition.get("kind") == "UnaryOperator" and condition.get("opcode") == "!" and len(parts) == 1 and reference(parts[0], owner_id))
    null_guard |= (condition.get("kind") == "BinaryOperator" and condition.get("opcode") == "==" and len(parts) == 2 and
                   ((reference(parts[0], owner_id) and literal(parts[1], 0)) or (reference(parts[1], owner_id) and literal(parts[0], 0))))
    if not null_guard:
        raise MigrationRejected("E_C_ALLOCATOR_FAILURE", "Expected if (!owner) or if (owner == NULL)")
    tail = body[3:]
    if len(tail) < 2 or call_name(tail[-2]) != "free" or len(tail[-2].get("inner", [])) != 2 or not reference(tail[-2]["inner"][1], owner_id) or tail[-1].get("kind") != "ReturnStmt":
        raise MigrationRejected("E_C_ALLOCATOR_FREE", "Owner must be freed once immediately before the final return")
    if any(node.get("kind") == "ReturnStmt" for statement in tail[:-2] for node in nodes(statement)):
        raise MigrationRejected("E_C_ALLOCATOR_ESCAPE", "Early returns while an allocation is live are outside this profile")
    if any(reference(node, owner_id) for node in nodes(tail[-1])):
        raise MigrationRejected("E_C_ALLOCATOR_AFTER_FREE", "Return reads owner after free")
    for statement in tail[:-2]:
        for node in nodes(statement):
            if node.get("kind") in {"BinaryOperator", "CompoundAssignOperator", "UnaryOperator"}:
                children = node.get("inner", [])
                if children and node.get("opcode") in {"=", "+=", "-=", "*=", "/=", "%=", "++", "--"} and reference(children[0], length["id"]):
                    raise MigrationRejected("E_C_ALLOCATOR_LENGTH", "Allocation length cannot change while owner is live")
            if node.get("kind") == "CallExpr" and any(reference(child, owner_id) for child in nodes(node)):
                raise MigrationRejected("E_C_ALLOCATOR_ESCAPE", "Passing allocated pointers to another function is not yet modeled")
    if allocation_kind == "malloc":
        _complete_initialization(tail[0], owner_id, length["id"], translator)
    # All structural requirements have now been checked. Source reads from
    # malloc occur after its explicit full-initialization loop. Zero-initialized
    # allocation does not invent a value for an uninitialized source read.
    from .c_translation import Expression
    owner = "owned_" + declaration["name"]
    translator.bindings[owner_id] = Expression(owner, "slice:u8")
    translator.binding_modes[owner] = "mut"
    length_value = translator.bindings[length["id"]]
    rendered = translator.stmt(guard)
    rendered += [f"    let allocation_result: Result<Buffer<u8>, u8> = try_buffer({length_value.text});",
                 "    match move allocation_result {", "        Result::Err(allocation_error) => {"]
    rendered += translator.stmt(one_statement(fc[1]), 3)
    rendered += ["        },", "        Result::Ok(allocation_owner) => {",
                 f"            let mut {owner}: Buffer<u8> = move allocation_owner;"]
    for statement in tail[:-2]:
        rendered += translator.stmt(statement, 3)
    rendered.append(f"            release(move {owner});")
    rendered += translator.stmt(tail[-1], 3)
    rendered += ["        },", "    }"]
    fn["allocation_profile"] = {"kind": allocation_kind, "element": "u8", "length_parameter": length["name"],
                                "failure": "source_return_preserved_via_Result_Err",
                                "malloc_initialized_before_read": allocation_kind == "malloc",
                                "zero_length": "source_early_return", "escape": "rejected", "free_count": 1,
                                "allocation_outcome_equivalence_proved": False,
                                "allocator_model": "standard_C_allocation_success_or_null_no_custom_side_effect_contract"}
    return rendered


def _complete_initialization(loop: dict, owner: str, length: str, translator) -> None:
    children = loop.get("inner", [])
    if loop.get("kind") != "ForStmt" or len(children) != 5 or children[1]:
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "malloc requires an immediate complete initialization loop")
    declaration = children[0].get("inner", [])
    if children[0].get("kind") != "DeclStmt" or len(declaration) != 1 or len(declaration[0].get("inner", [])) != 1 or not literal(declaration[0]["inner"][0], 0):
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization induction variable must start at zero")
    induction = declaration[0]
    if translator.typ(induction["type"]) != "usize":
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization induction variable must have size_t type")
    condition, increment, assignment = peel(children[2]), peel(children[3]), one_statement(children[4])
    test = condition.get("inner", [])
    if condition.get("opcode") != "<" or len(test) != 2 or not reference(test[0], induction["id"]) or not reference(test[1], length):
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization must cover every index below allocation length")
    if increment.get("kind") != "UnaryOperator" or increment.get("opcode") != "++" or not reference(increment["inner"][0], induction["id"]):
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization must increment exactly once")
    pair = assignment.get("inner", [])
    if assignment.get("kind") != "BinaryOperator" or assignment.get("opcode") != "=" or len(pair) != 2:
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization loop body must be one element assignment")
    target = peel(pair[0])
    subscript = target.get("inner", [])
    if target.get("kind") != "ArraySubscriptExpr" or len(subscript) != 2 or not reference(subscript[0], owner) or not reference(subscript[1], induction["id"]):
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initialization must write owner[induction]")
    if any(reference(node, owner) or node.get("kind") in {"CallExpr", "CompoundAssignOperator"} or node.get("opcode") in {"++", "--", "="} for node in nodes(pair[1])):
        raise MigrationRejected("E_C_ALLOCATOR_INITIALIZATION", "Initializer must not read uninitialized owner bytes or have side effects")
