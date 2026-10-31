"""One closed instruction contract for primitive HIA checkers and agent tools.

The table generates local operand/result, attribute, effect and version checks.
Ownership/CFG checks, execution, and lowering remain separate implementations;
publishing this catalog is not a soundness or native-refinement certificate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from types import MappingProxyType

from .hia_schema import LATEST_CORE_SCHEMA, PRIMITIVE_PROFILES

WIDTHS = MappingProxyType({**{f"{s}{n}": n for s in ("i", "u") for n in (8, 16, 32, 64)},
                          "isize": 64, "usize": 64})
SCALARS = frozenset(WIDTHS) | {"bool", "unit"}
OWNERS = frozenset({"buffer", "chain"})
BYTE_RESOURCES = frozenset({"buffer", "readbuf", "mutbuf"})
RESOURCES = BYTE_RESOURCES | OWNERS
TYPES = SCALARS | RESOURCES
EFFECTS = frozenset({"alloc", "read", "write", "trap"})
TRAP_CODES = frozenset({"user", "overflow", "division_by_zero", "bounds", "allocation"})
EXECUTION_RESOURCE_FIELDS = frozenset({
    "allocations", "frees", "allocation_attempts", "owners_created", "owners_dropped",
    "live_owners", "live_bytes", "peak_bytes", "loans_started", "loans_ended", "live_local_loans",
})
EXECUTION_CHAIN_FIELDS = frozenset({
    "chains_created", "chains_consumed", "live_chains", "chain_nodes_created",
    "chain_nodes_dropped", "live_chain_nodes",
})
# Each live recursive-chain node owns a real 24-byte storage allocation.
# Keep the interpreter and independent stopped-ledger checks on one size contract.
CHAIN_NODE_STORAGE_BYTES = 24
_GROUPS = MappingProxyType({"integer": frozenset(WIDTHS), "scalar": SCALARS,
    "equality": frozenset(WIDTHS) | {"bool"}, "owner": OWNERS, "bytes": BYTE_RESOURCES,
    "view": frozenset({"readbuf", "mutbuf"}), "mutable_source": frozenset({"buffer", "mutbuf"})})


class OpcodeRejected(ValueError):
    def __init__(self, message, code="E_HIA_OPCODE"):
        self.code = code
        super().__init__(message)


class ExecutionObservationRejected(ValueError):
    """An execution summary contradicts the shared outcome/ledger contract."""


def validate_execution_observation(status, ledger, *, steps, max_steps, max_heap_bytes,
                                   error_code=None, with_chains=False, allow_host_memory=False):
    """Check finite wire/accounting invariants, without running or admitting Core.

    Return, program trap and evaluator stop remain distinct. In particular a
    stopped invocation may retain resources; its observation must not erase
    those resources by contradicting the allocation/owner/loan counters. This
    validates a summary, not the truth of a producer or any program semantics.
    Normal errors and cooperative cancellation represented as values obey the
    ordinary-return rule. Host termination and arbitrary unwinding are absent.
    """
    def need(condition, message):
        if not condition:
            raise ExecutionObservationRejected("E_HIA_EXECUTION_CONTRACT: " + message)

    need(type(status) is str and status in {"returned", "trapped", "budget_exceeded"},
         "unknown execution outcome")
    need(type(with_chains) is bool and type(allow_host_memory) is bool, "exact profile flags required")
    fields = EXECUTION_RESOURCE_FIELDS | (EXECUTION_CHAIN_FIELDS if with_chains else frozenset())
    need(type(ledger) is dict and set(ledger) == fields, "resource field inventory differs")
    need(all(type(value) is int and 0 <= value < 1 << 64 for value in ledger.values()),
         "resource counters must be exact unsigned u64 integers")
    need(type(steps) is int and type(max_steps) is int and 1 <= max_steps <= 10_000_000
         and type(max_heap_bytes) is int and 0 <= max_heap_bytes <= 1024 * 1024 * 1024,
         "invalid explicit evaluator limits")
    allocated, freed = ledger["allocations"], ledger["frees"]
    created, dropped, live = ledger["owners_created"], ledger["owners_dropped"], ledger["live_owners"]
    nonempty = allocated - freed
    need(freed <= allocated <= ledger["allocation_attempts"] and allocated <= created
         and freed <= dropped <= created and live == created - dropped,
         "allocation and owner conservation differ")
    need(0 <= nonempty <= live and nonempty <= ledger["live_bytes"]
         and (nonempty == 0) == (ledger["live_bytes"] == 0),
         "live payload is inconsistent with live allocation/owner counts")
    need(ledger["loans_ended"] <= ledger["loans_started"]
         and ledger["live_local_loans"] == ledger["loans_started"] - ledger["loans_ended"],
         "local loan conservation differs")
    need(live > 0 or ledger["live_local_loans"] == 0, "a live loan has no live byte owner")
    need(ledger["live_bytes"] <= ledger["peak_bytes"] <= max_heap_bytes,
         "live/peak payload exceeds the explicit heap policy")
    if with_chains:
        need(ledger["chains_consumed"] <= ledger["chains_created"]
             and ledger["live_chains"] == ledger["chains_created"] - ledger["chains_consumed"]
             and ledger["chain_nodes_dropped"] <= ledger["chain_nodes_created"]
             and ledger["live_chain_nodes"] == ledger["chain_nodes_created"] - ledger["chain_nodes_dropped"],
             "recursive chain conservation differs")
        # Each still-live chain node owns its distinct payload and node-storage
        # byte owners, even after a quota interrupts iterative destruction.
        need(2 * ledger["live_chain_nodes"] <= live, "chain nodes have missing byte owners")
        need(ledger["live_bytes"] >= CHAIN_NODE_STORAGE_BYTES * ledger["live_chain_nodes"]
             and nonempty >= ledger["live_chain_nodes"],
             "live chain node storage is missing from the stopped payload/allocation ledger")
        # A successful push necessarily allocates a nonempty node-storage
        # owner; a completed pop/drop necessarily frees that same storage.
        # Stopped reports can retain live nodes, but cannot fabricate releases.
        need(ledger["chain_nodes_created"] <= allocated
             and ledger["chain_nodes_dropped"] <= freed,
             "chain node storage release/creation is not backed by nonempty allocator activity")
        # A node is only created by pushing through an existing chain
        # generation; a completed removal can only follow consumption of
        # its owning chain generation. Keep interrupted destruction legal:
        # zero live chain tokens may coexist with still-live detached nodes.
        need(ledger["chain_nodes_created"] <= ledger["chains_created"]
             and ledger["chain_nodes_dropped"] <= ledger["chains_consumed"],
             "chain node history lacks corresponding chain token events")
    if status == "returned":
        need(error_code is None, "ordinary return cannot carry an error outcome")
        need(live == ledger["live_local_loans"] == 0
             and (not with_chains or ledger["live_chains"] == ledger["live_chain_nodes"] == 0),
             "ordinary scalar return retains resources")
    else:
        permitted = TRAP_CODES if status == "trapped" else frozenset({"steps", "heap", "calls"})
        if status == "budget_exceeded" and allow_host_memory:
            permitted |= {"host_memory"}
        need(type(error_code) is str and error_code in permitted, "unknown or misclassified stop code")
    # The step count is a receipt-shape field just like ledger counters.
    # Python numeric comparisons would otherwise admit True, 1.0 or 1.5 as
    # plausible stopped execution steps; reject before any comparisons.
    need(type(steps) is int and 1 <= steps <= max_steps + 1,
         "execution steps must be exact integers within the declared tick limit")
    tick_stop = status == "budget_exceeded" and error_code == "steps"
    need(steps == max_steps + 1 if tick_stop else 1 <= steps <= max_steps,
         "tick count contradicts the execution outcome")


@dataclass(frozen=True, slots=True)
class OpcodeSpec:
    name: str
    operands: tuple[str, ...] | None
    results: tuple[str, ...] | None
    attributes: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    traps: tuple[str, ...] = ()
    since: int = 1
    guards: tuple[str, ...] = ()
    resource_transition: str = "none"
    semantic_rule: str = ""


def _table():
    rows = [OpcodeSpec("const", (), ("declared:scalar",), ("value",), semantic_rule="exact_scalar_literal")]
    for operator in ("add", "sub", "mul"):
        for mode in ("checked", "wrap"):
            rows.append(OpcodeSpec(f"int.{operator}.{mode}", ("integer", "=0"), ("=0",),
                effects=("trap",) if mode == "checked" else (),
                traps=("overflow",) if mode == "checked" else (), semantic_rule=f"integer_{operator}_{mode}"))
    for operator in ("div", "rem", "shl", "shr"):
        rows.append(OpcodeSpec(f"int.{operator}.checked", ("integer", "=0"), ("=0",),
            effects=("trap",), traps=("division_by_zero", "overflow") if operator in {"div", "rem"} else ("overflow",),
            semantic_rule=f"integer_{operator}_checked"))
    for operator in ("and", "or", "xor"):
        rows.append(OpcodeSpec("bit." + operator, ("integer", "=0"), ("=0",), semantic_rule="bit_" + operator))
    rows += [OpcodeSpec("bit.not", ("integer",), ("=0",), semantic_rule="bit_not"),
             OpcodeSpec("int.neg.checked", ("integer",), ("=0",), effects=("trap",), traps=("overflow",), semantic_rule="integer_neg_checked")]
    for operator in ("eq", "ne", "lt", "le", "gt", "ge"):
        rows.append(OpcodeSpec("compare." + operator, ("equality" if operator in {"eq", "ne"} else "integer", "=0"),
                               ("bool",), semantic_rule="compare_" + operator))
    for operator in ("not", "and", "or"):
        rows.append(OpcodeSpec("bool." + operator, ("bool",) if operator == "not" else ("bool", "bool"),
                               ("bool",), semantic_rule="bool_" + operator))
    rows += [
        OpcodeSpec("int.cast", ("integer",), ("declared:integer",), ("mode",), traps=("overflow_when_checked",), semantic_rule="integer_cast_mode"),
        OpcodeSpec("select", ("bool", "scalar", "=1"), ("=1",), semantic_rule="scalar_select"),
        OpcodeSpec("buffer.new", ("usize",), ("buffer",), effects=("alloc", "trap"), traps=("allocation",), resource_transition="allocate", semantic_rule="zeroed_byte_allocation"),
        OpcodeSpec("buffer.try_new", ("usize",), ("buffer", "bool"), effects=("alloc",), resource_transition="allocate", semantic_rule="zeroed_byte_allocation_or_empty_owner_false"),
        OpcodeSpec("buffer.len", ("bytes",), ("usize",), semantic_rule="byte_extent"),
        OpcodeSpec("chain.empty", (), ("chain",), since=7, resource_transition="empty_chain", semantic_rule="empty_chain"),
        OpcodeSpec("chain.try_push", ("chain", "buffer"), ("chain", "buffer", "bool"), effects=("alloc",), since=7, guards=("free:0", "free:1"), resource_transition="chain_transfer", semantic_rule="push_or_return_owned_inputs"),
        OpcodeSpec("chain.pop", ("chain",), ("chain", "buffer", "bool"), effects=("alloc",), since=7, guards=("free:0",), resource_transition="chain_transfer", semantic_rule="pop_or_empty_payload_false"),
        OpcodeSpec("chain.is_empty", ("chain",), ("bool",), since=7, semantic_rule="chain_empty_test"),
        OpcodeSpec("chain.head_read", ("chain",), ("readbuf",), effects=("read", "trap"), traps=("bounds",), since=7, resource_transition="chain_borrow", semantic_rule="shared_head_loan"),
        OpcodeSpec("chain.head_mut", ("chain",), ("mutbuf",), effects=("read", "trap"), traps=("bounds",), since=7, resource_transition="chain_borrow", semantic_rule="exclusive_head_loan"),
        OpcodeSpec("borrow.read", ("bytes",), ("readbuf",), resource_transition="borrow", semantic_rule="shared_loan"),
        OpcodeSpec("borrow.mut", ("mutable_source",), ("mutbuf",), resource_transition="borrow", semantic_rule="exclusive_loan"),
        OpcodeSpec("loan.end", ("view",), (), guards=("end_local_loan:0",), resource_transition="end_loan", semantic_rule="end_local_childless_loan"),
        OpcodeSpec("owner.move", ("owner",), ("=0",), guards=("free:0",), resource_transition="move_owner", semantic_rule="move_unborrowed_owner"),
        OpcodeSpec("owner.drop", ("owner",), (), effects=("alloc",), guards=("free:0",), resource_transition="drop_owner", semantic_rule="release_unborrowed_owner"),
        OpcodeSpec("buffer.load", ("view", "usize"), ("u8",), effects=("read", "trap"), traps=("bounds",), guards=("read:0",), semantic_rule="checked_byte_load"),
        OpcodeSpec("buffer.store", ("mutbuf", "usize", "u8"), (), effects=("write", "trap"), traps=("bounds",), guards=("write:0",), semantic_rule="checked_byte_store"),
        OpcodeSpec("buffer.fill", ("mutbuf", "u8"), (), effects=("write",), since=2, guards=("write:0",), semantic_rule="fill_entire_view"),
        OpcodeSpec("buffer.copy", ("mutbuf", "readbuf", "usize"), (), effects=("read", "write", "trap"), traps=("bounds",), since=2, guards=("write:0", "read:1", "distinct:0:1"), semantic_rule="checked_disjoint_copy"),
        OpcodeSpec("buffer.move_within", ("mutbuf", "usize", "usize", "usize"), (), effects=("read", "write", "trap"), traps=("bounds",), since=3, guards=("write:0",), semantic_rule="checked_overlap_memmove"),
        OpcodeSpec("buffer.swap", ("mutbuf", "usize", "usize"), (), effects=("read", "write", "trap"), traps=("bounds",), since=4, guards=("write:0",), semantic_rule="check_both_indices_before_swap"),
        OpcodeSpec("buffer.copy_range", ("mutbuf", "readbuf", "usize", "usize", "usize"), (), effects=("read", "write", "trap"), traps=("bounds",), since=5, guards=("write:0", "read:1", "distinct:0:1"), semantic_rule="checked_disjoint_offset_copy"),
        OpcodeSpec("buffer.fill_range", ("mutbuf", "usize", "usize", "u8"), (), effects=("write", "trap"), traps=("bounds",), since=6, guards=("write:0",), semantic_rule="check_complete_range_before_fill"),
        OpcodeSpec("call", None, None, ("function",), guards=("callee_interface",), resource_transition="call", semantic_rule="checked_callee_and_parameter_loan_contract"),
    ]
    assert len({row.name for row in rows}) == len(rows)
    return MappingProxyType({row.name: row for row in rows})


OPCODES = _table()
# Terminator structure is consumed by the same parser as instruction attributes.
TERMINATORS = MappingProxyType({"ret": ("op", "values"), "jump": ("op", "target", "args"),
                               "branch": ("op", "cond", "then", "else"), "trap": ("op", "code")})


def opcode_spec(name: str, schema: str = LATEST_CORE_SCHEMA) -> OpcodeSpec:
    if schema not in PRIMITIVE_PROFILES:
        raise OpcodeRejected("unknown primitive schema; legacy/composite input requires an explicit adapter")
    spec = OPCODES.get(name)
    if spec is None:
        raise OpcodeRejected(f"unsupported opcode {name}")
    if list(PRIMITIVE_PROFILES).index(schema) + 1 < spec.since:
        raise OpcodeRejected(f"{name} requires HIA program v{spec.since}")
    return spec


def scalar_value_valid(value, typ):
    if typ in WIDTHS:
        bits = WIDTHS[typ]
        low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if typ.startswith("i") else (0, (1 << bits) - 1)
        return type(value) is int and low <= value <= high
    return type(value) is bool if typ == "bool" else value is None if typ == "unit" else False


def _matches(rule, typ, operands):
    if rule.startswith("="):
        return typ == operands[int(rule[1:])]
    rule = rule.removeprefix("declared:")
    return typ in _GROUPS[rule] if rule in _GROUPS else typ == rule


def check_instruction(spec: OpcodeSpec, operands, results, attributes) -> frozenset[str]:
    """Generated local checker; caller still checks liveness, CFG and calls."""
    if type(attributes) is not dict or set(attributes) != set(spec.attributes):
        raise OpcodeRejected(f"{spec.name}: expected exactly {', '.join(spec.attributes)} attributes", "E_HIA_FORMAT")
    for actual, rules, label in ((operands, spec.operands, "operand"), (results, spec.results, "output")):
        if rules is not None:
            if len(actual) != len(rules):
                raise OpcodeRejected(f"{spec.name}: wrong {label} count", "E_HIA_TYPE")
            if any(not _matches(rule, typ, operands) for rule, typ in zip(rules, actual)):
                code = "E_HIA_LOAN" if label == "operand" and spec.name in {"borrow.read", "borrow.mut"} else "E_HIA_TYPE"
                raise OpcodeRejected(f"{spec.name}: {label} types must match {rules}", code)
    effects = set(spec.effects)
    if spec.name == "const" and not scalar_value_valid(attributes["value"], results[0]):
        raise OpcodeRejected("constant must be an exactly typed scalar", "E_HIA_TYPE")
    if spec.name == "int.cast":
        if type(attributes["mode"]) is not str or attributes["mode"] not in {"checked", "wrap"}:
            raise OpcodeRejected("unsupported integer cast", "E_HIA_TYPE")
        if attributes["mode"] == "checked":
            effects.add("trap")
    return frozenset(effects)


def opcode_catalog(schema: str | None = None) -> dict:
    """Detached complete catalog; hashes bind metadata, never grant admission."""
    schema = LATEST_CORE_SCHEMA if schema is None else schema
    if schema not in PRIMITIVE_PROFILES:
        raise OpcodeRejected("catalog requires an exact primitive schema")
    version = list(PRIMITIVE_PROFILES).index(schema) + 1
    rows = [asdict(spec) for spec in OPCODES.values() if spec.since <= version]
    visible_types = TYPES - ({"chain"} if version < 7 else set())
    result = {"schema": "hepta.hia.opcode-catalog.v1", "core_schema": schema,
        "profile": PRIMITIVE_PROFILES[schema], "word_bits": 64,
        "types": sorted(visible_types),
        "type_groups": {k: sorted(v & visible_types) for k, v in _GROUPS.items()},
        "signature_rules": {"=N": "same type as zero-based operand N", "declared:T": "explicit result type in group T",
                            "null": "arity/types/effects determined by verified callee interface"},
        "instructions": rows,
        "terminators": [{"name": name, "fields": list(fields)} for name, fields in TERMINATORS.items()],
        "function_contract": {"return_loans": "explicit formal-name/null per return; parameter origin checked" if version >= 8 else "loan returns forbidden"},
        "conditional_effects": {"int.cast": "checked mode requires trap", "call": "all callee effects"},
        "resource_checks": "all guards, transitions, exact CFG joins and return cleanup remain mandatory",
        "backend_scope": "VM and direct LLVM have separate supported-target/entry-ABI checks; catalog inclusion grants no native entry ABI",
        "admission_authority": "hepta.hia_program.verify_program", "safety_certificate": False,
        "generated_checker_scope": "opcode/version, operand/result signatures, attributes, effects, named resource guards",
        "not_generated_or_proved": ["CFG ownership algorithm", "interpreter", "LLVM lowering", "machine code"]}
    result["catalog_sha256"] = sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def render_opcode_reference() -> str:
    rows = ["# HIA primitive instruction reference", "", "Generated by `python tools/generate_hia_catalog.py`; edit `hepta/hia_opcodes.py`.", "",
        "This catalog generates local checking and agent discovery. The ownership/CFG checker, VM and native backend remain separate implementations and require independent validation.", "",
        "`=N` refers to the type of operand N (zero based); `declared:T` requires an explicit result type in group T. `call` uses its checked callee interface. All attributes are exact required sets.", "",
        "| Instruction | Since | Operands | Results | Attributes | Effects | Resource guards |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for spec in OPCODES.values():
        fmt = lambda values: "callee interface" if values is None else ", ".join(values) or "—"
        rows.append(f"| `{spec.name}` | v{spec.since} | {fmt(spec.operands)} | {fmt(spec.results)} | {fmt(spec.attributes)} | {fmt(spec.effects)} | {fmt(spec.guards)} |")
    rows += ["", "`int.cast` additionally requires `trap` in checked mode. `call` propagates all callee effects. Traps abort; normal/error-as-value returns must balance ownership. VM fuel, call depth, native stack, payload and allocator overhead are separate budgets.", "",
        "Core v8 adds explicit `return_loans` contracts; it does not invent new opcodes. Assembly v1 accepts explicit primitive v6/v7/v8 and preserves this field. Historical schemas are accepted only through their named adapters; no profile is guessed.", "",
        "Query the complete version-specific JSON with `hepta hia catalog --schema hepta.hia.program.v8`. The catalog includes terminators, conditional effects, resource transitions, trap descriptions and exact scope limitations.", ""]
    return "\n".join(rows)
