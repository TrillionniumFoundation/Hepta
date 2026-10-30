"""Finite proposals for the captured, unchanged stb_mod_eucl implementation.

The signed body comes from the existing C capture/migration frontend.  A closed
bit-pattern adapter makes its i32 ABI usable by the existing two-u32 research
executor.  Neither extraction nor specialization grants execution authority:
the executor must freshly check Core translation, selected LLVM and native
observations.  C source refinement and C undefined inputs are separate claims.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path

from .hia_finite_context import checked_profile
from .hia_program import HIAProgramRejected, verify_program
from .hia_specialization import _clone_blocks, _fresh, propose_guarded_specializations
from .hia_translation_validation import _profile

FUNCTION = "c_stb_mod_eucl"
LABELS = ("baseline", "guard_8", "guard_10", "guard_8_10")
MASK32 = (1 << 32) - 1


def _require(condition, message):
    if not condition:
        raise HIAProgramRejected(message, "E_HIA_STB_SPECIALIZATION")


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def bit_adapter(document):
    """Retain the exact captured scalar body behind explicit wrapping casts.

    This is a structural adapter, not a substitute implementation of remainder.
    All body operations/edges are retained; only entry/return bit casts and the
    export name change.  The actual captured signed Core remains in the receipt.
    """
    source = verify_program(document)
    original = source.as_dict()
    selected = [fn for fn in original["functions"] if fn["name"] == FUNCTION]
    _require(len(selected) == 1, "one actual captured stb_mod_eucl body required")
    fn = copy.deepcopy(selected[0])
    _require([p["type"] for p in fn["params"]] == ["i32", "i32"]
             and fn["returns"] == ["i32"] and set(fn["effects"]) <= {"trap"},
             "captured signed scalar signature differs")
    _profile(fn)
    captured_body_sha256 = sha256(_wire(fn)).hexdigest()
    values = {p["name"] for b in fn["blocks"] for p in
              [*b["params"], *[v for op in b["ops"] for v in op["out"]]]}
    blocks = {b["id"] for b in fn["blocks"]}
    args = [{"name": _fresh("stb_bits", values), "type": "u32"} for _ in range(2)]
    signed = [_fresh("stb_signed", values) for _ in range(2)]
    entry = {"id": _fresh("stb_adapter", blocks), "params": copy.deepcopy(args),
             "ops": [{"op": "int.cast", "args": [arg["name"]],
                      "out": [{"name": out, "type": "i32"}], "attrs": {"mode": "wrap"}}
                     for arg, out in zip(args, signed)],
             "term": {"op": "jump", "target": fn["entry"], "args": signed}}
    for block in fn["blocks"]:
        if block["term"]["op"] == "ret":
            _require(len(block["term"]["values"]) == 1, "signed return shape differs")
            out = _fresh("stb_result_bits", values)
            block["ops"].append({"op": "int.cast", "args": list(block["term"]["values"]),
                                 "out": [{"name": out, "type": "u32"}], "attrs": {"mode": "wrap"}})
            block["term"]["values"] = [out]
    fn.update(name="calculate", params=args, returns=["u32"], entry=entry["id"],
              blocks=[entry, *fn["blocks"]])
    adapted = checked_profile({"schema": original["schema"], "module": "stb_mod_eucl_bits",
                               "exports": ["calculate"], "functions": [fn]})
    return adapted.as_dict(), {"captured_core_sha256": source.sha256,
        "captured_function_sha256": captured_body_sha256, "function": FUNCTION,
        "adapted_core_sha256": adapted.sha256, "conversion": "i32/u32 wrapping bit casts",
        "source_C_equivalence_proved": False, "frontend_refinement_proved": False,
        "source_C_undefined_pairs": ["denominator=0", "numerator=INT_MIN and denominator=-1"],
        "source_undefined_behavior_is_HIA_equivalence": False,
        "structural_body_retained": True, "execution_authority": False}


def _dual_guard(document):
    """One generic body and two guarded clones, rather than nested duplication."""
    value = checked_profile(document).as_dict()
    fn = value["functions"][0]
    used = {p["name"] for p in fn["params"]}
    used_blocks = set()
    generic, generic_entry = _clone_blocks(fn, "stb_generic", used, used_blocks)
    specialized = [_clone_blocks(fn, "stb_hot" + str(n), used, used_blocks) for n in (8, 10)]
    guard_ids = [_fresh("stb_guard", used_blocks) for _ in range(2)]
    guards = []
    for index, n in enumerate((8, 10)):
        params = copy.deepcopy(fn["params"]) if index == 0 else [
            {"name": _fresh("stb_next", used), "type": "u32"} for _ in range(2)]
        constant, condition = _fresh("stb_divisor", used), _fresh("stb_match", used)
        guards.append({"id": guard_ids[index], "params": params, "ops": [
            {"op": "const", "args": [], "out": [{"name": constant, "type": "u32"}],
             "attrs": {"value": n}},
            {"op": "compare.eq", "args": [params[1]["name"], constant],
             "out": [{"name": condition, "type": "bool"}], "attrs": {}}],
            "term": {"op": "branch", "cond": condition,
                     "then": {"target": specialized[index][1], "args": [params[0]["name"], constant]},
                     "else": {"target": guard_ids[1] if index == 0 else generic_entry,
                              "args": [p["name"] for p in params]}}})
    fn.update(entry=guard_ids[0], blocks=[*guards, *generic,
                                      *specialized[0][0], *specialized[1][0]])
    return checked_profile(value).as_dict()


def candidates(baseline):
    """The same complete bank is available to fixed, greedy, DP and native NDU."""
    base = checked_profile(baseline)
    denominator = base.as_dict()["functions"][0]["params"][1]["name"]
    single = propose_guarded_specializations(base.as_dict(), function="calculate",
        assumptions=[{"parameter": denominator, "value": n} for n in (8, 10)])
    bank = {"baseline": base.as_dict(), "guard_8": single[0]["program"],
            "guard_10": single[1]["program"], "guard_8_10": _dual_guard(base.as_dict())}
    for program in bank.values():
        checked_profile(program)  # Existing 32-block/512-operation bound, unchanged.
    return bank


def oracle(numerator, denominator):
    """Independent Euclidean remainder on mathematical integers plus HIA traps."""
    _require(all(type(n) is int and 0 <= n <= MASK32 for n in (numerator, denominator)),
             "exact u32 input bit patterns required")
    a = numerator if numerator < 1 << 31 else numerator - (1 << 32)
    b = denominator if denominator < 1 << 31 else denominator - (1 << 32)
    if b == 0:
        return {"status": "trapped", "code": "division_by_zero"}
    if a == -(1 << 31) and b == -1:
        return {"status": "trapped", "code": "overflow"}
    return a % abs(b)


def edge_cases():
    """Exactly 64 fixed cases, including sign extremes, guards and HIA traps."""
    numerators = (0, 1, 7, 8, 9, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)
    denominators = (0, 1, 8, 10, 11, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)
    return [[a, b] for a in numerators for b in denominators]


def capture(directory, *, clang):
    """Run the existing full-component frontend; retain every captured artifact."""
    from .c_migrate import migrate_c_project
    from .hia_program_source import lower_source
    from .hia_scalar_call_validation import inline_scalar_calls, validate_scalar_calls
    from tools.qualify_c_stb_divide import FUNCTIONS, capture_fixture, verify_upstream
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=False)
    upstream = verify_upstream()
    database = capture_fixture(out / "upstream", [])
    migration = migrate_c_project(database, out / "translated", clang=clang)
    (out / "MIGRATION.json").write_bytes(_wire(migration) + b"\n")
    _require(migration["ok"] and migration["declaration_inventory_complete"]
             and migration["coverage"]["active_project_declarations"] == 12
             and migration["coverage"]["status_counts"] == {"function_converted": 6, "prototype_resolved": 6}
             and set(row["name"] for row in migration["functions"]) == set(FUNCTIONS),
             "complete unchanged stb component capture failed")
    for name, identity in migration["artifacts"].items():
        raw = (out / "translated" / name).read_bytes()
        _require(len(raw) == identity["bytes"] and sha256(raw).hexdigest() == identity["sha256"],
                 "published migration artifact changed")
    core = lower_source((out / "translated/source.hepta").read_text())
    (out / "captured.hia.json").write_bytes(core.canonical_bytes)
    inlined = inline_scalar_calls(core, function=FUNCTION)
    (out / "inlined.hia.json").write_bytes(verify_program(inlined).canonical_bytes)
    baseline, adapter = bit_adapter(inlined)
    # Encode the original captured caller/callee graph on the left.  The right
    # contains the proposed flat adapter; neither encoding calls the inliner.
    reference = core.as_dict()
    args = copy.deepcopy(baseline["functions"][0]["params"])
    wrapper = {"name": "calculate", "params": args, "returns": ["u32"],
        "effects": ["trap"], "entry": "stb_reference", "blocks": [{
            "id": "stb_reference", "params": copy.deepcopy(args), "ops": [
                {"op": "int.cast", "args": [args[0]["name"]], "out": [{"name": "a", "type": "i32"}], "attrs": {"mode": "wrap"}},
                {"op": "int.cast", "args": [args[1]["name"]], "out": [{"name": "b", "type": "i32"}], "attrs": {"mode": "wrap"}},
                {"op": "call", "args": ["a", "b"], "out": [{"name": "r", "type": "i32"}], "attrs": {"function": FUNCTION}},
                {"op": "int.cast", "args": ["r"], "out": [{"name": "out", "type": "u32"}], "attrs": {"mode": "wrap"}}],
            "term": {"op": "ret", "values": ["out"]}}]}
    reference["functions"].append(wrapper)
    reference["exports"] = ["calculate"]
    proposed = copy.deepcopy(reference)
    proposed["functions"][-1] = copy.deepcopy(baseline["functions"][0])
    for name, document in (("reference", reference), ("proposed", proposed)):
        (out / (name + ".hia.json")).write_bytes(verify_program(document).canonical_bytes)
    bridge = validate_scalar_calls(reference, proposed, function="calculate")
    (out / "SOURCE_BRIDGE.json").write_bytes(_wire(bridge) + b"\n")
    _require(bridge["status"] == "proved", "fresh captured call-closure/first-trap bridge did not pass")
    original_function = next(fn for fn in core.as_dict()["functions"] if fn["name"] == FUNCTION)
    adapter.update(captured_core_sha256=core.sha256, inlined_core_sha256=verify_program(inlined).sha256,
                   inlined_function_sha256=adapter["captured_function_sha256"],
                   captured_function_sha256=sha256(_wire(original_function)).hexdigest(),
                   structural_body_basis="exact inlined Core; original call body independently compared by the bridge",
                   original_call_body_byte_identical=False, call_closure_bridge=bridge)
    (out / "baseline.hia.json").write_bytes(verify_program(baseline).canonical_bytes)
    receipt = {"upstream": upstream, "adapter": adapter,
               "complete_component_capture": True, "selected_function": "stb_mod_eucl",
               "all_library_functions_are_optimization_targets": False}
    (out / "CAPTURE.json").write_bytes(_wire(receipt) + b"\n")
    return baseline, receipt
