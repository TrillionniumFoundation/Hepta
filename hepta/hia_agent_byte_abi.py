"""Opt-in copied-byte calls for the retained Agent lifecycle.

Wire values contain bytes, never pointers or owner capabilities. Each native
iteration and each reference invocation receives fresh, disjoint caller-owned
copies. Byte commitments are observations of one invocation, not semantic or
machine refinement proofs. The existing direct borrowed-byte wrapper defines
the native boundary; this adapter does not introduce another code generator.
"""
from __future__ import annotations

import base64
from hashlib import sha256

from .hia_agent_store import reject
from .hia_native_byte_abi import LOANS, MAX_EXTENT, normalize_exports

WORKLOAD_VERSION = "hepta.hia.agent.workload.v2"
ABI = "copied-borrowed-bytes.v1"
MAX_BATCH_BYTES = 4 * 1024 * 1024


def byte_value(data):
    return {"kind": "bytes", "base64": base64.b64encode(data).decode("ascii")}


def decode_bytes(value, maximum=MAX_EXTENT):
    if (type(value) is not dict or set(value) != {"kind", "base64"}
            or value.get("kind") != "bytes" or type(value.get("base64")) is not str
            or len(value["base64"]) > 4 * ((maximum + 2) // 3)):
        reject("E_HIA_ARGUMENTS", "borrowed arguments require bounded canonical base64 byte values")
    try:
        data = base64.b64decode(value["base64"], validate=True)
    except (ValueError, UnicodeError):
        reject("E_HIA_ARGUMENTS", "borrowed argument is not canonical base64")
    if len(data) > maximum or byte_value(data) != value:
        reject("E_HIA_ARGUMENTS", "borrowed argument exceeds its extent or is not canonical base64")
    return data


def workload_exports(workload, program=None):
    if workload["schema"] != WORKLOAD_VERSION:
        return ()
    reference_steps = workload.get("reference_max_steps", 1_000_000)
    if type(reference_steps) is not int or not 1 <= reference_steps <= 10_000_000:
        reject("E_HIA_BUDGET", "reference step budget requires an exact integer in 1..10000000")
    exports = tuple((row["function"], row["maximum_bytes"])
                    for row in workload["foreign_buffer_exports"])
    if len({name for name, _ in exports}) != len(exports):
        reject("E_HIA_ABI", "borrowed-byte exports must name each function exactly once")
    if any(type(extent) is not int or not 1 <= extent <= MAX_EXTENT for _, extent in exports):
        reject("E_HIA_ABI", "borrowed-byte export extents require exact bounded integers")
    total = 0
    for case in workload["cases"]:
        for value in case["arguments"]:
            if type(value) is dict:
                total += len(decode_bytes(value))
                if total > MAX_BATCH_BYTES:
                    reject("E_HIA_BUDGET", "frozen workload exceeds 4 MiB of copied input bytes")
    return tuple(sorted(exports)) if program is None else normalize_exports(exports, program)


def byte_signatures(program, exports):
    functions = {fn["name"]: fn for fn in program.as_dict()["functions"]}
    return {name: {"params": [p["type"] for p in functions[name]["params"]],
                   "returns": functions[name]["returns"], "abi": ABI,
                   "maximum_bytes": maximum}
            for name, maximum in normalize_exports(exports, program)}


def decode_arguments(signature, arguments):
    """Snapshot exact typed values before launching an owned native child."""
    from .hia_native_byte_runner import _arguments
    from .hia_program import scalar_value_valid
    if type(arguments) not in (tuple, list) or len(arguments) != len(signature["params"]):
        reject("E_HIA_ARGUMENTS", "call does not match the retained entry ABI")
    arguments = tuple(arguments)
    if signature.get("abi") != ABI:
        if not all(scalar_value_valid(value, typ) for value, typ in zip(arguments, signature["params"])):
            reject("E_HIA_ARGUMENTS", "call arguments do not have the exact declared scalar types")
        return arguments
    values = tuple(decode_bytes(value, signature["maximum_bytes"]) if typ in LOANS else value
                   for typ, value in zip(signature["params"], arguments))
    # Use the existing byte runner's exact scalar/loan argument admission.
    try:
        _arguments({"params": [{"type": typ} for typ in signature["params"]]},
                   values, signature["maximum_bytes"])
    except ValueError as exc:
        reject("E_HIA_ARGUMENTS", str(exc))
    if sum(len(value) for typ, value in zip(signature["params"], values) if typ in LOANS) > MAX_BATCH_BYTES:
        reject("E_HIA_BUDGET", "one copied-byte invocation exceeds 4 MiB")
    return values


def validate_cases(signatures, cases):
    total = 0
    for case in cases:
        signature = signatures.get(case["function"])
        if signature is None:
            reject("E_HIA_ARGUMENTS", "workload entry is absent from the retained public ABI")
        values = decode_arguments(signature, case["arguments"])
        total += sum(len(value) for typ, value in zip(signature["params"], values) if typ in LOANS)
        if total > MAX_BATCH_BYTES:
            reject("E_HIA_BUDGET", "native batch exceeds 4 MiB of copied input bytes")


def byte_observations(types, values):
    return [{"argument": index, "bytes": len(value), "sha256": sha256(value).hexdigest()}
            for index, (typ, value) in enumerate(zip(types, values)) if typ in LOANS]


def reference_observation(program, signature, case, *, steps=1_000_000, heap=16 * 1024 * 1024):
    """Use the existing Core interpreter on independent external byte copies.

External copies have no Core allocation/owner/loan events. Internally allocated
Core resources keep their ordinary ledger. Traps and budget stops publish no
completed byte result. The input-copy bytes are accounted separately.
    """
    from .hia_program import HIAProgramRejected
    from .hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap, HIAProgramBudgetExceeded
    values = decode_arguments(signature, case["arguments"])
    machine = _Machine(program, steps, heap, None, 256)
    function = machine.functions[case["function"]]
    owners, arguments = {}, []
    for index, (typ, value) in enumerate(zip(signature["params"], values)):
        if typ in LOANS:
            # Negative caller-local IDs cannot collide with Core-owned IDs;
            # these inputs are deliberately absent from machine.owners.
            owner = _Owner(-index - 1, bytearray(value))
            owners[index] = owner
            arguments.append(_View(owner, typ == "mutbuf"))
        else:
            arguments.append(value)

    def report(status, returned=None, error=None):
        result = machine.report(case["function"], status, returned, error)
        result["external_input_copies"] = {"bytes": sum(len(owner.data) for owner in owners.values()),
            "ranges": len(owners), "scope": "separate private copies; excluded from Core resource events"}
        return result

    try:
        returned = machine.invoke(function, arguments)
    except HIAProgramTrap as exc:
        return {"status": "trapped", "trap_code": exc.code, "ledger": report("trapped", error=exc)}
    except HIAProgramBudgetExceeded as exc:
        return {"status": "budget_exceeded", "budget_code": exc.code,
                "ledger": report("budget_exceeded", error=exc)}
    except RecursionError:
        exc = HIAProgramBudgetExceeded("calls", "host recursion limit reached")
        return {"status": "budget_exceeded", "budget_code": exc.code,
                "ledger": report("budget_exceeded", error=exc)}
    if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
        raise HIAProgramRejected("successful borrowed entry leaked a verified local resource", "E_HIA_RUNTIME_INVARIANT")
    output = [bytes(owners[index].data) if index in owners else value for index, value in enumerate(values)]
    if any(typ == "readbuf" and output[index] != values[index] for index, typ in enumerate(signature["params"])):
        raise HIAProgramRejected("borrowed reference changed a read-only input", "E_HIA_RUNTIME_INVARIANT")
    return {"status": "returned", "values": returned,
            "buffers": byte_observations(signature["params"], output), "ledger": report("returned", returned)}
