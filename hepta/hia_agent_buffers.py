"""Owned byte snapshots for the Agent's explicit borrowed-buffer call profile.

The wire carries bytes, never native addresses, aliases, ownership capabilities
or paths.  The disposable native child supplies distinct live allocations.  The
reference adapter supplies distinct external roots to the existing Core VM;
external storage is reported separately from Core's allocation/loan ledger.
This adapter is finite execution evidence, not a new equivalence theorem.
"""
from __future__ import annotations

from hashlib import sha256
import os
import re

from .hia_agent_store import reject
from .hia_native_byte_abi import LOANS, MAX_EXTENT, normalize_exports


PROFILE = "hepta.hia.agent.borrowed-byte-snapshots.v1"
MAX_WORKLOAD_BUFFER_BYTES = 32 * 1024 * 1024


def export_manifest(workload):
    if workload["schema"] == "hepta.hia.agent.workload.v1":
        return ()
    if workload["schema"] != "hepta.hia.agent.workload.v2":
        reject("E_HIA_WORKLOAD", "unknown invocation workload profile")
    exports = tuple((row["function"], row["max_buffer_bytes"])
                    for row in workload["foreign_buffer_exports"])
    if len({name for name, _ in exports}) != len(exports):
        reject("E_HIA_BYTE_ABI", "duplicate borrowed-buffer export name")
    for name, extent in exports:
        if (type(name) is not str or type(extent) is not int
                or not 1 <= extent <= MAX_EXTENT):
            reject("E_HIA_BYTE_ABI", "invalid frozen borrowed-buffer export")
    return tuple(sorted(exports))


def _buffer_size_reference(value):
    """Validate one immutable-value descriptor before allocating any bytes."""
    if type(value) is not dict:
        reject("E_HIA_ARGUMENTS", "borrowed arguments require a byte snapshot")
    if set(value) == {"bytes_hex"}:
        data = value["bytes_hex"]
        if (type(data) is not str or len(data) > 2 * MAX_EXTENT
                or len(data) % 2 or re.fullmatch("[0-9a-f]*", data) is None):
            reject("E_HIA_ARGUMENTS", "buffer bytes must be bounded canonical lowercase hex")
        return len(data) // 2
    if set(value) == {"byte_length", "fill_byte"}:
        size, fill = value["byte_length"], value["fill_byte"]
        if (type(size) is not int or not 0 <= size <= MAX_EXTENT
                or type(fill) is not int or not 0 <= fill <= 255):
            reject("E_HIA_ARGUMENTS", "buffer fill requires exact bounded integer length and byte")
        return size
    reject("E_HIA_ARGUMENTS", "buffer snapshot has missing or unknown fields")


def _buffer_bytes_reference(value):
    size = _buffer_size_reference(value)
    return (bytes.fromhex(value["bytes_hex"]) if "bytes_hex" in value
            else bytes([value["fill_byte"]]) * size)


def buffer_size(value):
    manifest = os.environ.get('HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST')
    if manifest:
        from .hia_agent_snapshot_native import installed_snapshot
        return installed_snapshot(manifest).evaluate(value)
    return _buffer_size_reference(value)


def buffer_bytes(value):
    manifest = os.environ.get('HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST')
    if manifest:
        from .hia_agent_snapshot_native import installed_snapshot
        return installed_snapshot(manifest).evaluate(value, materialize=True)
    return _buffer_bytes_reference(value)


def validate_arguments(signature, arguments):
    from .hia_program import scalar_value_valid
    if type(arguments) not in (list, tuple) or len(arguments) != len(signature["params"]):
        reject("E_HIA_ARGUMENTS", "call does not match the frozen public ABI")
    total = 0
    for typ, value in zip(signature["params"], arguments):
        if typ in LOANS:
            if signature.get("abi") != PROFILE:
                reject("E_HIA_ABI", "borrowed entry is absent from the frozen invocation profile")
            size = buffer_size(value)
            if size > signature["max_buffer_bytes"]:
                reject("E_HIA_BUFFER_EXTENT", "snapshot exceeds the frozen wrapper extent")
            total += size
        elif not scalar_value_valid(value, typ):
            reject("E_HIA_ARGUMENTS", "call arguments do not have the exact declared scalar types")
    return total


def validate_cases(signatures, cases):
    total = 0
    for case in cases:
        signature = signatures.get(case["function"])
        if signature is None:
            reject("E_HIA_ABI", "workload names an unavailable public entry")
        total += validate_arguments(signature, case["arguments"])
        if total > MAX_WORKLOAD_BUFFER_BYTES:
            reject("E_HIA_BUFFER_BUDGET", "frozen workload exceeds 32 MiB of external byte snapshots")
    return total


def buffer_observation(index, typ, data):
    return {"argument": index, "kind": typ, "byte_length": len(data),
            "sha256": sha256(data).hexdigest()}


def reference_observation(program, case, exports, *, steps, heap):
    """Call the existing VM on separately owned, nonaliased external roots.

    These roots are not VM allocations and cannot be dropped by admitted Core.
    Caller loans remain live for the whole synchronous call; nested Core loans
    must end on a normal return.  Traps retain the actual bytes and resource
    state without pretending cleanup happened.
    """
    from .hia_program import HIAProgramRejected, verify_program
    from .hia_program_runtime import (_Machine, _Owner, _View,
                                     HIAProgramBudgetExceeded, HIAProgramTrap)
    checked = verify_program(program)
    admitted = dict(normalize_exports(exports, checked))
    function = case["function"]
    if function not in admitted:
        reject("E_HIA_BYTE_ABI", "reference call lacks an exact frozen buffer export")
    fn = next(fn for fn in checked.as_dict()["functions"] if fn["name"] == function)
    signature = {"params": [p["type"] for p in fn["params"]], "returns": fn["returns"],
                 "abi": PROFILE, "max_buffer_bytes": admitted[function]}
    validate_arguments(signature, case["arguments"])
    machine = _Machine(checked, steps, heap, None, 256)
    external, arguments = [], []
    for index, (typ, value) in enumerate(zip(signature["params"], case["arguments"])):
        if typ in LOANS:
            # Negative identities cannot collide with VM-owned allocations.
            root = _Owner(-index - 1, bytearray(buffer_bytes(value)))
            view = _View(root, typ == "mutbuf")
            external.append((index, typ, root, view))
            arguments.append(view)
        else:
            arguments.append(value)

    def report(status, *, values=None, error=None):
        # Caller capabilities survive both normal and stopped invocations.
        # Check their actual objects before admitting external backing into
        # the VM's aggregate report invariant; never charge them to its heap.
        if any(type(view) is not _View or view.active is not True
               or view.parent is not root or view.mutable is not (typ == "mutbuf")
               for _, typ, root, view in external):
            raise HIAProgramRejected("invalid external runtime views", "E_HIA_RUNTIME_INVARIANT")
        ledger = machine.report(function, status, values=values, error=error,
                                external_roots=tuple(root for _, _, root, _ in external))
        buffers = [buffer_observation(index, typ, root.data)
                   for index, typ, root, _ in external]
        ledger["external_buffers"] = {"profile": PROFILE,
            "byte_length": sum(row["byte_length"] for row in buffers),
            "distinct_roots": len(external), "included_in_core_heap_ledger": False}
        return {"status": status, "buffers": buffers, "ledger": ledger}

    try:
        values = machine.invoke(fn, arguments)
    except HIAProgramTrap as exc:
        return {**report("trapped", error=exc), "trap_code": exc.code}
    except HIAProgramBudgetExceeded as exc:
        return {**report("budget_exceeded", error=exc), "budget_code": exc.code}
    except RecursionError:
        limit = HIAProgramBudgetExceeded("calls", "host recursion limit reached")
        return {**report("budget_exceeded", error=limit), "budget_code": limit.code}
    if (machine.owners or machine.chains or machine.loans_started != machine.loans_ended
            or any(not root.active or not view.active for _, _, root, view in external)):
        raise HIAProgramRejected("successful borrowed entry leaked or consumed a resource",
                                 "E_HIA_RUNTIME_INVARIANT")
    for index, typ, root, _view in external:
        if typ == "readbuf" and bytes(root.data) != buffer_bytes(case["arguments"][index]):
            raise HIAProgramRejected("reference changed a read-only snapshot", "E_HIA_RUNTIME_INVARIANT")
    return {**report("returned", values=values), "values": values}
