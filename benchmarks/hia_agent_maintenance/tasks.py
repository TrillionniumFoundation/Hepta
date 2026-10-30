"""Fresh authored maintenance contracts; author controls are not model output.

The surrounding functions are a disclosed synthetic maintenance fixture. Their
number is fixed here, not selected after a model or token comparison. Hidden
cases, oracles and author patches must never be sent to a prospective model.
"""
from __future__ import annotations

from copy import deepcopy

MASK = (1 << 32) - 1
TASKS = (
    {"id": "wrapped_stride", "focus": ["stride"],
     "description": "Maintain target(x:u32,y:u32)->u32. Let step=y modulo 13 + 1. Return (x*step + (y XOR 0xA5A5A5A5)) modulo 2^32 for all u32 inputs. The current stride helper incorrectly traps on some legitimate inputs. Repair that helper, preserving every function interface and all other function bodies.",
     "public": [[0, 0], [1, 13], [4294967295, 2], [2147483648, 5]],
     "resource_witness": False},
    {"id": "returned_view_byte", "focus": ["store_then_view"],
     "description": "Maintain target(x:u32,y:u32)->u32. The caller allocates a zeroed buffer of size n=x modulo 7 + 1, computes position y modulo n and byte (x+y) modulo 256, invokes store_then_view, reads the returned shared view, and releases the returned view, parent view and owner. Return 256*n + byte. The store_then_view helper currently loses the high bit of byte. Repair only its body, retain its exact returned-loan origin contract, and preserve actual store/read/release behavior. Scalar replacement of the resource behavior is forbidden.",
     "public": [[0, 0], [1, 127], [6, 255], [4294967295, 2]],
     "resource_witness": True},
)


def param(name, typ="u32"):
    return {"name": name, "type": typ}


def op(kind, args=(), output=None, typ="u32", **attrs):
    return {"op": kind, "args": list(args), "out": [] if output is None else [param(output, typ)],
            "attrs": attrs}


def const(name, value, typ="u32"):
    return op("const", output=name, typ=typ, value=value)


def function(name, params, returns, effects, operations, returned, *, origins=None):
    parameters = [param(*p) if isinstance(p, tuple) else param(p) for p in params]
    result = {"name": name, "params": parameters, "returns": returns, "effects": effects,
              "entry": "entry", "blocks": [{"id": "entry", "params": deepcopy(parameters),
                "ops": operations, "term": {"op": "ret", "values": list(returned)}}]}
    if origins is not None:
        result["return_loans"] = origins
    return result


def background():
    # Fixed synthetic surrounding bodies; these are not extra sampled tasks.
    return [function(f"background_{index:02d}", ["value"], ["u32"], [],
        [const("factor", 2 * index + 1), const("bias", 31 * index + 7),
         op("int.mul.wrap", ["value", "factor"], "scaled"),
         op("int.add.wrap", ["scaled", "bias"], "result")], ["result"])
        for index in range(24)]


def source(task_id):
    if task_id == "wrapped_stride":
        helper = function("stride", ["x", "y"], ["u32"], ["trap"], [
            const("modulus", 13), const("one", 1), const("salt", 0xA5A5A5A5),
            op("int.rem.checked", ["y", "modulus"], "remainder"),
            op("int.add.checked", ["remainder", "one"], "step"),
            op("int.mul.checked", ["x", "step"], "product"),
            op("bit.xor", ["y", "salt"], "bias"),
            op("int.add.wrap", ["product", "bias"], "result")], ["result"])
        target = function("target", ["x", "y"], ["u32"], ["trap"],
            [op("call", ["x", "y"], "result", function="stride")], ["result"])
    elif task_id == "returned_view_byte":
        helper = function("store_then_view", [("writer", "mutbuf"), ("position", "usize"), ("byte", "u8")],
            ["readbuf"], ["write", "trap"], [const("mask", 127, "u8"),
             op("bit.and", ["byte", "mask"], "clipped", "u8"),
             op("buffer.store", ["writer", "position", "clipped"]),
             op("borrow.read", ["writer"], "view", "readbuf")], ["view"], origins=["writer"])
        target = function("target", ["x", "y"], ["u32"], ["alloc", "read", "write", "trap"], [
            const("seven", 7), const("one", 1), const("tag", 256),
            op("int.rem.checked", ["x", "seven"], "n0"),
            op("int.add.checked", ["n0", "one"], "n"),
            op("int.rem.checked", ["y", "n"], "position32"),
            op("int.cast", ["n"], "size", "usize", mode="checked"),
            op("int.cast", ["position32"], "position", "usize", mode="checked"),
            op("int.add.wrap", ["x", "y"], "total"),
            op("int.cast", ["total"], "byte", "u8", mode="wrap"),
            op("buffer.new", ["size"], "owner", "buffer"),
            op("borrow.mut", ["owner"], "writer", "mutbuf"),
            op("call", ["writer", "position", "byte"], "view", "readbuf", function="store_then_view"),
            op("buffer.load", ["view", "position"], "readback", "u8"),
            op("loan.end", ["view"]), op("loan.end", ["writer"]), op("owner.drop", ["owner"]),
            op("int.cast", ["readback"], "wide", mode="checked"),
            op("int.mul.checked", ["n", "tag"], "prefix"),
            op("int.add.checked", ["prefix", "wide"], "result")], ["result"])
    else:
        raise ValueError("unregistered fresh maintenance task")
    return {"schema": "hepta.hia.program.v8", "module": "maintenance_" + task_id,
            "exports": ["target"], "functions": [target, helper, *background()]}


def oracle(task_id, x, y):
    if task_id == "wrapped_stride":
        # Mathematical modular arithmetic, independent of the fixture's CFG.
        return (x * (1 + y % 13) + (y ^ 0xA5A5A5A5)) % (1 << 32)
    if task_id == "returned_view_byte":
        memory = [0] * (x % 7 + 1)
        position = y % len(memory)
        memory[position] = (x + y) % 256
        return 256 * len(memory) + memory[position]
    raise ValueError("unregistered fresh maintenance task")


def cases(task, *, hidden=False):
    if not hidden:
        return deepcopy(task["public"])
    state = 0xC39D20A7
    values = [[MASK, MASK], [MASK, 0], [127, 1], [128, 0], [7, 248], [6, 122]]
    for _ in range(24):
        state = (1664525 * state + 1013904223) & MASK
        x = state
        state = (1664525 * state + 1013904223) & MASK
        values.append([x, state])
    return values


def author_patch(task_id, snapshot_sha256):
    """Positive harness control only. Never expose to prospective model input."""
    original = source(task_id)
    helper = original["functions"][1]
    index = 5 if task_id == "wrapped_stride" else 2
    operation = deepcopy(helper["blocks"][0]["ops"][index])
    if task_id == "wrapped_stride":
        operation["op"] = "int.mul.wrap"
    else:
        operation["args"][-1] = "byte"
    return {"schema": "hepta.hia.patch.v1", "expected_sha256": snapshot_sha256,
            "edits": [{"action": "replace_operation", "function": helper["name"],
                       "block": "entry", "index": index, "operation": operation}]}
