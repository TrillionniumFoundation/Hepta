"""Direct tail self-call fixtures, independent VM observations and native gates.

The VM reference retains recursive calls; it is not replaced with the native
    tail lowering. A separate deep native case has a closed integer oracle and an
explicit VM call-budget refusal, rather than a fictitious VM deep-call pass.
"""
from __future__ import annotations

from hashlib import sha256

from tools.hia_selfhost_cases import HEADER


def scalar_tail_source(count=63, *, large_frame=False):
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        raise ValueError("u32 iteration count required")
    source = (HEADER + f'  v3:u32 = const() {{"value":{count}}}\n'
        '  v4:u32 = const() {"value":17}\n'
        '  v5:u32 = const() {"value":83}\n'
        '  v6:u32 = call(v3,v4,v5) {"function":"f1"}\n'
        '  ret(v6)\nend\n'
        'fn f1(v0:u32,v1:u32,v2:u32) -> (u32) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:u32,v1:u32,v2:u32)\n'
        '  v3:u32 = const() {"value":0}\n')
    if large_frame:
        source += '  v2047:u32 = const() {"value":0}\n'
    source += ('  v4:bool = compare.eq(v0,v3)\n'
        '  branch v4 b1(v1,v2) b2(v0,v1,v2)\n'
        'block b1(v5:u32,v6:u32)\n'
        '  v7:u32 = const() {"value":257}\n'
        '  v8:u32 = int.mul.wrap(v5,v7)\n'
        '  v9:u32 = int.add.wrap(v8,v6)\n'
        '  ret(v9)\n'
        'block b2(v10:u32,v11:u32,v12:u32)\n'
        '  v13:u32 = const() {"value":1}\n'
        '  v14:u32 = int.sub.wrap(v10,v13)\n'
        '  v16:u32 = int.add.wrap(v11,v10)\n'
        '  v15:u32 = call(v14,v12,v16) {"function":"f1"}\n'
        '  ret(v15)\nend\n')
    return source.encode()


def scalar_tail_expected(count):
    pairs = count // 2
    left, right = ((83 + pairs * (pairs + 1), 17 + (pairs + 1) ** 2) if count % 2
                   else (17 + pairs * (pairs + 1), 83 + pairs ** 2))
    return (left * 257 + right) & 0xffffffff


def buffer_tail_source():
    return (HEADER + '  v3:usize = const() {"value":0}\n'
        '  v4:u32 = const() {"value":0}\n'
        '  v5:u32 = call(v0,v1,v3,v4) {"function":"f1"}\n'
        '  ret(v5)\nend\n'
        'fn f1(v0:readbuf,v1:mutbuf,v2:usize,v3:u32) -> (u32) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:readbuf,v1:mutbuf,v2:usize,v3:u32)\n'
        '  v4:usize = buffer.len(v0)\n'
        '  v5:bool = compare.ge(v2,v4)\n'
        '  branch v5 b1(v0,v1,v3) b2(v0,v1,v2,v3)\n'
        'block b1(v6:readbuf,v7:mutbuf,v8:u32)\n'
        '  ret(v8)\n'
        'block b2(v9:readbuf,v10:mutbuf,v11:usize,v12:u32)\n'
        '  v13:u8 = buffer.load(v9,v11)\n'
        '  _ = buffer.store(v10,v11,v13)\n'
        '  v14:u32 = int.cast(v13) {"mode":"wrap"}\n'
        '  v15:u32 = int.add.wrap(v12,v14)\n'
        '  v16:usize = const() {"value":1}\n'
        '  v17:usize = int.add.wrap(v11,v16)\n'
        '  v18:u32 = call(v9,v10,v17,v15) {"function":"f1"}\n'
        '  ret(v18)\nend\n').encode()


def tail_refusals():
    scalar = scalar_tail_source()
    # The first three are legal general Core, but fail this profile's exact
    # tail position/result rule. All are refused before output is written.
    wrong_result = scalar.replace(b'  ret(v15)\n', b'  ret(v14)\n')
    continuation = scalar.replace(b'  ret(v15)\n',
        b'  v17:u32 = int.add.wrap(v15,v13)\n  ret(v17)\n')
    edge = scalar.replace(b'  ret(v15)\nend\n',
        b'  jump b3(v15)\nblock b3(v18:u32)\n  ret(v18)\nend\n')
    wrong_type = scalar.replace(b'  v15:u32 = call(v14,v12,v16)',
        b'  v17:bool = const() {"value":false}\n  v15:u32 = call(v17,v12,v16)')
    mut_alias = (HEADER + '  v3:u32 = const() {"value":1}\n'
        '  v4:u32 = call(v1,v2,v3) {"function":"f1"}\n  ret(v4)\nend\n'
        'fn f1(v0:mutbuf,v1:mutbuf,v2:u32) -> (u32) effects(read,write,trap) entry(b0)\n'
        'block b0(v0:mutbuf,v1:mutbuf,v2:u32)\n'
        '  v3:u32 = call(v0,v0,v2) {"function":"f1"}\n  ret(v3)\nend\n').encode()
    return {
        "returned-other-value": (wrong_result, True),
        "instruction-after-call": (continuation, True),
        "edge-after-call": (edge, True),
        "missing-argument": (scalar.replace(b'call(v14,v12,v16)', b'call(v14,v12)'), False),
        "wrong-argument-type": (wrong_type, False),
        "mutable-call-alias": (mut_alias, False),
    }


def buffer_reference_document(data):
    """Same recursive helper, independent owned VM initialization/inspection."""
    from hepta.hia_agent_assembly import assemble_program
    doc = assemble_program(buffer_tail_source()).as_dict()
    ops, serial = [], 0

    def op(code, args, typ=None, **attrs):
        nonlocal serial
        result = f"v{serial}" if typ else None
        if typ:
            serial += 1
        ops.append({"op": code, "args": args,
            "out": [{"name": result, "type": typ}] if typ else [], "attrs": attrs})
        return result

    size = op("const", [], "usize", value=len(data))
    src_owner = op("buffer.new", [size], "buffer")
    src_init = op("borrow.mut", [src_owner], "mutbuf")
    for index, byte in enumerate(data):
        offset = op("const", [], "usize", value=index)
        value = op("const", [], "u8", value=byte)
        op("buffer.store", [src_init, offset, value])
    op("loan.end", [src_init])
    src = op("borrow.read", [src_owner], "readbuf")
    dst_owner = op("buffer.new", [size], "buffer")
    dst = op("borrow.mut", [dst_owner], "mutbuf")
    zero = op("const", [], "usize", value=0)
    total = op("const", [], "u32", value=0)
    result = op("call", [src, dst, zero, total], "u32", function="f1")
    values = [result]
    for index in range(len(data)):
        offset = op("const", [], "usize", value=index)
        values.append(op("buffer.load", [dst, offset], "u8"))
    op("loan.end", [src])
    op("loan.end", [dst])
    op("owner.drop", [src_owner])
    op("owner.drop", [dst_owner])
    doc["module"] = "tail_resource_reference"
    doc["functions"][0] = {"name": "f0", "params": [],
        "returns": ["u32", *(["u8"] * len(data))],
        "effects": ["alloc", "read", "write", "trap"], "entry": "b0",
        "blocks": [{"id": "b0", "params": [], "ops": ops,
                    "term": {"op": "ret", "values": values}}]}
    return doc


def independent_tail_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramBudgetExceeded
    observations = []
    for count in (0, 1, 62, 63, 127):
        source = scalar_tail_source(count)
        checked = assemble_program(source)
        scalar = checked.as_dict()
        scalar["functions"][0]["params"] = []
        scalar["functions"][0]["blocks"][0]["params"] = []
        result = execute_program(scalar, "f0", [])
        expected = scalar_tail_expected(count)
        if result["result"] != expected:
            raise AssertionError("recursive VM disagrees with parallel argument oracle")
        observations.append({"case": f"scalar-{count}", "source_sha256": sha256(source).hexdigest(),
            "general_core_sha256": checked.sha256, "count": count,
            "expected_result": expected, "reference_result": result,
            "scalar_boundary_change": "remove unused three borrowed f0 parameters only"})
    buffers = []
    for data in (b"", b"tail loans", bytes(range(32))):
        result = execute_program(buffer_reference_document(data), "f0", [])
        if result["values"] != [sum(data), *data]:
            raise AssertionError("recursive resource VM disagrees with byte-copy oracle")
        buffers.append({"input_hex": data.hex(), "expected_result": sum(data),
            "expected_output_hex": data.hex(), "reference_result": result,
            "boundary_change": "owned VM f0 initializes/inspects buffers; f1 unchanged"})
    deep = scalar_tail_source(1000001, large_frame=True)
    scalar = assemble_program(deep).as_dict()
    scalar["functions"][0]["params"] = []
    scalar["functions"][0]["blocks"][0]["params"] = []
    try:
        execute_program(scalar, "f0", [], max_call_depth=64)
    except HIAProgramBudgetExceeded as exc:
        deep_reference = exc.report
    else:
        raise AssertionError("recursive VM unexpectedly passed its declared call limit")
    rejections = []
    for name, (source, general_accepted) in tail_refusals().items():
        try:
            checked = assemble_program(source)
        except HIAProgramRejected as exc:
            if general_accepted:
                raise
            rejections.append({"case": name, "general_core": "rejected", "code": exc.code})
        else:
            if not general_accepted:
                raise AssertionError("general checker admitted invalid tail fixture " + name)
            rejections.append({"case": name, "general_core": "accepted", "core_sha256": checked.sha256})
    return {"scalar_cases": observations, "buffer_cases": buffers, "rejections": rejections,
        "deep_case": {"count": 1000001, "source_sha256": sha256(deep).hexdigest(),
            "expected_result": scalar_tail_expected(1000001), "ssa_index_max": 2047,
            "native_frame_bytes": (2047 + 2) * 16 + 544,
            "reference_result": deep_reference,
            "claim": "deep native integer recurrence and fixed stack gate; VM call-budget refusal retained"}}


def qualify_tailcalls(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, compile_stage, invoke,
                                          inspect_selfhost_object, digest)
    observations = []
    for label, compiler in compilers:
        for case in reference["scalar_cases"]:
            name = f'{label}-tail-{case["case"]}'
            image, build = compile_stage(directory, name, compiler, scalar_tail_source(case["count"]), workspace_fill=0xa7)
            result, _ = invoke(directory, name + "-run", image, b"", capacity=0, workspace_size=0)
            checks[name] = bool(result.get("status") == "returned" and result.get("core_u32") == case["expected_result"])
            observations += [build, result]
        name = label + "-tail-buffer"
        image, build = compile_stage(directory, name, compiler, buffer_tail_source())
        observations.append(build)
        for index, case in enumerate(reference["buffer_cases"]):
            data = bytes.fromhex(case["input_hex"])
            result, output = invoke(directory, name + "-run-" + str(index), image, data,
                capacity=len(data), workspace_size=0)
            checks[name + "-" + str(index)] = bool(result.get("status") == "returned"
                and result.get("core_u32") == case["expected_result"] and result.get("source_unchanged")
                and output.hex() == case["expected_output_hex"])
            observations.append(result)
        obj, obj_build = compile_stage(directory, name + "-elf", compiler,
            buffer_tail_source().replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
        inspection = inspect_selfhost_object(obj.read_bytes())
        checks[name + "-elf-text"] = inspection["text_sha256"] == digest(image.read_bytes())
        observations.append({**obj_build, "object_inspection": inspection})
        result, _ = invoke(directory, name + "-short-output", compiler, buffer_tail_source(),
            capacity=build["produced_bytes"] - 1)
        checks[name + "-transactional"] = bool(result.get("status") == "returned"
            and result.get("core_u32") == NO_SPACE and result.get("output_unchanged"))
        observations.append(result)
        deep = reference["deep_case"]
        name = label + "-tail-deep-large-frame"
        image, build = compile_stage(directory, name, compiler,
            scalar_tail_source(deep["count"], large_frame=True))
        result, _ = invoke(directory, name + "-run", image, b"", capacity=0, workspace_size=0)
        checks[name] = bool(result.get("status") == "returned"
            and result.get("core_u32") == deep["expected_result"]
            and result.get("limits", {}).get("stack_bytes") == 8 << 20)
        observations += [build, result]
        for case, (source, _) in tail_refusals().items():
            name = label + "-tail-refuse-" + case
            result, _ = invoke(directory, name, compiler, source)
            checks[name] = bool(result.get("status") == "returned" and result.get("core_u32") == INVALID
                and result.get("source_unchanged") and result.get("output_unchanged"))
            observations.append(result)
    return observations
