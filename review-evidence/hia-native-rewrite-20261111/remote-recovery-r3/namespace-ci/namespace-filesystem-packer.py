"""HIA packer for the private namespace filesystem syscall carrier.

NEW source. Generating/compiling this packer is not proof that the fixed carrier
or complete namespace storage has executed. The retained 1 MiB image limit is
the original compiler image ABI; it is not a namespace data/descriptor quota.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import struct
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b"HIANPX03", "little")
EXECUTOR_SOURCE_SHA256 = "fb28a7a44448c06fb12654ae8bf6b06fb19be30a4fb7556cf0a7c038b522b90e"
MAX_IMAGE = 1 << 20

def prefix_and_table(source: bytes, binary: bytes, layout: dict):
    assert sha256(source).hexdigest() == EXECUTOR_SOURCE_SHA256
    assert layout["source_sha256"] == EXECUTOR_SOURCE_SHA256
    assert sha256(binary).hexdigest() == layout["template_sha256"]
    assert len(binary) == layout["template_bytes"]
    assert layout["entry"] == 0 and layout["end"] == len(binary)
    assert layout["relocation_count"] == 0
    table = layout["image_table"]
    assert 0 <= table <= len(binary) - 16 and table % 16 == 0
    assert binary[table:table + 16] == bytes(16)
    header = (
        b"\x7fELF\x02\x01\x01" + bytes(9)
        + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    )
    assert len(header) == 176
    return header + binary, 176 + table

def source_program(prefix: bytes, table: int):
    assert 0 <= table <= len(prefix) - 16
    assert prefix[table:table + 16] == bytes(16)
    start = (len(prefix) + 15) & ~15
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > {64 + MAX_IMAGE}:
        return 4294967295
    if read64(s, 0) != {MAGIC} or read64(s, 8) != 3:
        return 4294967295
    size = read64(s, 16)
    if size == 0 or size > {MAX_IMAGE} or size != length(s) - 64:
        return 4294967295
    if read64(s, 24) != length(s):
        return 4294967295
    at = 32
    while at < 64:
        if read64(s, at) != 0:
            return 4294967295
        at = at + 8
    total = {start} + size
    if length(o) < total:
        return 4294967294
"""
    for number, _ in enumerate(range(0, len(prefix), 256)):
        source += f"    literal_{number}(o)\n"
    source += f"""    put(o, 96, total)
    put(o, 104, total)
    put(o, {table + 8}, {0x400000 + start})
    at = {len(prefix)}
    while at < {start}:
        store(o, at, 0)
        at = at + 1
    at = 0
    while at < size:
        store(o, {start} + at, byte(s, 64 + at))
        at = at + 1
    return total
"""
    for number, first in enumerate(range(0, len(prefix), 256)):
        source += f"\ndef literal_{number}(o:mutbuf) -> u64:\n"
        end = min(first + 256, len(prefix))
        for at in range(first, end, 8):
            raw = prefix[at:min(at + 8, end)]
            if len(raw) == 8:
                source += f"    put(o, {at}, {int.from_bytes(raw, 'little')})\n"
            else:
                for offset, value in enumerate(raw, at):
                    source += f"    store(o, {offset}, {value})\n"
        source += "    return 0\n"
    return source + VALUES[VALUES.index("\ndef read64("):]

def document(prefix: bytes, table: int):
    nodes = ast.parse(source_program(prefix, table)).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    assert len(names) == len(nodes)
    signatures = {
        node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
        for node in nodes
    }
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            "name": names[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks,
        })
    return compact_authoring_cfg({
        "schema": "hepta.hia.program.v8", "module": "namespace_filesystem_native_packer",
        "functions": functions,
    })
