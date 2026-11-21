"""Author the HIA durable job receipt publisher and its ELF packer."""
from __future__ import annotations

import ast
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_native_filter import bind_adapter, document as packer_document, elf_header
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/job_receipt.hepta'
PACKER_PATH = 'examples/hia_bootstrap/job_receipt_packer.hepta'
ADAPTER_PATH = 'tools/hia_job_receipt_syscalls.S'
PACKER_MAGIC = int.from_bytes(b'HIAJPK01', 'little')
REQUEST_MAGIC = int.from_bytes(b'HIAJRQ01', 'little')
TERMINAL_MAGIC = int.from_bytes(b'HIAJRQ02', 'little')
OWNER_MAGIC = int.from_bytes(b'HIAJRO01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAJRW01', 'little')

SOURCE = f'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 35 and uint(s, 0, 8) == {OWNER_MAGIC}:
        return advance_owner(s, o, w)
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        if prepare(s, o, observed(w, 16)) == 0:
            return 0
    elif result >> 63 != 0 or phase == 6:
        return acknowledge(o, phase, result)
    phase = phase + 1
    put(w, 0, phase, 8)
    return phase

def acknowledge(o:mutbuf, phase:u64, result:u64) -> u64:
    put(o, 0, {RESULT_MAGIC}, 8)
    put(o, 8, phase, 8)
    put(o, 16, result, 8)
    return 7

def advance_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        size = length(s)
        if size > 65568 or length(o) < 352 or uint(s, 8, 8) != size - 32:
            return 0
        pid = uint(s, 16, 8)
        if pid == 0 or pid > 2147483647 or pid != observed(w, 16) or uint(s, 24, 8) != 0:
            return 0
        if byte(s, 32) != 123 or byte(s, size - 1) != 125:
            return 0
        put(o, 24, 32, 8)
        put(o, 192, {int.from_bytes(b'owner-in', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'tent.jso', 'little')}, 8)
        put(o, 208, 110, 2)
    elif phase > 9:
        return 0
    elif result >> 63 != 0:
        return acknowledge(o, phase, result)
    elif phase == 9:
        return acknowledge(o, 6, result)
    elif phase == 4:
        # O_EXCL on each original name. The one directory barrier follows
        # both independently synced and closed records.
        put(o, 192, {int.from_bytes(b'started.', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'json', 'little')}, 5)
    put(w, 0, phase + 1, 8)
    if phase < 3:
        return phase + 1
    if phase == 3 or phase == 7:
        return 8
    if phase < 7:
        return phase - 3
    return 6

def prepare(s:readbuf, o:mutbuf, parent:u64) -> u64:
    size = length(s)
    if size < 35 or size > 4194464 or length(o) < 352:
        return 0
    magic = uint(s, 0, 8)
    if magic != {REQUEST_MAGIC} and magic != {TERMINAL_MAGIC}:
        return 0
    extent = uint(s, 8, 8)
    pid = uint(s, 16, 8)
    name_bytes = uint(s, 24, 8)
    if pid == 0 or pid > 2147483647 or pid != parent:
        return 0
    if extent < 2 or extent > 4194304 or name_bytes == 0 or name_bytes > 128:
        return 0
    start = 32 + name_bytes
    if size != start + extent:
        return 0
    if byte(s, start) != 123:
        return 0
    if magic == {TERMINAL_MAGIC}:
        if extent < 3 or extent > 1048576 or byte(s, size - 2) != 125 or byte(s, size - 1) != 10:
            return 0
        if name_bytes != 4 and name_bytes != 12:
            return 0
        if uint(s, 32, 4) != {int.from_bytes(b'exit', 'little')}:
            return 0
        if name_bytes == 12 and uint(s, 36, 8) != {int.from_bytes(b'.witness', 'little')}:
            return 0
    elif byte(s, size - 1) != 125:
        return 0
    at = 0
    while at < name_bytes:
        value = byte(s, 32 + at)
        if allowed(value) == 0:
            return 0
        store(o, 32 + at, value)
        store(o, 192 + at, value)
        at = at + 1
    put(o, 32 + at, {int.from_bytes(b'.json', 'little')}, 5)
    put(o, 192 + at, {int.from_bytes(b'.json.tm', 'little')}, 8)
    store(o, 200 + at, 112)
    store(o, 201 + at, 46)
    append_decimal(o, 202 + at, pid)
    put(o, 24, start, 8)
    return 1

def allowed(byte:u64) -> u64:
    if byte >= 48 and byte <= 57:
        return 1
    if (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122):
        return 1
    if byte == 45 or byte == 46 or byte == 64 or byte == 95:
        return 1
    return 0

def append_decimal(o:mutbuf, at:u64, value:u64) -> u64:
    divisor = 1
    while divisor <= value // 10:
        divisor = divisor * 10
    while divisor != 0:
        store(o, at, 48 + value // divisor)
        value = value % divisor
        divisor = divisor // 10
        at = at + 1
    store(o, at, 0)
    return 0

def uint(s:readbuf, start:u64, size:u64) -> u64:
    index = 0
    value = 0
    while index < size:
        value = value | (byte(s, start + index) << (index * 8))
        index = index + 1
    return value

def observed(w:mutbuf, start:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(w, start + index) << (index * 8))
        index = index + 1
    return value

def put(o:mutbuf, start:u64, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, start + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def document():
    nodes = ast.parse(SOURCE).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'job_receipt',
                                  'functions': functions})


def main():
    source = (ROOT / ADAPTER_PATH).read_bytes()
    with TemporaryDirectory(prefix='hia-job-receipt-adapter-') as directory:
        adapter, holes, _ = adapter_layout(Path(directory), ADAPTER_PATH, source, {'policy': 'policy_call_hole'})
    header = elf_header()
    hole = holes['policy']
    packer = packer_document(magic=PACKER_MAGIC, module='job_receipt_packer',
                             image_template=(header + adapter, (len(header) + hole,)))
    for path, item in ((SOURCE_PATH, document()), (PACKER_PATH, bind_adapter(packer, source, adapter, (hole,)))):
        (ROOT / path).write_text(render_assembly(item))


if __name__ == '__main__':
    main()
