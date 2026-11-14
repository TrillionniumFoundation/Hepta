"""HIA-owned ELF/startup layout for the explicit Linux process profile.

The CPU entry only captures and seals the actual kernel-startup storage, creates
fixed borrowed buffers/stack, calls the HIA program and exits. No .S file, host
assembler, payload JSON or environment-selection policy is consumed.
"""
from pathlib import Path
import ast
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_linux_stdio_entry import PackerBuilder
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
from hepta.hia_agent_assembly import render_assembly

LIMIT = 1048576
MAGIC = int.from_bytes(b'HIALNXE2', 'little')
CAP_MAGIC = int.from_bytes(b'HIALPRC1', 'little')
IMAGE_AT = 1024
ENTRY_AT = 232
DATA_BASE = 0x600000
OUTPUT_BASE = 0x601000
WORKSPACE_BASE = 0x701000
STACK_GUARD = 0x801000
STACK_BASE = 0x802000
STACK_TOP = 0x1002000
DATA_BYTES = STACK_TOP - DATA_BASE

SOURCE = r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != PACK_MAGIC or uint(s, 8, 8) != 1 or uint(s, 24, 8) != 0:
        return 4294967295
    image = uint(s, 16, 8)
    if image == 0 or image > 1047552 or length(s) != image + 32:
        return 4294967295
    file_size = (image + 1024 + 4095) & 18446744073709547520
    if file_size > 1048576 or length(o) < file_size:
        return 4294967294
    fill_range(o, 0, file_size, 0)
    headers(o, file_size)
    end = startup(o, 232)
    if end > 1024:
        return 4294967295
    copy_exact(o, s, 1024, 32, image)
    return file_size

def headers(o:mutbuf, file_size:u64) -> u64:
    write(o, 0, 282584257676671, 8)
    write(o, 16, 2, 2)
    write(o, 18, 62, 2)
    write(o, 20, 1, 4)
    write(o, 24, 4194536, 8)
    write(o, 32, 64, 8)
    write(o, 52, 64, 2)
    write(o, 54, 56, 2)
    write(o, 56, 3, 2)
    # Immutable file-backed executable text. No interpreter or RWX segment.
    write(o, 64, 1, 4)
    write(o, 68, 5, 4)
    write(o, 80, 4194304, 8)
    write(o, 88, 4194304, 8)
    write(o, 96, file_size, 8)
    write(o, 104, file_size, 8)
    write(o, 112, 4096, 8)
    # Zero BSS: capability page, output, workspace, guard page and 8MiB stack.
    write(o, 120, 1, 4)
    write(o, 124, 6, 4)
    write(o, 128, file_size, 8)
    write(o, 136, 6291456, 8)
    write(o, 144, 6291456, 8)
    write(o, 160, 10493952, 8)
    write(o, 168, 4096, 8)
    write(o, 176, 1685382481, 4)
    write(o, 180, 6, 4)
    write(o, 224, 16, 8)
    return 0

def startup(o:mutbuf, at:u64) -> u64:
    # Save the actual kernel stack before moving to our separate fixed stack.
    # mov r12,rsp; mov esp,STACK_TOP; xor ebp,ebp; cld; mov r13d,CAP.
    at = instruction(o, at, 0xe48949, 3)
    at = register32(o, at, 4, 16785408)
    at = instruction(o, at, 0xfced31, 3)
    at = register32(o, at, 13, 6291456)
    # PR_SET_DUMPABLE(0), preserving the previous native-child admission guard.
    at = register32(o, at, 7, 4)
    at = register32(o, at, 6, 0)
    at = instruction(o, at, 0xd231, 2)
    at = instruction(o, at, 0xd23145, 3)
    at = instruction(o, at, 0xc03145, 3)
    at = register32(o, at, 0, 157)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0xc08548, 3)
    fail1 = branch(o, at, 133)
    at = fail1 + 4
    # Store raw original stack, argc, argv and env-vector addresses. These
    # values come only from kernel entry, never a serialized caller descriptor.
    at = instruction(o, at, 0x0865894d, 4)
    at = instruction(o, at, 0x24048b49, 4)
    at = instruction(o, at, 0x10458949, 4)
    at = instruction(o, at, 0x0824748d4d, 5)
    at = instruction(o, at, 0x1875894d, 4)
    at = instruction(o, at, 0x10c47c8d4d, 5)
    at = instruction(o, at, 0x287d894d, 4)
    at = instruction(o, at, 0xd231, 2)
    env_loop = at
    # cmp qword[r15+rdx*8],0; count every entry, including empty/duplicate bytes.
    at = instruction(o, at, 0x00d73c8349, 5)
    env_done = branch(o, at, 132)
    at = env_done + 4
    at = instruction(o, at, 0xc2ff48, 3)
    at = jump(o, at, env_loop)
    patch(o, env_done, at)
    at = instruction(o, at, 0x20558949, 4)
    # Initial end covers both pointer terminators. Scan every non-null pointer
    # solely to find its NUL and the full mapped startup extent, without copies,
    # decoding, filtering, sorting, or an aggregate 1MiB admission ceiling.
    at = instruction(o, at, 0x08d75c8d49, 5)
    at = instruction(o, at, 0x104d8b49, 4)
    at = instruction(o, at, 0xd10148, 3)
    at = instruction(o, at, 0xc1ff48, 3)
    at = instruction(o, at, 0xf6894c, 3)
    pointer_loop = at
    at = instruction(o, at, 0xc98548, 3)
    pointers_done = branch(o, at, 132)
    at = pointers_done + 4
    at = instruction(o, at, 0x3e8b48, 3)
    at = instruction(o, at, 0x08c68348, 4)
    at = instruction(o, at, 0xc9ff48, 3)
    at = instruction(o, at, 0xff8548, 3)
    skip_null = branch(o, at, 132)
    at = skip_null + 4
    patch(o, skip_null, pointer_loop)
    string_loop = at
    at = instruction(o, at, 0x003f80, 3)
    string_done = branch(o, at, 132)
    at = string_done + 4
    at = instruction(o, at, 0xc7ff48, 3)
    at = jump(o, at, string_loop)
    patch(o, string_done, at)
    at = instruction(o, at, 0xc7ff48, 3)
    at = instruction(o, at, 0xdf3948, 3)
    at = instruction(o, at, 0xdf470f48, 4)
    at = jump(o, at, pointer_loop)
    patch(o, pointers_done, at)
    at = instruction(o, at, 0x305d8949, 4)
    # Seal every original startup page that the indexed primitive can touch.
    # Original RSP and the high end are kernel pointers, not public HIA values.
    at = instruction(o, at, 0xe7894c, 3)
    at = instruction(o, at, 0xfffff000e78148, 7)
    at = instruction(o, at, 0xde8948, 3)
    at = instruction(o, at, 0x00000fffc68148, 7)
    at = instruction(o, at, 0xfffff000e68148, 7)
    at = instruction(o, at, 0xfe2948, 3)
    at = register32(o, at, 2, 1)
    at = register32(o, at, 0, 10)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0xc08548, 3)
    fail2 = branch(o, at, 133)
    at = fail2 + 4
    # An inaccessible page separates the private program stack from workspace.
    at = register32(o, at, 7, 8392704)
    at = register32(o, at, 6, 4096)
    at = register32(o, at, 2, 0)
    at = register32(o, at, 0, 10)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0xc08548, 3)
    fail3 = branch(o, at, 133)
    at = fail3 + 4
    # Publish the capability only after the original storage is read-only.
    at = instruction(o, at, 0xb848, 2)
    write(o, at, STARTUP_MAGIC, 8)
    at = at + 8
    at = instruction(o, at, 0x00458949, 4)
    at = register32(o, at, 7, 6291456)
    at = register32(o, at, 6, 4096)
    at = register32(o, at, 2, 1)
    at = register32(o, at, 0, 10)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0xc08548, 3)
    fail4 = branch(o, at, 133)
    at = fail4 + 4
    # Preserve the six-argument HIA buffer ABI; startup storage is accessible
    # only through this profile's fixed primitive, not a writable public buffer.
    at = register32(o, at, 7, 4194304)
    at = register32(o, at, 6, 0)
    at = register32(o, at, 2, 6295552)
    at = register32(o, at, 1, 1048576)
    at = register32(o, at, 8, 7344128)
    at = register32(o, at, 9, 1048576)
    at = instruction(o, at, 232, 1)
    write(o, at, 1024 - at - 4, 4)
    at = at + 4
    at = instruction(o, at, 0xc789, 2)
    at = register32(o, at, 0, 60)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0x0b0f, 2)
    patch(o, fail1, at)
    patch(o, fail2, at)
    patch(o, fail3, at)
    patch(o, fail4, at)
    at = register32(o, at, 7, 126)
    at = register32(o, at, 0, 60)
    at = instruction(o, at, 0x050f, 2)
    at = instruction(o, at, 0x0b0f, 2)
    return at

def branch(o:mutbuf, at:u64, condition:u64) -> u64:
    store(o, at, 15)
    store(o, at + 1, condition)
    write(o, at + 2, 0, 4)
    return at + 2

def jump(o:mutbuf, at:u64, target:u64) -> u64:
    store(o, at, 233)
    write(o, at + 1, target - at - 5, 4)
    return at + 5

def patch(o:mutbuf, at:u64, target:u64) -> u64:
    write(o, at, target - at - 4, 4)
    return 0

def register32(o:mutbuf, at:u64, reg:u64, value:u64) -> u64:
    if reg >= 8:
        store(o, at, 65)
        at = at + 1
        reg = reg - 8
    store(o, at, 184 + reg)
    write(o, at + 1, value, 4)
    return at + 5

def instruction(o:mutbuf, at:u64, encoding:u64, size:u64) -> u64:
    write(o, at, encoding, size)
    return at + size
'''.replace('PACK_MAGIC', str(MAGIC)).replace('STARTUP_MAGIC', str(CAP_MAGIC))

_tree = ast.parse(LINK_SOURCE)
_helpers = [n for n in _tree.body if isinstance(n, ast.FunctionDef) and n.name in ('uint', 'write')]
assert {n.name for n in _helpers} == {'uint', 'write'}
SOURCE += '\n' + '\n\n'.join(ast.unparse(n) for n in _helpers) + '\n'


def document():
    nodes = ast.parse(SOURCE).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = PackerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'linux_process_entry_packer', 'functions': functions})


def frame(image):
    if type(image) is not bytes:
        raise TypeError('exact immutable image bytes required')
    return struct.pack('<QQQQ', MAGIC, 1, len(image), 0) + image


def generated():
    return render_assembly(document())


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text = generated()
    target = ROOT / 'examples/hia_bootstrap/linux_process_entry_packer.hepta'
    if args.check:
        if target.read_text() != text:
            raise SystemExit('Linux process entry packer source differs')
    else:
        target.write_text(text)
    print(json.dumps({'source': str(target.relative_to(ROOT)),
        'bytes': len(text.encode()), 'sha256': hashlib.sha256(text.encode()).hexdigest(),
        'matching_cold': False, 'whole': False}, sort_keys=True))


if __name__ == '__main__':
    main()
