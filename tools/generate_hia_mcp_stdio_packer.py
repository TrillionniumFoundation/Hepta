"""Author fixed Linux transports for the HIA sealed stdio ELF packer."""
from __future__ import annotations

import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document, writes
from tools.generate_hia_core_json_cli import LIMIT, source_program as core_packer_source

SOURCE = 'examples/hia_bootstrap/mcp_stdio_packer.hepta'
MAGIC = int.from_bytes(b'HIAMCPK1', 'little')
INPUT_MAX = 8 << 20
ARENA_BYTES = 64 + 262144 * 72 + INPUT_MAX
# A zero descriptor selects the variable-length reply contract.
DESCRIPTORS = (88, 0, 112, 24)
PAGE_MODE = len(DESCRIPTORS)
PAGE_OUTPUT = 40 + 69 + 4 * ((65536 + 2) // 3)
PAGE_WORKSPACE = 512 + 4128
MODES = {'mcp-request': 0, 'mcp-reply': 1, 'mcp-catalog': 1,
         'mcp-negotiation': 2, 'mcp-uri': 3, 'read-page': PAGE_MODE}


def template(mode):
    page = mode == PAGE_MODE
    descriptor = None if page else DESCRIPTORS[mode]
    scratch = PAGE_OUTPUT if page else ((4 << 20) if descriptor else INPUT_MAX + 32)
    prefix_bytes = 0 if page else 8
    workspace = PAGE_WORKSPACE if page else ARENA_BYTES
    minimum = 24 if page else 2
    maximum = ((64 << 20) + 32 + 512) if page else INPUT_MAX
    code, labels, branches = bytearray(), {}, []

    def emit(hexadecimal):
        code.extend(bytes.fromhex(hexadecimal))

    def word(value):
        code.extend(struct.pack('<I', value))

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def label(name):
        labels[name] = len(code)

    emit('48 83 3c 24 01')                      # argc == 1 at ELF entry
    branch('0f 85', 'bad_frame')
    emit('48 81 ec b0 00 00 00')                # aligned stat buffer
    emit('31 ff be 0a 04 00 00 b8 48 00 00 00 0f 05')  # fcntl(STDIN, F_GET_SEALS)
    emit('48 85 c0')
    branch('0f 88', 'bad_frame')
    emit('83 e0 0f 83 f8 0f')
    branch('0f 85', 'bad_frame')
    emit('31 ff 48 89 e6 b8 05 00 00 00 0f 05')  # fstat(STDIN, &stat)
    emit('48 85 c0')
    branch('0f 85', 'io_error')
    emit(f'4c 8b 6c 24 30 49 83 fd {minimum:02x}')  # r13 = stat.st_size
    branch('0f 82', 'bad_frame')
    emit('49 81 fd')
    word(maximum)
    branch('0f 87', 'bad_frame')

    # The sealed input is mapped read-only; result and kernel workspace stay RW.
    emit('31 ff 4c 89 ee ba 01 00 00 00 41 ba 02 00 00 00 45 31 c0 45 31 c9')
    emit('b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_error')
    emit('49 89 c4 31 ff be')
    word(prefix_bytes + scratch + workspace)
    emit('ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9')
    emit('b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_error')

    emit('49 89 c6 4c 89 e7 4c 89 ee')
    emit('4c 89 f2' if page else '49 8d 56 08')   # payload or status-prefixed result
    emit('b9')
    word(scratch)
    emit('4d 8d 86')
    word(prefix_bytes + scratch)
    emit('41 b9')
    word(workspace)
    emit('e8')
    branch_address = len(code)
    word(0)                                     # packer binds the actual HIA kernel
    if page:
        emit('48 83 f8 28')                      # complete 40-byte page header
        branch('0f 82', 'bad_frame')
        emit('48 3d')
        word(scratch)
        branch('0f 87', 'bad_frame')
        emit('48 89 c2 4c 89 f6')                # raw page without a status word
    else:
        emit('89 c0 49 89 06 4c 89 f6 ba 08 00 00 00')
        if descriptor:
            emit(f'83 f8 {descriptor:02x}')
            branch('0f 85', 'write_result')
            emit(f'83 c2 {descriptor:02x}')
        else:
            emit('83 f8 02')
            branch('0f 82', 'write_result')
            emit('3d')
            word(scratch)
            branch('0f 87', 'write_result')
            emit('01 c2')
    label('write_result')
    emit('bf 01 00 00 00 b8 01 00 00 00 0f 05 48 83 f8 fc')
    branch('0f 84', 'write_result')              # retry EINTR without dropping bytes
    emit('48 85 c0')
    branch('0f 8e', 'io_error')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write_result')
    emit('31 ff')
    branch('e9', 'exit')
    label('bad_frame')
    emit('bf 02 00 00 00')
    branch('e9', 'exit')
    label('io_error')
    emit('bf 04 00 00 00')
    label('exit')
    emit('b8 3c 00 00 00 0f 05 0f 0b')
    for offset, target in branches:
        struct.pack_into('<i', code, offset, labels[target] - offset - 4)

    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    prefix = header + code
    call = len(header) + branch_address
    return prefix, call


def render():
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = length(s)
    if count < 17 or count > {16 + LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    mode = read_word(s, 8)
'''
    for mode in range(PAGE_MODE + 1):
        source += f'    if mode == {mode}:\n        return pack_{mode}(s, o)\n'
    source += '    return 4294967295\n'
    for mode in range(PAGE_MODE + 1):
        prefix, call = template(mode)
        source += f'''
def pack_{mode}(s:readbuf, o:mutbuf) -> u32:
    size = {len(prefix)} + length(s) - 16
    if length(o) < size:
        return 4294967294
'''
        source += writes(prefix)
        source += f'''    put_word(o, 96, size)
    put_word(o, 104, size)
    put_four(o, {call}, {len(prefix) - call - 4})
    i = 16
    while i < length(s):
        store(o, {len(prefix)} + i - 16, byte(s, i))
        i = i + 1
    return size
'''
    helpers = core_packer_source()
    source += helpers[helpers.index('\ndef read_word('):]
    return render_assembly(document(source, 'mcp_stdio_packer'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
