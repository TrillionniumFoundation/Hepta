"""Author fixed Linux transports for the HIA stdio ELF packer."""
from __future__ import annotations

import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document, writes
from tools.generate_hia_core_json_cli import LIMIT, source_program as core_packer_source
from tools.generate_hia_mcp_connection import RESPONSE_BYTES, WORKSPACE_BYTES as CONNECTION_WORKSPACE
from tools.generate_hia_native_filter import WORKER_PRIVATE_BYTES, WORKER_WORKSPACE_BYTES

SOURCE = 'examples/hia_bootstrap/mcp_stdio_packer.hepta'
MAGIC = int.from_bytes(b'HIAMCPK1', 'little')
INPUT_MAX = 8 << 20
ARENA_BYTES = 64 + 262144 * 72 + INPUT_MAX
# A zero descriptor selects the variable-length reply contract.
DESCRIPTORS = (88, 0, 112, 24)
PAGE_MODE = len(DESCRIPTORS)
TERMINAL_MODE = PAGE_MODE + 1
SCHEMA_MODE = TERMINAL_MODE + 1
CONNECTION_MODE = SCHEMA_MODE + 1
SCHEMA_HEADER = 72  # little-endian tool ordinal and 64 ASCII catalog digest bytes
SCHEMA_ARENA_BYTES = 64 + 262144 * 56 + INPUT_MAX + 8192
PAGE_OUTPUT = 32 + 40 + 69 + 4 * ((65536 + 2) // 3) + 533
PAGE_WORKSPACE = 512 + 4128
MODES = {'mcp-request': 0, 'mcp-reply': 1, 'mcp-terminal': 1, 'mcp-catalog': 1,
         'mcp-negotiation': 2, 'mcp-uri': 3, 'read-page': PAGE_MODE,
         'mcp-input-schema': SCHEMA_MODE, 'mcp-response-schema': SCHEMA_MODE,
         'mcp-proof-schema': SCHEMA_MODE, 'mcp-connection': CONNECTION_MODE}


def elf_prefix(code):
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code


def resolve(code, labels, branches):
    for offset, target in branches:
        struct.pack_into('<i', code, offset, labels[target] - offset - 4)


def template(mode):
    if mode == CONNECTION_MODE:
        return connection_template()
    if mode == TERMINAL_MODE:
        return terminal_template()
    page = mode == PAGE_MODE
    schema = mode == SCHEMA_MODE
    descriptor = None if page or schema else DESCRIPTORS[mode]
    scratch = PAGE_OUTPUT if page else ((4 << 20) if descriptor or schema else INPUT_MAX + 32)
    prefix_bytes = 0 if page else 8
    workspace = PAGE_WORKSPACE if page else (SCHEMA_ARENA_BYTES if schema else ARENA_BYTES)
    minimum = 24 if page else (SCHEMA_HEADER + 2 if schema else 2)
    maximum = ((64 << 20) + 1024 + 512) if page else (INPUT_MAX + SCHEMA_HEADER if schema else INPUT_MAX)
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

    emit('49 89 c6')                            # r14 = private mapping base
    if schema:
        # Copy the sealed role and catalog digest into the schema arena.
        # The schema kernel, not the transport, validates those bytes.
        emit('49 8d be')
        word(prefix_bytes + scratch)
        emit('4c 89 e6 b9 09 00 00 00 f3 48 a5')
        emit('49 8d 7c 24 48 49 8d 75 b8')      # input pointer +72, bytes -72
    else:
        emit('4c 89 e7 4c 89 ee')
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
        elif not schema:                        # schema exports only the policy status
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
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + branch_address


def terminal_template():
    # RBP owns private header/IO control on the initial stack; R12/R13
    # are the payload/result mappings and R14/R15 the two HIA workspaces.
    frame_bytes, admission_bytes = 296, 88
    header_mode, extra, newline, sigpipe, stack = 304, 312, 313, 320, 352
    workspace = WORKER_WORKSPACE_BYTES
    private = workspace - WORKER_PRIVATE_BYTES
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

    def call(target):
        branch('e8', target)

    def call_with_extent(target, register, count):
        emit(register)
        word(count)
        call(target)

    def syscall(number):
        emit('b8')
        word(number)
        emit('0f 05')

    emit('fc 48 83 3c 24 01')                # cld; argc == 1
    branch('0f 85', 'bad_frame')
    emit('48 81 ec')
    word(stack)
    emit('48 89 e5 48 c7 85')               # RBP = frame base; mode = 4
    word(header_mode)
    word(4)
    emit('c6 85')
    word(newline)
    emit('0a')
    for offset, value in ((sigpipe, 1), (sigpipe + 8, 0),
                          (sigpipe + 16, 0), (sigpipe + 24, 0)):
        emit('48 c7 85')
        word(offset)
        word(value)
    emit('bf 0d 00 00 00 48 8d b5')        # rt_sigaction(SIGPIPE, &ignore, NULL, 8)
    word(sigpipe)
    emit('31 d2 41 ba 08 00 00 00')
    syscall(13)
    emit('48 85 c0')
    branch('0f 85', 'io_failure')
    emit('48 89 ee')                       # read frame marker, HIA selects full extent
    call_with_extent('read_exact', 'ba', 8)
    call_with_extent('check_header', 'be', 8)
    emit('83 f8 58')                       # admission header is 88 bytes
    branch('0f 84', 'admission')
    emit('3d')
    word(frame_bytes)
    branch('0f 85', 'bad_frame')
    emit('48 8d 75 08')
    call_with_extent('read_exact', 'ba', frame_bytes - 8)
    call_with_extent('check_header', 'be', frame_bytes)
    emit('83 f8 fe')
    branch('0f 84', 'budget')
    emit('3d')
    word(frame_bytes)
    branch('0f 85', 'bad_frame')

    call('allocate')                       # initialize request workspace and catalog pin
    emit('48 8b 45 18 49 89 46 08 48 8d 75 28')
    call('copy_catalog')
    emit('4c 89 e6 48 8b 55 08')
    call('read_exact')
    emit('4c 89 e7 48 8b 75 08 4c 89 ea 4d 89 f0')
    call('run_hia')
    emit('4c 89 e6 48 8b 55 10')
    call('read_exact')
    call('read_eof')
    call_with_extent('map_private', 'be', workspace)
    emit('49 89 c7 49 c7 07 03 00 00 00')   # second workspace with response-canonicalization mode
    emit('48 8b 45 18 49 89 47 08')
    emit('4c 89 e7 48 8b 75 10 4c 89 ea 4d 89 f8')
    call('run_hia')
    emit('48 89 c3 49 c7 06 02 00 00 00 48 8b 45 20')
    emit('49 89 86')                       # hand flags and remaining pins to HIA's renderer
    word(private + 520)
    emit('49 8d be')
    word(private + 528)
    emit('48 8d 75 68 b9 18 00 00 00 f3 48 a5')
    emit('4c 89 ef 48 89 de 4c 89 e2 4d 89 f0')
    call('run_hia')
    emit('48 89 c2 4c 89 e6')
    call('write_exact')
    emit('48 8d b5')
    word(newline)
    call_with_extent('write_exact', 'ba', 1)
    branch('e9', 'complete')

    label('admission')
    emit('48 8d 75 08')
    call_with_extent('read_exact', 'ba', admission_bytes - 8)
    call_with_extent('check_header', 'be', admission_bytes)
    emit('83 f8 fe')
    branch('0f 84', 'budget')
    emit('83 f8 58')
    branch('0f 85', 'bad_frame')
    call('allocate')
    emit('48 8b 45 10 49 89 46 08 48 8d 75 18')
    call('copy_catalog')
    emit('4c 89 e6 48 8b 55 08 48 85 d2')
    branch('0f 84', 'admission_eof')
    call('read_exact')
    label('admission_eof')
    call('read_eof')
    emit('4c 89 e7 48 8b 75 08 4c 89 ea 4d 89 f0')
    call('raw_hia')
    emit('89 c0 48 89 45 08 45 31 ff 3d')    # preserve raw admission status
    word(INPUT_MAX)
    branch('0f 86', 'admission_arena')
    emit('83 f8 e9')
    branch('0f 82', 'admission_reply')
    emit('83 f8 ef')
    branch('0f 87', 'admission_reply')
    label('admission_arena')
    emit('4d 8b 7e 20 49 83 ff 40')
    branch('0f 82', 'io_failure')
    emit('49 81 ff')
    word(private)
    branch('0f 87', 'io_failure')
    label('admission_reply')
    emit('48 b8')
    code.extend(b'HIAWRO02')
    emit('48 89 45 00 4c 89 7d 10 48 89 ee')
    call_with_extent('write_exact', 'ba', 24)
    emit('4d 85 ff')
    branch('0f 84', 'complete')
    emit('4c 89 f6 4c 89 fa')
    call('write_exact')
    label('complete')
    emit('31 ff')
    branch('e9', 'exit')

    label('allocate')
    call_with_extent('map_private', 'be', INPUT_MAX)
    emit('49 89 c4')
    call_with_extent('map_private', 'be', INPUT_MAX)
    emit('49 89 c5')
    call_with_extent('map_private', 'be', workspace)
    emit('49 89 c6 49 c7 06 01 00 00 00 c3')
    label('copy_catalog')
    emit('49 8d be')
    word(private + 64)
    emit('b9 08 00 00 00 f3 48 a5 c3')

    label('check_header')
    emit('48 89 ef 31 d2 31 c9 4c 8d 85')
    word(header_mode)
    emit('41 b9 08 00 00 00')
    branch('e9', 'kernel')
    label('run_hia')
    emit('48 83 ec 08')
    call('raw_hia')
    emit('48 83 c4 08 83 f8 fe')
    branch('0f 84', 'budget')
    emit('83 f8 ea')
    branch('0f 84', 'budget')
    emit('83 f8 fd')
    branch('0f 84', 'bad_frame')
    emit('3d 00 ff ff ff')
    branch('0f 83', 'rejected')
    emit('85 c0')
    branch('0f 84', 'io_failure')
    emit('3d')
    word(INPUT_MAX)
    branch('0f 87', 'io_failure')
    emit('89 c0 c3')
    label('raw_hia')
    emit('b9')
    word(INPUT_MAX)
    emit('41 b9')
    word(workspace)
    label('kernel')
    emit('e9')                            # tail jump bound by the HIA packer
    displacement = len(code)
    word(0)

    label('map_private')
    emit('31 ff ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9')
    syscall(9)
    emit('48 3d 01 f0 ff ff')
    branch('0f 83', 'io_failure')
    emit('c3')
    label('read_exact')
    emit('31 ff 31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read_exact')
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 84', 'bad_frame')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'read_exact')
    emit('c3')
    label('read_eof')
    emit('31 ff 48 8d b5')
    word(extra)
    emit('ba 01 00 00 00 31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read_eof')
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 85', 'bad_frame')
    emit('c3')
    label('write_exact')
    emit('bf 01 00 00 00')
    syscall(1)
    emit('48 83 f8 fc')
    branch('0f 84', 'write_exact')
    emit('48 85 c0')
    branch('0f 8e', 'io_failure')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write_exact')
    emit('c3')
    for name, status in (('rejected', 2), ('budget', 3), ('io_failure', 4), ('bad_frame', 64)):
        label(name)
        emit('bf')
        word(status)
        branch('e9', 'exit')
    label('exit')
    syscall(60)
    emit('0f 0b')
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + displacement


def connection_template():
    """Only Linux I/O stays in the adapter; the HIA kernel owns the session."""
    chunk_bytes = 4096
    code, labels, branches = bytearray(), {}, []

    def emit(value):
        code.extend(bytes.fromhex(value))

    def word(value):
        code.extend(struct.pack('<I', value))

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def label(name):
        labels[name] = len(code)

    def map_private(size, register):
        emit('be')
        word(size)
        branch('e8', 'map')
        emit(register)

    emit('48 83 3c 24 01')                     # argc == 1
    branch('0f 85', 'bad_frame')
    emit('48 83 ec 20 48 89 e5 fc')            # aligned local storage; clear DF
    map_private(INPUT_MAX + chunk_bytes, '49 89 c4')
    map_private(RESPONSE_BYTES, '49 89 c5')
    map_private(CONNECTION_WORKSPACE, '49 89 c6')
    emit('4d 8d bc 24')
    word(INPUT_MAX)                           # r15 = chunk after the input
    emit('31 db')                             # rbx = bytes in current frame

    label('read')
    emit('31 ff 4c 89 fe ba')
    word(chunk_bytes)
    emit('31 c0 0f 05 48 83 f8 fc')
    branch('0f 84', 'read')                    # EINTR
    emit('48 85 c0')
    branch('0f 88', 'io_failure')
    branch('0f 84', 'eof')
    emit('48 89 45 00 48 c7 45 08 00 00 00 00')

    label('next')
    emit('4c 8b 45 08 4c 3b 45 00')
    branch('0f 84', 'read')
    emit('43 0f b6 14 07 48 ff 45 08 80 fa 0a')
    branch('0f 84', 'frame')
    emit('48 81 fb')
    word(INPUT_MAX)
    branch('0f 83', 'bad_frame')
    emit('41 88 14 1c 48 ff c3')
    branch('e9', 'next')

    label('frame')
    emit('4c 89 e7 48 89 de 4c 89 ea b9')     # s, bytes, o, o_capacity
    word(RESPONSE_BYTES)
    emit('4d 89 f0 41 b9')                    # workspace, w_capacity
    word(CONNECTION_WORKSPACE)
    emit('e8')
    displacement = len(code)
    word(0)
    emit('31 db 89 c0 85 c0')                  # notification => zero output
    branch('0f 84', 'next')
    emit('3d')
    word(RESPONSE_BYTES)
    branch('0f 87', 'io_failure')
    emit('41 80 7c 05 ff 0a')
    branch('0f 85', 'io_failure')
    emit('4c 89 ee 89 c2')

    label('write')
    emit('bf 01 00 00 00 b8 01 00 00 00 0f 05 48 83 f8 fc')
    branch('0f 84', 'write')
    emit('48 85 c0')
    branch('0f 8e', 'io_failure')
    emit('48 01 c6 48 29 c2')
    branch('0f 85', 'write')
    branch('e9', 'next')

    label('map')
    emit('31 ff ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff')
    emit('45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff')
    branch('0f 83', 'io_failure')
    emit('c3')

    label('eof')
    emit('48 85 db')
    branch('0f 85', 'bad_frame')
    emit('31 ff')
    branch('e9', 'exit')
    for name, status in (('bad_frame', 64), ('io_failure', 4)):
        label(name)
        emit('bf')
        word(status)
        branch('e9', 'exit')
    label('exit')
    emit('b8 3c 00 00 00 0f 05 0f 0b')
    resolve(code, labels, branches)
    prefix = elf_prefix(code)
    return prefix, len(prefix) - len(code) + displacement


def render():
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = length(s)
    if count < 17 or count > {16 + LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    mode = read_word(s, 8)
'''
    for mode in range(CONNECTION_MODE + 1):
        source += f'    if mode == {mode}:\n        return pack_{mode}(s, o)\n'
    source += '    return 4294967295\n'
    for mode in range(CONNECTION_MODE + 1):
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
