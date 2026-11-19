"""Author the Linux journal adapter and the HIA packer that binds its two images."""
from __future__ import annotations

import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_stdio import ROOT, document, writes
from tools.generate_hia_core_json_cli import LIMIT, source_program
from tools.generate_hia_mcp_stdio_packer import elf_prefix, resolve

SOURCE = 'examples/hia_bootstrap/agent_journal_stdio_packer.hepta'
MAGIC = int.from_bytes(b'HIAJPK01', 'little')


def template():
    # Initial Linux stack becomes an aligned private frame. R12 holds the
    # sealed input, R13 its extent, R14 the outputs, and R15 the scratch extent.
    mode, extent, fd, held = 144, 152, 160, 168
    marker, iov, message, control = 680, 688, 704, 760
    prefix, sequence, transfer, carry, stack = 784, 792, 800, 824, 928
    limit, state, frame, private = 8 << 20, 512, 64, 32768
    output = 2 * limit + state
    code, labels, branches, holes = bytearray(), {}, [], []

    def emit(data):
        code.extend(bytes.fromhex(data))

    def word(value):
        code.extend(struct.pack('<I', value))

    def local(opcode, offset, suffix=''):
        emit(opcode)
        word(offset)
        if suffix:
            emit(suffix)

    def local_value(offset, value):
        local('48 c7 85', offset)
        word(value)

    def label(name):
        labels[name] = len(code)

    def branch(opcode, target):
        emit(opcode)
        branches.append((len(code), target))
        word(0)

    def call(target):
        branch('e8', target)

    def syscall(number):
        emit('b8')
        word(number)
        emit('0f 05')

    def image_call():
        emit('e8')
        holes.append(len(code))
        word(0)

    emit('fc 48 83 3c 24 01')
    branch('0f 84', 'single')
    emit('48 83 3c 24 02')
    branch('0f 85', 'bad_frame')
    emit('48 8b 54 24 10 48 b8')         # argv[1] == "--session"
    code.extend(b'--sessio')
    emit('48 39 02')
    branch('0f 85', 'bad_frame')
    emit('66 81 7a 08 6e 00')
    branch('0f 85', 'bad_frame')
    branch('e9', 'session_setup')

    label('single')
    emit('48 81 ec')
    word(stack)
    emit('48 89 e5')
    local_value(mode, 0)
    local_value(prefix, frame + state)
    local_value(sequence, 0)
    local_value(fd, 0)
    branch('e9', 'seal')

    label('session_setup')
    emit('48 81 ec')
    word(stack)
    emit('48 89 e5')
    local_value(mode, 1)
    local_value(prefix, frame)
    local_value(sequence, 1)
    local('48 8d bd', held)
    emit('b9 40 00 00 00 31 c0 f3 48 ab')
    # Fall through to the descriptor receive loop.
    label('receive')
    local('48 8d bd', message)
    emit('b9 07 00 00 00 31 c0 f3 48 ab')
    local('48 8d 85', marker)
    local('48 89 85', iov)
    local_value(iov + 8, 1)
    local('48 8d 85', iov)
    local('48 89 85', message + 16)
    local_value(message + 24, 1)
    local('48 8d 85', control)
    local('48 89 85', message + 32)
    local_value(message + 40, 24)
    emit('31 ff')
    local('48 8d b5', message)
    emit('ba 00 00 00 40')                # recvmsg(STDIN, ..., MSG_CMSG_CLOEXEC)
    syscall(47)
    emit('48 83 f8 fc')
    branch('0f 84', 'receive')
    emit('48 85 c0')
    branch('0f 84', 'complete')
    emit('48 83 f8 01')
    branch('0f 85', 'bad_frame')
    local('80 bd', marker, '4a')          # one marker and one non-truncated SCM_RIGHTS fd
    branch('0f 85', 'bad_frame')
    local('f7 85', message + 48)
    word(40)
    branch('0f 85', 'bad_frame')
    for opcode, offset, value in (('48 83 bd', message + 40, '18'),
                                  ('48 83 bd', control, '14'),
                                  ('83 bd', control + 8, '01'),
                                  ('83 bd', control + 12, '01')):
        local(opcode, offset, value)
        branch('0f 85', 'bad_frame')
    local('8b 85', control + 16)
    emit('85 c0')
    branch('0f 88', 'bad_frame')
    local('48 89 85', fd)

    label('seal')
    local('48 8b bd', fd)
    emit('be 0a 04 00 00')                 # require all four memfd seals
    syscall(72)
    emit('48 85 c0')
    branch('0f 88', 'bad_frame')
    emit('83 e0 0f 83 f8 0f')
    branch('0f 85', 'bad_frame')
    local('48 8b bd', fd)
    emit('48 89 ee')
    syscall(5)                            # fstat; file extent at +48
    emit('48 85 c0')
    branch('0f 85', 'io_error')
    emit('4c 8b 6d 30')
    local('4c 3b ad', prefix)
    branch('0f 82', 'bad_frame')
    local('4c 89 ad', extent)
    emit('4c 89 ee')
    local('4c 8b 85', fd)
    emit('ba 01 00 00 00 41 ba 02 00 00 00')
    call('map')
    emit('49 89 c4')
    local('48 83 bd', mode, '00')
    branch('0f 84', 'admit')
    local('48 8b bd', fd)
    syscall(3)
    emit('48 85 c0')
    branch('0f 85', 'io_error')

    label('admit')
    local_value(transfer, 15)
    local('48 8b 85', sequence)
    local('48 89 85', transfer + 8)
    emit('4c 89 e7 4c 89 ee 31 d2 31 c9')
    call('codec')
    emit('83 f8 01')
    branch('0f 85', 'bad_frame')
    emit('49 8b 5c 24 30')
    local('4c 2b ad', prefix)
    emit('49 29 dd 4d 8b 7c 24 10')
    emit('49 8d b7')
    word(output)
    emit('49 c7 c0 ff ff ff ff ba 03 00 00 00 41 ba 22 00 00 00')
    call('map')
    emit('49 89 c6 49 8d 96')              # RDX is the scratch view
    word(output)
    emit('49 8b 44 24 18 48 89 02 48 83 f8 0d')
    branch('0f 83', 'envelope')
    emit('49 8b 44 24 20 48 89 42 08 4a 8d bc 3a')
    word((1 << 32) - private)
    call('copy_state')
    emit('48 89 9f 50 ff ff ff 49 8b 44 24 28 48 89 87 58 ff ff ff')
    emit('4a 8d bc 3a')
    word((1 << 32) - private)
    emit('48 29 df')
    local('48 8b b5', prefix)
    emit('4c 01 e6 48 89 d9 f3 a4 b9')
    word(output)
    branch('e9', 'invoke')
    label('envelope')
    emit('48 8d 7a 08')
    call('copy_state')
    emit('b9 c0 00 00 00')
    label('invoke')
    local('48 8b bd', prefix)
    emit('4c 01 e7 48 01 df 4c 89 ee 49 89 d0 4c 89 f2 4d 89 f9')
    image_call()                           # journal transition image

    local_value(transfer, 16)             # codec admits result lengths, writes full reply header
    local('48 89 85', transfer + 8)
    emit('49 8b 44 24 18')
    local('48 89 85', transfer + 16)
    emit('4c 89 f7 49 8d b7')
    word(output)
    emit('48 89 ea b9 30 00 00 00')
    call('codec')
    emit('83 f8 01')
    branch('0f 87', 'bad_frame')
    local('48 89 85', carry)
    emit('48 89 ee ba 30 00 00 00')
    call('write_all')
    for index, base in enumerate((0, limit, 2 * limit, output)):
        emit('4c 89 f6' if base == 0 else '49 8d b6')
        if base:
            word(base)
        emit(f'48 8b 55 {16 + 8 * index:02x}')
        call('write_all')
    local('48 83 bd', mode, '00')
    branch('0f 84', 'complete')
    local('48 83 bd', carry, '00')
    branch('0f 84', 'release')
    local('48 8d bd', held)
    emit('49 8d b6')
    word(2 * limit)
    emit('b9 40 00 00 00 f3 48 a5')

    label('release')
    emit('4c 89 e7')
    local('48 8b b5', extent)
    syscall(11)
    emit('48 85 c0')
    branch('0f 85', 'io_error')
    emit('4c 89 f7 49 8d b7')
    word(output)
    syscall(11)
    emit('48 85 c0')
    branch('0f 85', 'io_error')
    local('48 ff 85', sequence)
    branch('0f 84', 'bad_frame')
    branch('e9', 'receive')

    label('copy_state')
    emit('49 8d 74 24 40')
    local('48 8d 85', held)
    local('48 83 bd', mode, '00')
    emit('48 0f 45 f0 b9 40 00 00 00 f3 48 a5 c3')
    label('codec')
    local('4c 8d 85', transfer)
    emit('41 b9 18 00 00 00 e9')           # tail jump to the wire codec
    holes.append(len(code))
    word(0)
    label('map')
    emit('31 ff 45 31 c9')
    syscall(9)
    emit('48 3d 01 f0 ff ff')
    branch('0f 83', 'io_error')
    emit('c3')
    label('write_all')
    emit('48 85 d2')
    branch('0f 84', 'write_done')
    emit('bf 01 00 00 00')
    syscall(1)
    emit('48 83 f8 fc')
    branch('0f 84', 'write_all')
    emit('48 85 c0')
    branch('0f 8e', 'io_error')
    emit('48 01 c6 48 29 c2')
    branch('e9', 'write_all')
    label('write_done')
    emit('c3')
    label('complete')
    emit('31 ff')
    branch('e9', 'exit')
    label('bad_frame')
    emit('bf 02 00 00 00')
    branch('e9', 'exit')
    label('io_error')
    emit('bf 04 00 00 00')
    label('exit')
    syscall(60)
    emit('0f 0b')
    code.extend(b'hepta.hia.agent-journal.session.v1\0')

    resolve(code, labels, branches)
    result = elf_prefix(code)
    return result, tuple(len(result) - len(code) + hole for hole in holes)


def render():
    prefix, (journal, codec) = template()
    body = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    extent = length(s)
    if extent < 26 or extent > {24 + 2 * LIMIT} or read_word(s, 0) != {MAGIC}:
        return 4294967295
    primary = read_word(s, 8)
    wire = read_word(s, 16)
    if primary == 0 or primary > {LIMIT} or wire == 0 or wire > {LIMIT}:
        return 4294967295
    if extent != 24 + primary + wire:
        return 4294967295
    total = {len(prefix)} + primary + wire
    if length(o) < total:
        return 4294967294
'''
    body += writes(prefix)
    body += f'''    put_word(o, 96, total)
    put_word(o, 104, total)
    put_four(o, {journal}, {len(prefix) - journal - 4})
    put_four(o, {codec}, {len(prefix) - codec - 4} + primary)
    index = 24
    while index < extent:
        store(o, {len(prefix)} + index - 24, byte(s, index))
        index = index + 1
    return total
'''
    helpers = source_program()
    body += helpers[helpers.index('\ndef read_word('):]
    return render_assembly(document(body, 'agent_journal_stdio_packer'))


if __name__ == '__main__':
    (ROOT / SOURCE).write_text(render(), encoding='utf-8')
