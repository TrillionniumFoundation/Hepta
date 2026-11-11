"""Author HIA release selection and a native packer sharing real release verify.

HIA owns the durable record, CAS, rollback and receipt. Descriptor operations
are fixed Linux syscalls. Existing installer policy and tree-verification code
are embedded directly; neither a child process nor a host state parser runs.
"""
from __future__ import annotations
import struct
import subprocess
import tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import policy_source as installer_policy_source

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIASPK01', 'little')
STATE_MAGIC = int.from_bytes(b'HIASEL01', 'little')
STATE_BYTES = 192
WORK_BYTES = 8192

POLICY_SOURCE = '''def selection(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192 or length(o) < 8192:
        return 16
    phase = get(w, 0)
    if phase == 0:
        return arguments(s, o, w)
    if phase == 2:
        return read_state(w)
    if phase == 3:
        if length(s) != 32 or get(w, 32) != 1:
            return 16
        i = 0
        while i < 32:
            if byte(s, i) != byte(w, 416 + i):
                return 11
            i = i + 1
        return 0
    if phase == 4:
        return transition(w)
    if phase == 6:
        if length(s) != 32:
            return 16
        i = 0
        while i < 32:
            store(w, 608 + i, byte(s, i))
            i = i + 1
        return 0
    if phase == 7:
        if regular(w, 912, 384, 0) == 0:
            return 10
        copy(w, 912, 1056, 144)
        return 0
    if phase == 8:
        if regular(w, 912, 256, 192) == 0:
            return 10
        if stable(w, 768, 912) == 0:
            return 12
        return 0
    if phase == 9:
        if regular(w, 912, 256, 192) == 0:
            return 10
        copy(w, 912, 1200, 144)
        return 0
    if phase == 10:
        STAGE_PREFIX
        i = 0
        while i < 16:
            v = byte(w, 704 + i)
            store(w, 661 + i * 2, hex(v >> 4))
            store(w, 662 + i * 2, hex(v & 15))
            i = i + 1
        store(w, 693, 0)
        return 0
    if phase == 11:
        if regular(w, 912, 256, 192) == 0:
            return 10
        if stable(w, 1200, 912) == 0:
            return 12
        return 0
    if phase == 12:
        i = 0
        while i < 192:
            if byte(w, 256 + i) != byte(w, 448 + i):
                return 12
            i = i + 1
        return 0
    if phase == 14:
        return receipt(o, w)
    if phase == 15:
        if regular(w, 912, 384, 0) == 0:
            return 10
        if stable(w, 1056, 912) == 0:
            return 12
        return 0
    if phase == 17:
        if get(w, 768) != get(w, 1200) or get(w, 776) != get(w, 1208):
            return 12
        if get(w, 784) != get(w, 1216) or get(w, 792) != get(w, 1224):
            return 12
        if get(w, 816) != get(w, 1248):
            return 12
        if get(w, 856) != get(w, 1288) or get(w, 864) != get(w, 1296):
            return 12
        return 0
    if phase == 16:
        if regular(w, 912, 256, 192) == 0:
            return 10
        copy(w, 912, 768, 144)
        return 0
    return 16

def arguments(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40:
        return 16
    a = uint(s, 0, 8)
    b = uint(s, 8, 8)
    c = uint(s, 16, 8)
    d = uint(s, 24, 8)
    e = uint(s, 32, 8)
    if a > 8 or b == 0 or b > 4095 or c > 20 or d > 64 or e > 64:
        return 16
    if length(s) != 40 + a + b + c + d + e:
        return 16
    op = 0
    if a == 8 and uint(s, 40, 8) == ACTIVATE:
        op = 1
    if a == 8 and uint(s, 40, 8) == ROLLBACK:
        op = 2
    if a == 6 and uint(s, 40, 6) == STATUS:
        op = 3
    if op == 0:
        return 16
    root = 40 + a
    sequence_at = root + b
    expected_at = sequence_at + c
    target_at = expected_at + d
    if op == 3:
        if c != 0 or d != 0 or e != 0:
            return 16
    else:
        if c == 0 or e != 64:
            return 16
        if c > 1 and byte(s, sequence_at) == 48:
            return 16
        sequence = 0
        i = 0
        while i < c:
            v = byte(s, sequence_at + i)
            if v < 48 or v > 57:
                return 16
            digit = v - 48
            if sequence > 1844674407370955161 or sequence == 1844674407370955161 and digit > 5:
                return 16
            sequence = sequence * 10 + digit
            i = i + 1
        put(w, 16, sequence)
        if sequence == 0:
            if d != 1 or byte(s, expected_at) != 45:
                return 16
        else:
            if d != 64:
                return 16
        i = 0
        while i < 64:
            v = byte(s, target_at + i)
            if unhex(v) > 15:
                return 16
            store(w, 192 + i, v)
            if sequence == 0:
                store(w, 128 + i, 0)
            else:
                v = byte(s, expected_at + i)
                if unhex(v) > 15:
                    return 16
                store(w, 128 + i, v)
            i = i + 1
    put(w, 8, op)
    put(w, 88, b)
    put(o, 0, 6)
    put(o, 8, b)
    put(o, 16, 64)
    write(o, 24, VERIFY, 6)
    i = 0
    while i < b:
        store(o, 30 + i, byte(s, root + i))
        i = i + 1
    i = 0
    while i < 64:
        v = 48
        if op != 3:
            v = byte(w, 192 + i)
        store(o, 30 + b + i, v)
        i = i + 1
    return 94 + b

def read_state(w:mutbuf) -> u32:
    if get(w, 32) == 0:
        put(w, 24, 0)
        i = 0
        while i < 192:
            store(w, 256 + i, 0)
            i = i + 1
        return 0
    if get(w, 32) != 1 or get(w, 72) != 192:
        return 11
    if get(w, 256) != STATE_MAGIC or get(w, 280) != 0:
        return 11
    sequence = get(w, 264)
    action = get(w, 272)
    if sequence == 0 or action != 1 and action != 2:
        return 11
    if sequence == 1 and action != 1:
        return 11
    i = 0
    difference = 0
    while i < 64:
        current = byte(w, 288 + i)
        previous = byte(w, 352 + i)
        if unhex(current) > 15:
            return 11
        if sequence == 1:
            if previous != 0:
                return 11
        else:
            if unhex(previous) > 15:
                return 11
        difference = difference | (current ^ previous)
        i = i + 1
    if difference == 0:
        return 11
    put(w, 24, sequence)
    return 0

def transition(w:mutbuf) -> u32:
    op = get(w, 8)
    if op != 1 and op != 2:
        return 16
    if get(w, 16) != get(w, 24):
        return 19
    i = 0
    equal = 1
    while i < 64:
        if byte(w, 128 + i) != byte(w, 288 + i):
            return 19
        if byte(w, 192 + i) != byte(w, 288 + i):
            equal = 0
        i = i + 1
    if equal == 1:
        return 19
    if op == 2:
        if get(w, 24) < 2:
            return 20
        i = 0
        while i < 64:
            if byte(w, 192 + i) != byte(w, 352 + i):
                return 20
            i = i + 1
    if get(w, 24) == 18446744073709551615:
        return 21
    put(w, 448, STATE_MAGIC)
    put(w, 456, get(w, 24) + 1)
    put(w, 464, op)
    put(w, 472, 0)
    i = 0
    while i < 64:
        store(w, 480 + i, byte(w, 192 + i))
        store(w, 544 + i, byte(w, 288 + i))
        i = i + 1
    return 0

def regular(w:mutbuf, at:u64, mode:u64, size:u64) -> u64:
    if get(w, at + 24) & 4294967295 != 32768 + mode:
        return 0
    if get(w, at + 28) & 4294967295 != get(w, 64) or get(w, at + 16) != 1:
        return 0
    if get(w, at + 48) != size:
        return 0
    return 1

def stable(w:mutbuf, a:u64, b:u64) -> u64:
    if get(w, a) != get(w, b) or get(w, a + 8) != get(w, b + 8):
        return 0
    if get(w, a + 16) != get(w, b + 16) or get(w, a + 24) != get(w, b + 24):
        return 0
    if get(w, a + 48) != get(w, b + 48):
        return 0
    if get(w, a + 88) != get(w, b + 88) or get(w, a + 96) != get(w, b + 96):
        return 0
    if get(w, a + 104) != get(w, b + 104) or get(w, a + 112) != get(w, b + 112):
        return 0
    return 1

def receipt(o:mutbuf, w:mutbuf) -> u32:
    RECEIPT_PREFIX
    at = RECEIPT_PREFIX_SIZE
    op = get(w, 8)
    if op == 1:
        at = append(o, at, ACTIVATE, 8)
    if op == 2:
        at = append(o, at, ROLLBACK, 8)
    if op == 3:
        at = append(o, at, STATUS, 6)
    RECEIPT_SEQUENCE
    at = decimal(o, at, get(w, 24))
    RECEIPT_CURRENT
    at = digest_or_null(o, at, w, 288)
    RECEIPT_PREVIOUS
    at = digest_or_null(o, at, w, 352)
    RECEIPT_VERIFIED
    if op == 3:
        at = append(o, at, 435728179558, 5)
    else:
        at = append(o, at, 1702195828, 4)
    at = append(o, at, 2685, 2)
    return at

def digest_or_null(o:mutbuf, at:u64, w:mutbuf, source:u64) -> u64:
    if byte(w, source) == 0:
        return append(o, at, 1819047278, 4)
    store(o, at, 34)
    at = at + 1
    i = 0
    while i < 64:
        store(o, at + i, byte(w, source + i))
        i = i + 1
    store(o, at + 64, 34)
    return at + 65
'''


def _writes(raw, *, base=0, append=False):
    lines = []
    for at in range(0, len(raw), 8):
        chunk = raw[at:at + 8]
        if append:
            lines.append(f'at = append(o, at, {int.from_bytes(chunk, "little")}, {len(chunk)})')
        else:
            lines.append(f'write(w, {base + at}, {int.from_bytes(chunk, "little")}, {len(chunk)})')
    return '\n        '.join(lines)


def policy_source():
    source = POLICY_SOURCE
    for name, raw in [('ACTIVATE', b'activate'), ('ROLLBACK', b'rollback'),
                      ('STATUS', b'status'), ('VERIFY', b'verify')]:
        source = source.replace(name, str(int.from_bytes(raw, 'little')))
    source = source.replace('STATE_MAGIC', str(STATE_MAGIC))
    stage = b'.hia-selection-stage-'
    assert len(stage) == 21
    source = source.replace('STAGE_PREFIX', _writes(stage, base=640))
    prefix = b'{"schema":"hepta.hia.release-selection.v1","operation":"'
    writes = _writes(prefix).replace('write(w,', 'write(o,').replace('\n        ', '\n    ')
    source = source.replace('RECEIPT_PREFIX_SIZE', str(len(prefix))).replace('RECEIPT_PREFIX', writes)
    for marker, raw in [('RECEIPT_SEQUENCE', b'","sequence":'),
                        ('RECEIPT_CURRENT', b',"current":'),
                        ('RECEIPT_PREVIOUS', b',"previous":'),
                        ('RECEIPT_VERIFIED', b',"release_verified":')]:
        source = source.replace(marker, _writes(raw, append=True).replace('\n        ', '\n    '))
    original = installer_policy_source()
    return source + original[original.index('\ndef decimal('):]


def adapter_source():
    original = (ROOT/'tools/hia_release_install_syscalls.S').read_text()
    source = (ROOT/'tools/hia_release_selection_syscalls.S').read_text()
    header = original[:original.index('_start:\n')]
    header = header.replace('sha_hole\n', 'sha_hole, selection_hole\n')
    header = header.replace('.equ MAPSIZE,229376', '.equ MAPSIZE,262144')
    capture_start = original.index(' /* Immutable captured package,')
    root_start = original.index(' mov eax,107\n')
    root_end = original.index(' cmp QWORD PTR [rbp+WORK+8],2\n')
    verify_start = original.index('open_release:\n')
    verify_end = original.index(' mov QWORD PTR [rbp+WORK],14\n')
    helpers_start = original.index('/* Capture every named file')
    helpers_end = original.index('success:\n')
    pieces = {'HEADER': header, 'CAPTURE': original[capture_start:root_start],
        'ROOT': original[root_start:root_end], 'VERIFY': original[verify_start:verify_end],
        'HELPERS': original[helpers_start:helpers_end], 'EXIT': original[helpers_end:]}
    for marker, raw in pieces.items():
        token = f'/* @INSTALLER_{marker}@ */'
        if source.count(token) != 1:
            raise ValueError('release selection adapter marker changed: ' + marker)
        source = source.replace(token, raw)
    return source


def template():
    with tempfile.TemporaryDirectory(prefix='hia-selection-template-') as folder:
        base = Path(folder)
        assembly, obj, raw = base/'adapter.S', base/'adapter.o', base/'adapter.bin'
        assembly.write_text(adapter_source())
        subprocess.run(['as', '--64', str(assembly), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            address, _, name = line.split()
            symbols[name] = int(address, 16)
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved selection adapter relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        + struct.pack('<IIQQQQQQ', 1,5,0,0x400000,0x400000,0,0,4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551,6,0,0,0,0,0,16))
    return header + code, {name:176 + symbols[name] for name in
        ('policy_initial_hole', 'policy_hole', 'sha_hole', 'selection_hole')}


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    selection = uint(s, 24, 8)
    if policy == 0 or sha == 0 or selection == 0:
        return 4294967295
    if policy > 1048576 or sha > 1048576 or selection > 1048576:
        return 4294967295
    if length(s) != 32 + policy + sha + selection:
        return 4294967295
    size = {len(prefix)} + policy + sha + selection
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at + 8]
        source += f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, offset in holes.items():
        target = str(len(prefix))
        if name in ('sha_hole', 'selection_hole'):
            target += ' + policy'
        if name == 'selection_hole':
            target += ' + sha'
        source += f'    write(o, {offset}, {target} - {offset + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 32, {len(prefix)}, policy + sha + selection)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in [('release_selection_policy', policy_source()),
                         ('release_selection_packer', packer_source())]:
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm'
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
