"""Author a HIA policy and HIA ELF packer for disposable shared-ELF observation.

The policy owns protocol admission, limits, continuations and response bytes.
The fixed bridge executes Linux/SysV operations and the existing foreign
dlopen/dlsym/dlclose ABI. GNU ld payloads and the system loader remain actual
foreign dependencies; this is not a replacement for arbitrary ELF loading.
"""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x400000
INTERPRETER = b'/lib64/ld-linux-x86-64.so.2\0'
HEADER_BYTES = 64 + 6 * 56
CODE_OFFSET = (HEADER_BYTES + len(INTERPRETER) + 15) & ~15
HASH = 32
SYMBOLS = 64
STRINGS = 160
RELOCATIONS = 224
DYNAMIC = 320
NAMES = b'\0dlopen\0dlsym\0dlclose\0libdl.so.2\0libc.so.6\0'
BRIDGE = bytes.fromhex(
    '488b04244881ec0001000048894424184531e44531ff31db31ed48c704240000'
    '000048c74424080000000048c7442410ffffffffbe00100000e825040000483d'
    '01f0ffff0f83ed0300004989c64c8da800020000488b442418498946084c89e7'
    '488b34244c89eab9000200004d89f041b900020000e80000000083f8000f84ae'
    '03000083f801744a83f8020f843401000083f8030f84a701000083f8040f84b4'
    '01000083f8050f84d901000083f8060f846d02000083f8070f84f602000083f8'
    '080f845c030000e96b03000049894610eb8bbf04000000498b7538b89d000000'
    '0f054885c075e5bf03000000b89d0000000f054885c075d4bf04000000498b75'
    '30e83f0300004885c075c131ff498b7508e82f0300004885c075b1bf09000000'
    '498b7510e81c0300004885c0759ebf03000000498b7518e8090300004885c075'
    '8bbf01000000498b7520e8f60200004885c00f8574ffffffbf07000000498b75'
    '28e8df0200004885c00f855dffffff498b7500e8eb020000483d01f0ffff0f83'
    '48ffffff4989c448c7042400000000498b5500482b14247425498d3424480334'
    '2431ff31c00f054883f8fc74e24885c00f8816ffffff740648010424ebd131c0'
    'e907ffffff488d3de7020000498b7510b83f0100000f054885c00f88ecfeffff'
    '4889442410498946184889c74c89e649037500498b5508e8860200004885c00f'
    '85c7feffff488b7c2410be09040000498b5518b8480000000f054885c00f85a9'
    'feffff488b7c2410be0a04000031d2b8480000000f054989462031c0e98bfeff'
    'ff498d7d40498b7500ff15000000004989c7e975feffff4c89ff498d7540ff15'
    '000000004889c349894620488b7c2410b8030000000f0548c7442410ffffffff'
    'e947feffff498b75084885f6750348ffc6e8cd010000483d01f0ffff0f832afe'
    'ffff48894424084889c7498b4d08418a4510fcf3aa498b75004885f6750348ff'
    'c649837d2800753131ffba0300000041ba010000004d8b45184531c9b8090000'
    '000f05483d01f0ffff0f83ddfdffff4889c531c0e9d3fdffffe865010000483d'
    '01f0ffff0f83c2fdffff4889c54889c7498b4d00418a4520fcf3aa31c0e9aafd'
    'ffffbf01000000488db42480000000b8e40000000f054885c00f858dfdffff4c'
    '89e749037d00498b75084889ea498b4d104c8b4424084d8b4d18ffd349894638'
    'bf01000000488db42490000000b8e40000000f054885c00f854ffdffff488b84'
    '248000000049894618488b84248800000049894620488b842490000000498946'
    '28488b8424980000004989463031c0e918fdffffbf01000000498db580000000'
    'ba18000000e8b80000004885c00f85f9fcffffbf010000004c89e64903750049'
    '8b5508e89a0000004885c00f85dbfcffffbf010000004889ee498b5510e88000'
    '00004885c00f85c1fcffffbf01000000488b742408498b5518e864000000e9a9'
    'fcffff4c89ffff1500000000e99bfcffff498b7d00eb05bf46000000b83c0000'
    '000f050f0b48897424f048897424f889fe31ff488d5424f04531d2b82e010000'
    '0f05c331ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f'
    '05c34885d27424b8010000000f054883f8fc74ee4885c0781274084801c64829'
    'c2ebdf48c7c0fbffffffc34885d2750231c0c36869612d6c696e6b65642d696d'
    '61676500'
)
BRIDGE_HOLES = {'policy_hole': 118, 'dlopen_hole': 587, 'dlsym_hole': 608, 'dlclose_hole': 1064}
RESPONSE_MAGIC = int.from_bytes(b'HIAOBR02', 'little')
FRAME_MAGIC = int.from_bytes(b'HIAOBS02', 'little')

POLICY_SOURCE = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 512 or length(w) < 512:
        return 70
    phase = get(w, 0)
    if phase == 0:
        if get(w, 8) != 1:
            return finish(o, 64)
        put(o, 0, 5242937)
        put(o, 8, 10)
        put(o, 16, 268435456)
        put(o, 24, 8388608)
        put(o, 32, 16777216)
        put(o, 40, 32)
        put(o, 48, 0)
        put(o, 56, 0)
        put(w, 0, 1)
        return 1
    if phase == 1:
        if get(w, 16) != 0:
            return finish(o, 4)
        if length(s) > 5242936:
            return finish(o, 3)
        if length(s) < 56:
            return finish(o, 2)
        if uint(s, 0) != FRAME_MAGIC_VALUE:
            return finish(o, 2)
        image = uint(s, 8)
        source = uint(s, 16)
        capacity = uint(s, 24)
        workspace = uint(s, 32)
        fill = uint(s, 40)
        descriptor = uint(s, 48)
        if image == 0 or image > 4194304 or source > 1048576:
            return finish(o, 2)
        if length(s) != 56 + image + source:
            return finish(o, 2)
        if capacity > 1048576 or workspace > 1048576 or fill > 255:
            return finish(o, 2)
        if descriptor != 18446744073709551615:
            if descriptor < 3 or descriptor > 2147483647:
                return finish(o, 2)
        put(w, 64, image)
        put(w, 72, source)
        put(w, 80, capacity)
        put(w, 88, workspace)
        put(w, 96, fill)
        put(w, 104, descriptor)
        put(o, 0, 56)
        put(o, 8, image)
        put(o, 16, 2)
        put(o, 24, 15)
        put(w, 0, 2)
        return 2
    if phase == 2:
        if get(w, 16) != 0 or get(w, 32) != 15:
            return finish(o, 4)
        descriptor = get(w, 24)
        if descriptor < 3 or descriptor >= 32:
            return finish(o, 4)
        path(o, descriptor)
        put(o, 0, 2)
        put(w, 0, 3)
        return 3
    if phase == 3:
        if get(w, 16) == 0:
            return finish(o, 1)
        write(o, 64, 12390, 2)
        store(o, 66, 0)
        put(w, 0, 4)
        return 4
    if phase == 4:
        if get(w, 16) != 0 or get(w, 32) == 0:
            return finish(o, 1)
        put(o, 0, get(w, 80))
        put(o, 8, get(w, 88))
        put(o, 16, get(w, 96))
        put(o, 24, get(w, 104))
        put(o, 32, 165)
        private = 0
        if get(w, 104) == 18446744073709551615:
            private = 1
        put(o, 40, private)
        put(w, 0, 5)
        return 5
    if phase == 5:
        if get(w, 16) != 0:
            return finish(o, 4)
        arguments(o, w)
        put(w, 0, 6)
        return 6
    if phase == 6:
        if get(w, 16) != 0:
            return finish(o, 4)
        elapsed = (get(w, 40) - get(w, 24)) * 1000000000 + get(w, 48) - get(w, 32)
        put(o, 128, RESPONSE_MAGIC_VALUE)
        put(o, 136, get(w, 56))
        put(o, 144, elapsed)
        arguments(o, w)
        put(w, 0, 7)
        return 7
    if phase == 7:
        if get(w, 16) != 0:
            return finish(o, 4)
        put(w, 0, 8)
        return 8
    if phase == 8:
        if get(w, 16) != 0:
            return finish(o, 1)
        return finish(o, 0)
    return finish(o, 70)

def arguments(o:mutbuf, w:mutbuf) -> u64:
    put(o, 0, 56 + get(w, 64))
    put(o, 8, get(w, 72))
    put(o, 16, get(w, 80))
    put(o, 24, get(w, 88))
    return 0

def finish(o:mutbuf, code:u64) -> u32:
    put(o, 0, code)
    return 0

def path(o:mutbuf, descriptor:u64) -> u64:
    write(o, 64, PATH_PREFIX_FIRST, 8)
    write(o, 72, PATH_PREFIX_SECOND, 6)
    at = 78
    tens = 0
    while descriptor >= 10:
        descriptor = descriptor - 10
        tens = tens + 1
    if tens != 0:
        store(o, at, tens + 48)
        at = at + 1
    store(o, at, descriptor + 48)
    store(o, at + 1, 0)
    return 0

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    return write(o, at, value, 8)

def write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def policy_source():
    return (POLICY_SOURCE.replace('FRAME_MAGIC_VALUE', str(FRAME_MAGIC))
            .replace('RESPONSE_MAGIC_VALUE', str(RESPONSE_MAGIC))
            .replace('PATH_PREFIX_FIRST', str(int.from_bytes(b'/proc/se', 'little')))
            .replace('PATH_PREFIX_SECOND', str(int.from_bytes(b'lf/fd/', 'little'))))


def dynamic_entries(data):
    address = BASE + data
    return [
        (1, NAMES.index(b'libdl.so.2')), (1, NAMES.index(b'libc.so.6')),
        (4, address + HASH), (5, address + STRINGS), (6, address + SYMBOLS),
        (10, len(NAMES)), (11, 24), (7, address + RELOCATIONS),
        (8, 72), (9, 24), (3, address), (24, 0), (30, 8),
        (0x6ffffffb, 1), (21, 0), (0, 0),
    ]


def header(data):
    address = BASE + data
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    raw = ident + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1,
                             BASE + CODE_OFFSET, 64, 0, 0, 64, 56, 6, 0, 0, 0)
    segments = [
        (3, 4, HEADER_BYTES, BASE + HEADER_BYTES, BASE + HEADER_BYTES,
         len(INTERPRETER), len(INTERPRETER), 1),
        (1, 5, 0, BASE, BASE, data, data, 4096),
        (1, 6, data, address, address, 4096, 4096, 4096),
        (2, 6, data + DYNAMIC, address + DYNAMIC, address + DYNAMIC,
         len(dynamic_entries(data)) * 16, len(dynamic_entries(data)) * 16, 8),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
        (0x6474e552, 4, data, address, address, 4096, 4096, 1),
    ]
    return raw + b''.join(struct.pack('<IIQQQQQQ', *row) for row in segments)


def data_page(data):
    raw = bytearray(4096)
    struct.pack_into('<7I', raw, HASH, 1, 4, 1, 0, 2, 3, 0)
    for index, name in enumerate((b'dlopen', b'dlsym', b'dlclose'), 1):
        struct.pack_into('<IBBHQQ', raw, SYMBOLS + index * 24,
                         NAMES.index(name), 18, 0, 0, 0, 0)
        struct.pack_into('<QQq', raw, RELOCATIONS + (index - 1) * 24,
                         BASE + data + (index - 1) * 8, (index << 32) | 6, 0)
    raw[STRINGS:STRINGS+len(NAMES)] = NAMES
    for index, row in enumerate(dynamic_entries(data)):
        struct.pack_into('<QQ', raw, DYNAMIC + index * 16, *row)
    return bytes(raw)


def assembled_bridge():
    # Source tests independently assemble the fixed foreign transport.
    # Qualification never invokes an assembler to construct this template.
    with tempfile.TemporaryDirectory(prefix='hia-linked-observer-authoring-') as folder:
        obj, binary = Path(folder)/'bridge.o', Path(folder)/'bridge.bin'
        subprocess.run(['as', '--64', str(ROOT/'tools/hia_linked_observer_bridge.S'), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)],
                       check=True, capture_output=True)
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved linked observer transport relocation')
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            offset, _, name = line.split()
            symbols[name] = int(offset, 16)
        bridge = binary.read_bytes()
    return bridge, {name: symbols[name] for name in BRIDGE_HOLES}


def template():
    prefix = header(0) + INTERPRETER
    prefix += bytes(CODE_OFFSET - len(prefix)) + BRIDGE
    return prefix, {name: CODE_OFFSET + offset for name, offset in BRIDGE_HOLES.items()}


def reference_image(policy):
    if not isinstance(policy, bytes) or not policy:
        raise ValueError('nonempty policy image required')
    prefix, holes = template()
    data = (len(prefix) + len(policy) + 4095) & ~4095
    if data + 4096 > 1 << 20:
        raise ValueError('observer image exceeds its existing one MiB output bound')
    raw = bytearray(prefix + policy + bytes(data-len(prefix)-len(policy)) + data_page(data))
    raw[:HEADER_BYTES] = header(data)
    for index, name in enumerate(('dlopen_hole', 'dlsym_hole', 'dlclose_hole')):
        struct.pack_into('<i', raw, holes[name], data + index * 8 - holes[name] - 4)
    struct.pack_into('<i', raw, holes['policy_hole'], len(prefix) - holes['policy_hole'] - 4)
    return bytes(raw)


def packer_source():
    prefix, holes = template()
    tail = data_page(0)
    text = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    policy = length(s)
    if policy == 0 or policy > 1048576:
        return 4294967295
    data = ({len(prefix)} + policy + 4095) & 18446744073709547520
    size = data + 4096
    if size > 1048576 or length(o) < size:
        return 4294967294
    i = 0
    while i < size:
        store(o, i, 0)
        i = i + 1
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        if any(chunk):
            text += f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    for at in range(0, len(tail), 8):
        chunk = tail[at:at+8]
        if any(chunk):
            text += f'    write(o, data + {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    # Program headers whose extents/addresses depend on the actual policy bytes.
    for at in (64 + 56 + 32, 64 + 56 + 40, 64 + 2*56 + 8, 64 + 5*56 + 8):
        text += f'    write(o, {at}, data, 8)\n'
    for at in (64 + 2*56 + 16, 64 + 2*56 + 24, 64 + 5*56 + 16, 64 + 5*56 + 24):
        text += f'    write(o, {at}, data + {BASE}, 8)\n'
    text += f'    write(o, {64+3*56+8}, data + {DYNAMIC}, 8)\n'
    for at in (64 + 3*56 + 16, 64 + 3*56 + 24):
        text += f'    write(o, {at}, data + {BASE+DYNAMIC}, 8)\n'
    for index, (tag, value) in enumerate(dynamic_entries(0)):
        if tag in (3, 4, 5, 6, 7):
            text += f'    write(o, data + {DYNAMIC+index*16+8}, data + {value}, 8)\n'
    for index in range(3):
        text += f'    write(o, data + {RELOCATIONS+index*24}, data + {BASE+index*8}, 8)\n'
    for index, name in enumerate(('dlopen_hole', 'dlsym_hole', 'dlclose_hole')):
        text += f'    write(o, {holes[name]}, data + {index*8} - {holes[name]+4}, 4)\n'
    text += f'    write(o, {holes["policy_hole"]}, {len(prefix)-holes["policy_hole"]-4}, 4)\n'
    text += f'''    i = 0
    while i < policy:
        store(o, {len(prefix)} + i, byte(s, i))
        i = i + 1
    return size
'''
    return text + POLICY_SOURCE[POLICY_SOURCE.index('\ndef write('):]


def main():
    for name, source in (('linked_observer_policy', policy_source()),
                         ('linked_observer_packer', packer_source())):
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm'
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
