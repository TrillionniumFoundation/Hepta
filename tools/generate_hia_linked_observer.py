"""HIA continuation policy and complete ET_REL packer for linked observation.

The policy originates in the published linked observer and owns all private
frame admission, resource-limit values, foreign-action sequencing, response
construction and terminal decisions. The fixed Linux/SysV bridge preserves
libc startup/exit and the exact complete shared object lifetime. It exposes
physical loader, memory, time and write operations; it does not reimplement
the HIA state machine. A real system linker constructs the dynamic executable.
"""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
IMPORTS = ("__libc_start_main", "dlopen", "dlsym", "dlerror", "exit")
RESPONSE_MAGIC = int.from_bytes(b'HIAOBR03', 'little')
FRAME_MAGIC = int.from_bytes(b'HIAOBS03', 'little')
BRIDGE = bytes.fromhex(
    '31ed4989d15e4889e24883e4f050544531c031c9488d3d07000000e800000000'
    '0f0b89f84881ec0801000048894424184531e44531ff31db31ed48c704240000'
    '000048c74424080000000048c7442410ffffffffbe00100000e8e7040000483d'
    '01f0ffff0f83ad0400004989c64c8da800020000488b442418498946084c89e7'
    '488b34244c89eab9000200004d89f041b900020000e80000000083f8000f846e'
    '04000083f801745383f8020f843d01000083f8030f84b901000083f8040f84c5'
    '01000083f8050f84e901000083f8060f847d02000083f8070f844f03000083f8'
    '080f84fd02000083f8090f84ac030000e92204000049894610eb82bf04000000'
    '498b7538b89d0000000f054885c075e5bf03000000b89d0000000f054885c075'
    'd4bf04000000498b7530e8f80300004885c075c131ff498b7508e8e803000048'
    '85c075b1bf09000000498b7510e8d50300004885c0759ebf03000000498b7518'
    'e8c20300004885c0758bbf01000000498b7520e8af0300004885c00f8574ffff'
    'ffbf07000000498b7528e8980300004885c00f855dffffff498b7500e8a40300'
    '00483d01f0ffff0f8348ffffff4989c448c7042400000000498b5500482b1424'
    '7425498d34244803342431ff31c00f054883f8fc74e24885c00f8816ffffff74'
    '0648010424ebd131c0e907ffffff488d3dd4030000498b7510b83f0100000f05'
    '4885c00f88ecfeffff4889442410498946184889c74c89e649037500498b5508'
    'e83f0300004885c00f85c7feffff488b7c2410be09040000498b5518b8480000'
    '000f054885c00f85a9feffff488b7c2410be0a04000031d2b8480000000f0549'
    '8946204885c00f8889feffff31c0e982feffff498d7d40498b7500e800000000'
    '4989c7e96dfeffff4c89ff498d7540e8000000004889c349894620488b7c2410'
    'b8030000000f0548c7442410ffffffffe940feffff498b75084885f6750348ff'
    'c6e87f020000483d01f0ffff0f8323feffff48894424084889c7498b4d08418a'
    '4510fcf3aa498b75004885f6750348ffc649837d2800753131ffba0300000041'
    'ba010000004d8b45184531c9b8090000000f05483d01f0ffff0f83d6fdffff48'
    '89c531c0e9ccfdffffe817020000483d01f0ffff0f83bbfdffff4889c54889c7'
    '498b4d00418a4520fcf3aa31c0e9a3fdffffbf01000000488db42480000000b8'
    'e40000000f054885c00f8586fdffff4c89e749037d00498b75084889ea498b4d'
    '104c8b4424084d8b4d18ffd349894638bf01000000488db42490000000b8e400'
    '00000f054885c00f8548fdffff488b84248000000049894618488b8424880000'
    '0049894620488b84249000000049894628488b8424980000004989463031c0e9'
    '11fdffff498b7d204889ee498b551041ba08000000e89b0100004885c00f85f2'
    'fcffff498b452848898424a0000000498b7d20488db424a0000000ba08000000'
    '4531d2e86d010000e9c8fcffffbf01000000498db580000000ba18000000e821'
    '0100004885c00f85a9fcffffbf010000004c89e649037500498b5508e8030100'
    '004885c00f858bfcffffbf010000004889ee498b5510e8e90000004885c00f85'
    '71fcffffbf01000000488b742408498b5518e8cd000000e959fcffffe8000000'
    '004885c074424889c631d2803c1600740548ffc2ebf5bf02000000e8a4000000'
    '4885c00f852cfcffffbf02000000488d3505010000ba01000000e88500000048'
    '85c00f850dfcffff48837c2410ff741a488b7c2410b8030000000f0548c74424'
    '10ffffffffe9ebfbffff31c0e9e4fbffff498b7d00eb05bf460000004883e4f0'
    'e8000000000f0b48897424f048897424f889fe31ff488d5424f04531d2b82e01'
    '00000f05c331ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000'
    '000f05c34885d27424b8010000000f054883f8fc74ee4885c0781274084801c6'
    '4829c2ebdf48c7c0fbffffffc34885d2750231c0c34885d27427b8120000000f'
    '054883f8fc74ee4885c07815740b4801c64901c24829c2ebdc48c7c0fbffffff'
    'c34885d2750231c0c36869612d6c696e6b65642d696d616765000a'
)
BRIDGE_RELOCATIONS = ((28, '__libc_start_main'), (636, 'dlopen'), (656, 'dlsym'), (1181, 'dlerror'), (1313, 'exit'))
POLICY_HOLE = 150
START_SIZE = 34
POLICY_SOURCE = 'def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(o) < 512 or length(w) < 512:\n        return 70\n    phase = get(w, 0)\n    if phase == 0:\n        if get(w, 8) != 1:\n            return finish(o, 64)\n        put(o, 0, 5242937)\n        put(o, 8, 10)\n        put(o, 16, 268435456)\n        put(o, 24, 8388608)\n        put(o, 32, 16777216)\n        put(o, 40, 32)\n        put(o, 48, 0)\n        put(o, 56, 0)\n        put(w, 0, 1)\n        return 1\n    if phase == 1:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        if length(s) > 5242936:\n            return finish(o, 3)\n        if length(s) < 56:\n            return finish(o, 2)\n        if uint(s, 0) != FRAME_MAGIC_VALUE:\n            return finish(o, 2)\n        image = uint(s, 8)\n        source = uint(s, 16)\n        capacity = uint(s, 24)\n        workspace = uint(s, 32)\n        fill = uint(s, 40)\n        descriptors = uint(s, 48)\n        descriptor = descriptors & 4294967295\n        snapshot = descriptors >> 32\n        if image == 0 or image > 4194304 or source > 1048576:\n            return finish(o, 2)\n        if length(s) != 56 + image + source:\n            return finish(o, 2)\n        if capacity > 1048576 or workspace > 1048576 or fill > 255:\n            return finish(o, 2)\n        if snapshot < 3 or snapshot > 2147483647:\n            return finish(o, 2)\n        if descriptor != 4294967295:\n            if descriptor < 3 or descriptor > 2147483647 or descriptor == snapshot:\n                return finish(o, 2)\n        put(w, 64, image)\n        put(w, 72, source)\n        put(w, 80, capacity)\n        put(w, 88, workspace)\n        put(w, 96, fill)\n        put(w, 104, descriptor)\n        put(w, 112, snapshot)\n        put(o, 0, 56)\n        put(o, 8, image)\n        put(o, 16, 2)\n        put(o, 24, 15)\n        put(w, 0, 2)\n        return 2\n    if phase == 2:\n        if get(w, 16) != 0 or get(w, 32) != 15:\n            return finish(o, 4)\n        descriptor = get(w, 24)\n        if descriptor < 3 or descriptor >= 32:\n            return finish(o, 4)\n        path(o, descriptor)\n        put(o, 0, 2)\n        put(w, 0, 3)\n        return 3\n    if phase == 3:\n        if get(w, 16) == 0:\n            put(w, 0, 10)\n            return 9\n        write(o, 64, 12390, 2)\n        store(o, 66, 0)\n        put(w, 0, 4)\n        return 4\n    if phase == 4:\n        if get(w, 16) != 0:\n            return finish(o, 1)\n        if get(w, 32) == 0:\n            put(w, 0, 10)\n            return 9\n        put(o, 0, get(w, 80))\n        put(o, 8, get(w, 88))\n        put(o, 16, get(w, 96))\n        put(o, 24, get(w, 104))\n        put(o, 32, 165)\n        private = 0\n        if get(w, 104) == 4294967295:\n            private = 1\n        put(o, 40, private)\n        put(w, 0, 5)\n        return 5\n    if phase == 5:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        arguments(o, w)\n        put(w, 0, 6)\n        return 6\n    if phase == 6:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        elapsed = (get(w, 40) - get(w, 24)) * 1000000000 + get(w, 48) - get(w, 32)\n        put(o, 128, RESPONSE_MAGIC_VALUE)\n        put(o, 136, get(w, 56))\n        put(o, 144, elapsed)\n        arguments(o, w)\n        put(o, 32, get(w, 112))\n        put(o, 40, get(w, 80) + 1)\n        put(w, 0, 7)\n        return 8\n    if phase == 7:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        arguments(o, w)\n        put(w, 0, 8)\n        return 7\n    if phase == 8:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        return finish(o, 0)\n    if phase == 10:\n        if get(w, 16) != 0:\n            return finish(o, 4)\n        return finish(o, 1)\n    return finish(o, 70)\n\ndef arguments(o:mutbuf, w:mutbuf) -> u64:\n    put(o, 0, 56 + get(w, 64))\n    put(o, 8, get(w, 72))\n    put(o, 16, get(w, 80))\n    put(o, 24, get(w, 88))\n    return 0\n\ndef finish(o:mutbuf, code:u64) -> u32:\n    put(o, 0, code)\n    return 0\n\ndef path(o:mutbuf, descriptor:u64) -> u64:\n    write(o, 64, PATH_PREFIX_FIRST, 8)\n    write(o, 72, PATH_PREFIX_SECOND, 6)\n    at = 78\n    tens = 0\n    while descriptor >= 10:\n        descriptor = descriptor - 10\n        tens = tens + 1\n    if tens != 0:\n        store(o, at, tens + 48)\n        at = at + 1\n    store(o, at, descriptor + 48)\n    store(o, at + 1, 0)\n    return 0\n\ndef uint(s:readbuf, at:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(s, at + i) << (i * 8))\n        i = i + 1\n    return value\n\ndef get(w:mutbuf, at:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(w, at + i) << (i * 8))\n        i = i + 1\n    return value\n\ndef put(o:mutbuf, at:u64, value:u64) -> u64:\n    return write(o, at, value, 8)\n\ndef write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:\n    i = 0\n    while i < count:\n        store(o, at + i, (value >> (i * 8)) & 255)\n        i = i + 1\n    return 0\n'


def policy_source():
    return (POLICY_SOURCE.replace('FRAME_MAGIC_VALUE', str(FRAME_MAGIC))
            .replace('RESPONSE_MAGIC_VALUE', str(RESPONSE_MAGIC))
            .replace('PATH_PREFIX_FIRST', str(int.from_bytes(b'/proc/se', 'little')))
            .replace('PATH_PREFIX_SECOND', str(int.from_bytes(b'lf/fd/', 'little'))))


def _parts():
    text = bytearray(BRIDGE)
    struct.pack_into('<i', text, POLICY_HOLE, len(text) - POLICY_HOLE - 4)
    names = ['', '_start', *IMPORTS]
    strings = bytearray(b'\0')
    positions = {'': 0}
    for name in names[1:]:
        positions[name] = len(strings)
        strings.extend(name.encode('ascii') + b'\0')
    symbols = [bytes(24), struct.pack('<IBBHQQ', 0, 3, 0, 1, 0, 0),
               struct.pack('<IBBHQQ', positions['_start'], 18, 0, 1, 0, START_SIZE)]
    symbol_at = {'_start': 2}
    for name in IMPORTS:
        symbol_at[name] = len(symbols)
        symbols.append(struct.pack('<IBBHQQ', positions[name], 18, 0, 0, 0, 0))
    relas = b''.join(struct.pack('<QQq', at, (symbol_at[name] << 32) | 4, -4)
                     for at, name in BRIDGE_RELOCATIONS)
    section_strings = b'\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'
    return bytes(text), relas, b''.join(symbols), bytes(strings), section_strings


def _header(section_offset):
    return struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                       1, 62, 1, 0, 0, section_offset, 0, 64, 0, 0, 64, 7, 5)


def _sections(policy, rela_at, symbols_at, strings_at, shstrings_at, stack_at):
    text, relas, symbols, strings, section_strings = _parts()
    name = {key: section_strings.index(key.encode() + b'\0')
            for key in ('.text', '.rela.text', '.symtab', '.strtab', '.shstrtab', '.note.GNU-stack')}
    rows = [
        bytes(64),
        struct.pack('<IIQQQQIIQQ', name['.text'], 1, 6, 0, 64, len(text)+policy, 0, 0, 16, 0),
        struct.pack('<IIQQQQIIQQ', name['.rela.text'], 4, 64, 0, rela_at, len(relas), 3, 1, 8, 24),
        struct.pack('<IIQQQQIIQQ', name['.symtab'], 2, 0, 0, symbols_at, len(symbols), 4, 2, 8, 24),
        struct.pack('<IIQQQQIIQQ', name['.strtab'], 3, 0, 0, strings_at, len(strings), 0, 0, 1, 0),
        struct.pack('<IIQQQQIIQQ', name['.shstrtab'], 3, 0, 0, shstrings_at, len(section_strings), 0, 0, 1, 0),
        struct.pack('<IIQQQQIIQQ', name['.note.GNU-stack'], 1, 0, 0, stack_at, 0, 0, 0, 1, 0),
    ]
    return b''.join(rows)


def reference_object(policy):
    'Independent struct-based whole-object representation for actual bytes.'
    if type(policy) is not bytes or not policy or len(policy) > 1 << 20:
        raise ValueError('nonempty bounded actual policy image required')
    text, relas, symbols, strings, section_strings = _parts()
    raw = bytearray(bytes(64) + text + policy)
    raw.extend(bytes((-len(raw)) % 8))
    rela_at = len(raw); raw.extend(relas)
    symbols_at = len(raw); raw.extend(symbols)
    strings_at = len(raw); raw.extend(strings)
    shstrings_at = len(raw); raw.extend(section_strings)
    stack_at = len(raw)
    raw.extend(bytes((-len(raw)) % 8))
    section_offset = len(raw)
    raw.extend(_sections(len(policy), rela_at, symbols_at, strings_at, shstrings_at, stack_at))
    if len(raw) > 1 << 20:
        raise ValueError('observer object exceeds existing one MiB output capacity')
    raw[:64] = _header(section_offset)
    return bytes(raw)


def packer_source():
    text, relas, symbols, strings, section_strings = _parts()
    parts = [('prefix', _header(0) + text),
             ('tail', relas + symbols + strings + section_strings),
             ('sections', _sections(0, 0, 0, 0, 0, 0))]
    functions = []
    calls = {}
    for name, data in parts:
        names = []
        for group, begin in enumerate(range(0, len(data), 48 * 8)):
            function = f'emit_{name}_{group}'
            names.append(function)
            lines = [f'def {function}(o:mutbuf, base:u64) -> u64:']
            for at in range(begin, min(begin + 48 * 8, len(data)), 8):
                chunk = data[at:at+8]
                if any(chunk):
                    lines.append(f'    write(o, base + {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})')
            lines.append('    return 0')
            functions.append('\n'.join(lines))
        calls[name] = names
    result = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    policy = length(s)
    if policy == 0 or policy > 1048576:
        return 4294967295
    relas = ({64+len(text)} + policy + 7) & 18446744073709551608
    symbols = relas + {len(relas)}
    strings = symbols + {len(symbols)}
    shstrings = strings + {len(strings)}
    stack = shstrings + {len(section_strings)}
    sections = (stack + 7) & 18446744073709551608
    size = sections + 448
    if size > 1048576 or length(o) < size:
        return 4294967294
    i = 0
    while i < size:
        store(o, i, 0)
        i = i + 1
'''
    for key, base in (('prefix','0'), ('tail','relas'), ('sections','sections')):
        for function in calls[key]:
            result += f'    {function}(o, {base})\n'
    result += f'''    write(o, 40, sections, 8)
    write(o, sections + 96, {len(text)} + policy, 8)
    write(o, sections + 152, relas, 8)
    write(o, sections + 216, symbols, 8)
    write(o, sections + 280, strings, 8)
    write(o, sections + 344, shstrings, 8)
    write(o, sections + 408, stack, 8)
    i = 0
    while i < policy:
        store(o, {64+len(text)} + i, byte(s, i))
        i = i + 1
    return size
'''
    return result + '\n\n' + '\n\n'.join(functions) + POLICY_SOURCE[POLICY_SOURCE.index('\ndef write('):]


def assembled_bridge():
    'Assemble the independent oracle only in source tests, never building.'
    with tempfile.TemporaryDirectory(prefix='hia-linked-observer-reference-') as folder:
        obj = Path(folder)/'reference.o'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_linked_observer_bridge.S'),'-o',str(obj)],
                       check=True,capture_output=True,timeout=30)
        raw = obj.read_bytes()
    header = struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    rows = [struct.unpack_from('<IIQQQQIIQQ',raw,header[6]+i*header[11]) for i in range(header[12])]
    r = rows[header[13]]; names = raw[r[4]:r[4]+r[5]]
    def string(data,at): return data[at:data.index(0,at)].decode('ascii')
    named = {string(names,r[0]):r for r in rows}
    text = named['.text']; table = named['.symtab']; r = rows[table[6]]
    strings = raw[r[4]:r[4]+r[5]]
    symbols = [struct.unpack_from('<IBBHQQ',raw,table[4]+i) for i in range(0,table[5],24)]
    values = {string(strings,row[0]):row for row in symbols}
    relas = []
    for row in rows:
        if row[1] == 4 and rows[row[7]] == text:
            for i in range(0,row[5],24):
                at,info,addend = struct.unpack_from('<QQq',raw,row[4]+i)
                if info & 0xffffffff != 4 or addend != -4:
                    raise AssertionError('foreign relocation representation differs')
                relas.append((at,string(strings,symbols[info>>32][0])))
    return (raw[text[4]:text[4]+text[5]],tuple(relas),values['policy_hole'][4],values['_start'][5])


def main():
    for name, source in (('linked_observer_policy',policy_source()), ('linked_observer_packer',packer_source())):
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(document(source,name)))
        print(path.name,path.stat().st_size)


if __name__ == '__main__':
    main()
