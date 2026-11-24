"""HIA-owned cold scalar-export observer and complete dynamic ELF object packer.

The only foreign actions are Linux byte custody, dlopen/dlsym and fixed SysV
integer calls. HIA owns all frame admission, ordering and response publication.
"""
from pathlib import Path
import struct, subprocess, tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
IMPORTS=("__libc_start_main","dlopen","dlsym","dlerror","exit")
FRAME_MAGIC=int.from_bytes(b'HIAEXQ01','little')
RESPONSE_MAGIC=int.from_bytes(b'HIAEXR01','little')
BRIDGE=bytes.fromhex('31ed4989d15e4889e24883e4f050544531c031c9488d3d07000000e8000000000f0b4881ecb800000048897c24184531e44531ff31db48c704240000000048c7442410ffffffffbe00100100e8d6020000483d01f0ffff0f839c0200004989c64c8da800000100488b442418498946084c89e7488b34244c89eab9000200004d89f041b900000100e80000000083f8000f845d02000083f801744183f8020f84b000000083f8030f842c01000083f8040f843801000083f8050f844301000083f8060f84c201000083f8070f84d3010000e92302000049894610eb94bf04000000498b7518e81f0200004885c075e731ff498b7508e80f0200004885c075d7bf09000000498b7510e8fc0100004885c075c4498b7500e80c020000483d01f0ffff73b34989c4498b5500482b142474204c89e64803342431ff31c00f054883f8fc74e34885c0788e740648010424ebd631c0eb82488d3d17020000498b7510b83f0100000f054885c00f8867ffffff4889442410498946184889c74c89e649037500498b5508e8bb0100004885c00f8542ffffff488b7c2410be09040000498b5518b8480000000f054885c00f8524ffffff488b7c2410be0a04000031d2b8480000000f05498946204885c00f8804ffffff31c0e9fdfeffff498d7d40498b7500e8000000004989c7e9e8feffff4c89ff498d7540e8000000004889c3e9d4feffff4883ec50498b453048890424498b45384889442408498b45404889442410498b45484889442418498b45504889442420498b45584889442428498b45604889442430498b45684889442438498b45704889442440498b45784889442448498b7d00498b7508498b5510498b4d184d8b45204d8b4d2831c0ffd34883c4504989463831c0e94cfeffffbf010000004c89f649037500498b5508e8a7000000e932feffffe8000000004885c0743e4889c631d2803c1600740548ffc2ebf5bf02000000e87e0000004885c00f8505feffffbf02000000488d35ac000000ba01000000e85f000000e9eafdffff31c0e9e3fdffff498b7d00eb05bf460000004883e4f0e8000000000f0b48897424f048897424f889fe31ff488d5424f04531d2b82e0100000f05c331ffba0300000041ba2200000049c7c0ffffffff4531c9b8090000000f05c34885d27424b8010000000f054883f8fc74ee4885c0781474084801c64829c2ebdf48c7c0fbffffffc331c0c36869612d636f6c642d6578706f72742d746172676574000a')
BRIDGE_RELOCATIONS=((28, '__libc_start_main'), (482, 'dlopen'), (502, 'dlsym'), (677, 'dlerror'), (771, 'exit'))
POLICY_HOLE=137
START_SIZE=34
POLICY_SOURCE='def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(o) < 512 or length(w) < 65536:\n        return 70\n    phase = get(w, 0)\n    result = get(w, 16)\n    if phase == 0:\n        if get(w, 8) != 1:\n            return finish(o, 64)\n        put(o, 0, 4489281)\n        put(o, 8, 10)\n        put(o, 16, 268435456)\n        put(o, 24, 0)\n        put(w, 0, 1)\n        return 1\n    if phase == 1:\n        if result != 0:\n            return finish(o, 4)\n        if length(s) > 4489280:\n            return finish(o, 3)\n        if length(s) < 64 or uint(s, 0) != FRAME_MAGIC_VALUE:\n            return finish(o, 2)\n        image = uint(s, 8)\n        count = uint(s, 16)\n        records = uint(s, 24)\n        if image == 0 or image > 4194304 or count == 0 or count > 1024:\n            return finish(o, 2)\n        if records != count * 288 or uint(s, 32) != 0 or uint(s, 40) != 0 or uint(s, 48) != 0:\n            return finish(o, 2)\n        if length(s) != 64 + records + image or uint(s, 56) != length(s):\n            return finish(o, 2)\n        index = 0\n        while index < count:\n            if valid_call(s, 64 + index * 288) == 0:\n                return finish(o, 2)\n            index = index + 1\n        put(w, 64, image)\n        put(w, 72, count)\n        put(w, 80, 64)\n        put(w, 88, 0)\n        put(w, 104, 64 + records)\n        put(w, 256, RESPONSE_MAGIC_VALUE)\n        put(w, 264, count)\n        put(w, 272, count * 24)\n        put(w, 280, 0)\n        put(o, 0, 64 + records)\n        put(o, 8, image)\n        put(o, 16, 2)\n        put(o, 24, 15)\n        put(w, 0, 2)\n        return 2\n    if phase == 2:\n        if result != 0 or get(w, 32) != 15:\n            return finish(o, 4)\n        descriptor = get(w, 24)\n        if descriptor < 3 or descriptor > 2147483647:\n            return finish(o, 4)\n        path(o, descriptor)\n        put(o, 0, 2)\n        put(w, 0, 3)\n        return 3\n    if phase == 3:\n        if result == 0:\n            put(w, 0, 10)\n            return 7\n        return next_name(s, o, w)\n    if phase == 4:\n        if result == 0:\n            put(w, 0, 10)\n            return 7\n        base = get(w, 80)\n        index = 0\n        while index < 16:\n            put(o, index * 8, uint(s, base + 160 + index * 8))\n            index = index + 1\n        put(w, 0, 5)\n        return 5\n    if phase == 5:\n        if result != 0:\n            return finish(o, 4)\n        index = get(w, 88)\n        kind = uint(s, get(w, 80) + 16)\n        returned = get(w, 56)\n        if kind == 0:\n            returned = 0\n        at = 288 + index * 24\n        put(w, at, index)\n        put(w, at + 8, kind)\n        put(w, at + 16, returned)\n        index = index + 1\n        put(w, 88, index)\n        if index == get(w, 72):\n            put(o, 0, 256)\n            put(o, 8, 32 + index * 24)\n            put(w, 0, 6)\n            return 6\n        put(w, 80, 64 + index * 288)\n        return next_name(s, o, w)\n    if phase == 6:\n        if result != 0:\n            return finish(o, 4)\n        return finish(o, 0)\n    if phase == 10:\n        if result != 0:\n            return finish(o, 4)\n        return finish(o, 1)\n    return finish(o, 70)\n\ndef valid_call(s:readbuf, at:u64) -> u64:\n    size = uint(s, at)\n    count = uint(s, at + 8)\n    kind = uint(s, at + 16)\n    if size == 0 or size > 128 or count > 16 or kind > 12 or uint(s, at + 24) != 0:\n        return 0\n    index = 0\n    while index < 128:\n        value = byte(s, at + 32 + index)\n        if index < size:\n            okay = (value >= 65 and value <= 90) or (value >= 97 and value <= 122) or value == 95\n            if index != 0 and value >= 48 and value <= 57:\n                okay = True\n            if okay == False:\n                return 0\n        elif value != 0:\n            return 0\n        index = index + 1\n    index = count\n    while index < 16:\n        if uint(s, at + 160 + index * 8) != 0:\n            return 0\n        index = index + 1\n    return 1\n\ndef next_name(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    at = get(w, 80)\n    size = uint(s, at)\n    index = 0\n    while index < size:\n        store(o, 64 + index, byte(s, at + 32 + index))\n        index = index + 1\n    store(o, 64 + size, 0)\n    put(w, 0, 4)\n    return 4\n\ndef path(o:mutbuf, descriptor:u64) -> u64:\n    write(o, 64, PATH_PREFIX_FIRST, 8)\n    write(o, 72, PATH_PREFIX_SECOND, 6)\n    started = False\n    at = 78\n    index = 0\n    while index < 10:\n        divisor = decimal_divisor(index)\n        digit = 0\n        while descriptor >= divisor:\n            descriptor = descriptor - divisor\n            digit = digit + 1\n        if digit != 0 or started or index == 9:\n            store(o, at, digit + 48)\n            at = at + 1\n            started = True\n        index = index + 1\n    store(o, at, 0)\n    return 0\n\ndef decimal_divisor(index:u64) -> u64:\n    if index == 0:\n        return 1000000000\n    if index == 1:\n        return 100000000\n    if index == 2:\n        return 10000000\n    if index == 3:\n        return 1000000\n    if index == 4:\n        return 100000\n    if index == 5:\n        return 10000\n    if index == 6:\n        return 1000\n    if index == 7:\n        return 100\n    if index == 8:\n        return 10\n    return 1\n\ndef finish(o:mutbuf, code:u64) -> u32:\n    put(o, 0, code)\n    return 0\n\ndef uint(s:readbuf, at:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(s, at + i) << (i * 8))\n        i = i + 1\n    return value\n\ndef get(w:mutbuf, at:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 8:\n        value = value | (byte(w, at + i) << (i * 8))\n        i = i + 1\n    return value\n\ndef put(o:mutbuf, at:u64, value:u64) -> u64:\n    return write(o, at, value, 8)\n\ndef write(o:mutbuf, at:u64, value:u64, count:u64) -> u64:\n    i = 0\n    while i < count:\n        store(o, at + i, (value >> (i * 8)) & 255)\n        i = i + 1\n    return 0\n'

def policy_source():
    return (POLICY_SOURCE.replace('FRAME_MAGIC_VALUE',str(FRAME_MAGIC))
       .replace('RESPONSE_MAGIC_VALUE',str(RESPONSE_MAGIC))
       .replace('PATH_PREFIX_FIRST',str(int.from_bytes(b'/proc/se','little')))
       .replace('PATH_PREFIX_SECOND',str(int.from_bytes(b'lf/fd/','little'))))

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
        subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_export_syscalls.S'),'-o',str(obj)],
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
    for name, source in (('cold_export_observer',policy_source()), ('cold_export_packer',packer_source())):
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hepta'
        path.write_text(render_assembly(document(source,name)))
        print(path.name,path.stat().st_size)


if __name__ == '__main__':
    main()
