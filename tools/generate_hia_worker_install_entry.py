"""Author the native Worker CLI using the qualified release entry mechanics.

The emitted HIA program owns argument parsing, source capture, streamed package
hashing, sealed descriptors, the complete HIAWIN01 request and child lifetime.
The common authoring renderer is reused without changing the release program.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import generate_hia_release_build_entry as shared

STATE = 2097152
HELP = (b'usage: hia-worker-install --output PATH --compiler PATH --cold-report PATH '
        b'--package PATH --package-sha256 HEX [--source ROOT] '
        b'[--timeout-seconds SECONDS] [--artifact-root PATH ...] '
        b'[--runtime-config PATH]\n')

WORKER_FUNCTIONS = r'''
def arguments(s:readbuf, w:mutbuf) -> u64:
    if uint(s, 0, 8) != 3544411325348268360:
        return 0
    count = uint(s, 8, 8)
    if count < 1 or count > 82:
        return 0
    at = 144
    first = uint(s, at, 8)
    if first == 0 or first > 4095:
        return 0
    copy(s, w, 2097152 + 53248, at + 8, first)
    store(w, 2097152 + 53248 + first, 0)
    put(w, 2097152 + 264, first)
    at = at + 9 + first
    if count == 2:
        size = uint(s, at, 8)
        if argument_equal(s, w, at + 8, size, 2097152 + 46400, 6) != 0:
            return 2
    if count < 11 or count & 1 == 0:
        return 0
    mask = 0
    index = 1
    while index < count:
        if at + 8 > 262144:
            return 0
        size = uint(s, at, 8)
        if size > 8192 or at + 9 + size > 262144:
            return 0
        bit = worker_option(s, w, at + 8, size)
        if bit == 0:
            return 0
        if bit != 128 and mask & bit != 0:
            return 0
        mask = mask | bit
        at = at + 9 + size
        if at + 8 > 262144:
            return 0
        size = uint(s, at, 8)
        if size > 4095 or at + 9 + size > 262144:
            return 0
        if size == 0 and bit != 128:
            return 0
        if worker_value(s, w, at + 8, size, bit) == 0:
            return 0
        at = at + 9 + size
        index = index + 2
    if mask & 103 != 103 or split_output(w) == 0:
        return 0
    i = 0
    while i < 4:
        nonzero = 0
        j = 0
        while j < 32:
            nonzero = nonzero | byte(s, 16 + i * 32 + j)
            j = j + 1
        if nonzero == 0:
            return 0
        i = i + 1
    copy(s, w, 2097152 + 512, 16, 128)
    return 1

def worker_option(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    bit = 0
    target = 0
    if argument_equal(s, w, at, size, 2097152 + 46080, 8) != 0:
        bit = 1
        target = 2097152 + 16384
    elif argument_equal(s, w, at, size, 2097152 + 46144, 10) != 0:
        bit = 2
        target = 2097152 + 24576
    elif argument_equal(s, w, at, size, 2097152 + 46208, 13) != 0:
        bit = 4
        target = 2097152 + 28672
    elif argument_equal(s, w, at, size, 2097152 + 46272, 8) != 0:
        bit = 8
        target = 2097152 + 20480
    elif argument_equal(s, w, at, size, 2097152 + 46336, 17) != 0:
        bit = 16
    elif argument_equal(s, w, at, size, 2097152 + 46528, 9) != 0:
        bit = 32
        target = 2097152 + 57344
    elif argument_equal(s, w, at, size, 2097152 + 46592, 16) != 0:
        bit = 64
    elif argument_equal(s, w, at, size, 2097152 + 46656, 15) != 0:
        bit = 128
    elif argument_equal(s, w, at, size, 2097152 + 46720, 24) != 0:
        bit = 128
    elif argument_equal(s, w, at, size, 2097152 + 46784, 16) != 0:
        bit = 256
        target = 2097152 + 61440
    put(w, 2097152 + 344, target)
    return bit

def worker_value(s:readbuf, w:mutbuf, at:u64, size:u64, bit:u64) -> u64:
    if bit == 16:
        if size > 6:
            return 0
        number = 0
        i = 0
        while i < size:
            ch = byte(s, at + i)
            if ch < 48 or ch > 57:
                return 0
            number = number * 10 + ch - 48
            i = i + 1
        if number == 0 or number > 604800:
            return 0
        put(w, 2097152 + 224, number)
        return 1
    if bit == 64:
        if size != 64:
            return 0
        i = 0
        while i < 32:
            high = hexval(byte(s, at + i * 2))
            low = hexval(byte(s, at + i * 2 + 1))
            if high > 15 or low > 15:
                return 0
            store(w, 2097152 + 1024 + i, (high << 4) | low)
            i = i + 1
        return 1
    if bit == 128:
        return worker_root(s, w, at, size)
    if bit == 256:
        put(w, 2097152 + 360, 1)
    target = get(w, 2097152 + 344)
    if target == 0:
        return 0
    copy(s, w, target, at, size)
    store(w, target + size, 0)
    return 1

def worker_root(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    count = get(w, 2097152 + 320)
    used = get(w, 2097152 + 328)
    if count >= 32 or size > 4095:
        return 0
    if worker_utf8(s, at, size) == 0:
        return 0
    normalized = worker_posix_path(s, w, at, size, 2097152 + 200000)
    if normalized == 0 or normalized > 4095 or used + 8 + normalized > 131304:
        return 0
    put(w, 2097152 + 65536 + used, normalized)
    copyw(w, 2097152 + 65536 + used + 8, 2097152 + 200000, normalized)
    put(w, 2097152 + 320, count + 1)
    put(w, 2097152 + 328, used + 8 + normalized)
    put(w, 2097152 + 65536, count + 1)
    return 1

def worker_posix_path(s:readbuf, w:mutbuf, at:u64, size:u64, target:u64) -> u64:
    leading = worker_path_prefix(s, at, size)
    prefix = 0
    if leading != 0:
        prefix = choose(leading == 2, 2, 1)
        store(w, target, 47)
        if prefix == 2:
            store(w, target + 1, 47)
    used = prefix
    start = leading
    while start < size:
        end = worker_path_end(s, at, start, size)
        count = end - start
        if count != 0:
            if count != 1 or byte(s, at + start) != 46:
                if used > prefix:
                    store(w, target + used, 47)
                    used = used + 1
                copy(s, w, target + used, at + start, count)
                used = used + count
        start = end + 1
    if used == 0:
        store(w, target, 46)
        return 1
    return used

def worker_path_prefix(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(s, at + i) != 47:
            return i
        i = i + 1
    return size

def worker_path_end(s:readbuf, at:u64, start:u64, size:u64) -> u64:
    end = start
    while end < size:
        if byte(s, at + end) == 47:
            return end
        end = end + 1
    return size

def worker_utf8(s:readbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        ch = byte(s, at + i)
        if ch == 0:
            return 0
        if ch < 128:
            i = i + 1
        else:
            needed = 0
            low = 128
            high = 191
            if ch >= 194 and ch <= 223:
                needed = 1
            elif ch >= 224 and ch <= 239:
                needed = 2
                if ch == 224:
                    low = 160
                if ch == 237:
                    high = 159
            elif ch >= 240 and ch <= 244:
                needed = 3
                if ch == 240:
                    low = 144
                if ch == 244:
                    high = 143
            else:
                return 0
            if i + needed >= size:
                return 0
            first = byte(s, at + i + 1)
            if first < low or first > high:
                return 0
            j = 2
            while j <= needed:
                value = byte(s, at + i + j)
                if value < 128 or value > 191:
                    return 0
                j = j + 1
            i = i + needed + 1
    return 1

def request(o:mutbuf, w:mutbuf) -> u64:
    at = 33554432
    namesize = get(w, 2097152 + 216)
    inventorysize = get(w, 2097152 + 200)
    rootsize = get(w, 2097152 + 328)
    tail = 288 + namesize + inventorysize
    size = tail + 64 + rootsize + get(w, 2097152 + 360) * 48
    if rootsize < 8 or rootsize > 131304 or size > 2097152:
        return 0
    put(o, at, MAGIC_WORKER_REQUEST)
    put(o, at + 8, get(w, 2097152 + 272))
    put(o, at + 16, get(w, 2097152 + 16))
    put(o, at + 24, get(w, 2097152 + 24))
    put(o, at + 32, get(w, 2097152 + 32))
    put(o, at + 40, get(w, 2097152 + 40))
    put(o, at + 48, get(w, 2097152 + 88))
    put(o, at + 56, get(w, 2097152 + 96))
    put(o, at + 64, get(w, 2097152 + 104))
    put(o, at + 72, get(w, 2097152 + 112))
    put(o, at + 80, get(w, 2097152 + 120))
    put(o, at + 88, get(w, 2097152 + 48))
    put(o, at + 96, get(w, 2097152 + 56))
    put(o, at + 104, namesize)
    put(o, at + 112, inventorysize)
    put(o, at + 120, 0)
    copy_between(w, o, at + 128, 2097152 + 800, 160)
    copy_between(w, o, at + 288, 2097152 + 40960, namesize)
    copyw(o, at + 288 + namesize, 16777216, inventorysize)
    put(o, at + tail, MAGIC_WORKER_OPTIONS)
    put(o, at + tail + 8, get(w, 2097152 + 312))
    put(o, at + tail + 16, rootsize)
    put(o, at + tail + 24, get(w, 2097152 + 360))
    copy_between(w, o, at + tail + 32, 2097152 + 1024, 32)
    copy_between(w, o, at + tail + 64, 2097152 + 65536, rootsize)
    if get(w, 2097152 + 360) != 0:
        put(o, at + tail + 64 + rootsize, MAGIC_WORKER_CONFIG)
        put(o, at + tail + 72 + rootsize, get(w, 2097152 + 352))
        copy_between(w, o, at + tail + 80 + rootsize, 2097152 + 992, 32)
    put(w, 2097152 + 192, size)
    return 1
'''


def policy_source():
    original = ast.parse(shared.POLICY_SOURCE)
    functions = {node.name: node for node in original.body}

    def change(name, replacements):
        source = ast.get_source_segment(shared.POLICY_SOURCE, functions[name])
        for before, after in replacements:
            if source.count(before) != 1:
                raise ValueError('shared release entry changed outside reviewed Worker splice: ' + name)
            source = source.replace(before, after)
        return ast.parse(source).body[0]

    replacements = {}
    replacements['advance'] = change('advance', [
        ('if get(w, 2097152 + 176) < 10:', 'if get(w, 2097152 + 176) < 11 + get(w, 2097152 + 360):')])
    replacements['entry_start'] = change('entry_start', [
        ('2097152 + 48000, 118,', '2097152 + 48000, ' + str(len(HELP)) + ',')])
    replacements['input_phase'] = change('input_phase', [
        ('if size == 0 or size > 67108864:',
         'if size == 0 or size >> 63 != 0:\n'
         '            return finish(o, w, 65)\n'
         '        if get(w, 2097152 + 176) != 7 and size > choose(get(w, 2097152 + 176) == 6, 536870912, 67108864):'),
        ('        copyw(w, 2097152 + 768 + index * 32, 4096, 32)',
         '        if index == 6 and same_bytes(w, 4096, 2097152 + 1024, 32) == 0:\n'
         '            return finish(o, w, 65)\n'
         '        copyw(w, 2097152 + 768 + index * 32, 4096, 32)'),
        ('        put(w, 2097152 + 80 + index * 8, get(w, 2097152 + 144))',
         '        if index == 6:\n'
         '            put(w, 2097152 + 312, get(w, 2097152 + 144))\n'
         '        elif index == 7:\n'
         '            put(w, 2097152 + 352, get(w, 2097152 + 144))\n'
         '        else:\n'
         '            put(w, 2097152 + 80 + index * 8, get(w, 2097152 + 144))'),
        ('if get(w, 2097152 + 176) < 6:', 'if get(w, 2097152 + 176) < 7 + get(w, 2097152 + 360):'),
    ])
    replacements['open_input'] = change('open_input', [
        ('        path = 2097152 + 28672',
         '        path = 2097152 + 28672\n'
         '    elif index == 6:\n'
         '        directory = 18446744073709551516\n'
         '        path = 2097152 + 57344\n'
         '    elif index == 7:\n'
         '        directory = 18446744073709551516\n'
         '        path = 2097152 + 61440'),
        ('put(w, 2097152 + 8192, 657408)', 'put(w, 2097152 + 8192, choose(index == 7, 526336, 657408))'),
        ('put(w, 2097152 + 8208, 6)', 'put(w, 2097152 + 8208, choose(index == 7, 0, 6))'),
    ])
    replacements['inherit'] = change('inherit', [
        ('    descriptor = get(o, 33554432 + 24 + index * 8)',
         '    descriptor = get(w, 2097152 + 312)\n'
         '    if index < 10:\n'
         '        descriptor = get(o, 33554432 + 24 + index * 8)\n'
         '    elif index == 11:\n'
         '        descriptor = get(w, 2097152 + 352)')])
    added = WORKER_FUNCTIONS.replace('MAGIC_WORKER_REQUEST', str(int.from_bytes(b'HIAWIN01', 'little')))
    added = added.replace('MAGIC_WORKER_OPTIONS', str(int.from_bytes(b'HIAWOP01', 'little')))
    added = added.replace('MAGIC_WORKER_CONFIG', str(int.from_bytes(b'HIAWCF01', 'little')))
    extra = ast.parse(added).body
    for node in extra:
        if node.name in functions:
            replacements[node.name] = node
    for index, node in enumerate(original.body):
        if node.name in replacements:
            original.body[index] = replacements[node.name]
        elif node.name == 'entry_constants':
            node.name = 'release_entry_constants'
    original.body.extend(node for node in extra if node.name not in functions)
    constants = 'def entry_constants(w:mutbuf) -> u64:\n    release_entry_constants(w)\n'
    for offset, raw in (
        (45120, b'hia-worker-install-owner\0'), (46528, b'--package\0'),
        (46592, b'--package-sha256\0'), (46656, b'--artifact-root\0'),
        (46720, b'--readonly-artifact-root\0'), (46784, b'--runtime-config\0'),
        (48000, HELP + b'\0'),
    ):
        for at in range(0, len(raw), 8):
            part = raw[at:at + 8]
            if len(part) == 8:
                constants += f'    put(w, {STATE + offset + at}, {int.from_bytes(part, "little")})\n'
            else:
                for i, value in enumerate(part):
                    constants += f'    store(w, {STATE + offset + at + i}, {value})\n'
    constants += f'    put(w, {STATE + 328}, 8)\n    return 0\n'
    original.body.extend(ast.parse(constants).body)
    return ast.unparse(ast.fix_missing_locations(original))


def render():
    with tempfile.TemporaryDirectory(prefix='hia-worker-entry-author-') as directory:
        return shared._render(Path(directory), policy_source=policy_source(),
                              module_prefix='worker_install_entry',
                              adapter_source=ROOT / 'tools/hia_worker_install_entry_syscalls.S')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs, metadata = render()
    for module, source in outputs.items():
        path = ROOT / 'examples/hia_bootstrap' / (module + '.hepta')
        if args.check:
            if not path.is_file() or path.read_text() != source:
                raise SystemExit('native Worker entry source differs: ' + module)
        else:
            path.write_text(source)
    print(json.dumps(metadata, sort_keys=True))


if __name__ == '__main__':
    main()
