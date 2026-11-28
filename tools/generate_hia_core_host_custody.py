"""Author the independent HIA decoder for complete Core host identity data."""
from __future__ import annotations
import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_source_helper_manifest import original, function, append_functions, exact_view
from tools.generate_hia_source_agent_helper_manifest import unchanged_profile
from tools.hia_core_host_custody import (ROOT, ARCHIVE_PATH, DECODER_SOURCE, ENTRIES,
    BAG_MAGIC, RECORD_MAGIC, REQUEST_MAGIC, MAX_ARCHIVE, capture_archive)

POLICY = "\ndef custody(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(s) < 40 or length(s) > MAX_REQUEST or length(w) < 65536:\n        return 16\n    if f23(s, 0, 8) != REQUEST_MAGIC:\n        return 16\n    wanted_role = f23(s, 8, 8)\n    wanted_kind = f23(s, 16, 8)\n    if wanted_role < 11 or wanted_role > 13 or wanted_kind < 1 or wanted_kind > 2:\n        return 16\n    if f23(s, 24, 8) != BAG_MAGIC or f23(s, 32, 8) != 6:\n        return 16\n    cursor = 40\n    role = 11\n    kind = 1\n    selected_at = 0\n    selected_size = 0\n    index = 0\n    while index < 6:\n        if cursor > length(s) or length(s) - cursor < 8:\n            return 16\n        extent = f23(s, cursor, 8)\n        cursor = cursor + 8\n        if extent < 128 or extent > length(s) - cursor:\n            return 16\n        if f23(s, cursor, 8) != RECORD_MAGIC or f23(s, cursor + 8, 8) != 1:\n            return 16\n        if f23(s, cursor + 16, 8) != role or f23(s, cursor + 24, 8) != kind:\n            return 16\n        if f23(s, cursor + 32, 8) != 420:\n            return 16\n        name_size = f23(s, cursor + 40, 8)\n        size = f23(s, cursor + 48, 8)\n        if name_size == 0 or name_size > 4095 or name_size > extent - 128:\n            return 16\n        if size == 0 or size > 1048576 or size != extent - 128 - name_size:\n            return 16\n        reserved = 108\n        while reserved < 128:\n            if byte(s, cursor + reserved) != 0:\n                return 16\n            reserved = reserved + 1\n        if custody_path(s, cursor + 128, name_size, role, kind) == 0:\n            return 16\n        at = cursor + 128 + name_size\n        f25(w, 48000, at)\n        f25(w, 48008, size)\n        f25(w, 48016, 0)\n        f46(s, w)\n        digest_at = 0\n        while digest_at < 32:\n            if byte(w, 48032 + digest_at) != byte(s, cursor + 76 + digest_at):\n                return 16\n            digest_at = digest_at + 1\n        if custody_git_sha1(s, w, at, size, cursor + 56) == 0:\n            return 16\n        if role == wanted_role and kind == wanted_kind:\n            selected_at = at\n            selected_size = size\n        cursor = cursor + extent\n        if kind == 1:\n            kind = 2\n        else:\n            role = role + 1\n            kind = 1\n        index = index + 1\n    if cursor != length(s) or selected_size == 0:\n        return 16\n    if selected_size > length(o):\n        return 17\n    index = 0\n    while index < selected_size:\n        store(o, index, byte(s, selected_at + index))\n        index = index + 1\n    f25(w, 88, selected_size)\n    f25(w, 16, 3)\n    return 0\n\ndef custody_rotate(value:u64, bits:u64) -> u64:\n    return ((value << bits) | (value >> (32 - bits))) & 4294967295\n\ndef custody_message_byte(s:readbuf, w:mutbuf, at:u64, size:u64, prefix:u64, total:u64, position:u64) -> u64:\n    if position < prefix:\n        return byte(w, 57000 + position)\n    if position - prefix < size:\n        return byte(s, at + position - prefix)\n    if position == prefix + size:\n        return 128\n    if position >= total - 8:\n        return (((prefix + size) * 8) >> ((total - 1 - position) * 8)) & 255\n    return 0\n\ndef custody_git_sha1(s:readbuf, w:mutbuf, at:u64, size:u64, expected:u64) -> u64:\n    store(w, 57000, 98)\n    store(w, 57001, 108)\n    store(w, 57002, 111)\n    store(w, 57003, 98)\n    store(w, 57004, 32)\n    power = 1\n    digits = 1\n    while power * 10 <= size:\n        power = power * 10\n        digits = digits + 1\n    remaining = size\n    digit_at = 0\n    while digit_at < digits:\n        place = 1\n        exponent = digit_at + 1\n        while exponent < digits:\n            place = place * 10\n            exponent = exponent + 1\n        digit = 0\n        while remaining >= place:\n            remaining = remaining - place\n            digit = digit + 1\n        store(w, 57005 + digit_at, digit + 48)\n        digit_at = digit_at + 1\n    prefix = 6 + digits\n    store(w, 57005 + digits, 0)\n    padded = prefix + size + 1\n    while (padded & 63) != 56:\n        padded = padded + 1\n    total = padded + 8\n    f25(w, 57600, 1732584193)\n    f25(w, 57608, 4023233417)\n    f25(w, 57616, 2562383102)\n    f25(w, 57624, 271733878)\n    f25(w, 57632, 3285377520)\n    block = 0\n    while block < total:\n        index = 0\n        while index < 16:\n            value = 0\n            part = 0\n            while part < 4:\n                value = (value << 8) | custody_message_byte(s, w, at, size, prefix, total, block + index * 4 + part)\n                part = part + 1\n            f25(w, 58000 + index * 8, value)\n            index = index + 1\n        while index < 80:\n            value = f24(w, 58000 + (index - 3) * 8) ^ f24(w, 58000 + (index - 8) * 8)\n            value = value ^ f24(w, 58000 + (index - 14) * 8) ^ f24(w, 58000 + (index - 16) * 8)\n            f25(w, 58000 + index * 8, custody_rotate(value, 1))\n            index = index + 1\n        a = f24(w, 57600)\n        b = f24(w, 57608)\n        c = f24(w, 57616)\n        d = f24(w, 57624)\n        e = f24(w, 57632)\n        index = 0\n        while index < 80:\n            if index < 20:\n                choice = (b & c) | ((b ^ 4294967295) & d)\n                constant = 1518500249\n            elif index < 40:\n                choice = b ^ c ^ d\n                constant = 1859775393\n            elif index < 60:\n                choice = (b & c) | (b & d) | (c & d)\n                constant = 2400959708\n            else:\n                choice = b ^ c ^ d\n                constant = 3395469782\n            temporary = (custody_rotate(a, 5) + choice + e + constant + f24(w, 58000 + index * 8)) & 4294967295\n            e = d\n            d = c\n            c = custody_rotate(b, 30)\n            b = a\n            a = temporary\n            index = index + 1\n        f25(w, 57600, (f24(w, 57600) + a) & 4294967295)\n        f25(w, 57608, (f24(w, 57608) + b) & 4294967295)\n        f25(w, 57616, (f24(w, 57616) + c) & 4294967295)\n        f25(w, 57624, (f24(w, 57624) + d) & 4294967295)\n        f25(w, 57632, (f24(w, 57632) + e) & 4294967295)\n        block = block + 64\n    index = 0\n    while index < 5:\n        value = f24(w, 57600 + index * 8)\n        part = 0\n        while part < 4:\n            if byte(s, expected + index * 4 + part) != ((value >> ((3 - part) * 8)) & 255):\n                return 0\n            part = part + 1\n        index = index + 1\n    return 1\n\ndef custody_path(s:readbuf, at:u64, size:u64, role:u64, kind:u64) -> u64:\n"

def source_program():
    source = POLICY
    for name, value in {'MAX_REQUEST': MAX_ARCHIVE + 24,
                        'BAG_MAGIC': int.from_bytes(BAG_MAGIC, 'little'),
                        'RECORD_MAGIC': int.from_bytes(RECORD_MAGIC, 'little'),
                        'REQUEST_MAGIC': int.from_bytes(REQUEST_MAGIC, 'little')}.items():
        source = source.replace(name, str(value))
    for role, kind, path in ENTRIES:
        source += (f'    if role == {role} and kind == {kind}:\n'
                   f'        return custody_path_{role}_{kind}(s, at, size)\n')
    source += '    return 0\n\n'
    for role, kind, path in ENTRIES:
        source += exact_view(f'custody_path_{role}_{kind}', path.encode('ascii'), 'f23')
    return source


def document():
    result = original('stage')
    result['module'] = 'source_core_host_custody'
    append_functions(result, source_program())
    functions = {fn['name']: fn for fn in result['functions']}
    reachable, pending = set(), ['custody']
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        if name not in functions:
            raise ValueError('missing complete host identity decoder callee: ' + name)
        reachable.add(name)
        pending.extend(op['attrs']['function'] for block in functions[name]['blocks']
                       for op in block['ops'] if op['op'] == 'call')
    result['functions'] = [functions['custody']] + [
        fn for fn in result['functions'] if fn['name'] in reachable and fn['name'] != 'custody']
    retained = original('stage')
    old = {fn['name']: fn for fn in retained['functions']}
    for fn in result['functions']:
        if fn['name'] in old and fn != old[fn['name']]:
            raise ValueError('retained independent SHA/byte operation changed: ' + fn['name'])
    return unchanged_profile(result)


def generated():
    return render_assembly(document()).encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--capture-receipt', type=Path)
    args = parser.parse_args()
    archive, receipt = capture_archive(ROOT)
    values = ((ARCHIVE_PATH, archive), (DECODER_SOURCE, generated()))
    for name, raw in values:
        path = ROOT / name
        if args.check:
            if path.read_bytes() != raw:
                raise SystemExit('complete host identity source differs: ' + name)
        else:
            path.write_bytes(raw)
            path.chmod(0o644)
        print(json.dumps({'path': name, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}))
    if args.capture_receipt:
        args.capture_receipt.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
