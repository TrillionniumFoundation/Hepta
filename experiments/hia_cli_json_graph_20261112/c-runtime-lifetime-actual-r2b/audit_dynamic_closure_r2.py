"""Read exact ELF bytes only; no loading, linking, symbol calls or compilation."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

PLAN = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r2b-20261112-e26e')
OUTPUT = Path('/tmp/hia-cli-json-c-runtime-lifetime-failure-r2b-20261112-e26e/dynamic-closure-r2')
sys.path.insert(0, str(PLAN / 'control'))
from common import read_file, wire, pin, identity, parent_fd
from support import system_file
import stat


def require(value, text):
    if not value:
        raise ValueError(text)


def save(path, raw):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            require(count > 0, 'short evidence write')
            at += count
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            value = os.read(fd, 65536)
            if not value:
                break
            chunks.append(value)
        require(b''.join(chunks) == raw, 'evidence descriptor readback differs')
    finally:
        os.close(fd)
    actual, record = read_file(path, 32 << 20)
    require(actual == raw, 'evidence name readback differs')
    return record



def bound_system_bytes(row):
    """Same frozen system metadata contract, additionally retaining bytes."""
    path = Path(row['physical_path'])
    chunks = []
    with parent_fd(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            information = os.fstat(fd)
            before = identity(information)
            require(stat.S_ISREG(information.st_mode) and before == row['identity']
                    and before == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'exact frozen system identity before read')
            require(information.st_size == row['bytes'] and information.st_size <= 64 << 20,
                    'exact frozen system size')
            remaining = information.st_size
            while remaining:
                part = os.read(fd, min(remaining, 65536))
                require(bool(part), 'frozen system input was truncated')
                chunks.append(part)
                remaining -= len(part)
            require(not os.read(fd, 1) and before == identity(os.fstat(fd))
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'exact frozen system changed during read')
        finally:
            os.close(fd)
    raw = b''.join(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    git = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    require(digest == row['sha256'] and git == row['git_blob'], 'exact frozen system full hashes')
    return raw, {'path': str(path), 'identity': before, 'bytes': len(raw), 'sha256': digest, 'git_blob': git}

def elf(raw):
    def span(offset, size):
        require(0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset, 'ELF bounds')
        return raw[offset:offset + size]

    h = struct.unpack('<16sHHIQQQIHHHHHH', span(0, 64))
    require(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[2] == 62 and h[3] == 1,
            'expected exact ELF64 little-endian x86-64')
    require(h[8] == 64 and h[9] == 56 and h[11] == 64 and h[12] > 0 and h[13] < h[12],
            'ELF table layout')
    sections = [struct.unpack('<IIQQQQIIQQ', span(h[6] + i * 64, 64)) for i in range(h[12])]
    section_names = span(sections[h[13]][4], sections[h[13]][5])

    def string(table, at):
        require(0 <= at < len(table), 'ELF string index')
        end = table.find(b'\0', at)
        require(end >= at, 'ELF string terminator')
        return table[at:end].decode('ascii', 'strict')

    names = [string(section_names, s[0]) for s in sections]
    dyn_indices = [i for i, s in enumerate(sections) if s[1] == 11]
    require(len(dyn_indices) == 1, 'exactly one complete dynamic symbol table required')
    dynamic_index = dyn_indices[0]
    table = sections[dynamic_index]
    require(table[9] == 24 and table[5] % 24 == 0 and table[6] < len(sections), 'dynamic symbol stride/link')
    strings_section = sections[table[6]]
    strings = span(strings_section[4], strings_section[5])
    symbol_count = table[5] // 24
    versyms = [i for i, s in enumerate(sections) if s[1] == 0x6fffffff]
    require(len(versyms) <= 1, 'duplicate GNU version-symbol table')
    versions = [1] * symbol_count
    if versyms:
        s = sections[versyms[0]]
        require(s[6] == dynamic_index and s[5] == 2 * symbol_count, 'complete GNU versym table')
        versions = list(struct.unpack('<' + 'H' * symbol_count, span(s[4], s[5])))

    version_requirements = {}
    version_definitions = {}
    version_records = []
    for section in sections:
        if section[1] not in (0x6ffffffe, 0x6ffffffd):
            continue
        require(section[6] < len(sections), 'version strings link')
        ts = sections[section[6]]
        text = span(ts[4], ts[5])
        data = span(section[4], section[5])
        at = 0
        seen = set()
        while True:
            require(at not in seen, 'cyclic version record')
            seen.add(at)
            if section[1] == 0x6ffffffe:
                require(at + 16 <= len(data), 'Verneed extent')
                version, count, file_at, aux, following = struct.unpack_from('<HHIII', data, at)
                require(version == 1 and count > 0, 'Verneed profile')
                aux_at = at + aux
                row = {'kind': 'need', 'file': string(text, file_at), 'versions': []}
                for index in range(count):
                    require(aux_at + 16 <= len(data), 'Vernaux extent')
                    hashed, flags, other, name_at, next_aux = struct.unpack_from('<IHHII', data, aux_at)
                    key = other & 0x7fff
                    require(key > 1 and key not in version_requirements, 'unique needed version index')
                    item = {'index': key, 'name': string(text, name_at), 'file': row['file'],
                            'flags': flags, 'hash': hashed}
                    version_requirements[key] = item
                    row['versions'].append(item)
                    require((index + 1 == count) == (next_aux == 0), 'complete Vernaux chain')
                    aux_at += next_aux
            else:
                require(at + 20 <= len(data), 'Verdef extent')
                version, flags, key, count, hashed, aux, following = struct.unpack_from('<HHHHIII', data, at)
                require(version == 1 and count > 0 and key not in version_definitions, 'unique Verdef profile')
                aux_at = at + aux
                labels = []
                for index in range(count):
                    require(aux_at + 8 <= len(data), 'Verdaux extent')
                    name_at, next_aux = struct.unpack_from('<II', data, aux_at)
                    labels.append(string(text, name_at))
                    require((index + 1 == count) == (next_aux == 0), 'complete Verdaux chain')
                    aux_at += next_aux
                row = {'kind': 'definition', 'index': key, 'name': labels[0],
                       'parents': labels[1:], 'flags': flags, 'hash': hashed}
                version_definitions[key] = row
            version_records.append(row)
            if not following:
                break
            require(following > 0 and at + following < len(data), 'version next extent')
            at += following

    symbols = []
    for i in range(symbol_count):
        n, info, visibility, section, value, extent = struct.unpack('<IBBHQQ', span(table[4] + i * 24, 24))
        version_index = versions[i] & 0x7fff
        mapping = version_requirements if section == 0 else version_definitions
        require(version_index <= 1 or version_index in mapping, 'dynamic symbol version index must resolve')
        symbols.append({'index': i, 'name': string(strings, n), 'bind': info >> 4,
                        'type': info & 15, 'visibility': visibility & 3, 'other': visibility,
                        'section': section, 'value': value, 'bytes': extent,
                        'version_index': version_index, 'version_hidden': bool(versions[i] & 0x8000),
                        'version': mapping.get(version_index)})

    needed = []
    dynamic = []
    for section in sections:
        if section[1] != 6:
            continue
        require(section[9] == 16 and section[5] % 16 == 0 and section[6] < len(sections), 'dynamic table shape')
        ts = sections[section[6]]
        text = span(ts[4], ts[5])
        for at in range(section[4], section[4] + section[5], 16):
            tag, value = struct.unpack('<qQ', span(at, 16))
            row = {'tag': tag, 'value': value}
            if tag in (1, 14, 15, 29):
                row['string'] = string(text, value)
                if tag == 1:
                    needed.append(row['string'])
            dynamic.append(row)
    interpreter = None
    for i in range(h[10]):
        ph = struct.unpack('<IIQQQQQQ', span(h[5] + i * 56, 56))
        if ph[0] == 3:
            require(interpreter is None, 'duplicate interpreter')
            text = span(ph[2], ph[5])
            require(text.endswith(b'\0') and b'\0' not in text[:-1], 'interpreter string')
            interpreter = text[:-1].decode('ascii')

    selected = {dynamic_index, table[6]}
    for i, section in enumerate(sections):
        if section[1] in (6, 0x6fffffff, 0x6ffffffe, 0x6ffffffd):
            selected.add(i)
            if section[6]:
                selected.add(section[6])
    raw_sections = []
    for i in sorted(selected):
        s = sections[i]
        value = span(s[4], s[5])
        raw_sections.append({'index': i, 'name': names[i], 'type': s[1], 'offset': s[4],
                             'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                             'base64': base64.b64encode(value).decode('ascii')})
    return {'symbols': symbols, 'version_records': version_records, 'needed': needed,
            'interpreter': interpreter, 'dynamic': dynamic, 'complete_original_sections': raw_sections}


def eligible_export(row):
    return bool(row['name'] and row['section'] != 0 and row['bind'] in (1, 2, 10)
                and row['visibility'] in (0, 3))


def satisfies(required, candidate):
    if not eligible_export(candidate) or required['name'] != candidate['name']:
        return False
    if required['version'] is None:
        return not candidate['version_hidden']
    return candidate['version'] is not None and required['version']['name'] == candidate['version']['name']


def main():
    require(not OUTPUT.exists(), 'new evidence namespace required')
    OUTPUT.mkdir(mode=0o700)
    policy_raw, policy_pin = read_file(PLAN / 'POLICY.json', 2 << 20)
    policy = json.loads(policy_raw)
    manifest_raw, manifest_pin = read_file(PLAN / 'SYSTEM-INPUTS.json', 8 << 20)
    require(manifest_pin['sha256'] == policy['system_manifest']['sha256'], 'frozen system manifest SHA')
    manifest = json.loads(manifest_raw)
    frozen = {row['physical_path']: row for row in manifest['files']}
    observed = {}
    original_pins = {}

    def bound_system(path):
        require(path in frozen, 'dependency must already be frozen: ' + path)
        raw, record = bound_system_bytes(frozen[path])
        original_pins[path] = record
        return elf(raw)

    root = policy['python']['path']
    pending = [root]
    order = []
    edges = []
    while pending:
        path = pending.pop(0)
        if path in observed:
            continue
        data = bound_system(path)
        observed[path] = data
        order.append(path)
        for name in data['needed']:
            candidates = [row for row in manifest['ELF_declared_dependencies']
                          if row['from'] == path and row.get('needed') == name]
            physical = {row['physical'] for row in candidates}
            require(len(physical) == 1, 'one already-bound resolution for each actual DT_NEEDED')
            target = next(iter(physical))
            edges.append({'from': path, 'needed': name, 'to': target, 'frozen_observations': candidates})
            pending.append(target)
        if data['interpreter'] is not None:
            candidates = [row for row in manifest['ELF_declared_dependencies']
                          if row['from'] == path and row.get('interpreter') == data['interpreter']]
            physical = {row['physical'] for row in candidates}
            require(len(physical) == 1, 'actual PT_INTERP needs one already-bound resolution')
            target = next(iter(physical))
            edges.append({'from': path, 'interpreter': data['interpreter'], 'to': target,
                          'frozen_observations': candidates})
            pending.append(target)

    raw, dso_pin = read_file(ACTUAL / 'work/c-build/cli-json.so', 1 << 20)
    require(dso_pin['size'] == 72464 and dso_pin['sha256'] ==
            '0d2a0d0085a851e77d463561025d7537915fa421298c058f92e0fc836023cf1d', 'exact original r2b DSO')
    dso = elf(raw)
    require(dso['needed'] == [] and dso['interpreter'] is None, 'original -nostdlib DSO topology')
    required = [row for row in dso['symbols'] if row['name'] and row['section'] == 0 and row['bind'] != 2]
    require(len(required) == 119 and all(row['bind'] == 1 for row in required), 'complete actual 119 strong imports')
    rows = []
    for row in required:
        matches = []
        for path in order:
            for candidate in observed[path]['symbols']:
                if satisfies(row, candidate):
                    matches.append({'provider': path, 'symbol': candidate})
        rows.append({'required': row, 'compatible_exports': matches, 'resolved_by_declared_scope': bool(matches)})
    missing = [row['required']['name'] for row in rows if not row['resolved_by_declared_scope']]
    require(missing == ['_PyErr_SetRaisedException'], 'exact complete unresolved set')
    outputs = []
    for index, path in enumerate(order):
        value = {'schema': 'hia.cli-json.complete-dynsym-original.v1', 'file': original_pins[path],
                 'elf': observed[path], 'file_or_function_executed': False}
        outputs.append(save(OUTPUT / ('provider-%02d.json' % index), wire(value)))
    outputs.append(save(OUTPUT / 'original-DSO.json', wire({'schema': 'hia.cli-json.complete-dynsym-original.v1',
                        'file': dso_pin, 'elf': dso, 'file_or_function_executed': False})))
    for path, expected in original_pins.items():
        require(system_file(frozen[path]) == expected, 'provider changed after full inspection')
    require(pin(ACTUAL / 'work/c-build/cli-json.so', 1 << 20) == dso_pin, 'original DSO changed')
    result = {'schema': 'hia.cli-json.r2b-complete-static-symbol-closure.v1',
              'status': 'COMPLETE_READONLY_AUDIT_ONE_UNRESOLVED_INTERNAL_FUNCTION',
              'qualification_status': 'HOLD', 'policy': policy_pin, 'system_manifest': manifest_pin,
              'dso': dso_pin, 'dynamic_symbol_count': len(dso['symbols']),
              'strong_undefined_count': len(required), 'weak_undefined_count': 0,
              'compatible_strong_count': len(required) - len(missing), 'unresolved': missing,
              'provider_count': len(observed), 'provider_resolution_order': order,
              'provider_dependencies': edges, 'all119_rows': rows,
              'complete_symbol_and_string_and_version_tables': outputs,
              'GNU_version_and_visibility_checked': True,
              'providers_full_file_identity_SHA_Git_before_after_checked': True,
              'runtime_mapped_view_reobserved': False,
              'scope': 'Static declared loader closure of actual Python plus its pinned transitive DT_NEEDED/PT_INTERP files; no dlopen or relocated-memory observation.',
              'new_compilation': False, 'new_DSO_load': False, 'new_HIA_or_native_execution': False}
    save(OUTPUT / 'REPORT.json', wire(result))
    print(json.dumps({k: result[k] for k in ('status', 'strong_undefined_count', 'compatible_strong_count',
                                          'unresolved', 'provider_count')}))


if __name__ == '__main__':
    main()
