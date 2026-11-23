"""Author the HIA verifier for the canonical register-leaf object and its public build receipt."""

from __future__ import annotations

import struct


OBJECT_REQUEST = b'HIASRO01'
REPORT_MAGIC = b'HIARSR01'
RECEIPT_MAGIC = b'HIAPRR03'
OBLIGATION_MAGIC = b'HIAPROR1'


def _word(raw):
    return int.from_bytes(raw, 'little')


def fixed_bytes(raw, offset):
    words = []
    for start in range(0, len(raw), 8):
        part = raw[start:start + 8]
        if len(part) == 8:
            words.append(f'word_load(s, {offset} + {start}) != {_word(part)}')
        else:
            words.extend(f'byte(s, {offset} + {start+i}) != {ch}' for i, ch in enumerate(part))
    return words


def guards(checks):
    return '\n'.join(f'    if {item}:\n        return 0' for item in checks)


def object_source():
    shstrings = b'\x00.text\x00.rela.text\x00.symtab\x00.strtab\x00.shstrtab\x00.note.GNU-stack\x00'
    rows = [
        (0, 0, 0, '0', '0', 0, 0, 0, 0),
        (1, 1, 6, '64', 'span', 0, 0, 16, 0),
        (7, 4, 0, 'rel', '24', 3, 1, 8, 24),
        (18, 2, 0, 'sym', '96', 4, 2, 8, 24),
        (26, 3, 0, 'strings', 'names', 0, 0, 1, 0),
        (34, 3, 0, 'section_names', '60', 0, 0, 1, 0),
        (44, 1, 0, 'section_names + 60', '0', 0, 0, 1, 0),
    ]
    checks = []
    for i, (name, kind, flags, offset, size, link, info, align, entry) in enumerate(rows):
        for j, value in enumerate((name | kind << 32, flags, 0, offset, size,
                                   link | info << 32, align, entry)):
            checks.append(f'word_load(s, sh + {i*64+j*8}) != {value}')
    header = struct.pack('<16sHHIQQQI6H', b'\x7fELF\x02\x01\x01', 1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 7, 5)
    return (OBJECT_SOURCE.replace('CHECK_ELF_HEAD', guards(fixed_bytes(header[:40], '0') +
                                                          fixed_bytes(header[48:], '48')))
            .replace('CHECK_SECTION_ROWS', guards(checks))
            .replace('CHECK_SECTION_NAMES', guards(fixed_bytes(shstrings, 'section_names')))
            .replace('CHECK_ABORT_NAME', guards(fixed_bytes(b'abort\0', 'strings + abort_off')))
            .replace('COLD_STUB', str(_word(b'\x55\xe8\0\0\0\0\x0f\x0b'))))


OBJECT_SOURCE = '''
def register_object(s:readbuf, o:mutbuf) -> u64:
    size = length(s)
    if size < 704 or size > 8388608 or length(o) < 288:
        return 0
CHECK_ELF_HEAD
    sh = word_load(s, 40)
    if sh != size - 448 or (sh & 7) != 0:
        return 0
    span = word_load(s, sh + 96)
    names = word_load(s, sh + 288)
    if span < 9 or span > sh - 64 or names < 9 or names > 264:
        return 0
    rel = (64 + span + 7) & 18446744073709551608
    sym = rel + 24
    strings = sym + 96
    section_names = strings + names
    if sh != ((section_names + 67) & 18446744073709551608):
        return 0
CHECK_SECTION_ROWS
CHECK_SECTION_NAMES
    if register_zero(s, 64 + span, rel) == 0 or register_zero(s, section_names + 60, sh) == 0:
        return 0
    if byte(s, 64 + span - 9) != 195 or word_load(s, 64 + span - 8) != COLD_STUB:
        return 0
    if word_load(s, rel) != span - 6 or word_load(s, rel + 8) != 12884901892 or word_load(s, rel + 16) != 18446744073709551612:
        return 0
    if register_zero(s, sym, sym + 24) == 0 or word_load(s, sym + 24) != 281487861612544 or register_zero(s, sym + 32, sym + 48) == 0:
        return 0
    defined = word_load(s, sym + 48)
    imported = word_load(s, sym + 72)
    if (defined >> 32) != 65554 or (imported >> 32) != 16 or word_load(s, sym + 56) != 0 or word_load(s, sym + 64) != span:
        return 0
    if register_zero(s, sym + 80, sym + 96) == 0 or byte(s, strings) != 0:
        return 0
    export_off = defined & 4294967295
    abort_off = imported & 4294967295
    count = names - 8
    if not ((abort_off == 1 and export_off == 7) or (export_off == 1 and abort_off == count + 2)):
        return 0
CHECK_ABORT_NAME
    start = strings + export_off
    if byte(s, start + count) != 0:
        return 0
    i = 0
    while i < count:
        ch = byte(s, start + i)
        if register_identifier(ch, i) == 0:
            return 0
        i = i + 1
    # The ELF writer orders the two names lexicographically.
    i = 0
    while i < count and i < 5 and byte(s, start + i) == byte(s, strings + abort_off + i):
        i = i + 1
    ch = byte(s, start + i)
    other = byte(s, strings + abort_off + i)
    if ch == other or ((ch < other) != (export_off == 1)):
        return 0
    word_store(o, 0, 64)
    word_store(o, 8, span)
    word_store(o, 16, span - 8)
    word_store(o, 24, count)
    return copy(s, o, start, start + count, 32)

def register_zero(s:readbuf, begin:u64, end:u64) -> u64:
    while begin < end:
        if byte(s, begin) != 0:
            return 0
        begin = begin + 1
    return 1

def register_identifier(ch:u64, i:u64) -> u64:
    return choose(ch == 95 or (ch >= 97 and ch <= 122) or (ch >= 65 and ch <= 90) or (i > 0 and ch >= 48 and ch <= 57), 1, 0)
'''


REPORT_SOURCE = r'''
def register_build_report(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 402 or length(w) < 1176 or length(w) > 2097152 or length(o) < 32768:
        return 0
    name = word_load(s, 200)
    path = word_load(s, 16)
    if name == 0 or name > 256 or path == 0 or path > 4095 or length(s) != 400 + name + path:
        return 0
    tail = 208 + name + path
    size = word_load(s, 8)
    span = word_load(s, 184)
    offset = word_load(w, 48)
    version = word_load(s, tail + 32)
    if version < 2 or version > 6 or word_load(s, tail + 40) != 0 or size < 64 or size > 8388608:
        return 0
    if word_load(w, 0) != REGISTER_RECEIPT_MAGIC or word_load(w, 8) != 1 or word_load(w, 16) != version:
        return 0
    if word_load(w, 24) > 6 or word_load(w, 24) != word_load(s, tail + 48) or word_load(w, 32) == 0 or word_load(w, 32) > 1024 or word_load(w, 32) != word_load(s, tail + 56):
        return 0
    if span < 9 or span != word_load(w, 56) or offset > size or span > size - offset or word_load(s, 192) != span - 8:
        return 0
    if word_load(w, 40) != 5 or word_load(w, 64) != name or word_load(w, 72) > 16384 or word_load(w, length(w) - 72) != size:
        return 0
    if register_same_hash(s, w, 24, 144) == 0 or register_same_hash(s, w, tail + 64, 80) == 0 or register_same_hash(s, w, tail + 96, 112) == 0 or register_same_hash(s, w, tail + 128, 176) == 0:
        return 0
    if register_same_hash(s, w, 56, length(w) - 64) == 0:
        return 0
    at = 56
    while at < 184:
        if register_zero(s, at, at + 32) != 0:
            return 0
        at = at + 32
    if register_zero(s, tail, tail + 32) != 0 or register_roles(w) == 0 or register_same_hash(s, w, tail + 160, length(w) - 32) == 0:
        return 0
    i = 0
    while i < name:
        ch = byte(s, 208 + i)
        if register_identifier(ch, i) == 0 or ch != byte(w, 208 + i):
            return 0
        i = i + 1
    i = name
    while i < 256:
        if byte(w, 208 + i) != 0:
            return 0
        i = i + 1
    at = 0
    LIT('{"schema":"hepta.hia.verified-scalar-build.v1","status":"smt_validated_not_executed","ok":true,"selected_strategy":"scalar","selection_refusals":[],"profile":"hia.verified-scalar.register-leaf.x86_64.v')
    at = decimal(o, at, version)
    LIT('","core_profile_version":')
    at = decimal(o, at, version)
    LIT(',"export":"')
    at = copy(s, o, 208, 208 + name, at)
    LIT('","output":"')
    at = register_path(s, o, at, 208 + name, tail)
    if at == 0:
        return 0
    LIT('","artifact_bytes":')
    at = decimal(o, at, size)
    LIT(',"artifact_sha256":"')
    at = digest(s, o, at, 24)
    LIT('","core_sha256":"')
    at = digest(s, o, at, tail + 160)
    LIT('","object_sha256":"')
    at = digest(s, o, at, tail + 96)
    LIT('","machine_text_sha256":"')
    at = digest(s, o, at, 56)
    LIT('","hot_text_bytes":')
    at = decimal(o, at, span - 8)
    LIT(',"hot_stack_bytes":0,"maximum_observed_stack_bytes":')
    at = decimal(o, at, word_load(w, 72))
    LIT(',"register_abi":"SysV AMD64 direct entry; caller-saved registers only on return paths","runtime_solver_calls":0,"wrapper_calls":0,"source_identity":{"register_leaf_emitter_sha256":"')
    at = digest(s, o, at, 88)
    LIT('","verified_linker_sha256":"')
    at = digest(s, o, at, 120)
    LIT('","supplied_safe_core_prover_sha256":"')
    at = digest(s, o, at, 152)
    LIT('"},"toolchain":{"mode":"hia","path":null,"flags":[],"role":"link_generated_object_only","version":"hia-direct-scalar-linkage.v1","sha256":"')
    at = digest(s, o, at, 120)
    LIT('"},')
    # The verified register receipt has the same five checked terminal roles.
    # Project the older public summary from this receipt and the rechecked ELF symbol.
    at = proof_prefix(o, at)
    at = decimal(o, at, word_load(w, 16))
    at = proof_hash_prefix(o, at)
    at = digest(s, o, at, tail)
    at = proof_suffix(o, at)
    at = inventory_prefix(o, at)
    at = claim_true(o, at)
    at = inventory_claims_suffix(o, at)
    LIT('["')
    at = copy(s, o, 208, 208 + name, at)
    LIT('"]')
    at = inventory_middle(o, at)
    at = import_list(o, at, 16)
    at = inventory_suffix(o, at)
    LIT('"claims":{"acyclic_model_termination_checked":true,"all_input_refinement_in_independent_model":true,"core_abort_and_foreign_memory_effects_preserved":true,"exact_final_image_and_relocations_bound":true,"foreign_memory_access_bounds_checked":true,"foreign_pointer_provenance_or_liveness_proved":false,"machine_checked_isa_refinement_proved":false,"python_checker_soundness_proved":false,"serialized_receipt_authorizes_execution":false,"sysv_saved_registers_and_stack_checked":true,"timing_or_side_channels_proved":false,"whole_language_soundness_proved":false},"validation":')
    at = append_checked_validation(s, o, at, tail)
    LIT('}\n')
    return at

def register_same_hash(s:readbuf, w:mutbuf, a:u64, b:u64) -> u64:
    i = 0
    while i < 32:
        if word_load(s, a + i) != word_load(w, b + i):
            return 0
        i = i + 8
    return 1

def register_roles(w:mutbuf) -> u64:
    end = length(w) - 72
    proof = 464
    index = 0
    while index < 5:
        if proof > end or end - proof < 128:
            return 0
        size = word_load(w, proof)
        base = proof + 8
        if size < 120 or size > end - base or word_load(w, base) != REGISTER_OBLIGATION_MAGIC:
            return 0
        if word_load(w, base + 8) != index or word_load(w, base + 16) != choose(index == 0, 1, 2):
            return 0
        body = word_load(w, base + 48)
        witness = word_load(w, base + 56)
        if body < 40 or body > size - 80 or witness > size - 80 - body or word_load(w, base + 64) != size - 80 - body - witness:
            return 0
        assignments = word_load(w, base + 72)
        table = word_load(w, base + 64)
        if (table == 0) != (assignments == 0) or assignments > 65536 or (assignments & (assignments - 1)) != 0:
            return 0
        proof = base + size
        index = index + 1
    return choose(proof == end, 1, 0)

def register_path(s:readbuf, o:mutbuf, at:u64, i:u64, end:u64) -> u64:
    while i < end:
        ch = byte(s, i)
        if ch == 0:
            return 0
        if ch < 32 or ch == 127:
            LIT('\\u00')
            store(o, at, hex_digit(ch >> 4))
            store(o, at + 1, hex_digit(ch & 15))
            at = at + 2
        elif ch >= 128:
            extent = register_utf8(s, i, end, ch)
            if extent == 0:
                LIT('\\udc')
                store(o, at, hex_digit(ch >> 4))
                store(o, at + 1, hex_digit(ch & 15))
                at = at + 2
            else:
                at = copy(s, o, i, i + extent, at)
                i = i + extent - 1
        else:
            if ch == 34 or ch == 92:
                store(o, at, 92)
                at = at + 1
            store(o, at, ch)
            at = at + 1
        i = i + 1
    return at

def register_utf8(s:readbuf, i:u64, end:u64, ch:u64) -> u64:
    if ch < 194 or ch > 244:
        return 0
    n = choose(ch < 224, 2, choose(ch < 240, 3, 4))
    if end - i < n:
        return 0
    second = byte(s, i + 1)
    if (ch == 224 and second < 160) or (ch == 237 and second >= 160) or (ch == 240 and second < 144) or (ch == 244 and second >= 144):
        return 0
    k = 1
    while k < n:
        b = byte(s, i + k)
        if b < 128 or b > 191:
            return 0
        k = k + 1
    return n
'''


def source_program():
    return (object_source() + '\n' + REPORT_SOURCE
            .replace('REGISTER_RECEIPT_MAGIC', str(_word(RECEIPT_MAGIC)))
            .replace('REGISTER_OBLIGATION_MAGIC', str(_word(OBLIGATION_MAGIC))))
