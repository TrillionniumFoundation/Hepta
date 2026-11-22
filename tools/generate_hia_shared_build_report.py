"""Author the standalone direct shared-library build receipt in HIA.

The input receipt was produced by the admitted direct-object compiler. The
linker and independent inventory owner provide the final extent, digests and
import set. They are never inferred from the earlier relocatable artifact.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import WorkerRequestBuilder

SOURCE_PATH = 'examples/hia_bootstrap/core_cli/shared_build_report.hepta'
MAGIC = b'HIASBR01'
VERIFIED_MAGIC = b'HIASBR02'
PROOF_MAGIC = b'HIAPRR01'
EXPORT_MAGIC = b'HIASEX01'
EXPORT_NAMES_MAGIC = b'HIASEN01'
SYMBOL_MAGIC = b'HIAELFA2'
ELF_MAGIC = b'\x7fELF\x02\x01\x01\x00'
SYMBOL_WORK = 16 + 65536 * 24
SYMBOL_HEAD = 64 + 128 * 16
EXPECTED_WORK = SYMBOL_WORK + 8 + 128 * 520
# Stable bit positions for the finite ABI allowlist in its public sort order.
IMPORTS = ('_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
           '__cxa_finalize', '__gmon_start__', 'abort', 'calloc', 'free',
           'malloc', 'memcpy', 'memmove', 'memset')
MEMBERS = ('artifact_bytes', 'artifact_sha256', 'binary_inventory', 'exports', 'kind', 'toolchain')

SOURCE = r'''
def shared_report(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = length(s)
    if n < 8:
        return 4294967293
    magic = word_load(s, 0)
    if magic == ELF_INPUT_MAGIC:
        return linked_import_mask(s, w)
    if magic == PROOF_INPUT_MAGIC:
        return admit_proof(s, w)
    if magic == EXPORT_NAMES_INPUT_MAGIC:
        # Use the same ELF inventory request for exports admitted directly
        # from the verified Core when there is no object-build report.
        if n < 10 or n > 65930 or byte(s, 8) != 91 or byte(s, n - 1) != 93:
            return 4294967293
        extent = expected_exports(s, o, 9, n - 1)
        if extent == EXPECTED_WORK_BYTES:
            sort_export_names(o)
        return extent
    proven = magic == VERIFIED_INPUT_MAGIC
    if proven:
        if n < 132:
            return 4294967293
        n = n - 40
        if word_load(s, n + 32) < 1 or word_load(s, n + 32) > 6:
            return 4294967293
    if n < 92 or n > 262232 or length(w) < 96:
        return 4294967293
    if not proven and magic != REPORT_MAGIC and magic != EXPORT_INPUT_MAGIC:
        return 4294967293
    if byte(s, 88) != 123 or byte(s, 89) != 10 or byte(s, n - 2) != 125 or byte(s, n - 1) != 10:
        return 4294967293
    if magic != EXPORT_INPUT_MAGIC and (word_load(s, 8) < 64 or word_load(s, 8) > 67108864 or word_load(s, 16) > 2047):
        return 4294967293
    # Each exact member must occur once. Record its original span before
    # emitting any bytes so a malformed receipt cannot produce partial JSON.
    slot = 0
    while slot < 96:
        word_store(w, slot, 0)
        slot = slot + 8
    cursor = 90
    while cursor < n - 2:
        if n - cursor < 5 or byte(s, cursor) != 32 or byte(s, cursor + 1) != 32 or byte(s, cursor + 2) != 34:
            return 4294967293
        end = member_end(s, cursor, n)
        if end == 0:
            return 4294967293
        field = member(s, cursor)
        if field != 0:
            slot = (field - 1) * 16
            if word_load(w, slot) != 0:
                return 4294967293
            word_store(w, slot, cursor)
            word_store(w, slot + 8, end)
        cursor = end
    slot = 0
    while slot < 96:
        if word_load(w, slot) == 0:
            return 4294967293
        slot = slot + 16
    if word_load(w, 72) - word_load(w, 64) != OBJECT_LINE_SIZE:
        return 4294967293
    if object_line(s, word_load(w, 64)) == 0 or toolchain_line(s, word_load(w, 80)) == 0:
        return 4294967293
    if word_load(w, 88) - word_load(w, 80) != TOOLCHAIN_LINE_SIZE:
        return 4294967293
    start = word_load(w, 48) + EXPORT_PREFIX_SIZE
    end = word_load(w, 56)
    if end - start < 4 or byte(s, start) != 91 or byte(s, end - 3) != 93 or byte(s, end - 2) != 44:
        return 4294967293
    if magic == EXPORT_INPUT_MAGIC:
        return expected_exports(s, o, start + 1, end - 3)
    if length(o) < n - 88 + 2 * (end - start) + 4096:
        return 4294967294

    at = copy(s, o, 88, 90, 0)
    cursor = 90
    while cursor < n - 2:
        end = member_end(s, cursor, n)
        field = member(s, cursor)
        if field == 1:
            at = bytes_prefix(o, at)
            at = decimal(o, at, word_load(s, 8))
            at = comma_line(o, at)
        elif field == 2:
            at = artifact_hash_prefix(o, at)
            at = digest(s, o, at, 24)
            at = quoted_comma_line(o, at)
        elif field == 3:
            at = inventory(s, o, w, at, proven)
        elif field == 5:
            at = shared_kind(o, at)
        elif field == 6:
            if proven:
                at = proof_prefix(o, at)
                at = decimal(o, at, word_load(s, n + 32))
                at = proof_hash_prefix(o, at)
                at = digest(s, o, at, n)
                at = proof_suffix(o, at)
            at = linker_prefix(o, at)
            at = digest(s, o, at, 56)
            if proven:
                at = verified_linker_suffix(o, at)
            else:
                at = linker_suffix(o, at)
        else:
            at = copy(s, o, cursor, end, at)
        cursor = end
    return copy(s, o, n - 2, n, at)

def admit_proof(s:readbuf, w:mutbuf) -> u64:
    if length(s) < 464 or length(s) > 2097152 or length(w) != 32:
        return 0
    profile = word_load(s, 16)
    if word_load(s, 8) != 1 or profile < 1 or profile > 6 or word_load(s, 40) != 5:
        return 0
    offset = 0
    while offset < 32:
        if word_load(s, 144 + offset) != word_load(w, offset):
            return 0
        offset = offset + 8
    return profile

def expected_exports(s:readbuf, o:mutbuf, start:u64, end:u64) -> u64:
    # Output is the independently defined ELF inventory work request.
    if length(o) != EXPECTED_WORK_BYTES:
        return 4294967294
    at = skip_space(s, start, end)
    count = 0
    while at < end:
        if count == 128 or byte(s, at) != 34:
            return 4294967293
        begin = at + 1
        at = begin
        while at < end and byte(s, at) != 34:
            value = byte(s, at)
            letter = value == 95 or (value >= 65 and value <= 90) or (value >= 97 and value <= 122)
            digit = value >= 48 and value <= 57
            if not letter and (at == begin or not digit):
                return 4294967293
            at = at + 1
        size = at - begin
        if at == end or size == 0 or size > 512:
            return 4294967293
        slot = SYMBOL_WORK_BYTES + 8 + count * 520
        word_store(o, slot, size)
        copy(s, o, begin, at, slot + 8)
        count = count + 1
        at = skip_space(s, at + 1, end)
        if at < end:
            if byte(s, at) != 44:
                return 4294967293
            at = skip_space(s, at + 1, end)
            if at == end:
                return 4294967293
    word_store(o, 0, SYMBOL_MODE_MAGIC)
    word_store(o, SYMBOL_WORK_BYTES, count)
    return EXPECTED_WORK_BYTES

def sort_export_names(o:mutbuf) -> u64:
    # The inventory expects strictly ordered names. Move entire fixed-size
    # records without dropping or merging any entry: duplicates still refuse.
    first = SYMBOL_WORK_BYTES + 8
    end = first + 520 * word_load(o, SYMBOL_WORK_BYTES)
    at = first + 520
    while at < end:
        current = at
        while current > first and name_before(o, current, current - 520):
            index = 0
            previous = current - 520
            while index < 520:
                value = word_load(o, previous + index)
                word_store(o, previous + index, word_load(o, current + index))
                word_store(o, current + index, value)
                index = index + 8
            current = previous
        at = at + 520
    return 0

def name_before(o:mutbuf, left:u64, right:u64) -> bool:
    first = word_load(o, left)
    second = word_load(o, right)
    index = 0
    while index < first and index < second:
        a = byte(o, left + 8 + index)
        b = byte(o, right + 8 + index)
        if a != b:
            return a < b
        index = index + 1
    return first < second

def skip_space(s:readbuf, at:u64, end:u64) -> u64:
    while at < end:
        value = byte(s, at)
        if value != 32 and value != 10:
            return at
        at = at + 1
    return at

def linked_import_mask(s:readbuf, w:mutbuf) -> u64:
    extent = length(w)
    if extent < SYMBOL_HEADER_BYTES or word_load(w, 0) != 0 or word_load(w, 16) != 1:
        return 4294967293
    count = word_load(w, 8)
    if count > 65536 or extent != SYMBOL_HEADER_BYTES + 24 * count:
        return 4294967293
    mask = 0
    row = SYMBOL_HEADER_BYTES
    while row < extent:
        kind = word_load(w, row + 16)
        if kind == 0:
            start = word_load(w, row)
            size = word_load(w, row + 8)
            if size == 0 or start >= length(s) or size >= length(s) - start:
                return 4294967293
            if byte(s, start + size) != 0:
                return 4294967293
            bit = import_bit(s, start, size)
            if bit == 0 or mask & bit != 0:
                return 4294967293
            mask = mask | bit
        elif kind != 1:
            return 4294967293
        row = row + 24
    return mask + 1

def member_end(s:readbuf, start:u64, n:u64) -> u64:
    cursor = start
    while cursor < n - 2:
        if byte(s, cursor) == 10:
            next = cursor + 1
            if next == n - 2:
                return next
            if n - next >= 3 and byte(s, next) == 32 and byte(s, next + 1) == 32 and byte(s, next + 2) == 34:
                return next
        cursor = cursor + 1
    return 0

def inventory(s:readbuf, o:mutbuf, w:mutbuf, at:u64, proven:bool) -> u64:
    at = inventory_prefix(o, at)
    if proven:
        at = claim_true(o, at)
    else:
        at = claim_false(o, at)
    at = inventory_claims_suffix(o, at)
    start = word_load(w, 48) + EXPORT_PREFIX_SIZE
    end = word_load(w, 56) - 2
    while start < end:
        value = byte(s, start)
        store(o, at, value)
        at = at + 1
        if value == 10:
            store(o, at, 32)
            store(o, at + 1, 32)
            at = at + 2
        start = start + 1
    at = inventory_middle(o, at)
    mask = word_load(s, 16)
    if mask != 0:
        at = import_list(o, at, mask)
    return inventory_suffix(o, at)

def copy(s:readbuf, o:mutbuf, start:u64, end:u64, at:u64) -> u64:
    while start < end:
        store(o, at, byte(s, start))
        at = at + 1
        start = start + 1
    return at

def decimal(o:mutbuf, at:u64, value:u64) -> u64:
    place = 1
    while place <= value // 10:
        place = place * 10
    while place != 0:
        store(o, at, 48 + value // place)
        at = at + 1
        value = value % place
        place = place // 10
    return at

def digest(s:readbuf, o:mutbuf, at:u64, offset:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(s, offset + i)
        store(o, at, hex_digit(value >> 4))
        store(o, at + 1, hex_digit(value & 15))
        at = at + 2
        i = i + 1
    return at

def hex_digit(digit:u64) -> u64:
    return choose(digit < 10, digit + 48, digit + 87)

def append_word(o:mutbuf, at:u64, word:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, at + index, word >> (8 * index) & 255)
        index = index + 1
    return at + size
'''

LITERALS = {
    'bytes_prefix': '  "artifact_bytes": ',
    'artifact_hash_prefix': '  "artifact_sha256": "',
    'comma_line': ',\n',
    'quoted_comma_line': '",\n',
    'shared_kind': '  "kind": "shared",\n',
    'linker_prefix': ('  "toolchain": {\n    "default_target": "elf_x86_64",\n'
                      '    "mode": "hia",\n    "path": null,\n'
                      '    "role": "link_generated_object_only",\n    "sha256": "'),
    'linker_suffix': '",\n    "version": "hia-elf-shared-linker.v1"\n  }\n',
    'verified_linker_suffix': '",\n    "version": "hia-direct-scalar-linkage.v1"\n  }\n',
    'proof_prefix': ('  "machine_proof": {\n    "obligations_proven": 5,\n'
                     '    "profile": '),
    'proof_hash_prefix': ',\n    "receipt_sha256": "',
    'proof_suffix': ('",\n    "schema": "hepta.hia.supplied-safe-core-proof.v1"\n  },\n'),
    'inventory_prefix': ('  "binary_inventory": {\n'
                         '    "claims": {\n      "backend_refinement_proven": '),
    'claim_false': 'false,\n',
    'claim_true': 'true,\n',
    'inventory_claims_suffix': ('      "binary_abi_observed": true,\n      "native_execution_proven": false,\n'
                         '      "whole_language_memory_safety_proven": false\n    },\n'
                         '    "dynamic_exports": '),
    'inventory_middle': (',\n    "format": "ELF64",\n    "kind": "ET_DYN",\n'
                         '    "machine": 62,\n    "schema": "hepta.elf-shared-abi.v1",\n'
                         '    "source_exports_rechecked": true,\n    "unresolved_imports": ['),
    'inventory_suffix': ']\n  },\n',
    'import_first': '\n      ',
    'import_rest': ',\n      ',
    'import_end': '\n    ',
}

OBJECT_LINE = '  "kind": "object",\n'
TOOLCHAIN_LINE = '  "toolchain": null\n'


def append_function(name, literal):
    source = f'\ndef {name}(o:mutbuf, at:u64) -> u64:\n'
    raw = literal.encode('ascii')
    for start in range(0, len(raw), 8):
        part = raw[start:start + 8]
        source += f"    at = append_word(o, at, {int.from_bytes(part, 'little')}, {len(part)})\n"
    return source + '    return at\n'


def match_function(name, literal):
    raw = literal.encode('ascii')
    source = f'\ndef {name}(s:readbuf, at:u64) -> u64:\n'
    source += f'    if length(s) - at < {len(raw)}:\n        return 0\n'
    for offset, byte in enumerate(raw):
        source += f'    if byte(s, at + {offset}) != {byte}:\n        return 0\n'
    return source + '    return 1\n'


def source_program():
    source = (SOURCE.replace('REPORT_MAGIC', str(int.from_bytes(MAGIC, 'little')))
              .replace('VERIFIED_INPUT_MAGIC', str(int.from_bytes(VERIFIED_MAGIC, 'little')))
              .replace('PROOF_INPUT_MAGIC', str(int.from_bytes(PROOF_MAGIC, 'little')))
              .replace('EXPORT_INPUT_MAGIC', str(int.from_bytes(EXPORT_MAGIC, 'little')))
              .replace('EXPORT_NAMES_INPUT_MAGIC', str(int.from_bytes(EXPORT_NAMES_MAGIC, 'little')))
              .replace('ELF_INPUT_MAGIC', str(int.from_bytes(ELF_MAGIC, 'little')))
              .replace('SYMBOL_MODE_MAGIC', str(int.from_bytes(SYMBOL_MAGIC, 'little')))
              .replace('SYMBOL_WORK_BYTES', str(SYMBOL_WORK))
              .replace('SYMBOL_HEADER_BYTES', str(SYMBOL_HEAD))
              .replace('EXPECTED_WORK_BYTES', str(EXPECTED_WORK))
              .replace('OBJECT_LINE_SIZE', str(len(OBJECT_LINE)))
              .replace('TOOLCHAIN_LINE_SIZE', str(len(TOOLCHAIN_LINE)))
              .replace('EXPORT_PREFIX_SIZE', str(len('  "exports": '))))
    for name, literal in LITERALS.items():
        source += append_function(name, literal)
    source += match_function('object_line', OBJECT_LINE)
    source += match_function('toolchain_line', TOOLCHAIN_LINE)
    for name in MEMBERS:
        source += match_function('has_' + name, f'  "{name}": ')
    source += '\ndef member(s:readbuf, at:u64) -> u64:\n'
    for index, name in enumerate(MEMBERS, 1):
        source += f'    if has_{name}(s, at) != 0:\n        return {index}\n'
    source += '    return 0\n'
    for index, symbol in enumerate(IMPORTS):
        source += append_function(f'import_{index}', f'"{symbol}"')
        source += match_function(f'has_import_{index}', symbol)
    source += '\ndef import_bit(s:readbuf, at:u64, size:u64) -> u64:\n'
    for index, symbol in enumerate(IMPORTS):
        source += (f'    if size == {len(symbol)} and has_import_{index}(s, at) != 0:\n'
                   f'        return {1 << index}\n')
    source += '    return 0\n'
    source += '\ndef import_list(o:mutbuf, at:u64, mask:u64) -> u64:\n    written = 0\n'
    for index, _ in enumerate(IMPORTS):
        source += (f'    if mask & {1 << index} != 0:\n'
                   '        if written == 0:\n            at = import_first(o, at)\n'
                   '        else:\n            at = import_rest(o, at)\n'
                   f'        at = import_{index}(o, at)\n        written = 1\n')
    return source + '    return import_end(o, at)\n'


class ReportBuilder(WorkerRequestBuilder):
    def expr(self, expression):
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            return self.op('bool.not', [self.expr(expression.operand)], 'bool')
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, (ast.FloorDiv, ast.Mod)):
            left, right = self.expr(expression.left), self.expr(expression.right)
            op = 'int.div.checked' if isinstance(expression.op, ast.FloorDiv) else 'int.rem.checked'
            return self.op(op, [left, right], 'u64')
        return super().expr(expression)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ReportBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9',
                                 'module': 'shared_build_report', 'functions': functions})


if __name__ == '__main__':
    (Path(__file__).resolve().parents[1] / SOURCE_PATH).write_text(render_assembly(document()))
