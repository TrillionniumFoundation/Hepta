"""Installed HIA reader for the independent Safe Core ELF inventory."""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_safe_core_elf import SafeCoreELFRejected, require

SOURCE = _source_resource_path('examples/hia_bootstrap/safe_core_elf_inventory.hepta')
SCHEMA = 'hepta.hia.safe-core-elf-inventory-native.v1'
SELECTOR = 'HEPTA_HIA_SAFE_CORE_ELF_INVENTORY_MANIFEST'
MAX_ELF = 8 * 1024 * 1024
MAX_SECTIONS = 64
MAX_SEGMENTS = 16
HEADER = struct.Struct('<3Q')
SECTION = struct.Struct('<12Q')
SEGMENT = struct.Struct('<7Q')
SYMBOL = struct.Struct('<7Q')
DYNAMIC_TAG = struct.Struct('<2Q')
RELOCATION = struct.Struct('<3Qq')
OBJECT_INVENTORY_CONTROL_BYTES = 9 * 8
OBJECT_RELOCATION_CONTROL_BYTES = 8 * 8
CAPACITY = HEADER.size + MAX_SECTIONS * SECTION.size + MAX_SEGMENTS * SEGMENT.size
SECTION_FIELDS = ('type', 'flags', 'addr', 'offset', 'size', 'link', 'info', 'align', 'entsize')
SEGMENT_FIELDS = ('type', 'flags', 'offset', 'addr', 'filesz', 'memsz', 'align')
SYMBOL_FIELDS = ('info', 'other', 'shndx', 'value', 'size')
MAX_SYMBOLS = 32
FUNCTION_SYMBOL_MAGIC = int.from_bytes(b'HIAELFF1', 'little')
OWNED_FUNCTION_MAGIC = int.from_bytes(b'HIAELFG1', 'little')
FUNCTION_RECEIPT_MAGIC = int.from_bytes(b'HIAELFN1', 'little')
FUNCTION_LINK_MAGIC = int.from_bytes(b'HIAELFL1', 'little')
FUNCTION_LINK_RECEIPT_MAGIC = int.from_bytes(b'HIAELFL2', 'little')
FUNCTION_LINK_COORDINATES = struct.Struct('<3Q')
FUNCTION_LINK_NAME_BYTES = 256
FUNCTION_LINK_ROW_BYTES = 5 * 8 + FUNCTION_LINK_NAME_BYTES
FUNCTION_LINK_SOURCE_OFFSET = 64 + FUNCTION_LINK_NAME_BYTES
FUNCTION_LINK_TARGET_OFFSET = FUNCTION_LINK_SOURCE_OFFSET + 2 * FUNCTION_LINK_ROW_BYTES
FUNCTION_LINK_BYTES = FUNCTION_LINK_TARGET_OFFSET + 2 * FUNCTION_LINK_ROW_BYTES
FUNCTION_RECEIPT_GEOMETRY = struct.Struct('<2Q')
FUNCTION_RECEIPT_BYTES = FUNCTION_RECEIPT_GEOMETRY.size + 2 * FUNCTION_LINK_ROW_BYTES
DYNAMIC_SYMBOL_MAGIC = int.from_bytes(b'HIAELFD1', 'little')
DYNAMIC_SYMBOL_NAME_OFFSET = 104
LOADER_SECTION_MAGIC = int.from_bytes(b'HIAELFS1', 'little')
EXECUTABLE_LAYOUT_MAGIC = int.from_bytes(b'HIAELFE1', 'little')
DYNAMIC_RELOCATION_MAGIC = int.from_bytes(b'HIAELFR1', 'little')
DYNAMIC_ORDER_MAGIC = int.from_bytes(b'HIAELFY1', 'little')
OBJECT_INVENTORY_MAGIC = int.from_bytes(b'HIAELFO1', 'little')
UNWINDING_MAGIC = int.from_bytes(b'HIAELFU1', 'little')
TEXT_GEOMETRY_MAGIC = int.from_bytes(b'HIAELFJ1', 'little')
AUTHORITY_MAGIC = int.from_bytes(b'HIAELFM1', 'little')
LOADER_AUTHORITIES = (
    '.hash', '.gnu.hash', '.dynsym', '.dynstr', '.gnu.version', '.gnu.version_r',
    '.rela.plt', '.plt', '.text', '.eh_frame', '.dynamic', '.got',
)
SECTION_AUTHORITIES = (*LOADER_AUTHORITIES, '.rela.text', '.symtab', '.strtab')
AUTHORITY_BYTES = 8 * len(SECTION_AUTHORITIES)
LOOKUP_MAGIC = int.from_bytes(b'HIAELFK1', 'little')
LOOKUP_NAME = 64
LOOKUP_ROLES = LOOKUP_NAME + 256
LOOKUP_WORK = LOOKUP_ROLES + AUTHORITY_BYTES
LOADER_EXECUTABLE_MAGIC = int.from_bytes(b'HIAELFP1', 'little')
LOADER_EXECUTABLE_WORK = LOOKUP_WORK + 8
FINAL_LOADER_MAGIC = int.from_bytes(b'HIAELFQ1', 'little')
FINAL_LOADER_RECEIPT_MAGIC = int.from_bytes(b'HIAELFQ2', 'little')
FINAL_LOADER_COORDINATES = struct.Struct('<4Q')
FINAL_LOADER_NAME = LOADER_EXECUTABLE_WORK + 8
FINAL_LOADER_WORK = FINAL_LOADER_NAME + 256
LOOKUP_TYPED = ('.dynamic', '.got', '.rela.plt', '.hash', '.gnu.hash',
                '.gnu.version', '.gnu.version_r', '.dynstr')
LOOKUP_REQUIRED = ('.dynsym', *LOOKUP_TYPED)
REFUSALS = (
    ('extent', 'expected bounded immutable ELF bytes'),
    ('identity', 'ELF identity is outside the profile'),
    ('sections', 'invalid or extended section inventory'),
    ('range', 'ELF range lies outside the file'),
    ('missing_names', 'missing section-name string table'),
    ('name_index', 'string index is outside the table'),
    ('name_length', 'unterminated or oversized name'),
    ('name_ascii', 'non-ASCII ELF name'),
    ('duplicate', 'duplicate section name'),
    ('section_extent', 'NOBITS or oversized section is outside the profile'),
    ('segments', 'invalid segment inventory'),
    ('segment_extent', 'invalid segment extent'),
    ('segment_authority', 'unreviewed program-header authority'),
    ('load_extent', 'load alignment or zero-fill range is outside the profile'),
    ('load_order', 'PT_LOAD entries are not in ascending virtual-address order'),
    ('load_overlap', 'PT_LOAD page ranges overlap'),
    ('object_segments', 'relocatable object has load segments'),
    ('symbol_table', 'symbol table is outside the profile'),
    ('symbol_link', 'invalid symbol string-table link'),
    ('symbol_names', 'symbol name table has wrong kind'),
    ('missing_load', 'section has ambiguous or missing PT_LOAD authority'),
    ('load_binding', 'section bytes differ from the loader mapping'),
    ('dynamic_authority', "dynamic section is not the loader's dynamic table"),
    ('dynamic_extent', 'truncated dynamic table'),
    ('dynamic_tag', 'unreviewed loader hook or relocation tag'),
    ('dynamic_tail', 'nonzero dynamic entries follow DT_NULL'),
    ('dynamic_duplicate', 'duplicated dynamic authority'),
    ('dynamic_plt', 'PLT is not the exact immediately bound abort slot'),
    ('sysv_authority', 'SysV hash authority differs'),
    ('sysv_shape', 'SysV hash shape differs'),
    ('sysv_index', 'invalid SysV hash index'),
    ('sysv_lookup', 'SysV hash cycle, duplicate or wrong name bucket'),
    ('sysv_missing', 'SysV lookup omits a dynamic symbol'),
    ('gnu_authority', 'GNU hash authority differs'),
    ('gnu_shape', 'GNU hash shape differs'),
    ('gnu_lookup', 'GNU lookup does not exactly resolve the checked export'),
    ('plt_slot', 'abort GOT relocation changed'),
    ('plt_target', 'abort PLT instruction or GOT target differs'),
    ('object_operand', 'object relocation does not name an E8 rel32 operand'),
    ('object_call', 'unreviewed or duplicate call relocation'),
    ('object_displacement', 'linked call is outside rel32'),
    ('object_text', 'final text differs outside exact resolved call fields'),
    ('version_authority', 'loader symbol-version authority differs'),
    ('version_import', 'abort is not bound to the reviewed libc symbol version'),
    ('relro_count', 'expected exactly one RELRO authority'),
    ('relro_mapping', 'RELRO differs from the reviewed writable load mapping'),
    ('relro_got', 'GOT is outside the effective RELRO page protection'),
    ('function_extent', 'function is repeated or lies outside exact text'),
    ('function_inventory', 'closed function inventory differs'),
    ('function_partition', 'function ranges do not exactly partition text'),
    ('function_link', 'linker changed a function identity or extent'),
    ('dynamic_export', 'loader export identity differs'),
    ('dynamic_import', 'Safe Core admits only the nonreturning abort import'),
    ('loader_section_unallocated', 'loader section lacks required allocation flag: '),
    ('loader_section_unreviewed', 'unreviewed allocated loader section'),
    ('plt_got_shape', 'PLT/GOT shape is outside the immediate-binding profile'),
    ('executable_section', 'unexpected executable section'),
    ('executable_segment', 'additional executable load segment'),
    ('executable_partition', 'executable segment contains unbound bytes'),
    ('dynamic_relocation', 'unreviewed dynamic relocation inventory'),
    ('dynamic_order', 'closed dynamic symbol order differs'),
    ('object_inventory', 'object relocation inventory is outside the one-function profile'),
    ('unwinding', 'unreviewed nonempty unwinding metadata'),
    ('text_shape', 'source and final text shapes differ'),
    ('text_budget', 'Safe Core text budget exceeded'),
    *((f'lookup_missing_{name}', 'missing section ' + name) for name in LOOKUP_REQUIRED),
    *((f'lookup_kind_{name}', 'section kind differs: ' + name) for name in LOOKUP_TYPED),
    ('owned_missing_text', 'missing section .text'),
    ('owned_missing_symbols', 'missing section .symtab'),
    ('owned_text_kind', 'section kind differs: .text'),
    ('loader_missing_plt', 'missing section .plt'),
    ('loader_plt_kind', 'section kind differs: .plt'),
)
REFUSAL_IDS = {name: number for number, (name, _) in enumerate(REFUSALS, 1)}

OWNED_SHARED_MAGIC = int.from_bytes(b'HIAELFA1', 'little')
OWNED_SHARED_MAX = 64 << 20
OWNED_SHARED_HEAD = struct.Struct('<8Q')
OWNED_SHARED_SEGMENT = struct.Struct('<2Q')
OWNED_SHARED_SYMBOL_MAGIC = int.from_bytes(b'HIAELFA2', 'little')
OWNED_SHARED_SYMBOL_HEAD = OWNED_SHARED_HEAD.size + 128 * OWNED_SHARED_SEGMENT.size
OWNED_SHARED_SYMBOL_ROW = struct.Struct('<3Q')
OWNED_SHARED_SYMBOL_CAPACITY = OWNED_SHARED_SYMBOL_HEAD + 65536 * OWNED_SHARED_SYMBOL_ROW.size
OWNED_SHARED_SYMBOL_WORK = 16 + 65536 * 24
OWNED_SHARED_EXPECTED_COUNT = 128
OWNED_SHARED_EXPECTED_RECORD = 8 + 512
OWNED_SHARED_EXPECTED_WORK = OWNED_SHARED_SYMBOL_WORK + 8 + OWNED_SHARED_EXPECTED_COUNT * OWNED_SHARED_EXPECTED_RECORD
OWNED_SHARED_REFUSALS = (
    ('identity', 'not Linux/x86-64 ELF64 ET_DYN'),
    ('sections', 'missing or out-of-file ELF section table'),
    ('section_range', 'section points outside artifact'),
    ('headers', 'missing or invalid program headers'),
    ('interpreter', 'PT_INTERP or PT_TLS is outside the checked shared-library profile'),
    ('stack_flags', 'PT_GNU_STACK requires reviewed non-executable RW permissions'),
    ('dynamic_range', 'invalid loader dynamic table bounds'),
    ('load_flags', 'PT_LOAD has unreviewed permissions or is writable-executable'),
    ('load_range', 'invalid load segment range'),
    ('stack_count', 'missing or duplicated explicit non-executable PT_GNU_STACK'),
    ('exec_count', 'no executable load segment'),
    ('dynamic_count', 'missing or duplicated PT_DYNAMIC loader table'),
    ('sym_count', 'expected exactly one dynamic symbol table'),
    ('symbols', 'invalid dynamic symbols or string table'),
    ('dyn_bound', 'unbounded loader dynamic table'),
    ('redirect', 'unreviewed dynamic loader redirect, audit, filter or text-relocation tag'),
    ('flags', 'DT_FLAGS enables unreviewed origin, symbolic binding or text relocations'),
    ('flags_one', 'DT_FLAGS_1 enables unreviewed loader side effects'),
    ('duplicate', 'duplicate loader symbol metadata'),
    ('dynamic_identity', 'loader dynamic symbol/string authority disagrees with ELF sections'),
    ('dependency_range', 'unbounded loader dependency'),
    ('dependency', 'unreviewed DT_NEEDED shared library dependency'),
    ('symbol_name_offset', 'dynamic string name points outside table'),
    ('symbol_name_termination', 'unterminated dynamic symbol name'),
    ('symbol_name_ascii', 'non-ASCII dynamic symbol'),
    ('symbol_name_spelling', 'unknown/empty dynamic symbol spelling'),
    ('symbol_binding', 'unknown dynamic symbol binding'),
    ('symbol_duplicate', 'duplicate external symbol identity'),
    ('symbol_import', 'unreviewed external import: '),
    ('symbol_export', 'unknown, repeated, or invalid public function export: '),
    ('symbol_mapping', 'export not wholly inside executable file-backed code: '),
)
OWNED_SHARED_NAMED_ERRORS = frozenset(('symbol_import', 'symbol_export', 'symbol_mapping'))


class NativeSafeCoreElfInventory(NativeHiaJsonImage):
    def owned_shared_symbols(self, data, expected=None):
        from .elf_shared_abi import _fail

        source = ctypes.create_string_buffer(data, len(data))
        work = ctypes.create_string_buffer(OWNED_SHARED_SYMBOL_WORK if expected is None else OWNED_SHARED_EXPECTED_WORK)
        struct.pack_into('<Q', work, 0, OWNED_SHARED_SYMBOL_MAGIC)
        if expected is not None:
            if len(expected) > OWNED_SHARED_EXPECTED_COUNT:
                raise ValueError('outside native shared ELF source export profile')
            struct.pack_into('<Q', work, OWNED_SHARED_SYMBOL_WORK, len(expected))
            for index, symbol in enumerate(expected):
                offset = OWNED_SHARED_SYMBOL_WORK + 8 + index * OWNED_SHARED_EXPECTED_RECORD
                size = min(len(symbol), 513)
                struct.pack_into('<Q', work, offset, size)
                if size <= 512:
                    ctypes.memmove(ctypes.addressof(work) + offset + 8, symbol.encode('ascii'), size)
        output = ctypes.create_string_buffer(OWNED_SHARED_SYMBOL_CAPACITY)
        size = self._checked_default_entry(source, len(data), output, len(output), work, len(work))
        header = OWNED_SHARED_HEAD.size
        if not header <= size <= len(output):
            raise RuntimeError('invalid native shared ELF symbol extent')
        status, count, position, *remaining = OWNED_SHARED_HEAD.unpack_from(output)
        if status:
            if status > len(OWNED_SHARED_REFUSALS) or size != header:
                raise RuntimeError('invalid native shared ELF symbol refusal')
            reason, message = OWNED_SHARED_REFUSALS[status - 1]
            if reason in OWNED_SHARED_NAMED_ERRORS:
                message += self._owned_symbol_name(data, count, position)
            elif count or position:
                raise RuntimeError('unexpected native shared ELF symbol refusal detail')
            if any(remaining):
                raise RuntimeError('unexpected native shared ELF symbol refusal data')
            _fail(message)
        if (not 0 <= count <= 65536 or any(remaining)
                or (position not in (1, 2) if expected is not None else position != 0)
                or size != OWNED_SHARED_SYMBOL_HEAD + count * OWNED_SHARED_SYMBOL_ROW.size):
            raise RuntimeError('invalid native shared ELF symbol reply')
        exports, undefined = set(), set()
        records = ctypes.string_at(ctypes.addressof(output) + OWNED_SHARED_SYMBOL_HEAD, size - OWNED_SHARED_SYMBOL_HEAD)
        for offset, extent, kind in OWNED_SHARED_SYMBOL_ROW.iter_unpack(records):
            if kind not in (0, 1):
                raise RuntimeError('invalid native shared ELF symbol classification')
            (exports if kind else undefined).add(self._owned_symbol_name(data, offset, extent))
        return (exports, undefined) if expected is None else (exports, undefined, position == 1)

    @staticmethod
    def _owned_symbol_name(data, offset, extent):
        if not 0 < extent <= 512 or not 0 <= offset < len(data) or offset + extent >= len(data):
            raise RuntimeError('invalid native shared ELF symbol name extent')
        return data[offset:offset + extent].decode('ascii')

    def owned_shared_layout(self, data):
        from .elf_shared_abi import _fail

        request = ctypes.create_string_buffer(struct.pack('<Q', OWNED_SHARED_MAGIC), 8)
        source = ctypes.create_string_buffer(data, len(data))
        output = ctypes.create_string_buffer(CAPACITY)
        size = self._checked_default_entry(source, len(data), output, len(output), request, len(request))
        header = OWNED_SHARED_HEAD.size
        if not header <= size <= len(output):
            raise RuntimeError('invalid native shared ELF layout extent')
        status, count, shoff, shnum, symoff, symsize, stroff, strsize = OWNED_SHARED_HEAD.unpack_from(output)
        if status:
            if status > len(OWNED_SHARED_REFUSALS) or size != header or any(output.raw[8:header]):
                raise RuntimeError('invalid native shared ELF refusal')
            _fail(OWNED_SHARED_REFUSALS[status - 1][1])
        if (not 1 <= count <= 128 or not 1 <= shnum <= 4096
                or size != header + count * OWNED_SHARED_SEGMENT.size
                or not all(not extent or 0 <= offset <= len(data) and extent <= len(data) - offset
                           for offset, extent in ((shoff, shnum * 64), (symoff, symsize), (stroff, strsize)))):
            raise RuntimeError('invalid native shared ELF layout reply')
        executable = [(address, address + length) for address, length in
                      OWNED_SHARED_SEGMENT.iter_unpack(output.raw[header:size])]
        return shoff, shnum, executable, symoff, symsize, stroff, strsize

    def _exchange(self, data, arguments, suffix=b'', *, capacity=CAPACITY):
        packet = struct.pack(f'<{len(arguments)}Q', *arguments) + suffix
        return self._exchange_packet(data, packet, capacity=capacity)

    def _exchange_packet(self, data, packet, *, capacity=CAPACITY):
        require(type(data) is bytes and 64 <= len(data) <= MAX_ELF, REFUSALS[0][1])
        source = ctypes.create_string_buffer(data, len(data))
        output = ctypes.create_string_buffer(capacity)
        scratch = ctypes.create_string_buffer(packet, len(packet))
        size = self._checked_default_entry(source, len(data), output, capacity, scratch, len(scratch))
        if not HEADER.size <= size <= capacity:
            raise RuntimeError('invalid native Safe Core ELF response extent')
        status, first, second = HEADER.unpack_from(output)
        if status:
            if status > len(REFUSALS) or size != HEADER.size:
                raise RuntimeError('invalid native Safe Core ELF refusal')
            name, reason = REFUSALS[status - 1]
            if name == 'loader_section_unallocated':
                require(False, reason + self._name(data, first, second))
            if first or second:
                raise RuntimeError('unexpected native Safe Core ELF refusal detail')
            if name == 'name_ascii':
                raise SafeCoreELFRejected(reason)
            require(False, reason)
        return output, size, first, second

    @staticmethod
    def _name(data, offset, count):
        if offset >= len(data) or count > min(256, len(data) - offset - 1):
            raise RuntimeError('invalid native Safe Core ELF name extent')
        return data[offset:offset + count].decode('ascii')

    def inventory(self, data, kind, *, authorities=False, raw=False):
        if type(kind) is not int or not 0 <= kind <= 65535:
            require(False, REFUSALS[1][1])
        authorities = authorities or raw
        arguments = (AUTHORITY_MAGIC, kind) if authorities else (kind,)
        extra = AUTHORITY_BYTES if authorities else 0
        output, size, section_count, segment_count = self._exchange(data, arguments, capacity=CAPACITY + extra)
        if (not 1 <= section_count <= MAX_SECTIONS or segment_count > MAX_SEGMENTS
                or size != HEADER.size + section_count * SECTION.size + segment_count * SEGMENT.size + extra):
            raise RuntimeError('invalid native Safe Core ELF inventory counts')
        if raw:
            return output.raw[:size]
        cursor = HEADER.size
        sections = []
        for ordinal in range(section_count):
            index, name_at, name_len, *fields = SECTION.unpack_from(output, cursor)
            cursor += SECTION.size
            if index != ordinal:
                raise RuntimeError('invalid native Safe Core ELF section index')
            section = dict(zip(SECTION_FIELDS, fields, strict=True))
            offset, extent = section['offset'], section['size']
            if offset > len(data) or extent > len(data) - offset:
                raise RuntimeError('invalid native Safe Core ELF section extent')
            section.update(index=index, name=self._name(data, name_at, name_len),
                           data=data[offset:offset + extent])
            sections.append(section)
        segments = []
        for _ in range(segment_count):
            segments.append(dict(zip(SEGMENT_FIELDS, SEGMENT.unpack_from(output, cursor), strict=True)))
            cursor += SEGMENT.size
        if not authorities:
            return sections, segments
        roles = struct.unpack_from(f'<{len(SECTION_AUTHORITIES)}Q', output, cursor)
        if any(index > section_count for index in roles):
            raise RuntimeError('invalid native Safe Core ELF authority index')
        return sections, segments, {name: sections[index - 1] if index else None
                                    for name, index in zip(SECTION_AUTHORITIES, roles, strict=True)}

    def symbols(self, data, index):
        return self._symbol_rows(data, (index, 0))

    def functions(self, data, table, section):
        fields = (FUNCTION_SYMBOL_MAGIC, table, section['index'], section['addr'], section['size'], 0, 0)
        return {row['name']: row for row in self._symbol_rows(data, fields)}

    def owned_functions(self, data, kind):
        rows = self._symbol_rows(data, (OWNED_FUNCTION_MAGIC, kind), capacity=CAPACITY + AUTHORITY_BYTES)
        return {row['name']: row for row in rows}

    def owned_function_receipt(self, data, kind, *, raw=False):
        output, size, count, reserved = self._exchange(
            data, (FUNCTION_RECEIPT_MAGIC, kind),
            capacity=CAPACITY + AUTHORITY_BYTES + FUNCTION_RECEIPT_BYTES,
        )
        begin = HEADER.size + count * SYMBOL.size
        if reserved or count > MAX_SYMBOLS or size != begin + FUNCTION_RECEIPT_BYTES:
            raise RuntimeError('invalid native Safe Core function receipt')
        if raw:
            return output.raw[:size]
        rows = self._read_symbol_rows(data, output, begin, count)
        return {row['name']: row for row in rows}, output.raw[begin:size]

    def verify_raw_function_link(self, source, target, export, projector):
        packet = projector.elf_function_link_frame(source, target, export)
        require(packet is not None, REFUSALS[REFUSAL_IDS['function_inventory'] - 1][1])
        if len(packet) != FUNCTION_LINK_BYTES:
            raise RuntimeError('invalid native Safe Core function link frame')
        return self._function_link_result(packet, receipt=True)

    def verify_owned_function_link(self, source, target, export, *, receipt=False):
        source_symbols, source_receipt = source
        target_symbols, target_receipt = target
        _, extent = FUNCTION_RECEIPT_GEOMETRY.unpack_from(source_receipt)
        address, _ = FUNCTION_RECEIPT_GEOMETRY.unpack_from(target_receipt)
        packet = self._function_link_header(export, extent, address, len(source_symbols), len(target_symbols))
        geometry_size = FUNCTION_RECEIPT_GEOMETRY.size
        packet[FUNCTION_LINK_SOURCE_OFFSET:FUNCTION_LINK_TARGET_OFFSET] = source_receipt[geometry_size:]
        packet[FUNCTION_LINK_TARGET_OFFSET:] = target_receipt[geometry_size:]
        return self._function_link_result(packet, receipt=receipt)

    def verify_function_link(self, source, target, export, size, address):
        packet = self._function_link_header(export, size, address, len(source), len(target))
        for start, functions in ((FUNCTION_LINK_SOURCE_OFFSET, source),
                                 (FUNCTION_LINK_TARGET_OFFSET, target)):
            if len(functions) > 2:
                continue
            for index, row in enumerate(functions.values()):
                at = start + index * FUNCTION_LINK_ROW_BYTES
                raw = row['name'].encode('ascii')
                struct.pack_into('<5Q', packet, at, len(raw), row['value'], row['size'], row['info'], row['other'])
                packet[at + 40:at + 40 + len(raw)] = raw
        return self._function_link_result(packet)

    @staticmethod
    def _function_link_header(export, size, address, source_count, target_count):
        name = export.encode('utf-8')
        if len(name) > FUNCTION_LINK_NAME_BYTES:
            require(False, REFUSALS[REFUSAL_IDS['function_inventory'] - 1][1])
        packet = bytearray(FUNCTION_LINK_BYTES)
        struct.pack_into('<5Q', packet, 0, address, size, source_count, target_count, len(name))
        packet[64:64 + len(name)] = name
        return packet

    def _function_link_result(self, packet, *, receipt=False):
        magic = FUNCTION_LINK_RECEIPT_MAGIC if receipt else FUNCTION_LINK_MAGIC
        output, extent, direct, reserved = self._exchange(bytes(packet), (magic,))
        expected = HEADER.size + (FUNCTION_LINK_COORDINATES.size if receipt else 0)
        if extent != expected or direct not in (0, 1) or reserved:
            raise RuntimeError('invalid native Safe Core function linkage')
        if receipt:
            return bool(direct), *FUNCTION_LINK_COORDINATES.unpack_from(output, HEADER.size)
        return bool(direct)

    def _symbol_rows(self, data, fields, *, capacity=CAPACITY):
        output, size, count, reserved = self._exchange(data, fields, capacity=capacity)
        if reserved:
            raise RuntimeError('invalid native Safe Core ELF symbol inventory')
        return self._read_symbol_rows(data, output, size, count)

    def verify_dynamic_symbols(self, data, table, text, export):
        name = export['name'].encode('ascii')
        fields = (DYNAMIC_SYMBOL_MAGIC, table, text['index'], text['addr'], text['size'], 0, 0,
                  len(name), *(export[field] for field in SYMBOL_FIELDS))
        output, size, count, abort_symbols = self._exchange(data, fields, name)
        if abort_symbols == 0 or abort_symbols >> count:
            raise RuntimeError('invalid native Safe Core abort symbol mask')
        return self._read_symbol_rows(data, output, size, count), abort_symbols

    def verify_loader_sections(self, data):
        self._verify_terminal(data, (LOADER_SECTION_MAGIC,))

    def verify_executable_layout(self, data, text, plt, got):
        self._verify_terminal(data, (EXECUTABLE_LAYOUT_MAGIC, text['index'], plt['index'], got['index'], 0, 0, 0, 0, 0))

    def verify_dynamic_relocations(self, data, rela, dynamic_table, got):
        self._verify_terminal(data, (DYNAMIC_RELOCATION_MAGIC, rela['index'], dynamic_table['index'], got['index'], 0, 0, 0, 0, 0))

    def verify_dynamic_order(self, data, dynamic_table, export):
        name = export.encode('utf-8')
        self._verify_terminal(data, (DYNAMIC_ORDER_MAGIC, dynamic_table['index'], len(name), 0, 0, 0, 0, 0), name)

    def verify_loader_lookup(self, data, export):
        name = export.encode('utf-8')
        require(len(name) <= 256, REFUSALS[REFUSAL_IDS['dynamic_order'] - 1][1])
        fields = (LOOKUP_MAGIC, len(name), 0, 0, 0, 0, 0, 0)
        self._verify_terminal(data, fields, name.ljust(LOOKUP_WORK - LOOKUP_NAME, b'\0'),
                              capacity=CAPACITY + AUTHORITY_BYTES)

    def verify_loader_executable(self, data, abort_symbols):
        arguments = (LOADER_EXECUTABLE_MAGIC, abort_symbols)
        self._verify_terminal(data, arguments, bytes(LOADER_EXECUTABLE_WORK - 16),
                              capacity=CAPACITY + AUTHORITY_BYTES)

    def verify_final_loader(self, data, export, *, receipt=False):
        name = export.encode('utf-8')
        require(len(name) <= 256, REFUSALS[REFUSAL_IDS['dynamic_order'] - 1][1])
        packet = bytes(FINAL_LOADER_NAME - 16) + name.ljust(256, b'\0')
        magic = FINAL_LOADER_RECEIPT_MAGIC if receipt else FINAL_LOADER_MAGIC
        output, size, first, second = self._exchange(
            data, (magic, len(name)), packet, capacity=CAPACITY + AUTHORITY_BYTES,
        )
        expected = HEADER.size + (FINAL_LOADER_COORDINATES.size if receipt else 0)
        if size != expected or first or second:
            raise RuntimeError('invalid native Safe Core final loader response')
        if receipt:
            return FINAL_LOADER_COORDINATES.unpack_from(output, HEADER.size)

    def verify_object_inventory(self, data, rela, text, symbols, *, direct):
        fields = (OBJECT_INVENTORY_MAGIC, rela['index'], text['index'], symbols['index'], int(direct), 0, 0, 0, 0)
        self._verify_terminal(data, fields)

    def verify_unwinding(self, data, section):
        self._verify_terminal(data, (UNWINDING_MAGIC, section['index'], 0, 0, 0, 0, 0, 0))

    def verify_text_geometry(self, data, source, linked, text):
        fields = (TEXT_GEOMETRY_MAGIC, source['index'], linked['flags'], linked['size'], 0, 0, 0, 0)
        self._verify_terminal(data, fields, text)

    def _verify_terminal(self, data, fields, suffix=b'', *, capacity=CAPACITY):
        self._require_terminal_response(self._exchange(data, fields, suffix, capacity=capacity))

    @staticmethod
    def _require_terminal_response(result):
        _, size, first, second = result
        if size != HEADER.size or first or second:
            raise RuntimeError('invalid native Safe Core layout response')

    def _read_symbol_rows(self, data, output, size, count):
        if count > MAX_SYMBOLS or size != HEADER.size + count * SYMBOL.size:
            raise RuntimeError('invalid native Safe Core ELF symbol inventory')
        symbols = []
        for at in range(HEADER.size, size, SYMBOL.size):
            offset, extent, *attributes = SYMBOL.unpack_from(output, at)
            symbols.append(dict(zip(SYMBOL_FIELDS, attributes, strict=True),
                                name=self._name(data, offset, extent)))
        return symbols

    def string(self, data, offset, size, index):
        require(0 <= index < size, REFUSALS[REFUSAL_IDS['name_index'] - 1][1])
        require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
                REFUSALS[REFUSAL_IDS['range'] - 1][1])
        _, extent, start, length = self._exchange(data, (offset, size, index))
        if extent != HEADER.size:
            raise RuntimeError('invalid native Safe Core ELF string response')
        return self._name(data, start, length)

    def load_binding(self, data, section, permissions):
        arguments = (section['addr'], section['size'], section['offset'], permissions)
        output, size, first, second = self._exchange(data, arguments)
        if size != HEADER.size + SEGMENT.size or first or second:
            raise RuntimeError('invalid native Safe Core ELF load authority')
        return dict(zip(SEGMENT_FIELDS, SEGMENT.unpack_from(output, HEADER.size), strict=True))

    def dynamic_tags(self, data, dynamic, got, rela):
        arguments = (dynamic['offset'], dynamic['size'], dynamic['addr'], got['addr'], rela['addr'])
        output, size, count, reserved = self._exchange(data, arguments)
        if reserved or count > 16 or size != HEADER.size + count * DYNAMIC_TAG.size:
            raise RuntimeError('invalid native Safe Core dynamic authority')
        tags = dict(DYNAMIC_TAG.iter_unpack(output.raw[HEADER.size:size]))
        if len(tags) != count:
            raise RuntimeError('duplicate native Safe Core dynamic authority')
        return tags

    def verify_hash(self, data, table, authority, export, *, gnu):
        # Presence is separate from value: an absent loader tag is not address zero.
        name = export.encode('ascii')
        arguments = (int(gnu), table['offset'], table['size'], table['addr'],
                     int(authority is not None), authority if authority is not None else 0,
                     len(name), 0)
        _, size, first, second = self._exchange(data, arguments, name)
        if size != HEADER.size or first or second:
            raise RuntimeError('invalid native Safe Core loader hash response')

    def verify_plt_slot(self, data, plt, got, rela, abort_symbols):
        arguments = (plt['offset'], plt['addr'], got['addr'], rela['offset'], abort_symbols, 0)
        self._require_empty_response(data, arguments)

    def object_relocations(self, data, relocations, source, linked, plt, helper):
        calls, records, _ = self.object_relocations_owned(
            data, relocations, source, linked['data'], linked['addr'], plt['addr'] + 16, helper,
        )
        return calls, records

    def object_relocations_owned(self, data, relocations, source, final_text, address, abort, helper, *, wire=False):
        arguments = (2, relocations['offset'], source['offset'], source['size'],
                     address, abort, helper, relocations['link'])
        result = self._exchange(data, arguments, final_text)
        return self._decode_object_relocations(result, source['size'], address, helper, wire)

    def object_relocation_wire(self, data, final_text, address, abort, helper, projector, *, wire=False):
        layout = self.inventory(data, 1, raw=True)
        packet = projector.elf_object_relocation_frame(layout, final_text, address, abort, helper)
        require(packet is not None, REFUSALS[REFUSAL_IDS['object_inventory'] - 1][1])
        head = OBJECT_INVENTORY_CONTROL_BYTES
        if len(packet) != head + OBJECT_RELOCATION_CONTROL_BYTES + len(final_text):
            raise RuntimeError('invalid native Safe Core relocation control extent')
        self._require_terminal_response(self._exchange_packet(data, packet[:head]))
        # All original symbol names are checked before resolving a call.
        symbols, = struct.unpack_from('<Q', packet, 24)
        self.symbols(data, symbols)
        result = self._exchange_packet(data, packet[head:])
        return self._decode_object_relocations(result, len(final_text), address, helper, wire)

    @staticmethod
    def _decode_object_relocations(result, text_size, address, helper, wire):
        output, size, count, reserved = result
        expected = 2 if helper else 1
        if reserved or count != expected or size != HEADER.size + count * RELOCATION.size:
            raise RuntimeError('invalid native Safe Core call relocation response')
        calls, records = {}, []
        for at in range(HEADER.size, size, RELOCATION.size):
            offset, symbol, target, displacement = RELOCATION.unpack_from(output, at)
            if not 1 <= symbol <= expected or not 0 < offset <= text_size - 4 or offset - 1 in calls:
                raise RuntimeError('invalid native Safe Core call relocation')
            name = 'abort' if symbol == 1 else '__hia_native_fn_0'
            calls[offset - 1] = 'abort' if symbol == 1 else target - address
            records.append(dict(offset=offset, symbol=name, type=4, addend=-4,
                                linked_target=target, displacement=displacement))
        return calls, records, output.raw[:size] if wire else None

    def _require_empty_response(self, data, arguments):
        _, size, first, second = self._exchange(data, arguments)
        if size != HEADER.size or first or second:
            raise RuntimeError('invalid native Safe Core verification response')

    def verify_version_tables(self, data, versions, needed, tags):
        keys = (0x6ffffff0, 0x6ffffffe, 0x6fffffff)
        present = sum(1 << index for index, tag in enumerate(keys) if tag in tags)
        arguments = (3, versions['offset'], versions['size'], versions['addr'],
                     needed['offset'], needed['size'], needed['addr'], present,
                     *(tags.get(tag, 0) for tag in keys))
        self._require_empty_response(data, arguments)

    def verify_version_names(self, data, needed, strings):
        arguments = (4, needed['offset'], strings['offset'], strings['size'], 0, 0, 0, 0)
        self._require_empty_response(data, arguments)

    def verify_relro(self, data, writable, got):
        arguments = (5, writable['addr'], writable['offset'], writable['filesz'], writable['memsz'],
                     got['addr'], got['size'], 0)
        self._require_empty_response(data, arguments)


def installed_safe_core_elf_inventory(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeSafeCoreElfInventory)


def selected_safe_core_elf_inventory():
    selected = os.environ.get(SELECTOR)
    if selected is not None:
        return installed_safe_core_elf_inventory(selected)
    from .hia_default_native import default_image
    return default_image(SELECTOR)


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
