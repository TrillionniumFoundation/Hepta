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
CAPACITY = HEADER.size + MAX_SECTIONS * SECTION.size + MAX_SEGMENTS * SEGMENT.size
SECTION_FIELDS = ('type', 'flags', 'addr', 'offset', 'size', 'link', 'info', 'align', 'entsize')
SEGMENT_FIELDS = ('type', 'flags', 'offset', 'addr', 'filesz', 'memsz', 'align')
SYMBOL_FIELDS = ('info', 'other', 'shndx', 'value', 'size')
MAX_SYMBOLS = 32
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
)
REFUSAL_IDS = {name: number for number, (name, _) in enumerate(REFUSALS, 1)}


class NativeSafeCoreElfInventory(NativeHiaJsonImage):
    def _exchange(self, data, arguments, suffix=b''):
        require(type(data) is bytes and 64 <= len(data) <= MAX_ELF, REFUSALS[0][1])
        source = ctypes.create_string_buffer(data, len(data))
        output = ctypes.create_string_buffer(CAPACITY)
        packet = struct.pack(f'<{len(arguments)}Q', *arguments) + suffix
        scratch = ctypes.create_string_buffer(packet, len(packet))
        size = self._entry(source, len(data), output, CAPACITY, scratch, len(scratch))
        if not HEADER.size <= size <= CAPACITY:
            raise RuntimeError('invalid native Safe Core ELF response extent')
        status, first, second = HEADER.unpack_from(output)
        if status:
            if status > len(REFUSALS) or size != HEADER.size or first or second:
                raise RuntimeError('invalid native Safe Core ELF refusal')
            name, reason = REFUSALS[status - 1]
            if name == 'name_ascii':
                raise SafeCoreELFRejected(reason)
            require(False, reason)
        return output, size, first, second

    @staticmethod
    def _name(data, offset, count):
        if offset >= len(data) or count > min(256, len(data) - offset - 1):
            raise RuntimeError('invalid native Safe Core ELF name extent')
        return data[offset:offset + count].decode('ascii')

    def inventory(self, data, kind):
        if type(kind) is not int or not 0 <= kind <= 65535:
            require(False, REFUSALS[1][1])
        output, size, section_count, segment_count = self._exchange(data, (kind,))
        if (not 1 <= section_count <= MAX_SECTIONS or segment_count > MAX_SEGMENTS
                or size != HEADER.size + section_count * SECTION.size + segment_count * SEGMENT.size):
            raise RuntimeError('invalid native Safe Core ELF inventory counts')
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
        return sections, segments


    def symbols(self, data, index):
        output, size, count, reserved = self._exchange(data, (index, 0))
        if reserved or count > MAX_SYMBOLS or size != HEADER.size + count * SYMBOL.size:
            raise RuntimeError('invalid native Safe Core ELF symbol inventory')
        symbols = []
        for at in range(HEADER.size, size, SYMBOL.size):
            offset, extent, *fields = SYMBOL.unpack_from(output, at)
            symbols.append(dict(zip(SYMBOL_FIELDS, fields, strict=True),
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
        arguments = (2, relocations['offset'], source['offset'], source['size'],
                     linked['addr'], plt['addr'] + 16, helper, relocations['link'])
        output, size, count, reserved = self._exchange(data, arguments, linked['data'])
        expected = 2 if helper else 1
        if reserved or count != expected or size != HEADER.size + count * RELOCATION.size:
            raise RuntimeError('invalid native Safe Core call relocation response')
        calls, records = {}, []
        for at in range(HEADER.size, size, RELOCATION.size):
            offset, symbol, target, displacement = RELOCATION.unpack_from(output, at)
            if not 1 <= symbol <= expected or not 0 < offset <= source['size'] - 4 or offset - 1 in calls:
                raise RuntimeError('invalid native Safe Core call relocation')
            name = 'abort' if symbol == 1 else '__hia_native_fn_0'
            calls[offset - 1] = 'abort' if symbol == 1 else target - linked['addr']
            records.append(dict(offset=offset, symbol=name, type=4, addend=-4,
                                linked_target=target, displacement=displacement))
        return calls, records

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
    return None if selected is None else installed_safe_core_elf_inventory(selected)
