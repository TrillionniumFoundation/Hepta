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
CAPACITY = HEADER.size + MAX_SECTIONS * SECTION.size + MAX_SEGMENTS * SEGMENT.size
SECTION_FIELDS = ('type', 'flags', 'addr', 'offset', 'size', 'link', 'info', 'align', 'entsize')
SEGMENT_FIELDS = ('type', 'flags', 'offset', 'addr', 'filesz', 'memsz', 'align')
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
)
REFUSAL_IDS = {name: number for number, (name, _) in enumerate(REFUSALS, 1)}


class NativeSafeCoreElfInventory(NativeHiaJsonImage):
    def inventory(self, data, kind):
        require(type(data) is bytes and 64 <= len(data) <= MAX_ELF, REFUSALS[0][1])
        if type(kind) is not int or not 0 <= kind <= 65535:
            require(False, REFUSALS[1][1])
        source = ctypes.create_string_buffer(data, len(data))
        output = ctypes.create_string_buffer(CAPACITY)
        scratch = ctypes.create_string_buffer(struct.pack('<Q', kind), 8)
        size = self._entry(source, len(data), output, CAPACITY, scratch, len(scratch))
        if not HEADER.size <= size <= CAPACITY:
            raise RuntimeError('invalid native Safe Core ELF inventory size')
        status, section_count, segment_count = HEADER.unpack_from(output)
        if status:
            if status > len(REFUSALS) or size != HEADER.size or section_count or segment_count:
                raise RuntimeError('invalid native Safe Core ELF refusal')
            name, reason = REFUSALS[status - 1]
            if name == 'name_ascii':
                raise SafeCoreELFRejected(reason)
            require(False, reason)
        if (not 1 <= section_count <= MAX_SECTIONS or segment_count > MAX_SEGMENTS
                or size != HEADER.size + section_count * SECTION.size + segment_count * SEGMENT.size):
            raise RuntimeError('invalid native Safe Core ELF inventory counts')
        cursor = HEADER.size
        sections = []
        for ordinal in range(section_count):
            index, name_at, name_len, *fields = SECTION.unpack_from(output, cursor)
            cursor += SECTION.size
            if index != ordinal or name_at >= len(data) or name_len > min(256, len(data) - name_at - 1):
                raise RuntimeError('invalid native Safe Core ELF name extent')
            section = dict(zip(SECTION_FIELDS, fields, strict=True))
            offset, extent = section['offset'], section['size']
            if offset > len(data) or extent > len(data) - offset:
                raise RuntimeError('invalid native Safe Core ELF section extent')
            section.update(index=index, name=data[name_at:name_at + name_len].decode('ascii'),
                           data=data[offset:offset + extent])
            sections.append(section)
        segments = []
        for _ in range(segment_count):
            segments.append(dict(zip(SEGMENT_FIELDS, SEGMENT.unpack_from(output, cursor), strict=True)))
            cursor += SEGMENT.size
        return sections, segments


def installed_safe_core_elf_inventory(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeSafeCoreElfInventory)


def selected_safe_core_elf_inventory():
    selected = os.environ.get(SELECTOR)
    return None if selected is None else installed_safe_core_elf_inventory(selected)
