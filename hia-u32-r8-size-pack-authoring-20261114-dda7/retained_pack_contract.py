"""Three unchanged retained inspection/frame functions; no product imports."""
from hashlib import sha256
import struct
CAPACITY = 1 << 20
PACK_MAGIC = int.from_bytes(b'HFRTPAK1', 'little')
LABELS = ('controller', 'representation', 'semantic')

def _digest(raw):
    return sha256(raw).hexdigest()


def _frame(images):
    if type(images) is not tuple or len(images) != 3 or any(type(x) is not bytes for x in images):
        raise TypeError('exact controller/representation/semantic-checker image tuple required')
    if any(not 0 < len(x) <= CAPACITY - 1024 for x in images):
        raise ValueError('each nonempty component must leave room for the ELF entry')
    raw = struct.pack('<6Q', PACK_MAGIC, 1, *(len(x) for x in images), 0) + b''.join(images)
    if len(raw) > CAPACITY:
        raise ValueError('the complete three-image frame exceeds the original 1 MiB bound')
    return raw


def _elf_structure(elf, images):
    """Inspect actual HIA output; this function emits no instruction or ELF byte."""
    _frame(images)
    offsets = []
    cursor = 1024
    for image in images:
        offsets.append(cursor)
        cursor = (cursor + len(image) + 15) & -16
    size = (offsets[-1] + len(images[-1]) + 4095) & -4096
    if (type(elf) is not bytes or not 4096 <= len(elf) <= CAPACITY or len(elf) != size
            or struct.unpack_from('<16sHHIQQQIHHHHHH', elf) !=
               (b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1, 0x400000 + 232,
                64, 0, 0, 64, 56, 3, 0, 0, 0)
            or struct.unpack_from('<IIQQQQQQ', elf, 64) !=
               (1, 5, 0, 0x400000, 0x400000, size, size, 4096)
            or struct.unpack_from('<IIQQQQQQ', elf, 120) !=
               (1, 6, size, 0x600000, 0x600000, 0, 0x1204000, 4096)
            or struct.unpack_from('<IIQQQQQQ', elf, 176) !=
               (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError('HIA-produced ELF differs from the fixed entry/segment contract')
    regions = []
    for i, (label, offset, image) in enumerate(zip(LABELS, offsets, images, strict=True)):
        end = offset + len(image)
        next_offset = offsets[i + 1] if i < 2 else size
        if elf[offset:end] != image or any(elf[end:next_offset]):
            raise ValueError('actual HIA image bytes or alignment padding differ')
        regions.append({'label': label, 'offset': offset, 'bytes': len(image), 'sha256': _digest(image)})
    return {'file_bytes': size, 'entry_offset': 232, 'regions': regions,
        'elf_interpreter': False, 'writable_executable_segment': False, 'executable_stack': False,
        'buffer_extents': [8388609, CAPACITY, CAPACITY], 'buffer_addresses': [0x602000, 0xe03000, 0xf03000],
        'startup_capability_page': 0x600000, 'stack_guard_address': 0x1003000,
        'stack_extent': 8 * CAPACITY,
        'resident_call_targets': [0x400000 + x for x in offsets[1:]],
        'component_authority': 'two fixed captured images; no arbitrary call target'}

