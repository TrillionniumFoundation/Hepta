"""The source-bound private artifact-delivery entry and fixed receipt frame.

The ordinary ELF entry retains the four-argument public CLI. No argv, env or
stdin value selects this ABI. Admission derives one fixed private executable
by changing its declared ELF entry. Its separate stdin ABI prefixes the exact
original payload with a 16-byte nonce; the executable never changes per call.
HIA owns the disposition; these checks admit a complete transport frame only.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import struct


ELF_BASE = 0x400000
NOTE_OFFSET = 232
NOTE_BYTES = 120
NOTE_NAME = b'HIADELIV\0'
DESCRIPTOR_OFFSET = 256
DESCRIPTOR_BYTES = 96
PUBLIC_CODE_OFFSET = 352
NONCE_BYTES = 16
ENTRY_WORD_OFFSET = 24
DESCRIPTOR_MAGIC = int.from_bytes(b'HIADCTL1', 'little')
ACK_MAGIC = int.from_bytes(b'HIAPDLV1', 'little')
ACK_END = int.from_bytes(b'HIAPEND1', 'little')
ACK_BYTES = 128
VERSION = 1
OPERATIONS_MASK = 63
RETURNED, REFUSED, UNCONFIRMED = 1, 2, 3

TEMP_CREATED = 1 << 0
TEMP_IDENTITY = 1 << 1
TEMP_CLEANED = 1 << 2
TEMP_CLEANUP_UNKNOWN = 1 << 3
LINK_CREATED = 1 << 4
OWN_LINK_REMOVED = 1 << 5
COMPETING_LINK = 1 << 6
LINK_CLEANUP_UNKNOWN = 1 << 7
DIRECTORY_SYNC_REFUSED = 1 << 8
STDOUT_STARTED = 1 << 9
STDOUT_COMPLETE = 1 << 10
SHA_REFUSED = 1 << 11
TEMP_COMPETITOR = 1 << 12
MUTATION_INTERRUPTED = 1 << 13
PREFIX_COMPLETE = 1 << 14
FACTS_MASK = (1 << 15) - 1


@dataclass(frozen=True)
class ControlDescriptor:
    public_entry: int
    private_entry: int
    prefix_bytes: int


def control_descriptor(code, *, private=False):
    if type(code) is not bytes or len(code) < PUBLIC_CODE_OFFSET:
        raise ValueError('artifact private entry descriptor absent')
    header = struct.unpack_from('<HHIQQQIHHHHHH', code, 16)
    if (code[:16] != b'\x7fELF\x02\x01\x01' + bytes(9)
            or header != (2, 62, 1, header[3], 64, 0, 0, 64, 56, 3, 0, 0, 0)):
        raise ValueError('artifact private entry ELF header differs')
    expected = (
        (1, 5, 0, ELF_BASE, ELF_BASE, len(code), len(code), 4096),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
        (4, 4, NOTE_OFFSET, ELF_BASE + NOTE_OFFSET,
         ELF_BASE + NOTE_OFFSET, NOTE_BYTES, NOTE_BYTES, 4),
    )
    for index, record in enumerate(expected):
        if struct.unpack_from('<II6Q', code, 64 + index * 56) != record:
            raise ValueError('artifact private entry program header differs')
    if (struct.unpack_from('<III', code, NOTE_OFFSET) != (9, DESCRIPTOR_BYTES, 1)
            or code[244:256] != NOTE_NAME + bytes(3)):
        raise ValueError('artifact private entry note differs')
    words = struct.unpack_from('<12Q', code, DESCRIPTOR_OFFSET)
    public_entry, private_entry = words[2:4]
    if (words != (DESCRIPTOR_MAGIC, VERSION, public_entry, private_entry,
                  NONCE_BYTES, ACK_BYTES, DESCRIPTOR_BYTES, ENTRY_WORD_OFFSET,
                  0, 0, OPERATIONS_MASK, 0)
            or public_entry != ELF_BASE + PUBLIC_CODE_OFFSET
            or not public_entry < private_entry < ELF_BASE + len(code)
            or header[3] != (private_entry if private else public_entry)):
        raise ValueError('artifact private entry capability differs')
    return ControlDescriptor(public_entry, private_entry, NONCE_BYTES)


def private_executable(code):
    descriptor = control_descriptor(code)
    result = bytearray(code)
    struct.pack_into('<Q', result, ENTRY_WORD_OFFSET, descriptor.private_entry)
    return bytes(result)


def public_executable(code):
    descriptor = control_descriptor(code, private=True)
    result = bytearray(code)
    struct.pack_into('<Q', result, ENTRY_WORD_OFFSET, descriptor.public_entry)
    return bytes(result)


@dataclass(frozen=True)
class ArtifactAcknowledgement:
    operation: int
    outcome: int
    exit_code: int
    phase: int
    input_bytes: int
    stdout_bytes: int
    facts: int
    failure_phase: int
    cleanup_phase: int


def acknowledgement(raw, nonce, returncode, stdout):
    if (type(raw) is not bytes or len(raw) != ACK_BYTES
            or type(nonce) is not bytes or len(nonce) != NONCE_BYTES
            or type(returncode) is not int or not 0 <= returncode <= 255
            or type(stdout) is not bytes):
        raise ValueError('artifact delivery acknowledgement extent invalid')
    words = struct.unpack('<16Q', raw)
    if (words[:2] != (ACK_MAGIC, VERSION)
            or words[2:4] != struct.unpack('<2Q', nonce)
            or not 0 <= words[4] <= 6 or words[5] not in (RETURNED, REFUSED, UNCONFIRMED)
            or words[6] != returncode or words[7] > 63
            or words[9] != len(stdout) or words[10] & ~FACTS_MASK
            or words[11] > 63 or words[12] > 63
            or raw[104:120] != sha256(raw[:104]).digest()[:16] or words[15] != ACK_END):
        raise ValueError('artifact delivery acknowledgement identity invalid')
    if (words[5] == RETURNED and (returncode != 0 or words[4] == 0)
            or words[5] == REFUSED and (returncode == 0 or stdout)
            or words[5] != UNCONFIRMED and words[10] & PREFIX_COMPLETE == 0):
        raise ValueError('artifact delivery terminal disposition inconsistent')
    return ArtifactAcknowledgement(*words[4:13])
