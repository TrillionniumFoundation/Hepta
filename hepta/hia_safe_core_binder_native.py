"""Transport and decode a package-pinned HIA two-ELF binding."""
from __future__ import annotations

from hashlib import sha256
import os
import struct
import subprocess

from .hia_safe_core_elf import SafeCoreELFRejected, _binding_result, require
from .hia_safe_core_elf_inventory_native import (
    MAX_ELF, OWNED_SHARED_NAMED_ERRORS, OWNED_SHARED_REFUSALS, REFUSALS, RELOCATION,
    NativeSafeCoreElfInventory,
)

DIAGNOSTIC_REQUEST = int.from_bytes(b'HIAEBND2', 'little')
DIAGNOSTIC_REPLY = int.from_bytes(b'HIAEBNX1', 'little')
REPLY_MAGIC = int.from_bytes(b'HIAEBNR1', 'little')
MAX_EXECUTABLE = 1 << 20
ENTRY = struct.Struct('<10Q')
ERROR = struct.Struct('<5Q')


class NativeSafeCoreBinder:
    def __init__(self, raw, expected, source):
        if (sha256(raw).hexdigest() != expected or len(raw) < 176
                or raw[:7] != b'\x7fELF\x02\x01\x01'
                or struct.unpack_from('<2H', raw, 16) != (2, 62)):
            raise ValueError('package Safe Core ELF binder identity mismatch')
        self._raw = raw
        self.image_sha256 = expected
        self.admitted_source_sha256 = source

    def bind(self, obj, final, export, *, native_wire):
        from .hia_program_selfhost import _sealed_executable
        from .hia_scalar_reference_native import sealed_reference_bytes

        require(all(type(data) is bytes and 64 <= len(data) <= MAX_ELF for data in (obj, final)),
                REFUSALS[0][1])
        name = export.encode('ascii')
        require(0 < len(name) <= 256, 'invalid Safe Core export identity')
        header = struct.pack('<4Q256s', DIAGNOSTIC_REQUEST, len(obj), len(final), len(name), name)
        try:
            descriptor, _ = _sealed_executable(self._raw)
            try:
                with sealed_reference_bytes(header, obj, final) as request:
                    os.lseek(request, 0, os.SEEK_SET)
                    result = subprocess.run(['/proc/self/fd/' + str(descriptor)], stdin=request,
                                            env={'PATH': ''}, pass_fds=(descriptor,), capture_output=True,
                                            timeout=10, check=False)
            finally:
                os.close(descriptor)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SafeCoreELFRejected('native Safe Core ELF binder execution unavailable') from error
        require(not result.returncode and not result.stderr, 'native Safe Core ELF binder refused')
        raw = result.stdout
        if len(raw) == ERROR.size and ERROR.unpack_from(raw)[0] == DIAGNOSTIC_REPLY:
            self._refusal(raw, final, export)
        require(len(raw) >= ENTRY.size, 'invalid Safe Core ELF binding response')
        magic, offset, address, span, entry, helper, abort, direct, extent, reserved = ENTRY.unpack_from(raw)
        require(magic == REPLY_MAGIC and reserved == 0 and direct in (0, 1)
                and 0 <= entry < span <= 64 * 1024 and offset + span <= len(final)
                and extent == 24 + RELOCATION.size * (2 - direct)
                and len(raw) == ENTRY.size + span + extent,
                'invalid Safe Core ELF binding coordinates')
        text = raw[ENTRY.size:ENTRY.size + span]
        require(text == final[offset:offset + span], 'native Safe Core text receipt differs')
        wire = raw[ENTRY.size + span:]
        calls, records = NativeSafeCoreElfInventory.read_relocation_wire(wire, span, address, helper)
        return _binding_result(obj, final, export, offset, address, text, entry, direct, calls, records,
                               wire if native_wire else None)

    @staticmethod
    def _refusal(raw, final, export):
        from .elf_shared_abi import _fail

        _, phase, status, first, second = ERROR.unpack(raw)
        if phase == 1:
            if 0 < status <= len(OWNED_SHARED_REFUSALS):
                name, reason = OWNED_SHARED_REFUSALS[status - 1]
                if name in OWNED_SHARED_NAMED_ERRORS:
                    reason += NativeSafeCoreElfInventory._owned_symbol_name(final, first, second)
                _fail(reason)
            _fail('public ABI symbols differ from source: expected ' + repr((export,)))
        if 0 < status <= len(REFUSALS):
            name, reason = REFUSALS[status - 1]
            if name == 'loader_section_unallocated':
                reason += NativeSafeCoreElfInventory._name(final, first, second)
            require(False, reason)
        reasons = {
            0: 'expected bounded immutable ELF bytes',
            3: 'missing section .eh_frame',
            8: 'closed function inventory differs',
            10: 'source and final text shapes differ',
            11: 'object relocation inventory is outside the one-function profile',
        }
        require(False, reasons.get(phase, 'invalid native Safe Core ELF binding response'))


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
