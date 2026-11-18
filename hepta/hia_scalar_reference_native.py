"""Select an independent HIA integer/boolean evaluator for reference execution."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
import os
import struct

from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/scalar_reference.hepta')
SCHEMA = 'hepta.hia.scalar-reference-native.v1'
SELECTOR = 'HEPTA_HIA_SCALAR_REFERENCE_MANIFEST'
MAGIC = int.from_bytes(b'HIASCP01', 'little')
RESULT = int.from_bytes(b'HIASCR01', 'little')
WORD_MASK = (1 << 64) - 1
_ACTIVE = ContextVar('hia_scalar_reference_child', default=None)
OPCODES = {name: index for index, name in enumerate((
    'int.add.wrap', 'int.sub.wrap', 'int.mul.wrap', 'int.add.checked', 'int.sub.checked',
    'int.mul.checked', 'int.div.checked', 'int.rem.checked', 'int.shl.checked', 'int.shr.checked',
    'int.neg.checked', 'bit.and', 'bit.or', 'bit.xor', 'bit.not', 'compare.eq', 'compare.ne',
    'compare.lt', 'compare.le', 'compare.gt', 'compare.ge', 'bool.and', 'bool.or', 'bool.not',
    'cast.wrap', 'cast.checked', 'select',
), 1)}


class NativeScalarReference(NativeHiaJsonImage):
    @contextmanager
    def sealed_descriptor(self):
        """Pass the selected bytes themselves, never a child-reopened pathname."""
        import fcntl

        fd = os.memfd_create('hia-reference-evaluator', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            image = self._mapping[:]
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(image)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _seals(fcntl))
            yield fd
        finally:
            os.close(fd)

    def operation(self, opcode, typ, arguments):
        from .hia_program_runtime import HIAProgramTrap
        from .hia_program import WIDTHS

        signed = typ.startswith('i')
        boolean = typ == 'bool'
        width = 1 if boolean else WIDTHS[typ]
        words = [int(value) for value in arguments]
        prefix = int(signed)
        for index, value in enumerate(words):
            prefix |= int(value < 0) << (index + 1)
        words = [value & WORD_MASK for value in words]
        words.extend([0] * (3 - len(words)))
        wire = struct.pack('<7Q', MAGIC, OPCODES[opcode], width, prefix, *words)
        source = ctypes.create_string_buffer(wire)
        output = ctypes.create_string_buffer(24)
        unused = ctypes.create_string_buffer(1)
        size = self._entry(source, len(wire), output, len(output), unused, 0)
        identity, error, result = struct.unpack('<3Q', output.raw)
        if size != 24 or identity != RESULT or error > 4 or error and result:
            raise RuntimeError('invalid HIA scalar reference result')
        if error == 1:
            raise HIAProgramTrap('overflow', f'result is outside {typ}')
        if error == 2:
            raise HIAProgramTrap('division_by_zero', 'integer divisor is zero')
        if error == 3:
            raise HIAProgramTrap('overflow', 'signed minimum divided by minus one')
        if error == 4:
            raise HIAProgramTrap('overflow', 'shift count is outside the word width')
        if boolean:
            if result > 1:
                raise RuntimeError('invalid HIA scalar reference boolean')
            return bool(result)
        return result - (1 << 64) if signed and result >> 63 else result


def selected_scalar_reference():
    active = _ACTIVE.get()
    if active is not None:
        return active
    path = os.environ.get(SELECTOR)
    return None if path is None else _installed_json_image(path, SOURCE, SCHEMA, NativeScalarReference)


def _seals(fcntl):
    return fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK


@contextmanager
def child_scalar_reference(record):
    if record is None:
        yield None
        return
    if (type(record) is not dict or set(record) != {'fd', 'sha256'}
            or type(record['fd']) is not int or record['fd'] < 3):
        raise ValueError('invalid reference evaluator descriptor')
    fd = record['fd']
    import fcntl

    try:
        size = os.fstat(fd).st_size
        required = _seals(fcntl)
        if (not 0 < size <= MAX_IMAGE_BYTES
                or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required):
            raise ValueError('reference evaluator descriptor is not sealed')
        image = os.pread(fd, size, 0)
        if len(image) != size:
            raise ValueError('incomplete reference evaluator descriptor')
        selected = NativeScalarReference(image, record['sha256'])
    finally:
        os.close(fd)
    token = _ACTIVE.set(selected)
    try:
        yield selected
    finally:
        _ACTIVE.reset(token)
