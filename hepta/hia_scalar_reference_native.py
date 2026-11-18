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
BYTE_MAGIC = int.from_bytes(b'HIASBM01', 'little')
ALLOCATION_MAGIC = int.from_bytes(b'HIASAM01', 'little')
WORD_MASK = (1 << 64) - 1
_ACTIVE = ContextVar('hia_scalar_reference_child', default=None)
OPCODES = {name: index for index, name in enumerate((
    'int.add.wrap', 'int.sub.wrap', 'int.mul.wrap', 'int.add.checked', 'int.sub.checked',
    'int.mul.checked', 'int.div.checked', 'int.rem.checked', 'int.shl.checked', 'int.shr.checked',
    'int.neg.checked', 'bit.and', 'bit.or', 'bit.xor', 'bit.not', 'compare.eq', 'compare.ne',
    'compare.lt', 'compare.le', 'compare.gt', 'compare.ge', 'bool.and', 'bool.or', 'bool.not',
    'cast.wrap', 'cast.checked', 'select',
), 1)}
BYTE_OPERATIONS = {
    'load': (1, 'byte load outside the borrowed buffer'),
    'store': (2, 'byte store outside the borrowed buffer'),
    'fill': (3, 'fill range exceeds owned extent'),
    'copy': (4, 'bulk copy exceeds an owner extent'),
    'move': (5, 'in-place byte range exceeds owned extent'),
    'swap': (6, 'swap byte offset outside owner extent'),
    'copy_range': (4, 'cross-owner range copy exceeds byte extent'),
}
ALLOCATION_DECISIONS = ('empty', 'object-model', 'heap-budget', 'injected', 'allocate')


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
        if error:
            raise self._arithmetic_error(error, typ)
        return self._value(typ, result)

    def byte_operation(self, name, destination, *, offset=0, source=None,
                       source_offset=0, count=0, value=0):
        from .hia_program_runtime import HIAProgramTrap

        opcode, message = BYTE_OPERATIONS[name]
        request = struct.pack('<6Q', BYTE_MAGIC, opcode, offset, source_offset, count, value)
        wire = ctypes.create_string_buffer(request)
        # ctypes holds the two existing buffers fixed through the native call.
        # Zero extents still use a non-null unused pointer.
        out = ((ctypes.c_ubyte*len(destination)).from_buffer(destination)
               if destination else ctypes.create_string_buffer(1))
        other = ((ctypes.c_ubyte*len(source)).from_buffer(source)
                 if source else ctypes.create_string_buffer(1))
        status = self._entry(wire, len(request), out, len(destination), other, len(source or ()))
        if status == 0xfffffffd:
            raise HIAProgramTrap('bounds', message)
        if name == 'load' and 256 <= status <= 511:
            return status - 256
        if name != 'load' and status == 0:
            return None
        raise RuntimeError('invalid HIA reference byte result')

    def allocation(self, size, maximum, live, attempts, fail_at):
        # An index above the wire width cannot match an admitted finite run.
        failure = fail_at if fail_at is not None and fail_at <= WORD_MASK else 0
        request = struct.pack('<6Q', ALLOCATION_MAGIC, size, maximum, live, attempts, failure)
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(24)
        unused = ctypes.create_string_buffer(1)
        size = self._entry(source, len(request), output, len(output), unused, 0)
        identity, decision, new_attempts = struct.unpack('<3Q', output.raw)
        if (size != 24 or identity != RESULT or decision >= len(ALLOCATION_DECISIONS)
                or new_attempts != attempts + (decision >= 3)):
            raise RuntimeError('invalid HIA reference allocation decision')
        return ALLOCATION_DECISIONS[decision], new_attempts

    @staticmethod
    def _arithmetic_error(error, typ):
        from .hia_program_runtime import HIAProgramTrap

        code, message = (
            ('overflow', f'result is outside {typ}'),
            ('division_by_zero', 'integer divisor is zero'),
            ('overflow', 'signed minimum divided by minus one'),
            ('overflow', 'shift count is outside the word width'),
        )[error - 1]
        return HIAProgramTrap(code, message)

    @staticmethod
    def _value(typ, result):
        if typ == 'unit':
            if result:
                raise RuntimeError('invalid HIA scalar reference unit')
            return None
        if typ == 'bool':
            if result > 1:
                raise RuntimeError('invalid HIA scalar reference boolean')
            return bool(result)
        return result - (1 << 64) if typ.startswith('i') and result >> 63 else result

    def program(self, canonical, function, arguments, max_steps, max_call_depth):
        from .hia_program import scalar_value_valid
        from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
        from .hia_scalar_reference_wire import (
            MAX_PACKET_BYTES, PROGRAM_MAGIC, PROGRAM_RESULT, TRAPS, TYPES, program_wire,
        )

        compiled = program_wire(canonical, function)
        if compiled is None:
            return None
        body, registers, bounce, returns = compiled
        if len(body) + 8*len(arguments) > MAX_PACKET_BYTES:
            return None
        header = struct.pack('<8Q', PROGRAM_MAGIC, max_steps, max_call_depth,
                             registers, bounce, len(body), len(arguments), len(returns))
        words = struct.pack(f'<{len(arguments)}Q', *(int(arg or 0) & WORD_MASK for arg in arguments))
        wire = header + body[64:] + words
        source = ctypes.create_string_buffer(wire)
        output = ctypes.create_string_buffer(32 + 8*len(returns))
        workspace = ctypes.create_string_buffer(64 + (registers + bounce + 1)*8*max_call_depth)
        size = self._entry(source, len(wire), output, len(output), workspace, len(workspace))
        identity, status, steps, typ = struct.unpack_from('<4Q', output.raw)
        if (identity != PROGRAM_RESULT or not 0 <= status <= 11 or steps > max_steps + 1
                or size != (32 if status else len(output))):
            raise RuntimeError('invalid HIA scalar Core reference terminal')
        if status == 0:
            values = struct.unpack_from(f'<{len(returns)}Q', output.raw, 32)
            decoded = [self._value(kind, value) for kind, value in zip(returns, values)]
            if any(not scalar_value_valid(value, kind) for kind, value in zip(returns, decoded)):
                raise RuntimeError('invalid HIA scalar Core reference value')
            return steps, decoded, None
        if 1 <= status <= 4:
            if typ >= len(TYPES):
                raise RuntimeError('invalid HIA scalar Core reference trap type')
            error = self._arithmetic_error(status, TYPES[typ])
        elif status == 5:
            error = HIAProgramBudgetExceeded('steps', 'finite step limit reached')
        elif status == 6:
            error = HIAProgramBudgetExceeded('calls', 'finite call-depth limit reached')
        else:
            error = HIAProgramTrap(TRAPS[status - 7], 'explicit core trap')
        return steps, None, error


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
