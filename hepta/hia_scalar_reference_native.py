"""Select an independent HIA integer/boolean evaluator for reference execution."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
from hashlib import sha256
import os
import signal
import struct
import subprocess

from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/scalar_reference.hepta')
SOURCES = {'owned': _source_resource_path('examples/hia_bootstrap/owned_reference.hepta')}
SCHEMA = 'hepta.hia.scalar-reference-native.v1'
SELECTOR = 'HEPTA_HIA_SCALAR_REFERENCE_MANIFEST'
MAGIC = int.from_bytes(b'HIASCP01', 'little')
RESULT = int.from_bytes(b'HIASCR01', 'little')
BYTE_MAGIC = int.from_bytes(b'HIASBM01', 'little')
ALLOCATION_MAGIC = int.from_bytes(b'HIASAM01', 'little')
DOMAIN_MAGIC = int.from_bytes(b'HIASDM01', 'little')
OBSERVATION_MAGIC = int.from_bytes(b'HIASOM01', 'little')
LOAN_MAGIC = int.from_bytes(b'HIASLM01', 'little')
CHAIN_MAGIC = int.from_bytes(b'HIASCM01', 'little')
OWNER_MAGIC = int.from_bytes(b'HIASOW01', 'little')
STORAGE_MAGIC = int.from_bytes(b'HIASOS01', 'little')
ARENA_BYTES_MAGIC = int.from_bytes(b'HIASOB01', 'little')
OWNER_RECORD_BYTES = 112
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


_STANDALONE = ContextVar('hia-standalone-reference', default=None)
_OWNED = ContextVar('hia-standalone-owned-reference', default=None)


@contextmanager
def sealed_reference_bytes(image):
    import fcntl

    fd = os.memfd_create('hia-reference-evaluator', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(image)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _seals(fcntl))
        yield fd
    finally:
        os.close(fd)


class _StandaloneReference:
    def __init__(self, fd, digest, *, allow_space=False):
        self.fd = fd
        self.digest = digest
        self.calls = 0
        self.allow_space = allow_space

    def run(self, wire):
        # Install custody before accepting cancellation between fork and exec.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        try:
            proc = subprocess.Popen(['/proc/self/fd/' + str(self.fd)], env={'PATH': ''}, pass_fds=(self.fd,),
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except BaseException:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            raise
        with proc:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                stdout, stderr = proc.communicate(wire)
            except BaseException:
                proc.kill()
                raise
        if self.allow_space and proc.returncode == 3 and not stdout and not stderr:
            self.calls += 1
            return None
        if proc.returncode or stderr:
            raise RuntimeError('standalone HIA reference did not return a complete machine reply')
        self.calls += 1
        return stdout


class NativeScalarReference(NativeHiaJsonImage):
    def sealed_descriptor(self):
        """Pass the selected bytes themselves, never a child-reopened pathname."""
        return sealed_reference_bytes(self._mapping[:])

    def matches_standalone(self, image):
        return image.startswith(b'\x7fELF') and image.endswith(self._mapping[:])

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

    def finite_arguments(self, types, ordinal, required):
        # One-byte kinds encode Boolean, unsigned byte, and signed byte.
        kinds = bytes({'bool': 1, 'u8': 8, 'i8': 136}[kind] for kind in types)
        request = struct.pack('<3Q', DOMAIN_MAGIC, ordinal, len(kinds)) + kinds
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(8 + 8 * len(kinds))
        unused = ctypes.create_string_buffer(1)
        size = self._entry(source, len(request), output, len(output), unused, 0)
        if size != len(output) or struct.unpack_from('<Q', output.raw)[0] != required:
            raise RuntimeError('invalid HIA finite-domain argument result')
        words = struct.unpack_from(f'<{len(kinds)}q', output.raw, 8)
        return tuple(bool(value) if kind == 'bool' else value for kind, value in zip(types, words))

    def same_observation(self, first, second):
        request = struct.pack('<3Q', OBSERVATION_MAGIC, len(first), len(second)) + first + second
        source = ctypes.create_string_buffer(request)
        unused = ctypes.create_string_buffer(1)
        status = self._entry(source, len(request), unused, 0, unused, 0)
        if status not in (0, 1):
            raise RuntimeError('invalid HIA finite-domain observation result')
        return bool(status)

    def loan_operation(self, workspace, operation, first, second=0, mutable=False):
        request = struct.pack('<5Q', LOAN_MAGIC, operation, first, second, int(mutable))
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(32)
        table = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        size = self._entry(source, len(request), output, len(output), table, len(workspace))
        identity, status, result, root = struct.unpack_from('<4Q', output)
        if size != 32 or identity != RESULT or status > 4:
            raise RuntimeError('invalid HIA native loan result')
        return status, result, root

    def chain_operation(self, workspace, operation, subject, payload=0, storage=0, allocated=False):
        request = struct.pack('<6Q', CHAIN_MAGIC, operation, subject, payload, storage, int(allocated))
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(56)
        table = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        size = self._entry(source, len(request), output, len(output), table, len(workspace))
        identity, status, first, payload, storage, present, live = struct.unpack_from('<7Q', output)
        if size != 56 or identity != RESULT or status not in (0, 1, 3) or present > 1:
            raise RuntimeError('invalid HIA native chain result')
        return status, first, payload, storage, bool(present), live

    def owner_operation(self, workspace, operation, subject, maximum, fail_at=0):
        failure = fail_at if fail_at is not None and fail_at <= WORD_MASK else 0
        request = struct.pack('<5Q', OWNER_MAGIC, operation, subject, maximum, failure)
        source = ctypes.create_string_buffer(request)
        output = ctypes.create_string_buffer(80)
        table = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        size = self._entry(source, len(request), output, len(output), table, len(workspace))
        identity, status, result, *counters = struct.unpack_from('<10Q', output)
        if size != 80 or identity != RESULT or status not in (0, 1, 3):
            raise RuntimeError('invalid HIA native owner result')
        return status, result, counters

    def attach_storage(self, workspace, storage, amount, maximum):
        request = struct.pack('<3Q', STORAGE_MAGIC, amount, maximum)
        wire = ctypes.create_string_buffer(request)
        capacity = 0 if storage is None else len(storage)
        backing = ((ctypes.c_ubyte * capacity).from_buffer(storage)
                   if capacity else ctypes.create_string_buffer(1))
        table = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        status = self._entry(wire, len(request), backing, capacity, table, len(workspace))
        if status not in (0, 2, 3):
            raise RuntimeError('invalid HIA native storage result')
        return status, struct.unpack_from('<Q', workspace, OWNER_RECORD_BYTES - 8)[0]

    def storage_bytes(self, name, workspace, storage, destination, *, source=0, offset=0,
                      source_offset=0, count=0, value=0):
        from .hia_program_runtime import HIAProgramTrap

        opcode, message = BYTE_OPERATIONS[name]
        request = struct.pack('<8Q', ARENA_BYTES_MAGIC, opcode, destination, source,
                              offset, source_offset, count, value)
        wire = ctypes.create_string_buffer(request)
        capacity = 0 if storage is None else len(storage)
        backing = ((ctypes.c_ubyte * capacity).from_buffer(storage)
                   if capacity else ctypes.create_string_buffer(1))
        table = (ctypes.c_ubyte * len(workspace)).from_buffer(workspace)
        status = self._entry(wire, len(request), backing, capacity, table, len(workspace))
        if status == 0xfffffffd:
            raise HIAProgramTrap('bounds', message)
        if name == 'load' and 256 <= status <= 511:
            return status - 256
        if name != 'load' and status == 0:
            return None
        raise RuntimeError('invalid HIA native storage byte result')

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

    def program(self, canonical, function, arguments, max_steps, max_call_depth, *, machine=None):
        from .hia_opcodes import OWNERS, RESOURCES
        from .hia_program_runtime import HIAProgramBudgetExceeded, _ReferenceResources
        from .hia_scalar_reference_wire import (
            MAX_PACKET_BYTES, PROGRAM_MAGIC, PROGRAM_RESULT, RESOURCE_PROGRAM_MAGIC,
            program_wire, resource_request,
        )

        compiled = program_wire(canonical, function, allow_resources=machine is not None)
        if compiled is None:
            return None
        body, registers, bounce, returns, resource_sites = compiled
        if len(body) + 8*len(arguments) > MAX_PACKET_BYTES:
            return None
        kinds = ([param['type'] for param in machine.functions[function]['params']]
                 if machine is not None else ())
        owned = _OWNED.get()
        if (machine is not None and owned is not None
                and (resource_sites or any(kind in RESOURCES for kind in kinds))
                and not any(kind in OWNERS for kind in kinds)
                and not any(kind in RESOURCES for kind in returns)):
            header = struct.pack('<8Q', RESOURCE_PROGRAM_MAGIC, max_steps, max_call_depth,
                                 registers, bounce, len(body), len(arguments), len(returns))
            suffix, external = self._owned_arguments(kinds, arguments, machine)
            if len(body) + len(suffix) <= MAX_PACKET_BYTES:
                return self._owned_result(owned.run(header + body[64:] + suffix), machine, returns, external)
        resources = (_ReferenceResources(machine)
                     if resource_sites or any(kind in RESOURCES for kind in kinds) else None)
        magic = RESOURCE_PROGRAM_MAGIC if resource_sites else PROGRAM_MAGIC
        header = struct.pack('<8Q', magic, max_steps, max_call_depth,
                             registers, bounce, len(body), len(arguments), len(returns))
        if resources is not None:
            encoded = (resources.encode(kind, value) for kind, value in zip(kinds, arguments))
        else:
            encoded = (int(arg or 0) & WORD_MASK for arg in arguments)
        words = struct.pack(f'<{len(arguments)}Q', *encoded)
        wire = header + body[64:] + words
        standalone = _STANDALONE.get()
        if standalone is not None and resources is None:
            result = standalone.run(wire)
            if len(result) < 32:
                raise RuntimeError('truncated standalone HIA reference machine reply')
            identity, status, steps, typ = struct.unpack_from('<4Q', result)
            if identity != PROGRAM_RESULT or steps > max_steps + 1:
                raise RuntimeError('invalid standalone HIA reference progress')
            if status == 12 and len(result) == 32 and steps <= max_steps and typ == 0:
                return steps, None, HIAProgramBudgetExceeded(
                    'host_memory', 'cannot extend reference call workspace')
            return self._program_result(result, len(result), status, steps, typ, returns)

        source = ctypes.create_string_buffer(wire)
        output = ctypes.create_string_buffer(32 + 8*(bounce if resource_sites else len(returns)))
        stride = (registers + bounce + 1) * 8
        workspace = ctypes.create_string_buffer(64 + stride)
        previous = 0
        while True:
            size = self._entry(source, len(wire), output, len(output), workspace, len(workspace))
            identity, status, steps, typ = struct.unpack_from('<4Q', output)
            if identity != PROGRAM_RESULT or not previous <= steps <= max_steps + 1:
                raise RuntimeError('invalid HIA Core reference progress')
            if status == 14:
                required = typ
                limit = 64 + stride * max_call_depth
                if (size != 32 or not previous < steps <= max_steps
                        or required != len(workspace) + stride or required > limit):
                    raise RuntimeError('invalid HIA Core reference workspace request')
                try:
                    capacity = min(limit, 64 + 2*(len(workspace)-64))
                    expanded = ctypes.create_string_buffer(capacity)
                    ctypes.memmove(expanded, workspace, len(workspace))
                except MemoryError:
                    return steps, None, HIAProgramBudgetExceeded(
                        'host_memory', 'cannot extend reference call workspace')
                workspace = expanded
                previous = steps
                continue
            if status != 13:
                break
            if resources is None or steps <= previous or steps > max_steps:
                raise RuntimeError('invalid HIA Core reference resource request')
            request = resource_request(wire, typ)
            if size != 32 + 8*request.inputs:
                raise RuntimeError('invalid HIA Core reference resource arguments')
            operands = struct.unpack_from(f'<{request.inputs}Q', output, 32)
            machine.steps = steps
            returned = resources.operation(request, operands)
            if len(returned) != request.outputs:
                raise RuntimeError('invalid HIA Core reference resource results')
            struct.pack_into(f'<{len(returned)}Q', output, 32, *returned)
            struct.pack_into('<Q', workspace, 0, machine.steps)
            previous = machine.steps
        return self._program_result(output, size, status, steps, typ, returns)

    @staticmethod
    def _owned_arguments(kinds, arguments, machine):
        from .hia_program_runtime import HIAProgramRejected, _Owner, _View

        words, records, external = [], [], []
        for index, (kind, value) in enumerate(zip(kinds, arguments)):
            if kind not in ('readbuf', 'mutbuf'):
                words.append(int(value or 0) & WORD_MASK)
                continue
            mutable = kind == 'mutbuf'
            if (type(value) is not _View or type(value.parent) is not _Owner
                    or value.parent.ident >= 0 or not value.parent.active
                    or not value.active or value.mutable is not mutable):
                raise HIAProgramRejected('invalid external runtime view', 'E_HIA_RUNTIME_INVARIANT')
            words.append(0)
            records.extend((index, int(mutable), len(value.parent.data)))
            external.append((value.parent.data, mutable))
        if len({id(data) for data, _ in external}) != len(external):
            raise HIAProgramRejected('non-distinct external runtime views', 'E_HIA_RUNTIME_INVARIANT')
        failure = machine.allocation_fail_at or 0
        if failure > machine.max_steps:
            failure = 0
        head = struct.pack(f'<{len(words) + 2}Q', *words, machine.max_heap_bytes, failure)
        if external:
            head += struct.pack(f'<{len(records) + 1}Q', len(external), *records)
            head = b''.join([head, *(data for data, _ in external)])
        return head, external

    def _owned_result(self, output, machine, returns, external):
        from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
        from .hia_scalar_reference_wire import PROGRAM_RESULT, RESOURCE_NAMES

        if output is None:
            return 0, None, HIAProgramBudgetExceeded('host_memory', 'cannot allocate private HIA resource workspace')
        size = len(output) - 112 - sum(len(data) for data, _ in external)
        if size < 32:
            raise RuntimeError('truncated standalone HIA owned reference result')
        identity, status, steps, detail = struct.unpack_from('<4Q', output)
        if identity != PROGRAM_RESULT or steps > machine.max_steps + 1:
            raise RuntimeError('invalid standalone HIA owned reference progress')
        if status <= 11:
            outcome = self._program_result(output, size, status, steps, detail, returns)
        elif 15 <= status <= 19 and size == 32 and 1 <= detail <= len(RESOURCE_NAMES):
            operation = RESOURCE_NAMES[detail - 1]
            if status in (15, 17) and operation == 'buffer.new':
                message = ('allocation exceeds the 64-bit object-size model' if status == 15
                           else 'allocator returned failure')
                error = HIAProgramTrap('allocation', message)
            elif status == 16 and operation in ('buffer.new', 'buffer.try_new', 'chain.try_push'):
                error = HIAProgramBudgetExceeded('heap', 'finite live-byte limit reached')
            elif status == 18 and operation.startswith('buffer.'):
                name = {'fill_range': 'fill', 'move_within': 'move'}.get(operation[7:], operation[7:])
                if name not in BYTE_OPERATIONS:
                    raise RuntimeError('invalid standalone HIA owned reference bounds operation')
                error = HIAProgramTrap('bounds', BYTE_OPERATIONS[name][1])
            elif status == 19 and operation in ('chain.head_read', 'chain.head_mut'):
                error = HIAProgramTrap('bounds', 'head borrow of an empty chain')
            else:
                raise RuntimeError('invalid standalone HIA owned reference error')
            outcome = steps, None, error
        else:
            raise RuntimeError('invalid standalone HIA owned reference status')
        (machine.allocation_attempts, machine.allocations, machine.frees, machine.owner_count, machine.drops,
         machine.live_bytes, machine.peak_bytes, machine.loans_started, machine.loans_ended,
         machine.chains_created, machine.chains_consumed, machine.chain_nodes_created,
         machine.chain_nodes_dropped, machine.native_chain_count) = struct.unpack_from('<14Q', output, size)
        machine.native_owner_count = machine.owner_count - machine.drops
        offset = size + 112
        snapshot = memoryview(output)
        for data, mutable in external:
            extent = len(data)
            result = snapshot[offset:offset + extent]
            if mutable:
                data[:] = result
            elif data != result:
                raise RuntimeError('standalone HIA changed a read-only external buffer')
            offset += extent
        return outcome

    def _program_result(self, output, size, status, steps, typ, returns):
        from .hia_program import scalar_value_valid
        from .hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
        from .hia_scalar_reference_wire import TRAPS, TYPES

        if not 0 <= status <= 11 or size != (32 if status else 32 + 8*len(returns)):
            raise RuntimeError('invalid HIA scalar Core reference terminal')
        if status == 0:
            values = struct.unpack_from(f'<{len(returns)}Q', output, 32)
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
def _sealed_reference_record(record):
    import fcntl

    if (type(record) is not dict or set(record) != {'fd', 'sha256'}
            or type(record['fd']) is not int or record['fd'] < 3):
        raise ValueError('invalid reference evaluator descriptor')
    fd = record['fd']
    try:
        size = os.fstat(fd).st_size
        required = _seals(fcntl)
        if (not 0 < size <= MAX_IMAGE_BYTES
                or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required != required):
            raise ValueError('reference evaluator descriptor is not sealed')
        image = os.pread(fd, size, 0)
        if len(image) != size or sha256(image).hexdigest() != record['sha256']:
            raise ValueError('reference evaluator descriptor identity differs')
        yield fd, image
    finally:
        os.close(fd)


@contextmanager
def child_scalar_reference(record):
    if record is None:
        yield None
        return
    with _sealed_reference_record(record) as (_, image):
        selected = NativeScalarReference(image, record['sha256'])
    token = _ACTIVE.set(selected)
    try:
        yield selected
    finally:
        _ACTIVE.reset(token)


@contextmanager
def child_standalone_reference(record, reference):
    if record is None:
        yield None
        return
    with _sealed_reference_record(record) as (fd, image):
        if reference is None or not reference.matches_standalone(image):
            raise ValueError('standalone reference does not contain the selected HIA image')
        standalone = _StandaloneReference(fd, record['sha256'])
        token = _STANDALONE.set(standalone)
        try:
            yield standalone
        finally:
            _STANDALONE.reset(token)


@contextmanager
def child_owned_reference(record):
    if record is None:
        yield None
        return
    with _sealed_reference_record(record) as (fd, image):
        if not image.startswith(b'\x7fELF'):
            raise ValueError('invalid standalone HIA owned reference image')
        standalone = _StandaloneReference(fd, record['sha256'], allow_space=True)
        token = _OWNED.set(standalone)
        try:
            yield standalone
        finally:
            _OWNED.reset(token)
