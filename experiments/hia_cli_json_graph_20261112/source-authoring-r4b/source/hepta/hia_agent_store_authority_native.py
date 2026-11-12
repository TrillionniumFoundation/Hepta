"""Explicit HIA AgentStore reference/profile authority; hosted SQL and file IO.

The continuation chooses every lookup, identity comparison, rejection and
publication/metadata route. This is not a native database or a replacement for
the independently selected file publisher, JSON codec or retained field-shape
admission. The old AgentStore methods remain independent reference owners.
"""
from __future__ import annotations

import ctypes
import struct
import sys

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_json_wire_native import _private_zeroed_buffer
from .hia_worker_report_native import WorkerGraphObserver, _dict_primitives, _pure_builtin_key_hash

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_store_authority.hiaasm')
SCHEMA = 'hepta.hia.agent-store-authority-native.v2'
SELECTOR = 'HEPTA_HIA_AGENT_STORE_AUTHORITY_MANIFEST'
MAGIC = int.from_bytes(b'HIASTA02', 'little')
HIGH = 1 << 63


def _retained_publish_file(store, content_hash, data):
    """Existing unselected immutable-file publisher, explicitly still hosted.

    This copied boundary preserves file/race/cleanup semantics independently
    from the original put oracle. HIA decides whether and when to invoke it;
    selecting the existing artifact publisher uses that native owner instead.
    """
    from . import hia_agent_store as m
    destination = store.artifacts / content_hash
    temporary = store.artifacts / ('.write-' + m.uuid.uuid4().hex)
    descriptor = m.os.open(temporary, m.os.O_WRONLY | m.os.O_CREAT | m.os.O_EXCL | m.os.O_CLOEXEC | m.os.O_NOFOLLOW, 0o400)
    try:
        with m.os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            m.os.fsync(stream.fileno())
        try:
            m.os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError:
            if m.stable_read(destination, m.MAX_ARTIFACT_BYTES) != data:
                m.reject('E_HIA_ARTIFACT_CORRUPT', 'stored content does not match its immutable identity')
        directory_fd = m.os.open(store.artifacts, m.os.O_RDONLY | m.os.O_DIRECTORY | m.os.O_CLOEXEC)
        try:
            m.os.fsync(directory_fd)
        finally:
            m.os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class StoreGraphObserver(WorkerGraphObserver):
    """Mechanically materialize only containers explicitly described by HIA.

    Foreign values are original objects, never recursively copied or encoded.
    The small acyclic virtual graph contains only HIA-selected literals,
    concatenations, SQL parameter tuples and output reference/profile objects.
    """
    def __init__(self, session):
        super().__init__(session)
        self.materialized = {}

    def child(self, handle, index, part):
        if handle < HIGH:
            return self.foreign.child(handle, index, part)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind == 6 and 0 <= index < size and part == 0:
            return struct.unpack_from('<Q', self.session.workspace, a + index * 8)[0]
        return super().child(handle, index, part)

    def value(self, handle):
        if handle < HIGH:
            return self.foreign.value(handle)
        if handle in self.materialized:
            return self.materialized[handle]
        kind, size, subtype, a, b, c = self._node(handle)
        if kind == 7:
            result = {}
            self.materialized[handle] = result
            for index in range(size):
                result[self.value(self.child(handle, index, 0))] = self.value(self.child(handle, index, 1))
        elif kind == 6:
            result = tuple(self.value(self.child(handle, index, 0)) for index in range(size))
        else:
            result = super().value(handle)
        self.materialized[handle] = result
        return result


class StoreAuthoritySession:
    """One-shot foreign observations over private HIA continuation memory."""
    def __init__(self, image, store, mode, argument=None, second=None, third=None):
        if type(mode) is not int or not 0 <= mode <= 5:
            raise ValueError('unknown HIA AgentStore authority operation')
        self.image, self.store = image, store
        self.workspace = _private_zeroed_buffer(262144)
        self.output = ctypes.create_string_buffer(8)
        self.observer = StoreGraphObserver(self)
        reg = self.observer.register
        self.packet = struct.pack('<11Q', MAGIC, 0, 0, mode, reg(store), reg(argument),
                                  reg(second), reg(third), reg(None), 0, 0)
        self.finished = False
        self.pending = False
        self.prepared = True
        self._dict_operations = None

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native AgentStore continuation is terminal')
        if packet is None and not self.prepared:
            raise RuntimeError('native AgentStore observation has not produced an acknowledgement')
        raw = self.packet if packet is None else packet
        if type(raw) is not bytes:
            self.finished = True
            raise TypeError('native AgentStore packet must be exact bytes')
        self.pending = False
        self.prepared = False
        try:
            # The immutable bytes object stays strongly referenced for the
            # complete synchronous native call. HIA has a read-only parameter.
            status = self.image._entry(raw, len(raw), self.output, len(self.output),
                                       self.workspace, len(self.workspace))
        except BaseException:
            self.finished = True
            raise
        if status == 1:
            self.pending = True
        else:
            self.finished = True
        return status

    def _dict_api(self):
        if self._dict_operations is None:
            self._dict_operations = _dict_primitives()
        return self._dict_operations

    def observe(self):
        if self.finished or not self.pending:
            raise RuntimeError('native AgentStore has no unconsumed foreign observation')
        # Consume before an effect. A failed SQL/callback can never be retried
        # implicitly by asking observe() again or by running a finally stage.
        self.pending = False
        try:
            self.packet = self._observe()
        except BaseException:
            self.finished = True
            raise
        self.prepared = True
        return self.packet

    def _observe(self):
        from . import hia_agent_store as m
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        a, b, c, d = struct.unpack_from('<4Q', self.workspace, 200)
        reg, value = self.observer.register, self.observer.value
        x = y = z = t = 0
        payload = b''
        if opcode == 1:
            x, y, z, t = self.observer.summary(a)
        elif opcode == 2:
            x = self.observer.child(a, b, d)
        elif opcode in (3, 4):
            observe = self.observer.points if opcode == 3 else self.observer.limbs
            words = observe(a, b, c)
            x = len(words)
            payload = struct.pack('<' + 'I' * x, *words)
        elif opcode == 5:
            x = reg(value(a)[value(b)])
        elif opcode == 7:
            x = reg(getattr(value(a), value(b)))
        elif opcode == 16:
            reject = value(c) if c else m.reject
            reject(value(a), value(b))
        elif opcode == 20:
            # The shared HIA equality walker requests rich comparison only at
            # opaque foreign leaves. Builtin graphs and scalars remain HIA.
            x = reg(value(a) != value(b) if c else value(a) == value(b))
        elif opcode == 21:
            x = int(bool(value(a)))
        elif opcode == 31:
            _, lookup, _ = self._dict_api()
            pointer = lookup(value(a), value(b), ctypes.c_ssize_t(c).value)
            x = int(bool(pointer))
            if pointer:
                y = reg(ctypes.cast(pointer, ctypes.py_object).value)
        elif opcode == 33:
            x = reg(value(a) + value(b))
        elif opcode == 34:
            next_item, _, has_hash = self._dict_api()
            position = ctypes.c_ssize_t(b)
            key, item, stored_hash = ctypes.py_object(), ctypes.py_object(), ctypes.c_ssize_t()
            arguments = (value(a), ctypes.byref(position), ctypes.byref(key), ctypes.byref(item))
            x = int(next_item(*arguments, ctypes.byref(stored_hash)) if has_hash else next_item(*arguments))
            if x:
                key_value, item_value = key.value, item.value
                if not has_hash:
                    stored_hash.value = _pure_builtin_key_hash(key_value)
                y, z = reg(key_value), reg(item_value)
            t = position.value
            payload = struct.pack('<Q', stored_hash.value & ((1 << 64) - 1))
        elif opcode == 35:
            x = sys.getrecursionlimit()
        elif opcode == 36:
            grown = _private_zeroed_buffer(a)
            ctypes.memmove(grown, self.workspace, len(self.workspace))
            self.workspace = grown
        elif opcode == 37:
            raise RecursionError('maximum recursion depth exceeded in comparison')
        elif opcode == 40:
            x = reg({})
        elif opcode == 41:
            value(a)[value(b)] = value(c)
            x = reg(None)
        elif opcode == 42:
            # Explicit retained schema-admission owner; its set/hash/foreign
            # key semantics are not relabelled as HIA reference authority.
            m.keys(value(a), ('id', 'sha256', 'uri'), label='artifact reference')
            x = reg(None)
        elif opcode == 43:
            execute = value(c) if c else self.store.db.execute
            x = reg(execute(value(a), value(b)).fetchone())
        elif opcode == 44:
            x = reg(self.store._ref(value(a)))
        elif opcode == 45:
            operation = value(a)
            function, root = value(d) if d else (m._native_artifact_file, self.store.artifacts)
            if operation == 'store-get':
                x = reg(function(operation, root, content_hash=value(b)))
            else:
                x = reg(function(operation, root, data=value(b), _admission=value(c)))
        elif opcode == 46:
            function, root = value(b) if b else (m.stable_read, self.store.artifacts)
            x = reg(function(root / value(a), m.MAX_ARTIFACT_BYTES))
        elif opcode == 47:
            x = reg(m.sha256(value(a)).hexdigest())
        elif opcode == 48:
            decoder = value(b) if b else m.decode_data
            x = reg(decoder(value(a)))
        elif opcode == 49:
            x = reg(self.store.get(value(a)))
        elif opcode == 50:
            x = reg(self.store.json(value(a), value(b)))
        elif opcode == 51:
            x = reg(value(a))
        elif opcode == 52:
            x = reg(m.wire(value(a)))
        elif opcode == 53:
            x = reg(value(a).decode())
        elif opcode == 54:
            execute = value(c) if c else self.store.db.execute
            x = reg(execute(value(a), value(b)))
        elif opcode == 55:
            get_json = value(c) if c else self.store.get_json
            x = reg(get_json(value(a), kind=value(b)))
        elif opcode == 56:
            x = reg(value(a)[b])
        elif opcode == 57:
            observed = value(a)
            x = int(type(observed) is bytes)
            y = len(observed) if x else 0
        elif opcode == 58:
            x = reg(m._native_artifact_admission())
        elif opcode == 59:
            x = reg(m.digest(value(a)))
        elif opcode == 60:
            x = reg(_retained_publish_file(self.store, value(a), value(b)))
        elif opcode == 61:
            x = reg(self.store.get(value(a), kind=value(b)))
        elif opcode == 62:
            x = reg(m.uuid.uuid4())
        elif opcode == 63:
            x = reg(self.store.db.execute)
        elif opcode == 64:
            x = reg(m._native_artifact_file)
            y = reg(self.store.artifacts)
        elif opcode == 65:
            x = reg(m.stable_read)
            y = reg(self.store.artifacts)
        elif opcode == 66:
            x = reg(m.decode_data)
        elif opcode == 67:
            x = reg(m.reject)
        elif opcode == 68:
            x = reg(self.store.get_json)
        else:
            raise RuntimeError('unknown HIA AgentStore foreign instruction')
        return struct.pack('<8Q', MAGIC, sequence, opcode, 0, x, y, z, t) + payload

    def run(self):
        while True:
            status = self.step()
            if status == 1:
                self.observe()
            elif status == 2:
                handle, = struct.unpack_from('<Q', self.workspace, 96)
                return self.observer.value(handle)
            else:
                raise RuntimeError('HIA AgentStore continuation refused its protocol')


class NativeAgentStoreAuthority(NativeHiaJsonImage):
    def run(self, store, mode, argument=None, second=None, third=None):
        return StoreAuthoritySession(self, store, mode, argument, second, third).run()


def installed_agent_store_authority(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentStoreAuthority)
