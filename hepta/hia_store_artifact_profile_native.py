"""HIA-owned Store artifact/profile policies with hosted opaque-object effects.

Literal calls preserve actual method binding before arguments. HIA owns policy,
reference iteration, argument continuations and cleanup order. Filesystem,
SQLite, hash, JSON and object protocols remain foreign. The separate transaction
context manager is unchanged. Causal loss custody here covers this owner only.
"""
from __future__ import annotations
from contextvars import ContextVar
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import threading
import types

from .hia_store_artifact_profile_protocol import MODES, ARGUMENT_MODES, PORT, PORTS
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_store_lifecycle_native import _regular_bytes

SOURCE = _source_resource_path('examples/hia_bootstrap/store_artifact_profile.hepta')
SCHEMA = 'hepta.hia.store-artifact-profile.v1'
SELECTOR = 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HSAPRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSAPRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HSAPST01', 'little')
STATE_BYTES, OUTPUT_BYTES = 128, 96
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)
_ACTIVE_FOREIGN_CALL = ContextVar('hia_store_artifact_profile_foreign_call', default=None)


class StoreArtifactProfileUnknown(RuntimeError):
    """An actual native observation is unconfirmed; this frame cannot retry."""


class _ForeignStoreCall:
    def __init__(self, frame):
        self.frame, self.active = frame, False

    def __enter__(self):
        self.active = True
        self.token = _ACTIVE_FOREIGN_CALL.set(self)

    def __exit__(self, kind, error, traceback):
        self.active = False
        _ACTIVE_FOREIGN_CALL.reset(self.token)
        return False


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise StoreArtifactProfileUnknown('Store artifact custody belongs to its creator process')
    return _CUSTODY_LOCK


class NativeStoreArtifactProfile(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_store(raw, digest, source_digest):
    image = NativeStoreArtifactProfile(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_store_artifact_profile(manifest_path):
    if not manifest_path:
        raise ValueError('Store artifact selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeStoreArtifactProfile)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid Store artifact manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('Store artifact image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('Store artifact source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('Store artifact image identity mismatch')
    if selected is None:
        selected = _mapped_store(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeStoreArtifactProfile or selected.image_sha256 != value['image_sha256']:
        raise ValueError('Store artifact selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('Store artifact selection changed during admission')
    return selected


def _global_value(namespace, builtins, name):
    try:
        value = namespace[name]
    except KeyError:
        pass
    else:
        return value
    try:
        value = builtins[name]
    except KeyError:
        pass
    else:
        return value
    raise NameError("name '" + name + "' is not defined", name=name)


_MISSING_SPECIAL = object()
_TYPE_MRO = type.__dict__['__mro__']
_TYPE_DICTIONARY = type.__dict__['__dict__']
_TYPE_NAME = type.__dict__['__name__']


def _class_special(kind, name):
    for base in _TYPE_MRO.__get__(kind, type(kind)):
        members = _TYPE_DICTIONARY.__get__(base, type(base))
        if name in members:
            return members[name]
    return _MISSING_SPECIAL


def _bind_special_descriptor(descriptor, instance, owner):
    """Hosted special-method descriptor ABI, without Store policy decisions."""
    kind = type(descriptor)
    getter = _class_special(kind, '__get__')
    if getter is _MISSING_SPECIAL:
        return descriptor
    if (kind is types.FunctionType or kind is types.MethodDescriptorType or kind is types.WrapperDescriptorType
            or kind is types.GetSetDescriptorType or kind is types.MemberDescriptorType
            or kind is staticmethod or kind is classmethod or kind is property):
        return getter(descriptor, instance, owner)
    bound_getter = _bind_special_descriptor(getter, descriptor, kind)
    return bound_getter(instance, owner)


def _context_special(manager, name):
    kind = type(manager)
    descriptor = _class_special(kind, name)
    if descriptor is _MISSING_SPECIAL:
        suffix = ' (missed __exit__ method)' if name == '__exit__' else ''
        raise TypeError("'" + _TYPE_NAME.__get__(kind, type(kind))
                        + "' object does not support the context manager protocol" + suffix)
    return _bind_special_descriptor(descriptor, manager, kind)


@lru_cache(maxsize=1)
def _runtime_context_lookup_order():
    """Observe private with-protocol facts without a version threshold."""
    order = []

    class Special:
        def __init__(self, tag, value):
            self.tag, self.value = tag, value

        def __get__(self, instance, owner):
            order.append(self.tag)
            return self.value

    class Probe:
        __enter__ = Special(1, lambda: None)
        __exit__ = Special(2, lambda kind, error, traceback: False)

    with Probe():
        pass
    return tuple(order)


# Literal expressions bind methods/providers before HIA-owned argument calls.
# They do not catch provider StopIteration or retain an aborted suspension.
def _literal_json_put(store, kind, metadata, argument):
    return store.put(argument(), kind, metadata)


def _literal_artifact_insert(store, argument):
    return store.db.execute('INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)', argument())


def _literal_profile_insert(store, argument):
    return store.db.execute('INSERT OR IGNORE INTO profiles VALUES (?,?,?)', argument())


def _literal_native_get(provider, store, argument):
    return provider('store-get', store.artifacts, content_hash=argument())


def _literal_fallback_read(provider, argument, limit):
    return provider(argument(), limit())


def _literal_stream_fsync(os_provider, argument):
    return os_provider.fsync(argument())


def _literal_check_get_json(store, argument):
    return store.get_json(argument(), kind='profile')


@dataclass(frozen=True)
class StoreArtifactProfileReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int


class StoreArtifactProfileFrame:
    def __init__(self, image, mode, store, arguments, *, namespace=None):
        if type(image) is not NativeStoreArtifactProfile:
            raise TypeError('Store artifact owner requires an admitted image')
        if type(mode) is not int or mode not in (*MODES.values(), *ARGUMENT_MODES.values()):
            raise ValueError('Store artifact owner requires an original method or argument mode')
        from . import hia_agent_store
        if namespace is None:
            namespace = vars(hia_agent_store)
        self.image, self.mode, self.store, self.namespace = image, mode, store, namespace
        self.global_builtins = hia_agent_store._STORE_ARTIFACT_PROFILE_BUILTINS
        self.context_lookup_order = _runtime_context_lookup_order()
        self.data = {'arguments': arguments}
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
        parent = _ACTIVE_FOREIGN_CALL.get()
        self.parent_scope = parent if (parent is not None and parent.active
            and parent.frame.creator == self.creator and parent.frame.thread == self.thread) else None
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = self.finished = self.unconfirmed = self.native_failed = False
        self.effect_started = False
        with _custody_lock():
            _FRAME_CUSTODY[id(self)] = self
        try:
            self.call(0)
        except BaseException:
            self._release()
            raise

    def _release(self):
        with _custody_lock():
            _FRAME_CUSTODY.pop(id(self), None)

    def _propagate_native_loss(self):
        scope = self.parent_scope
        while scope is not None and scope.active:
            parent = scope.frame
            parent.fenced = parent.native_failed = True
            parent.unconfirmed = parent.effect_started
            scope = parent.parent_scope

    def call(self, event, observation=0):
        if self.fenced or self.finished or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise StoreArtifactProfileUnknown('Store artifact frame cannot be resumed or inherited')
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, self.mode,
                              *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16):
                raise StoreArtifactProfileUnknown('Store artifact continuation return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw)
            expected_sequence = 1 if event == 0 else sequence if event == 1 else sequence + 1
            expected_phases = (1, 4, 5, 7) if event == 2 else (2,) if event == 1 else (1, 5) if event == 3 else (1,)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or state[8] > 7 or state[9] != 0 or state[11] > 3 or state[13] > 1
                    or state[14:16] != (0, 0)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != int(words[4] == 5)
                    or (event == 1 and words[2] != port)
                    or (words[4] in (4, 5) and (words[2] != 0 or state[8] != 0))
                    or (words[4] in (1, 2, 7) and not 1 <= words[2] <= len(PORTS))):
                raise StoreArtifactProfileUnknown('Store artifact receipt differs from issued state')
            self.receipt = StoreArtifactProfileReceipt(*words[2:7])
            return self.receipt
        except BaseException as error:
            self.fenced = self.native_failed = True
            self.unconfirmed = self.effect_started
            self._propagate_native_loss()
            if isinstance(error, Exception) and (
                    not isinstance(error, RuntimeError) or isinstance(error, _REQUEST_REJECTIONS)):
                raise StoreArtifactProfileUnknown('Store artifact continuation observation failed') from error
            raise

    def _confirmed_foreign_failure(self):
        if self.receipt.phase != 5:
            self.fenced = True
            raise StoreArtifactProfileUnknown('Store artifact exception was not confirmed')
        self.finished, self.unconfirmed = True, False
        self._release()

    def _exception_continuation(self):
        """Perform HIA-issued cleanup inside the active original handler.

Nested finally failures enter another handler, retaining replacement exception
context. The image marks cleanup as claimed before execution, so ACK loss never
causes a repeated close, unlink, or exit.
        """
        while self.receipt.phase == 1:
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                with _ForeignStoreCall(self):
                    observed = self.effect(self.receipt.port)
            except BaseException:
                if self.native_failed:
                    self.fenced = self.unconfirmed = True
                    raise
                self.data['exception'] = sys.exc_info()
                self.call(3)
                self.unconfirmed = False
                if self.receipt.phase == 5:
                    self._confirmed_foreign_failure()
                    raise
                self._exception_continuation()
                return
            self.call(2, observed)
            self.unconfirmed = False
        if self.receipt.phase == 7:
            return
        self._confirmed_foreign_failure()
        raise

    def finish(self):
        if self.finished:
            raise StoreArtifactProfileUnknown('Store artifact frame already completed')
        while True:
            if self.receipt.phase not in (1, 7):
                self.fenced = True
                raise StoreArtifactProfileUnknown('Store artifact effect is not newly issued')
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                with _ForeignStoreCall(self):
                    observed = self.effect(self.receipt.port)
            except BaseException:
                if self.native_failed:
                    self.fenced = self.unconfirmed = True
                    raise
                self.data['exception'] = sys.exc_info()
                self.call(3)
                self.unconfirmed = False
                if self.receipt.phase == 5:
                    self._confirmed_foreign_failure()
                    raise
                self._exception_continuation()
                self.data.pop('exception')
                continue
            self.call(2, observed)
            self.unconfirmed = False
            if self.receipt.phase == 4:
                self.finished = True
                self._release()
                return self.data['result']

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def argument(self, name):
        child = StoreArtifactProfileFrame(self.image, ARGUMENT_MODES[name], self.store,
                                          (self.data,), namespace=self.namespace)
        return child.finish()

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != 2 or self.receipt.port != port
                or not 1 <= port <= len(PORTS)):
            raise StoreArtifactProfileUnknown('Store artifact effect has no matching claim')
        name = PORTS[port - 1]
        d, s = self.data, self.store
        if name == 'put_arguments':
            d['data'], d['kind'], d['metadata'] = d['arguments']
            d['native_hash'] = None
        elif name == 'put_data_not_bytes':
            return int(self._global('type')(d['data']) is not self._global('bytes'))
        elif name == 'put_data_limit_exceeded':
            # Original global binding and opaque rich comparison stay hosted;
            # HIA chooses the rejection branch from this single truth fact.
            return int(bool(self._global('len')(d['data']) > self._global('MAX_ARTIFACT_BYTES')))
        elif name == 'put_metadata_is_none':
            return int(d['metadata'] is None)
        elif name == 'put_empty_metadata':
            d['metadata'] = {}
        elif name == 'put_admission':
            d['admission'] = self._global('_native_artifact_admission')()
        elif name == 'put_admission_is_none':
            return int(d['admission'] is None)
        elif name == 'put_native_hash':
            d['native_hash'] = self._global('_native_artifact_file')(
                'store-hash', s.artifacts, data=d['data'], _admission=d['admission'])
        elif name == 'put_native_hash_is_none':
            return int(d['native_hash'] is None)
        elif name == 'put_native_content_hash':
            d['content_hash'] = d['native_hash']['sha256']
        elif name == 'put_python_hash':
            d['content_hash'] = self._global('sha256')(d['data']).hexdigest()
        elif name == 'put_content_key':
            d['content_key'] = self._global('digest')({
                'sha256': d['content_hash'], 'kind': d['kind'], 'metadata': d['metadata']})
        elif name == 'put_find_previous':
            d['cursor'] = s.db.execute('SELECT * FROM artifacts WHERE content_key=?', (d['content_key'],))
        elif name == 'put_previous_row':
            d['previous'] = d.pop('cursor').fetchone()
        elif name == 'put_previous_is_none':
            return int(d['previous'] is None)
        elif name == 'put_previous_ref':
            d['ref'] = s._ref(d['previous'])
        elif name == 'put_previous_verify':
            s.get(d['ref'], kind=d['kind'])
        elif name == 'put_previous_result':
            d['result'] = d['ref']
        elif name == 'put_hash_is_none_for_write':
            return int(d['native_hash'] is None)
        elif name == 'put_native_put':
            d['stored'] = self._global('_native_artifact_file')(
                'store-put', s.artifacts, data=d['data'], _admission=d['admission'])
        elif name == 'put_native_receipt_differs':
            return int(bool(d['stored'] != d['native_hash']))
        elif name == 'put_destination':
            d['destination'] = s.artifacts / d['content_hash']
        elif name == 'put_temporary':
            d['temporary'] = s.artifacts / self.argument('temporary_name')
        elif name == 'put_open_temporary':
            d['descriptor'] = self._global('os').open(d['temporary'],
                self._global('os').O_WRONLY | self._global('os').O_CREAT | self._global('os').O_EXCL
                | self._global('os').O_CLOEXEC | self._global('os').O_NOFOLLOW, 0o400)
        elif name == 'put_fdopen':
            d['manager'] = self._global('os').fdopen(d['descriptor'], 'wb')
        elif name == 'put_context_lookup_init':
            d['context_lookup'] = iter(self.context_lookup_order)
        elif name == 'put_context_lookup_next':
            try:
                return next(d['context_lookup'])
            except StopIteration:
                d.pop('context_lookup')
                d.pop('manager')
                return 0
        elif name == 'put_context_lookup_enter':
            d['enter'] = _context_special(d['manager'], '__enter__')
        elif name == 'put_context_lookup_exit':
            d['exit'] = _context_special(d['manager'], '__exit__')
        elif name == 'put_enter':
            d['stream'] = d.pop('enter')()
        elif name == 'put_stream_write':
            d['stream'].write(d['data'])
        elif name == 'put_stream_flush':
            d['stream'].flush()
        elif name == 'put_stream_fsync':
            _literal_stream_fsync(self._global('os'), lambda: self.argument('stream_descriptor'))
        elif name == 'put_exit_normal':
            d.pop('exit')(None, None, None)
        elif name == 'put_link':
            self._global('os').link(d['temporary'], d['destination'], follow_symlinks=False)
        elif name == 'put_open_directory':
            d['directory_fd'] = self._global('os').open(s.artifacts,
                self._global('os').O_RDONLY | self._global('os').O_DIRECTORY | self._global('os').O_CLOEXEC)
        elif name == 'put_fsync_directory':
            self._global('os').fsync(d['directory_fd'])
        elif name in ('put_close_directory', 'error_cleanup_close'):
            self._global('os').close(d['directory_fd'])
        elif name in ('put_unlink_temporary', 'error_cleanup_unlink'):
            d['temporary'].unlink(missing_ok=True)
        elif name == 'put_id_uuid':
            d['uuid'] = self._global('uuid').uuid4()
        elif name == 'put_id_hex':
            d['id_hex'] = d.pop('uuid').hex
        elif name == 'put_id_value':
            d['id'] = 'a-' + d.pop('id_hex')
        elif name == 'put_uri_uuid':
            d['uuid'] = self._global('uuid').uuid4()
        elif name == 'put_uri_hex':
            d['uri_hex'] = d.pop('uuid').hex
        elif name == 'put_uri_value':
            d['uri'] = 'hia://artifacts/' + d.pop('uri_hex')
        elif name == 'put_ref_construct':
            d['ref'] = {'id': d.pop('id'), 'sha256': d['content_hash'], 'uri': d.pop('uri')}
        elif name == 'put_insert':
            _literal_artifact_insert(s, lambda: self.argument('put_insert'))
        elif name == 'put_find_winner':
            d['cursor'] = s.db.execute('SELECT * FROM artifacts WHERE content_key=?', (d['content_key'],))
        elif name == 'put_winner_row':
            d['row'] = d.pop('cursor').fetchone()
        elif name == 'put_winner_ref':
            d['result'] = s._ref(d['row'])
        elif name == 'put_result':
            pass
        elif name == 'json_arguments':
            d['value'], d['kind'], d['metadata'] = d['arguments']
        elif name == 'json_call_put':
            d['result'] = _literal_json_put(s, d['kind'], d['metadata'], lambda: self.argument('json_wire'))
        elif name == 'json_result':
            pass
        elif name == 'ref_arguments':
            d['row'], = d['arguments']
        elif name == 'ref_new':
            d['result'] = {}
        elif name == 'ref_get':
            index = struct.unpack_from('<Q', self.buffer, 88)[0]
            d['ref_name'] = ('id', 'sha256', 'uri')[index]
            d['ref_value'] = d['row'][d['ref_name']]
        elif name == 'ref_set':
            d['result'][d.pop('ref_name')] = d.pop('ref_value')
        elif name == 'ref_result':
            pass
        elif name == 'get_arguments':
            d['ref'], d['kind'] = d['arguments']
        elif name == 'get_validate_keys':
            self._global('keys')(d['ref'], ('id', 'sha256', 'uri'), label='artifact reference')
        elif name == 'get_find':
            d['cursor'] = s.db.execute('SELECT * FROM artifacts WHERE id=?', (d['ref']['id'],))
        elif name == 'get_row':
            d['row'] = d.pop('cursor').fetchone()
        elif name == 'get_row_is_none':
            return int(d['row'] is None)
        elif name == 'get_identity_ref':
            d['identity_ref'] = s._ref(d['row'])
        elif name == 'get_identity_differs':
            return int(bool(d.pop('identity_ref') != d['ref']))
        elif name == 'get_kind_is_none':
            return int(d['kind'] is None)
        elif name == 'get_kind_differs':
            return int(bool(d['row']['kind'] != d['kind']))
        elif name == 'get_native':
            d['data'] = _literal_native_get(self._global('_native_artifact_file'), s,
                                           lambda: self.argument('native_get_hash'))
        elif name == 'get_native_is_none':
            return int(d['data'] is None)
        elif name == 'get_file_read':
            d['data'] = _literal_fallback_read(self._global('stable_read'),
                lambda: self.argument('fallback_path'), lambda: self._global('MAX_ARTIFACT_BYTES'))
        elif name == 'get_content_hash':
            d['content_hash'] = self._global('sha256')(d['data']).hexdigest()
        elif name == 'get_hash_differs':
            return int(bool(d.pop('content_hash') != d['row']['sha256']))
        elif name == 'get_metadata':
            d['metadata'] = self._global('decode_data')(d['row']['metadata'])
        elif name == 'get_result':
            d['result'] = d['data'], d['metadata']
        elif name == 'get_json_arguments':
            d['ref'], d['kind'] = d['arguments']
        elif name == 'get_json_call':
            d['data'], d['metadata'] = s.get(d['ref'], kind=d['kind'])
        elif name == 'get_json_decode':
            d['decoded'] = self._global('decode_data')(d['data'])
        elif name == 'get_json_result':
            d['result'] = d['decoded'], d['metadata']
        elif name == 'resolve_arguments':
            d['uri'], = d['arguments']
        elif name == 'resolve_find':
            d['cursor'] = s.db.execute('SELECT * FROM artifacts WHERE uri=?', (d['uri'],))
        elif name == 'resolve_row':
            d['row'] = d.pop('cursor').fetchone()
        elif name == 'resolve_is_none':
            return int(d['row'] is None)
        elif name == 'resolve_ref':
            d['ref'] = s._ref(d['row'])
        elif name == 'resolve_verify':
            s.get(d['ref'])
        elif name == 'resolve_result':
            d['result'] = d['ref']
        elif name == 'profile_arguments':
            d['identifier'], d['value'] = d['arguments']
        elif name == 'profile_call_json':
            d['ref'] = s.json(d['value'], 'profile')
        elif name == 'profile_sha':
            d['sha'] = d['ref']['sha256']
        elif name == 'profile_construct':
            d['profile'] = {'id': d['identifier'], 'sha256': d.pop('sha')}
        elif name == 'profile_insert':
            _literal_profile_insert(s, lambda: self.argument('profile_insert'))
        elif name == 'profile_result':
            d['result'] = d['profile'], d['ref']
        elif name == 'check_arguments':
            d['ref'], d['expected'] = d['arguments']
        elif name == 'check_differs':
            return int(bool(d['ref'] != d['expected']))
        elif name == 'check_find':
            d['cursor'] = s.db.execute('SELECT artifact FROM profiles WHERE id=? AND sha256=?',
                                      (d['ref']['id'], d['ref']['sha256']))
        elif name == 'check_row':
            d['row'] = d.pop('cursor').fetchone()
        elif name == 'check_is_none':
            return int(d['row'] is None)
        elif name == 'check_call_get_json':
            d['call_result'] = _literal_check_get_json(s, lambda: self.argument('profile_reference'))
        elif name == 'check_result':
            d['result'] = d.pop('call_result')[0]
        elif name == 'exception_is_file_exists':
            return int(isinstance(d['exception'][1], self._global('FileExistsError')))
        elif name == 'put_existing_read':
            d['existing'] = self._global('stable_read')(d['destination'], self._global('MAX_ARTIFACT_BYTES'))
        elif name == 'put_existing_differs':
            return int(bool(d.pop('existing') != d['data']))
        elif name == 'put_exit_exception':
            d['exit_result'] = d.pop('exit')(*d['exception'])
        elif name == 'put_exit_truth':
            return int(bool(d.pop('exit_result')))
        elif name == 'reject_put_limit':
            self._global('reject')('E_HIA_ARTIFACT_LIMIT', 'artifact exceeds the 64 MiB store limit')
        elif name == 'reject_put_native_corrupt':
            self._global('reject')('E_HIA_ARTIFACT_CORRUPT', 'native artifact hash and durable file receipt differ')
        elif name == 'reject_put_existing_corrupt':
            self._global('reject')('E_HIA_ARTIFACT_CORRUPT', 'stored content does not match its immutable identity')
        elif name == 'reject_get_identity':
            self._global('reject')('E_HIA_ARTIFACT_IDENTITY', 'artifact reference was not issued in this runtime namespace')
        elif name == 'reject_get_kind':
            self._global('reject')('E_HIA_ARTIFACT_AUTHORITY', 'input bytes cannot impersonate a retained ' + d['kind'])
        elif name == 'reject_get_corrupt':
            self._global('reject')('E_HIA_ARTIFACT_CORRUPT', 'artifact bytes no longer match their recorded digest')
        elif name == 'reject_resolve':
            self._global('reject')('E_HIA_ARTIFACT_IDENTITY', 'resource URI was not issued in this runtime namespace')
        elif name == 'reject_profile_stale':
            self._global('reject')('E_HIA_PROFILE_STALE', 'profile is unavailable or differs from the installed implementation')
        elif name == 'reject_profile_authority':
            self._global('reject')('E_HIA_PROFILE_AUTHORITY', 'profile does not resolve to a retained server record')
        elif name == 'argument_parent':
            d['parent'], = d['arguments']
        elif name == 'argument_result':
            pass
        elif name == 'arg_wire_value':
            d['result'] = self._global('wire')(d['parent']['value'])
        elif name == 'arg_temp_uuid':
            d['uuid'] = self._global('uuid').uuid4()
        elif name == 'arg_temp_hex':
            d['hex'] = d.pop('uuid').hex
        elif name == 'arg_temp_name':
            d['result'] = '.write-' + d.pop('hex')
        elif name == 'arg_stream_descriptor':
            d['result'] = d['parent']['stream'].fileno()
        elif name == 'arg_insert_id':
            d['id'] = d['parent']['ref']['id']
        elif name == 'arg_insert_uri':
            d['uri'] = d['parent']['ref']['uri']
        elif name == 'arg_insert_wire':
            d['wire'] = self._global('wire')(d['parent']['metadata'])
        elif name == 'arg_insert_decode':
            d['text'] = d.pop('wire').decode()
        elif name == 'arg_insert_tuple':
            p = d['parent']
            d['result'] = d.pop('id'), p['content_hash'], d.pop('uri'), p['kind'], d.pop('text'), p['content_key']
        elif name == 'arg_native_hash':
            d['result'] = d['parent']['row']['sha256']
        elif name == 'arg_path_root':
            d['root'] = s.artifacts
        elif name == 'arg_path_hash':
            d['hash'] = d['parent']['row']['sha256']
        elif name == 'arg_path_join':
            d['result'] = d.pop('root') / d.pop('hash')
        elif name == 'arg_profile_sha':
            d['sha'] = d['parent']['ref']['sha256']
        elif name == 'arg_profile_wire':
            d['wire'] = self._global('wire')(d['parent']['ref'])
        elif name == 'arg_profile_decode':
            d['text'] = d.pop('wire').decode()
        elif name == 'arg_profile_tuple':
            d['result'] = d['parent']['identifier'], d.pop('sha'), d.pop('text')
        elif name == 'arg_reference_decoder':
            d['decoder'] = self._global('decode_data')
        elif name == 'arg_reference_payload':
            d['payload'] = d['parent']['row']['artifact']
        elif name == 'arg_reference_decode':
            d['result'] = d.pop('decoder')(d.pop('payload'))
        else:
            raise StoreArtifactProfileUnknown('Store artifact issued an unknown primitive')
        return 0
