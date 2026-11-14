"""HIA control for the complete original compile and public emission methods.

The image owns ordered branches, loops, temporary-directory exit and exception
continuations. Core, emitter, linker, filesystem, Store, clock, digest and
opaque Python object protocols remain explicit foreign providers.
"""
from __future__ import annotations
import ctypes
from contextvars import ContextVar
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

from .hia_emission_protocol import PORT, PORTS, MODES
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_store_lifecycle_native import _regular_bytes

SOURCE = _source_resource_path('examples/hia_bootstrap/emission.hepta')
SCHEMA = 'hepta.hia.emission-native.v1'
SELECTOR = 'HEPTA_HIA_EMISSION_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HEMIRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HEMIRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HEMIST01', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 96
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)
_ACTIVE_FOREIGN_CALL = ContextVar('hia_emission_foreign_call', default=None)


class EmissionUnknown(RuntimeError):
    """A native observation is unconfirmed; the frame must not be replayed."""


class _ForeignEmissionCall:
    """Carry causal custody during one issued foreign operation."""
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
        raise EmissionUnknown('native emission custody belongs to its creator process')
    return _CUSTODY_LOCK


class NativeEmission(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_emission(raw, digest, source_digest):
    image = NativeEmission(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_emission(manifest_path):
    if not manifest_path:
        raise ValueError('native emission selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeEmission)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native emission manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native emission image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native emission source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native emission image identity mismatch')
    if selected is None:
        selected = _mapped_emission(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeEmission or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native emission selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native emission selection changed during admission')
    return selected


_MISSING_SPECIAL = object()
_TYPE_MRO = type.__dict__['__mro__']
_TYPE_DICTIONARY = type.__dict__['__dict__']
_TYPE_NAME = type.__dict__['__name__']


def _class_special(kind, name):
    """Read a type's special-method slot without instance or metaclass hooks."""
    for base in _TYPE_MRO.__get__(kind, type(kind)):
        members = _TYPE_DICTIONARY.__get__(base, type(base))
        if name in members:
            return members[name]
    return _MISSING_SPECIAL


def _bind_special_descriptor(descriptor, instance, owner):
    """Apply the descriptor protocol without consulting instance shadows.

The exact built-in descriptor implementations supply the terminating primitive;
custom descriptors bind their own class-defined getter in the same way. In
particular a static or class method used as __get__ retains its binding behavior.
    """
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
    """The ordinary descriptor boundary used by Python's with protocol.

Instance fields do not participate in special-method lookup. Bind the original
class descriptor to the actual manager, not to None through a class access.
This is object interoperation, not an emission/cleanup policy decision.
    """
    kind = type(manager)
    descriptor = _class_special(kind, name)
    if descriptor is _MISSING_SPECIAL:
        suffix = ' (missed __exit__ method)' if name == '__exit__' else ''
        raise TypeError("'" + _TYPE_NAME.__get__(kind, type(kind))
                        + "' object does not support the context manager protocol" + suffix)
    return _bind_special_descriptor(descriptor, manager, kind)


@lru_cache(maxsize=1)
def _runtime_context_lookup_order():
    """Observe this interpreter's with entry on private descriptors only.

HIA consumes the recorded protocol facts and chooses each original user lookup.
There is no Python-version threshold and no user manager participates here.
    """
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


@lru_cache(maxsize=1)
def _runtime_generator_reiterations():
    """Measure the genexpr entry protocol without running any user iterator."""
    class Probe:
        def __init__(self):
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            return self

        def __next__(self):
            raise StopIteration

    probe = Probe()
    generator = (None for _ in probe)
    before = probe.iterations
    try:
        next(generator)
    except StopIteration:
        pass
    return probe.iterations - before


def _unbound_result():
    result = result


def _unbound_data():
    data = data


def _global_value(namespace, builtins, name):
    """Resolve an original provider global with its bound builtins fallback."""
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


@dataclass(frozen=True)
class EmissionReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int
    flags: int


class EmissionFrame:
    def __init__(self, image, mode, service, arguments, *, namespace=None):
        if type(image) is not NativeEmission:
            raise TypeError('native emission requires an admitted image')
        if type(mode) is not int or mode not in (1, 2):
            raise ValueError('native emission requires one original mode')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
        self.global_builtins = hia_agent_service._EMISSION_GLOBAL_BUILTINS
        self.image, self.mode, self.service, self.namespace = image, mode, service, namespace
        self.context_lookup_order = _runtime_context_lookup_order()
        self.generator_reiterations = _runtime_generator_reiterations()
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
            # Growable custody is reserved before effects, with no new quota
            # or service-wide exclusion policy imposed on the original domain.
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
            raise EmissionUnknown('native emission frame cannot be resumed or inherited')
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, self.mode, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16):
                raise EmissionUnknown('native emission continuation return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw)
            expected_sequence = 1 if event == 0 else sequence if event == 1 else sequence + 1
            expected_phases = (1, 4, 5, 7) if event == 2 else (2,) if event == 1 else (1, 5) if event == 3 else (1,)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != state[8] | (state[9] << 8) | (state[11] << 16)
                    or words[10:12] != (0, 0)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != int(words[4] == 5)
                    or (event == 1 and words[2] != port)):
                raise EmissionUnknown('native emission receipt differs from issued state')
            self.receipt = EmissionReceipt(*words[2:8])
            return self.receipt
        except BaseException as error:
            self.fenced = self.native_failed = True
            self.unconfirmed = self.effect_started
            self._propagate_native_loss()
            # RuntimeError identity and BaseException signals retain their
            # original behavior. RuntimeError subclasses also caught by the
            # public request rejection wrapper (notably RecursionError) must
            # still be classified unknown, never a completed foreign refusal.
            if isinstance(error, Exception) and (
                    not isinstance(error, RuntimeError) or isinstance(error, _REQUEST_REJECTIONS)):
                raise EmissionUnknown('native emission continuation observation failed') from error
            raise

    def _confirmed_foreign_failure(self):
        if self.receipt.phase != 5:
            self.fenced = True
            raise EmissionUnknown('native emission exception was not confirmed')
        self.finished, self.unconfirmed = True, False
        self._release()

    def _exception_continuation(self):
        """Drive only native-issued cleanup while the original except is active.

Keeping this call inside that except preserves sys.exception(), replacement
exception context, and a bare reraising of the original provider exception.
The image alone chooses suppression, propagation, and the next effect.
        """
        while self.receipt.phase == 1:
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                with _ForeignEmissionCall(self):
                    observed = self.effect(self.receipt.port)
            except BaseException:
                if self.native_failed:
                    self.fenced = self.unconfirmed = True
                    raise
                self.data['exception'] = sys.exc_info()
                self.call(3)
                self._confirmed_foreign_failure()
                raise
            self.call(2, observed)
            self.unconfirmed = False
        if self.receipt.phase == 7:
            return
        self._confirmed_foreign_failure()
        raise

    def finish(self):
        if self.finished:
            raise EmissionUnknown('native emission frame already completed')
        while True:
            if self.receipt.phase not in (1, 7):
                self.fenced = True
                raise EmissionUnknown('native emission effect is not newly issued')
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                with _ForeignEmissionCall(self):
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
                # Leaving the except suite restores the original exception
                # context before a suppressed-error continuation resumes.
                continue
            self.call(2, observed)
            self.unconfirmed = False
            if self.receipt.phase == 4:
                self.finished = True
                self._release()
                return self.data['result']

    def _next(self, iterator, target):
        try:
            self.data[target] = next(self.data[iterator])
        except StopIteration:
            return 0
        return 1

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def effect(self, port):
        """Perform one fixed foreign operation; HIA chooses its continuation."""
        if not 1 <= port <= len(PORTS):
            raise EmissionUnknown('native emission issued an unknown port')
        name = PORTS[port - 1]
        d, s = self.data, self.service
        if name == 'compile_arguments':
            (d['program'], d['kind'], d['machine_plan'], d['timeout_ms'],
             d['foreign_buffer_exports']) = d['arguments']
            from .hia_program_native import emit_program_machine, compile_program_machine
            d['emitter'], d['compiler'] = emit_program_machine, compile_program_machine
        elif name == 'compile_budget_expired':
            return int(bool(d['timeout_ms'] <= 0))
        elif name == 'compile_deadline':
            d['deadline'] = self._global('time').monotonic() + d['timeout_ms'] / 1000
        elif name == 'compile_emit':
            d['image'] = d['emitter'](d['program'], machine_plan=d['machine_plan'],
                                     foreign_buffer_exports=d['foreign_buffer_exports'])
        elif name == 'compile_object_not_bytes':
            d['object_bytes'] = d['image'].object_bytes
            return int(type(d['object_bytes']) is not bytes)
        elif name == 'compile_temporary':
            d['commands'] = []
            d['manager'] = self._global('tempfile').TemporaryDirectory(prefix='build-', dir=s.store.root)
            d['context_lookup_iterator'] = iter(self.context_lookup_order)
        elif name == 'compile_context_lookup_next':
            return next(d['context_lookup_iterator'], 0)
        elif name == 'compile_context_lookup_enter':
            d['enter'] = _context_special(d['manager'], '__enter__')
        elif name == 'compile_context_lookup_exit':
            d['exit'] = _context_special(d['manager'], '__exit__')
        elif name == 'compile_enter':
            del d['context_lookup_iterator']
            d['directory'] = d['enter']()
        elif name == 'compile_output_prefix':
            d['output_prefix'] = self._global('Path')(d['directory'])
        elif name == 'compile_kind_object':
            return int(bool(d['kind'] == 'object'))
        elif name == 'compile_output_object':
            d['output'] = d['output_prefix'] / 'program.o'
        elif name == 'compile_output_shared':
            d['output'] = d['output_prefix'] / 'program.so'
        elif name == 'compile_remaining':
            d['remaining'] = d['deadline'] - self._global('time').monotonic()
        elif name == 'compile_remaining_positive':
            return int(bool(d['remaining'] > 0))
        elif name == 'compile_timeout_zero':
            d['timeout_seconds'] = 0
        elif name == 'compile_timeout_remaining':
            d['timeout_seconds'] = d['remaining']
        elif name == 'compile_timeout_below_bound':
            return int(bool(d['timeout_seconds'] < 3600))
        elif name == 'compile_timeout_bound':
            d['timeout_seconds'] = 3600
        elif name == 'compile_call':
            d['build_result'] = d['compiler'](d['image'], program=d['program'], output=d['output'], kind=d['kind'],
                linker='ld', command_log=d['commands'], machine_plan=d['machine_plan'], parent_death_guard=True,
                timeout_seconds=d['timeout_seconds'])
        elif name == 'compile_read':
            d['data'] = d['output'].read_bytes()
        elif name == 'compile_exit_normal':
            d['exit'](None, None, None)
        elif name == 'compile_exit_exception':
            d['exit_outcome'] = d['exit'](*d['exception'])
        elif name == 'compile_exit_truth':
            return int(bool(d['exit_outcome']))
        elif name == 'compile_pop_output':
            d['build_result'].pop('output', None)
        elif name == 'compile_commands':
            d['build_result']['commands'] = d['commands']
        elif name == 'compile_object_digest_differs':
            return int(bool(d['build_result'].get('object_sha256') != self._global('sha256')(d['object_bytes']).hexdigest()))
        elif name == 'compile_core_digest_differs':
            return int(bool(d['build_result'].get('core_sha256') != d['program'].sha256))
        elif name == 'compile_artifact_digest_value':
            d['artifact_digest'] = d['build_result'].get('artifact_sha256')
            # The callable lookup precedes loading data. A suppressed read
            # failure must not mask an earlier missing provider global.
            d['artifact_hasher'] = self._global('sha256')
        elif name == 'compile_artifact_digest_differs':
            return int(bool(d['artifact_digest'] != d['artifact_hasher'](d['data']).hexdigest()))
        elif name == 'compile_final_kind_object':
            return int(bool(d['kind'] == 'object'))
        elif name == 'compile_final_bytes_differs':
            return int(bool(d['data'] != d['object_bytes']))
        elif name == 'compile_store_object':
            d['build_result']['object_artifact'] = s.store.put(d['object_bytes'], 'build-object', {
                'schema': 'hepta.hia.agent.build-object.v1', 'core_sha256': d['program'].sha256,
                'machine_plan_sha256': d['build_result']['machine_plan_sha256'], 'installation': s.identities})
        elif name == 'compile_result':
            d['result'] = (d['data'], d['build_result'])
        elif name == 'reject_budget':
            self._global('reject')('E_HIA_BUDGET', 'frozen context deadline expired before emission', 'codegen')
        elif name == 'reject_object_bytes':
            self._global('reject')('E_HIA_RECEIPT_BINDING', 'emission did not produce immutable object bytes', 'codegen')
        elif name == 'reject_build':
            self._global('reject')('E_HIA_RECEIPT_BINDING', 'native build metadata differs from the actual emitted bytes', 'codegen')
        elif name == 'unbound_compile_result':
            _unbound_result()
        elif name == 'unbound_compile_data':
            _unbound_data()
        elif name == 'emit_arguments_profile':
            d['args'], = d['arguments']
            s._profile(d['args']['backend_profile'], 'backend')
        elif name == 'emit_context':
            d['context'] = s._context(d['args']['context'])
        elif name == 'emit_program':
            d['program'] = s._program(d['args']['candidate'])
        elif name == 'emit_receipts_init':
            d['verification_receipts'] = iter(d['args']['verification_receipts'])
        elif name == 'emit_receipt_next':
            return self._next('verification_receipts', 'verification_ref')
        elif name == 'emit_verify_receipt':
            s._verification(d['verification_ref'], d['args']['context'], d['args']['candidate'])
        elif name == 'emit_receipts_release':
            del d['verification_receipts']
        elif name == 'emit_codegen':
            d['codegen'], d['plan'] = d['args']['codegen'], None
        elif name == 'emit_canonical':
            return int(bool(d['codegen']['kind'] == 'canonical'))
        elif name == 'emit_lowering_profile':
            s._profile(d['codegen']['lowering_profile'], 'lowering')
        elif name == 'emit_plan_profile':
            s._profile(d['codegen']['plan_profile'], 'plan')
        elif name == 'emit_plan_get':
            d['plan'], d['plan_metadata'] = s.store.get_json(d['codegen']['plan'])
        elif name == 'emit_plan_validate':
            self._global('validate')(d['plan'], self._global('PLAN_SCHEMA'), 'machine_plan')
        elif name == 'emit_plan_verify':
            d['verification'] = s._verification(d['codegen']['verification_receipt'], d['args']['context'], d['args']['candidate'])
        elif name == 'emit_expected_subject':
            d['expected_subject'] = {'kind': 'agent_machine_plan', 'backend_profile': d['args']['backend_profile'],
                'plan_profile': d['codegen']['plan_profile'], 'plan': d['codegen']['plan']}
        elif name == 'emit_subject_differs':
            return int(bool(d['verification']['subject'] != d['expected_subject']))
        elif name == 'emit_checks_init':
            d['checks'] = iter(d['verification']['checks'])
            d['checks_initial'] = d['checks']
            return self.generator_reiterations
        elif name == 'emit_checks_reiterate':
            try:
                d['checks'] = iter(d['checks'])
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'emit_check_next':
            return self._next('checks', 'check')
        elif name == 'emit_claim_compare':
            try:
                d['check_comparison'] = d['check']['claim'] == 'lowering_refinement'
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'emit_claim_truth':
            try:
                return int(bool(d['check_comparison']))
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'emit_status_compare':
            try:
                d['check_comparison'] = d['check']['status'] == 'proved'
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'emit_check_truth':
            try:
                return int(bool(d['check_comparison']))
            finally:
                del d['check_comparison']
        elif name in ('emit_checks_release_pass', 'emit_checks_release_reject'):
            del d['checks_initial']
            del d['checks']
            d.pop('check', None)
        elif name == 'reject_plan':
            self._global('reject')('E_HIA_PLAN_RECEIPT', 'plan lacks an exact subject-bound qualified layout receipt', 'codegen')
        elif name == 'emit_exports_init':
            d['exports_iterator'] = iter(map(tuple, d['context'].get('foreign_buffer_exports', [])))
            d['export_pairs'] = []
        elif name == 'emit_exports_next':
            return self._next('exports_iterator', 'export_pair')
        elif name == 'emit_exports_append':
            d['export_pairs'].append(d['export_pair'])
        elif name == 'emit_exports_finish':
            d['exports'] = tuple(d['export_pairs'])
            del d['exports_iterator']
            del d['export_pairs']
            d.pop('export_pair', None)
        elif name == 'emit_compile_function':
            d['compile_function'] = s._compile
        elif name == 'emit_compile_arguments':
            d['output_kind'] = d['args']['output_kind']
            d['remaining_ms'] = s._remaining_ms(d['context'])
        elif name == 'emit_exports_present':
            return int(bool(d['exports']))
        elif name == 'emit_compile_with_exports':
            d['data'], d['native_build'] = d['compile_function'](d['program'], d['output_kind'], d['plan'],
                d['remaining_ms'], foreign_buffer_exports=d['exports'])
        elif name == 'emit_compile_without_exports':
            d['data'], d['native_build'] = d['compile_function'](d['program'], d['output_kind'], d['plan'], d['remaining_ms'])
        elif name == 'emit_metadata_prefix':
            d['metadata'] = {'context': d['args']['context'], 'candidate': d['args']['candidate'],
                'core_sha256': d['program'].sha256, 'output_kind': d['args']['output_kind'], 'codegen': d['codegen'],
                'machine_plan': d['plan'], 'installation': s.identities, 'signatures': self._global('_signatures')(d['program'], d['exports'])}
        elif name == 'emit_export_lists_init':
            d['export_list_pairs'] = iter(d['exports'])
            d['export_lists'] = []
        elif name == 'emit_export_lists_next':
            return self._next('export_list_pairs', 'export_pair')
        elif name == 'emit_export_lists_append':
            d['export_lists'].append(list(d['export_pair']))
        elif name == 'emit_export_lists_release':
            del d['export_list_pairs']
            d.pop('export_pair', None)
        elif name == 'emit_metadata_finish':
            d['metadata']['foreign_buffer_exports'] = d['export_lists']
            d['metadata']['object_artifact'] = d['native_build']['object_artifact']
            d['metadata']['object_sha256'] = d['native_build']['object_sha256']
        elif name == 'emit_native_put':
            d['artifact'] = s.store.put(d['data'], 'native', d['metadata'])
        elif name == 'emit_receipt_put':
            d['receipt'] = s.store.json({'schema': 'hepta.hia.agent.build.v1', **d['metadata'],
                'native_artifact': d['artifact'], 'native_build': d['native_build'],
                'backend_profile': d['args']['backend_profile'], 'target_profile': d['context']['target_profile'],
                'verification_receipts': d['args']['verification_receipts']}, 'build-receipt')
        elif name == 'emit_result':
            d['result'] = {'candidate': d['args']['candidate'], 'native_artifact': d['artifact'], 'build_receipt': d['receipt'],
                'backend_profile': d['args']['backend_profile'], 'target_profile': d['context']['target_profile'],
                'codegen_backend': 'hia-direct', 'llvm_codegen_used': False, 'external_assembler_used': False,
                'linker_used': d['args']['output_kind'] == 'shared', 'native_execution_observed': False, 'adopted': False}
        else:
            raise EmissionUnknown('native emission port has no foreign operation')
        return 0

