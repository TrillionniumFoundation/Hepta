"""HIA-owned signature, native-artifact and exact build-receipt admission.

The image owns the four original control flows, including every ordered short
circuit and loop. Python carries opaque objects and exposes the original Core,
ABI, Store, SHA-256 and individual object operations. Those providers remain
explicit interoperability boundaries; they are not claimed newly native.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import threading

from .hia_native_build_admission_protocol import PORT, PORTS, MODES
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_store_lifecycle_native import _regular_bytes

SOURCE = _source_resource_path('examples/hia_bootstrap/native_build_admission.hepta')
SCHEMA = 'hepta.hia.native-build-admission.v1'
SELECTOR = 'HEPTA_HIA_NATIVE_BUILD_ADMISSION_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HNBARQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HNBARS01', 'little')
STATE_MAGIC = int.from_bytes(b'HNBAST01', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 96
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)


class NativeBuildAdmissionUnknown(RuntimeError):
    """A native observation is unconfirmed; the frame must not be replayed."""


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise NativeBuildAdmissionUnknown('native build admission custody belongs to its creator process')
    return _CUSTODY_LOCK


class NativeBuildAdmission(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_admission(raw, digest, source_digest):
    image = NativeBuildAdmission(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_native_build_admission(manifest_path):
    if not manifest_path:
        raise ValueError('native build admission selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeBuildAdmission)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native build admission manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native build admission image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native build admission source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native build admission image identity mismatch')
    if selected is None:
        selected = _mapped_admission(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeBuildAdmission or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native build admission selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native build admission selection changed during admission')
    return selected


@dataclass(frozen=True)
class NativeBuildAdmissionReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int


class NativeBuildAdmissionFrame:
    def __init__(self, image, mode, service, arguments, *, namespace=None):
        if type(image) is not NativeBuildAdmission:
            raise TypeError('native build admission requires an admitted image')
        if type(mode) is not int or mode not in (1, 2, 3, 4):
            raise ValueError('native build admission requires one original mode')
        if namespace is None:
            from . import hia_agent_service
            namespace = vars(hia_agent_service)
        self.image, self.mode, self.service, self.namespace = image, mode, service, namespace
        self.data = {'arguments': arguments}
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
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

    def call(self, event, observation=0):
        if self.fenced or self.finished or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise NativeBuildAdmissionUnknown('native build admission frame cannot be resumed or inherited')
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, self.mode, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16):
                raise NativeBuildAdmissionUnknown('native build admission continuation return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw)
            expected_sequence = 1 if event == 0 else sequence if event == 1 else sequence + 1
            expected_phases = (1, 4) if event == 2 else (2,) if event == 1 else (5,) if event == 3 else (1,)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != int(event == 3)
                    or (event == 1 and words[2] != port)):
                raise NativeBuildAdmissionUnknown('native build admission receipt differs from issued state')
            self.receipt = NativeBuildAdmissionReceipt(*words[2:7])
            return self.receipt
        except BaseException as error:
            self.fenced = self.native_failed = True
            self.unconfirmed = self.effect_started
            # RuntimeError identity and BaseException signals retain their
            # original behavior. RuntimeError subclasses also caught by the
            # public request rejection wrapper (notably RecursionError) must
            # still be classified unknown, never a completed foreign refusal.
            if isinstance(error, Exception) and (
                    not isinstance(error, RuntimeError) or isinstance(error, _REQUEST_REJECTIONS)):
                raise NativeBuildAdmissionUnknown('native build admission continuation observation failed') from error
            raise

    def finish(self):
        if self.finished:
            raise NativeBuildAdmissionUnknown('native build admission frame already completed')
        while True:
            if self.receipt.phase != 1:
                self.fenced = True
                raise NativeBuildAdmissionUnknown('native build admission effect is not newly issued')
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                observed = self.effect(self.receipt.port)
            except BaseException:
                if self.native_failed:
                    self.fenced = self.unconfirmed = True
                    raise
                self.call(3)
                if self.receipt.phase != 5:
                    self.fenced = True
                    raise NativeBuildAdmissionUnknown('native build admission exception was not confirmed')
                self.finished, self.unconfirmed = True, False
                self._release()
                raise
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

    def effect(self, port):
        """Perform one named primitive; HIA alone chooses its successor."""
        if not 1 <= port <= len(PORTS):
            raise NativeBuildAdmissionUnknown('native build admission issued an unknown port')
        name = PORTS[port - 1]
        d, s, api = self.data, self.service, self.namespace
        if name == 'args_signatures':
            d['program'], d['foreign_buffer_exports'] = d['arguments']
        elif name == 'signature_imports':
            from .hia_program_native import WIDTHS
            from .hia_native_byte_abi import normalize_exports
            from .hia_agent_buffers import PROFILE as BUFFER_PROFILE
            d['widths'], d['normalize_exports'], d['buffer_profile'] = WIDTHS, normalize_exports, BUFFER_PROFILE
        elif name == 'signature_document':
            d['document'] = d['program'].as_dict()
        elif name == 'signature_scalar_init':
            d['signature_functions'] = iter(d['document']['functions'])
            d['signatures'] = {}
        elif name == 'signature_fn_next':
            return self._next('signature_functions', 'fn')
        elif name == 'signature_fn_entry':
            return int(d['fn']['name'] in d['program'].scalar_entrypoints)
        elif name == 'signature_param_init':
            d['signature_parameters'] = iter(d['fn']['params'])
        elif name == 'signature_param_next':
            return self._next('signature_parameters', 'parameter')
        elif name == 'signature_param_allowed':
            try:
                return int(d['parameter']['type'] in set(d['widths']) | {'bool'})
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'signature_return_length':
            return len(d['fn']['returns'])
        elif name == 'signature_returns_init':
            d['signature_returns'] = iter(d['fn']['returns'])
        elif name == 'signature_returns_next':
            return self._next('signature_returns', 'return_type')
        elif name == 'signature_return_allowed':
            try:
                return int(d['return_type'] in set(d['widths']) | {'bool', 'unit'})
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'signature_capture_name':
            # Dict-comprehension keys are evaluated before their values.
            d['signature_name'] = d['fn']['name']
        elif name == 'signature_params_init':
            d['signature_parameter_values'] = iter(d['fn']['params'])
            d['parameter_types'] = []
        elif name == 'signature_params_next':
            return self._next('signature_parameter_values', 'parameter')
        elif name == 'signature_params_append':
            d['parameter_types'].append(d['parameter']['type'])
        elif name == 'signature_scalar_publish':
            d['signatures'][d['signature_name']] = {
                'params': d['parameter_types'], 'returns': d['fn']['returns']}
        elif name == 'signature_normalize':
            d['signature_exports'] = dict(d['normalize_exports'](d['foreign_buffer_exports'], d['program']))
        elif name == 'signature_exports_iter':
            d['signature_export_functions'] = iter(d['document']['functions'])
        elif name == 'signature_export_fn_next':
            return self._next('signature_export_functions', 'fn')
        elif name == 'signature_export_contains':
            return int(d['fn']['name'] in d['signature_exports'])
        elif name == 'signature_export_params_init':
            d['signature_export_parameters'] = iter(d['fn']['params'])
            d['parameter_types'] = []
        elif name == 'signature_export_params_next':
            return self._next('signature_export_parameters', 'parameter')
        elif name == 'signature_export_params_append':
            d['parameter_types'].append(d['parameter']['type'])
        elif name == 'signature_export_publish':
            # Assignment is different from dict comprehension: the whole RHS,
            # including exports[fn['name']], precedes the target fn['name'].
            d['signatures'][d['fn']['name']] = {
                'params': d['parameter_types'], 'returns': d['fn']['returns'],
                'abi': d['buffer_profile'], 'max_buffer_bytes': d['signature_exports'][d['fn']['name']]}
        elif name == 'signature_result':
            d['result'] = d['signatures']
        elif name == 'args_native':
            d['native_ref'], d['context_ref'] = d['arguments']
        elif name == 'native_get':
            d['data'], d['metadata'] = s.store.get(d['native_ref'], kind='native')
        elif name == 'native_installation_differs':
            return int(bool(d['metadata']['installation'] != s.identities))
        elif name == 'native_context_present':
            return int(d['context_ref'] is not None)
        elif name == 'native_context_differs':
            return int(bool(d['metadata']['context'] != d['context_ref']))
        elif name == 'native_program':
            d['program'] = s._program(d['metadata']['candidate'])
        elif name == 'native_context':
            d['retained_context'] = s._context(d['metadata']['context'])
        elif name == 'native_exports_init':
            # Keep the original map transformation and its StopIteration
            # behavior. HIA controls each outer next and accumulation step.
            d['native_exports'] = iter(map(tuple, d['retained_context'].get('foreign_buffer_exports', [])))
            d['export_pairs'] = []
        elif name == 'native_exports_next':
            return self._next('native_exports', 'export_pair')
        elif name == 'native_exports_append':
            d['export_pairs'].append(d['export_pair'])
        elif name == 'native_exports_finish':
            d['foreign_buffer_exports'] = tuple(d['export_pairs'])
        elif name == 'native_core_differs':
            return int(bool(d['metadata']['core_sha256'] != d['program'].sha256))
        elif name == 'native_signatures_differs':
            return int(bool(d['signatures'] != d['metadata']['signatures']))
        elif name == 'native_exports_list_init':
            d['recorded_exports'] = d['metadata'].get('foreign_buffer_exports', [])
            d['native_export_pairs'] = iter(d['foreign_buffer_exports'])
            d['export_lists'] = []
        elif name == 'native_exports_list_next':
            return self._next('native_export_pairs', 'export_pair')
        elif name == 'native_exports_list_append':
            d['export_lists'].append(list(d['export_pair']))
        elif name == 'native_exports_differs':
            return int(bool(d['recorded_exports'] != d['export_lists']))
        elif name == 'native_result':
            d['result'] = (d['data'], d['metadata'], d['program'])
        elif name == 'args_build':
            d['build_ref'], d['context_ref'], d['native_ref'] = d['arguments']
        elif name == 'build_get':
            d['record'], d['build_metadata'] = s.store.get_json(d['build_ref'], kind='build-receipt')
        elif name == 'build_context_differs':
            return int(bool(d['record']['context'] != d['context_ref']))
        elif name == 'build_artifact_differs':
            return int(bool(d['record']['native_artifact'] != d['native_ref']))
        elif name == 'build_installation_differs':
            return int(bool(d['record']['installation'] != s.identities))
        elif name == 'build_target_differs':
            return int(bool(d['record'].get('target_profile') != s.profiles['target']))
        elif name == 'build_backend_differs':
            return int(bool(d['record'].get('backend_profile') != s.profiles['backend']))
        elif name == 'build_metadata_init':
            d['metadata_items'] = iter(d['metadata'].items())
        elif name == 'build_metadata_next':
            return self._next('metadata_items', 'metadata_item')
        elif name == 'build_metadata_unpack':
            try:
                d['metadata_name'], d['metadata_value'] = d['metadata_item']
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'build_metadata_compare':
            try:
                d['metadata_comparison'] = d['record'].get(d['metadata_name']) != d['metadata_value']
            except StopIteration as error:
                raise RuntimeError('generator raised StopIteration') from error
        elif name == 'build_metadata_truth':
            # any() applies truth outside the generator. A StopIteration here
            # remains the original exception, unlike a generator-body error.
            return int(bool(d['metadata_comparison']))
        elif name == 'build_built':
            d['built'] = d['record'].get('native_build')
        elif name == 'build_built_not_dict':
            return int(type(d['built']) is not dict)
        elif name == 'build_object_ref_not_dict':
            return int(type(d['record'].get('object_artifact')) is not dict)
        elif name == 'build_object_ref_differs':
            return int(bool(d['record']['object_artifact'] != d['built'].get('object_artifact')))
        elif name == 'build_object_sha_differs':
            return int(bool(d['record'].get('object_sha256') != d['built'].get('object_sha256')))
        elif name == 'build_core_sha_differs':
            return int(bool(d['built'].get('core_sha256') != d['program'].sha256))
        elif name == 'build_input_sha_differs':
            return int(bool(d['built'].get('input_sha256') != d['program'].input_sha256))
        elif name == 'build_implementation_differs':
            return int(bool(d['built'].get('implementation_sha256') != s.identities['backend_sha256']))
        elif name == 'build_kind_differs':
            return int(bool(d['built'].get('kind') != d['record']['output_kind']))
        elif name == 'build_exports_differs':
            return int(bool(d['built'].get('foreign_buffer_exports') != d['record'].get('foreign_buffer_exports', [])))
        elif name == 'build_final_sha_differs':
            return int(bool(d['built'].get('artifact_sha256') != api['sha256'](d['data']).hexdigest()))
        elif name == 'build_object_get':
            d['object_bytes'], d['object_metadata'] = s.store.get(d['record']['object_artifact'], kind='build-object')
        elif name == 'build_expected_metadata':
            d['expected_metadata'] = {'schema': 'hepta.hia.agent.build-object.v1',
                'core_sha256': d['program'].sha256,
                'machine_plan_sha256': d['built'].get('machine_plan_sha256'), 'installation': s.identities}
        elif name == 'build_object_metadata_differs':
            return int(bool(d['object_metadata'] != d['expected_metadata']))
        elif name == 'build_object_bytes_sha_differs':
            return int(bool(api['sha256'](d['object_bytes']).hexdigest() != d['record']['object_sha256']))
        elif name == 'build_ref_object_sha_differs':
            return int(bool(d['record']['object_artifact']['sha256'] != d['record']['object_sha256']))
        elif name == 'build_output_is_object':
            return int(bool(d['record']['output_kind'] == 'object'))
        elif name == 'build_object_bytes_differs':
            return int(bool(d['object_bytes'] != d['data']))
        elif name == 'build_result':
            d['result'] = (d['record'], d['data'], d['object_bytes'], d['program'])
        elif name == 'receipt_result':
            d['result'] = d['result'][0]
        elif name == 'reject_native_subject':
            api['reject']('E_HIA_RECEIPT_BINDING', 'native artifact belongs to a different context or implementation')
        elif name == 'reject_native_identity':
            api['reject']('E_HIA_RECEIPT_BINDING', "native artifact's admitted Core identity differs")
        elif name == 'reject_build_subject':
            api['reject']('E_HIA_RECEIPT_BINDING', 'build receipt belongs to a different native subject')
        elif name == 'reject_metadata':
            api['reject']('E_HIA_RECEIPT_BINDING', 'build record differs from retained native metadata')
        elif name == 'reject_build_bytes':
            api['reject']('E_HIA_RECEIPT_BINDING', 'build record differs from actual artifact bytes')
        elif name == 'reject_object':
            api['reject']('E_HIA_RECEIPT_BINDING', 'retained object differs from its exact build binding')
        else:
            raise NativeBuildAdmissionUnknown('native build admission port has no foreign operation')
        return 0
