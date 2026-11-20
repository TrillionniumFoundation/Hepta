"""Explicit HIA executable-capture owner; the original selfhost route is unchanged.

A separately expected manifest authorizes two immutable images: the HIA policy
and a seven-syscall mechanical primitive. This is a CPython 3.14.10/Linux x86-64
component profile, not a change to the package's supported Python versions.
Neither a compiler-v1 manifest nor an environment variable selects this owner.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import sys
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path
from .hia_native_delivery import DeliveryRecord, NativeCall, _resource_loss
from .hia_program_selfhost import SelfhostBuildRejected, _read

SCHEMA = 'hepta.hia.executable-capture-component.v1'
BUILD_SCHEMA = 'hepta.hia.executable-capture-build.v1'
PROFILE = 'cpython-3.14.10-linux-x86_64-lp64-gil'
POLICY_SOURCE = 'examples/hia_bootstrap/executable_capture.hepta'
RAW_SOURCE = 'tools/hia_executable_capture_syscalls.S'
MAX_BYTES = 1 << 20
MASK = (1 << 64) - 1
REQUEST_MAGIC = 0x3152504143584548
STATE_MAGIC = 0x3154534143584548
RECEIPT_MAGIC = 0x31524f4143584548
RAW_REQUEST_MAGIC = 0x3152534143584548
RAW_RECEIPT_MAGIC = 0x31524f5343584548
CANARY = bytes.fromhex('a716b95a28e54fb70cde1349f2a8613d')
SOURCE_INPUTS = (
    POLICY_SOURCE, RAW_SOURCE,
    'hepta/hia_executable_capture.py',
    'tools/generate_hia_executable_capture.py',
    'tools/build_hia_executable_capture.py',
    'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_store_file_capture_originals.py',
    'tools/generate_hia_selfhost.py',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_program_selfhost.py',
    'hepta/hia_json_preflight_native.py',
    'hepta/hia_native_admission_io.py',
    'hepta/hia_native_delivery.py',
    'hepta/hia_native_helpers.py',
    'tests/fixtures/executable_capture_r19_original.py.txt',
    'tests/hia_executable_capture_originals.py',
    'tests/fixtures/executable_capture_cases.json',
    'tests/test_hia_executable_capture.py',
    'tests/hia_executable_capture_receipt_controls.py',
    'tests/test_hia_executable_capture_receipt.py',
    'tests/fixtures/executable_capture_receipt_controls_v2.json',
    'docs/HIA_EXECUTABLE_CAPTURE.md',
)
# Literal package-data authority for the wheel build hook; no runtime tools import.
PACKAGE_RESOURCES = (
    'examples/hia_bootstrap/executable_capture.hepta',
    'tools/hia_executable_capture_syscalls.S',
    'tools/generate_hia_executable_capture.py',
    'tools/build_hia_executable_capture.py',
    'tools/qualify_hia_selfhost.py',
    'tools/build_hia_source_build.py',
    'tools/build_hia_json_preflight.py',
    'tools/qualify_hia_store_file_capture_originals.py',
    'tools/generate_hia_selfhost.py',
    'tests/fixtures/executable_capture_r19_original.py.txt',
    'tests/hia_executable_capture_originals.py',
    'tests/fixtures/executable_capture_cases.json',
    'tests/test_hia_executable_capture.py',
    'tests/hia_executable_capture_receipt_controls.py',
    'tests/test_hia_executable_capture_receipt.py',
    'tests/fixtures/executable_capture_receipt_controls_v2.json',
    'docs/HIA_EXECUTABLE_CAPTURE.md',
)
_SCHEMA_KEYS = {'schema', 'profile', 'policy_path', 'policy_sha256',
                'effects_path', 'effects_sha256', 'receipt_path', 'receipt_sha256',
                'component_inputs', 'runtime_modules', 'compiler_sha256', 'scope', 'cold_report_sha256'}
_HOST_ABI = None
_HOST_LOCK = threading.RLock()


class ExecutableCaptureUnknown(RuntimeError):
    """The invocation's actual native/foreign outcome lacks a complete receipt."""


def _reset_host_lock():
    global _HOST_LOCK
    _HOST_LOCK = threading.RLock()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_reset_host_lock)


def _profile():
    if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 10)
            or platform.system() != 'Linux' or platform.machine() != 'x86_64'
            or ctypes.sizeof(ctypes.c_void_p) != 8
            or not sys._is_gil_enabled()):
        raise ValueError('executable capture requires its explicit ' + PROFILE + ' profile')


def _host_abi():
    global _HOST_ABI
    with _HOST_LOCK:
        if _HOST_ABI is None:
            library = ctypes.PyDLL(None, use_errno=True)
            audit = library.PySys_Audit
            audit.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            audit.restype = ctypes.c_int
            check = library.PyErr_CheckSignals
            check.argtypes = []
            check.restype = ctypes.c_int
            error = library.PyErr_SetFromErrno
            error.argtypes = [ctypes.py_object]
            error.restype = ctypes.py_object
            _HOST_ABI = (library, _AuditABI(audit), check, error)
        return _HOST_ABI


class _AuditABI:
    """Use the original CPython C formatting ABI, including fresh integer args."""
    def __init__(self, audit):
        self.audit = audit

    def __call__(self, event, *arguments):
        if event == 'os.chmod':
            descriptor, mode, directory = arguments
            return self.audit(b'os.chmod', b'iii', ctypes.c_int(descriptor),
                              ctypes.c_int(mode), ctypes.c_int(directory))
        descriptor, command, argument = arguments
        return self.audit(b'fcntl.fcntl', b'iiO', ctypes.c_int(descriptor),
                          ctypes.c_int(command), ctypes.py_object(argument))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate executable-capture manifest field')
        result[key] = value
    return result


def _json(raw):
    def nonfinite(value):
        raise ValueError('nonfinite executable-capture manifest field')
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=nonfinite)


def _digest(value):
    return (type(value) is str and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _runtime_names():
    package = Path(__file__).parent
    return tuple(sorted('hepta/' + item.relative_to(package).as_posix()
                        for item in package.rglob('*.py')
                        if item.relative_to(package).parts[0] != '_data'))


def _resource(name):
    if name.startswith('hepta/') and name.endswith('.py'):
        return Path(__file__).parent / name[6:]
    return _source_resource_path(name)


def _relative(value):
    return (type(value) is str and value not in ('', '.', '..')
            and '/' not in value and '\\' not in value and '\0' not in value)


def _sum_words(raw):
    value = 1469598103934665603
    for (word,) in struct.iter_unpack('<Q', raw):
        value = ((value ^ word) * 1099511628211) & MASK
    return value


class ExecutableCapture:
    """Immutable admitted code; every call gets a distinct resource workspace."""

    def __init__(self, path, expected_sha256, *, allow_development=False):
        _profile()
        if not _digest(expected_sha256) or type(allow_development) is not bool:
            raise ValueError('an exact executable-capture manifest digest is required')
        path = Path(path).absolute()
        snapshot = _read(path, 65536)
        if sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('executable-capture manifest digest differs')
        manifest = _json(snapshot.raw)
        if (type(manifest) is not dict or set(manifest) != _SCHEMA_KEYS
                or manifest['schema'] != SCHEMA or manifest['profile'] != PROFILE
                or any(not _relative(manifest[key]) for key in
                       ('policy_path', 'effects_path', 'receipt_path'))
                or any(not _digest(manifest[key]) for key in
                       ('policy_sha256', 'effects_sha256', 'receipt_sha256', 'compiler_sha256'))
                or type(manifest['component_inputs']) is not dict
                or set(manifest['component_inputs']) != set(SOURCE_INPUTS)
                or any(not _digest(value) for value in manifest['component_inputs'].values())):
            raise ValueError('invalid executable-capture manifest schema')
        if (manifest['scope'] not in ('DEVELOPMENT_COMPONENT', 'MATCHING_SOURCE_COLD_COMPONENT')
                or (manifest['scope'] == 'DEVELOPMENT_COMPONENT'
                    and (not allow_development or manifest['cold_report_sha256'] is not None))
                or (manifest['scope'] == 'MATCHING_SOURCE_COLD_COMPONENT'
                    and not _digest(manifest['cold_report_sha256']))):
            raise ValueError('executable-capture construction scope differs')
        runtime_names = _runtime_names()
        if (type(manifest['runtime_modules']) is not dict
                or tuple(sorted(manifest['runtime_modules'])) != runtime_names
                or any(not _digest(value) for value in manifest['runtime_modules'].values())):
            raise ValueError('executable-capture complete runtime inventory differs')
        self.runtime_names = runtime_names
        pins = [snapshot]
        for name in runtime_names:
            captured = _read(_resource(name), 1 << 20)
            if sha256(captured.raw).hexdigest() != manifest['runtime_modules'][name]:
                raise ValueError('executable-capture runtime module differs: ' + name)
            pins.append(captured)
        for name in SOURCE_INPUTS:
            captured = _read(_resource(name), 1 << 20)
            if sha256(captured.raw).hexdigest() != manifest['component_inputs'][name]:
                raise ValueError('current executable-capture source differs: ' + name)
            pins.append(captured)
        images = []
        for prefix in ('policy', 'effects'):
            captured = _read(path.parent / manifest[prefix + '_path'], MAX_BYTES)
            if sha256(captured.raw).hexdigest() != manifest[prefix + '_sha256']:
                raise ValueError('executable-capture image differs')
            pins.append(captured)
            images.append(captured.raw)
        receipt = _read(path.parent / manifest['receipt_path'], 1 << 20)
        if sha256(receipt.raw).hexdigest() != manifest['receipt_sha256']:
            raise ValueError('executable-capture build receipt differs')
        build = _json(receipt.raw)
        if (type(build) is not dict or build.get('schema') != BUILD_SCHEMA
                or build.get('component_inputs') != manifest['component_inputs']
                or build.get('runtime_modules') != manifest['runtime_modules']
                or build.get('compiler_sha256') != manifest['compiler_sha256']
                or build.get('scope') != manifest['scope']
                or build.get('cold_report_sha256') != manifest['cold_report_sha256']
                or build.get('policy_sha256') != manifest['policy_sha256']
                or build.get('effects_sha256') != manifest['effects_sha256']):
            raise ValueError('executable-capture receipt does not bind this bundle')
        pins.append(receipt)
        self.pid = os.getpid()
        self._pins = tuple(pins)
        self.manifest_sha256 = expected_sha256
        self.scope = manifest['scope']
        self.host_abi = _host_abi()
        self.policy = NativeHiaJsonImage(images[0], manifest['policy_sha256'])
        self.effects = NativeHiaJsonImage(images[1], manifest['effects_sha256'])
        self.check()

    def check(self):
        if self.pid != os.getpid():
            raise ValueError('an executable-capture selection is not inherited across fork')
        if _runtime_names() != self.runtime_names:
            raise ValueError('executable-capture runtime inventory changed')
        for previous in self._pins:
            current = _read(previous.path, max(1, len(previous.raw)))
            if current.raw != previous.raw or current.identity != previous.identity:
                raise ValueError('executable-capture input changed after admission')
        if _runtime_names() != self.runtime_names:
            raise ValueError('executable-capture runtime inventory changed during readback')

    def capture(self, raw):
        # This private component's admitted input is the actual bytes captured by
        # the old compiler selection. It does not silently narrow the old helper.
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('outside executable-capture exact-bytes profile')
        return _CaptureFrame(self, raw).finish()


def load_executable_capture(manifest, expected_sha256, *, allow_development=False):
    return ExecutableCapture(manifest, expected_sha256,
                             allow_development=allow_development)


class _CaptureFrame:
    def __init__(self, owner, raw):
        self.owner = owner
        self.raw = raw
        self.nonce = struct.unpack('<QQ', os.urandom(16))
        if self.nonce == (0, 0):
            raise ValueError('zero executable-capture nonce')
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.used = False
        self._started = False
        self._known_error = None
        self._errors = [None, None, None]
        self._activations = []
        self._last_child = None
        self._accepted_policy = None
        self._accepted_state = None
        self.request = ctypes.create_string_buffer(128 + len(raw) + len(CANARY))
        self.output = ctypes.create_string_buffer(128 + len(CANARY))
        self.state_size = 257 + len(raw)
        self.state = ctypes.create_string_buffer(self.state_size + len(CANARY))
        self.raw_request = ctypes.create_string_buffer(96 + len(raw) + len(CANARY))
        self.raw_output = ctypes.create_string_buffer(96 + len(CANARY))
        self.raw_state = ctypes.create_string_buffer(97 + len(raw) + len(CANARY))
        ctypes.memmove(ctypes.addressof(self.request) + 128, raw, len(raw))
        self.record = DeliveryRecord(self)
        try:
            self.record.associate(self, unknown=ExecutableCaptureUnknown)
        except BaseException as error:
            self.record.failed(error)
            self.record.retire()
            raise

    def _check(self):
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise ExecutableCaptureUnknown('capture workspace cannot transfer process or thread')
        self.record.check(ExecutableCaptureUnknown)
        for activation in self._activations:
            holder = activation.pending_resources
            if holder.has_borrowed_resources:
                holder.check_borrowed_resources()
            for entry in holder.entries:
                if entry is None or not entry.pending_for(holder.activation_id):
                    continue
                resource = entry.observation.resource
                if resource is not None:
                    origin = _resource_loss(resource)
                    if origin is not None and self.record.loss is None:
                        self.record.loss = origin
                        self.record.publish(origin.error)
                self.record.check(ExecutableCaptureUnknown)

    def _guarded(self, record, size, *, effect):
        self._check()
        record.enter_native()
        if effect:
            self.record.observed()
            self._started = True
        return size

    @staticmethod
    def _canary(buffer, size):
        ctypes.memmove(ctypes.addressof(buffer) + size, CANARY, len(CANARY))

    @staticmethod
    def _intact(buffer, size):
        return bytes(buffer[size:size + len(CANARY)]) == CANARY

    @staticmethod
    def _fits(buffer, extent):
        return (type(extent) is int and extent >= 0
                and isinstance(buffer, ctypes.Array)
                and type(buffer)._type_ is ctypes.c_char
                and extent + len(CANARY) <= ctypes.sizeof(buffer))

    def _state_words(self):
        n = len(self.raw)
        if (type(self.raw) is not bytes or n > MAX_BYTES
                or self.state_size != 257 + n
                or not self._fits(self.state, self.state_size)):
            raise ExecutableCaptureUnknown('invalid executable-capture state allocation')
        return struct.unpack('<32Q', bytes(self.state[:256]))

    def _policy_operands(self, fields, state):
        # Projection of the declared action ABI only. HIA chooses the action,
        # retry, branch, cleanup and terminal; this never makes that decision.
        kind, action, fd, offset, count, arg = (
            fields[2], fields[4], fields[5], fields[6], fields[7], fields[8])
        n = len(self.raw)
        if kind != 1:
            if action != 0 or (offset, count, arg) != (0, 0, 0):
                raise ExecutableCaptureUnknown('invalid terminal capture operands')
            if kind == 2:
                if not 0 <= fd <= 2147483647 or fields[9] != 0 or state[13] != 0:
                    raise ExecutableCaptureUnknown('invalid successful capture terminal')
            elif kind == 3:
                if (not 1 <= fields[9] <= 2
                        or (fd == MASK and (fields[9] != 1 or state[13] != 0))
                        or (fd != MASK and (not 0 <= fd <= 2147483647 or state[13] != 1))):
                    raise ExecutableCaptureUnknown('invalid exceptional capture terminal')
            else:
                raise ExecutableCaptureUnknown('invalid capture terminal kind')
            return
        if not 1 <= action <= 11:
            raise ExecutableCaptureUnknown('invalid capture action')
        if action == 1:
            expected = (MASK, 0, 0, 3)
        else:
            # RAISE_ERRNO also represents a failed MEMFD before any fd exists.
            if not (0 <= fd <= 2147483647 or (action == 10 and fd == MASK)):
                raise ExecutableCaptureUnknown('invalid capture descriptor operand')
            if action == 2:
                if not state[8] < n:
                    raise ExecutableCaptureUnknown('invalid capture write extent')
                expected = (fd, state[8], n - state[8], 0)
            elif action == 3:
                expected = (fd, 0, 0, 320)
            elif action == 4:
                expected = (fd, 0, 0, 15)
            elif action == 6:
                expected = (fd, 0, n + 1, 0)
            elif action in (5, 7):
                if action == 7 and (state[13] != 1 or not 1 <= state[11] <= 2):
                    raise ExecutableCaptureUnknown('close has no current error continuation')
                expected = (fd, 0, 0, 0)
            elif action == 8:
                if not 3 <= state[15] <= 5:
                    raise ExecutableCaptureUnknown('invalid capture audit operand')
                expected = (fd, 0, 0, state[15])
            elif action == 9:
                if not 2 <= state[12] <= 6:
                    raise ExecutableCaptureUnknown('invalid capture signal operand')
                expected = (fd, 0, 0, state[12])
            else:
                if ((action == 10 and not 1 <= state[14] <= 4095)
                        or (action == 11 and state[14] not in (1, 2))):
                    raise ExecutableCaptureUnknown('invalid capture error operand')
                expected = (fd, 0, 0, state[14])
        if (fd, offset, count, arg) != expected:
            raise ExecutableCaptureUnknown('capture action operands differ from state')

    def _effect_fields(self, fields):
        self._check()
        if (type(fields) is not tuple or len(fields) != 16
                or any(type(value) is not int or not 0 <= value <= MASK for value in fields)
                or fields is not self._accepted_policy or fields[2] != 1):
            raise ExecutableCaptureUnknown('capture effect has no current confirmed action')
        state = self._state_words()
        if (state != self._accepted_state or fields[2] != state[4]
                or fields[3] != state[5] or fields[4] != state[6]
                or fields[5] != state[7] or fields[9] != state[11]
                or fields[10:12] != self.nonce or fields[12] != state[4]):
            raise ExecutableCaptureUnknown('capture state changed before its effect')
        self._policy_operands(fields, state)
        return fields[4:9]

    def _step(self, event, sequence, action, result=0, error=0):
        self._check()
        if (any(type(value) is not int or not 0 <= value <= MASK
                for value in (event, sequence, action, result, error))
                or event not in (0, 1, 2)
                or not self._fits(self.request, 128 + len(self.raw))
                or not self._fits(self.output, 128)):
            raise ExecutableCaptureUnknown('invalid executable-capture policy request')
        before_state = self._state_words()
        if event == 0:
            if ((sequence, action, result, error) != (0, 0, 0, 0)
                    or self._accepted_policy is not None or self._accepted_state is not None
                    or any(before_state)):
                raise ExecutableCaptureUnknown('invalid initial capture invocation')
        else:
            if (self._accepted_policy is None or before_state != self._accepted_state
                    or before_state[4] != 1 or not 1 <= sequence < MASK
                    or sequence != before_state[5] or action != before_state[6]
                    or not 1 <= action <= 11
                    or (event == 1 and error != 0)
                    or (event == 2 and (result != 0 or error != before_state[11] + 1
                                       or error > 2))):
                raise ExecutableCaptureUnknown('capture continuation differs from invocation')
        header = (REQUEST_MAGIC, 1, event, sequence, action, result,
                  error, len(self.raw), *self.nonce, 0, 0, 0, 0, 0, 0)
        struct.pack_into('<16Q', self.request, 0, *header)
        size = 128 + len(self.raw)
        before = bytes(self.request[:size])
        self._canary(self.request, size)
        self._canary(self.output, 128)
        self._canary(self.state, self.state_size)
        with NativeCall((self, self.request, self.output, self.state)) as record:
            record.associate(self, unknown=ExecutableCaptureUnknown)
            self._last_child = record
            status = self.owner.policy._entry(
                self.request, size, self.output, 128, self.state,
                self._guarded(record, self.state_size, effect=False))
            receipt = bytes(self.output[:128])
            state_header = bytes(self.state[:256])
            if (status != 128 or bytes(self.request[:size]) != before
                    or not self._intact(self.request, size)
                    or not self._intact(self.output, 128)
                    or not self._intact(self.state, self.state_size)):
                raise ExecutableCaptureUnknown('incomplete executable-capture policy receipt')
            fields = struct.unpack('<16Q', receipt)
            state = struct.unpack('<32Q', state_header)
            if (fields[:2] != (RECEIPT_MAGIC, 1) or fields[2] not in (1, 2, 3)
                    or fields[10:12] != self.nonce or fields[14:] != (0, 0)
                    or fields[13] != _sum_words(receipt[:104])
                    or state[:2] != (STATE_MAGIC, 1) or state[2:4] != self.nonce
                    or state[16] != _sum_words(state_header[:128])
                    or any(state[17:]) or fields[2] != fields[12]
                    or fields[2] != state[4] or fields[3] != state[5]
                    or fields[4] != state[6] or fields[5] != state[7]
                    or fields[9] != state[11] or state[9] != len(self.raw)
                    or state[8] > state[9] or state[11] > 2 or state[13] > 1
                    or state[10] > 2147483647 or state[12] not in (0, 2, 3, 4, 5, 6)
                    or state[14] > 4095 or state[15] not in (0, 3, 4, 5)):
                raise ExecutableCaptureUnknown('invalid executable-capture policy state')
            if event == 0:
                if state[:16] != (STATE_MAGIC, 1, *self.nonce, 1, 1, 1, MASK,
                                  0, len(self.raw), 0, 0, 0, 0, 0, 0):
                    raise ExecutableCaptureUnknown('initial capture receipt is not MEMFD sequence one')
            else:
                expected_sequence = sequence + 1 if fields[2] == 1 else sequence
                expected_error = before_state[11] if event == 1 else error
                expected_fd = before_state[7]
                if event == 1 and action == 1 and 0 <= result <= 2147483647:
                    expected_fd = result
                if (fields[3] != expected_sequence or state[11] != expected_error
                        or state[7] != expected_fd or state[13] < before_state[13]):
                    raise ExecutableCaptureUnknown('capture receipt does not acknowledge this invocation')
            self._policy_operands(fields, state)
            if fields[2] == 3:
                selected_error = self._errors[fields[9]]
                if selected_error is None or sys.exception() is not selected_error:
                    raise ExecutableCaptureUnknown('capture receipt names no current exception')
            # Bind the complete decoded result to this particular workspace
            # before its actual native delivery is confirmed.
            outcome = tuple(fields)
            self._accepted_policy, self._accepted_state = outcome, state
            record.check(ExecutableCaptureUnknown)
            record.confirmed(terminal=True)
        self._check()
        return outcome

    def _raw_effect(self, fields):
        action, fd, offset, count, arg = self._effect_fields(fields)
        if not 1 <= action <= 7:
            raise ExecutableCaptureUnknown('invalid executable-capture raw action')
        n = len(self.raw)
        request_buffer, output_buffer, state_buffer = (
            self.raw_request, self.raw_output, self.raw_state)
        policy_buffer, policy_size = self.state, self.state_size
        if action == 1:
            valid = (fd, offset, count, arg) == (MASK, 0, 0, 3)
        elif not 0 <= fd <= 2147483647:
            valid = False
        elif action == 2:
            valid = (0 <= offset < n and 0 < count <= n - offset and arg == 0)
        elif action == 6:
            valid = offset == 0 and count == n + 1 and 1 <= count <= MAX_BYTES + 1 and arg == 0
        else:
            valid = (offset, count, arg) == (0, 0, 320 if action == 3 else 15 if action == 4 else 0)
        if not valid:
            raise ExecutableCaptureUnknown('invalid executable-capture raw operands')
        payload = self.raw[offset:offset + count] if action == 2 else b''
        size = 96 + len(payload)
        state_size = 96 + (count if action == 6 else 0)
        if ((action == 2 and len(payload) != count)
                or not self._fits(request_buffer, size)
                or not self._fits(output_buffer, 96)
                or not self._fits(state_buffer, state_size)
                or (action == 6 and (256 + count > policy_size
                                    or not self._fits(policy_buffer, policy_size)))):
            raise ExecutableCaptureUnknown('executable-capture raw allocation is too small')
        # Every action/operand/extent and actual allocation was checked above.
        # No pack, memset, memmove, canary write or raw entry precedes it.
        header = (RAW_REQUEST_MAGIC, 1, action, fd, offset, count,
                  *self.nonce, fields[3], arg, len(payload), 0)
        struct.pack_into('<12Q', request_buffer, 0, *header)
        if payload:
            ctypes.memmove(ctypes.addressof(request_buffer) + 96, payload, len(payload))
        ctypes.memset(state_buffer, 0, 96)
        self._canary(request_buffer, size)
        self._canary(output_buffer, 96)
        self._canary(state_buffer, state_size)
        before = bytes(request_buffer[:size])
        with NativeCall((self, request_buffer, output_buffer, state_buffer, policy_buffer)) as record:
            record.associate(self, unknown=ExecutableCaptureUnknown)
            self._last_child = record
            status = self.owner.effects._entry(
                request_buffer, size, output_buffer, 96, state_buffer,
                self._guarded(record, state_size, effect=True))
            receipt = bytes(output_buffer[:96])
            state = struct.unpack('<12Q', bytes(state_buffer[:96]))
            got = struct.unpack('<12Q', receipt)
            expected_prefix = (RAW_RECEIPT_MAGIC, 1, action, 2)
            if (status != 96 or got[:4] != expected_prefix
                    or got[5:8] != (*self.nonce, fields[3])
                    or any(got[8:]) or state != (
                        2, action, got[4], *self.nonce, fields[3],
                        fd, offset, count, arg, 0, 0)
                    or bytes(request_buffer[:size]) != before
                    or not self._intact(request_buffer, size)
                    or not self._intact(output_buffer, 96)
                    or not self._intact(state_buffer, state_size)):
                raise ExecutableCaptureUnknown('incomplete executable-capture syscall receipt')
            value = got[4]
            captured = b''
            if action == 6 and value < (1 << 63):
                if value > count or 256 + value > policy_size:
                    raise ExecutableCaptureUnknown('pread receipt exceeds its admitted buffer')
                captured = bytes(state_buffer[96:96 + value])
            result = (value, captured)
            if action == 6 and captured:
                ctypes.memmove(ctypes.addressof(policy_buffer) + 256, captured, len(captured))
            record.check(ExecutableCaptureUnknown)
            record.confirmed(terminal=True)
        self._check()
        return result[0]

    def _host_effect(self, fields):
        action, fd, _, _, arg = self._effect_fields(fields)
        if (action not in (8, 9, 10, 11)
                or (action == 8 and arg not in (3, 4, 5))
                or (action == 9 and not 2 <= arg <= 6)
                or (action == 10 and not 1 <= arg <= 4095)
                or (action == 11 and arg not in (1, 2))):
            failure = ExecutableCaptureUnknown('invalid mechanical host operand')
            self.record.failed(failure)
            raise failure
        # Capture actual callback resources until the whole operation's ACK.
        # This is distinct from confirming a single HIA or syscall receipt.
        activation = self.record.foreign(capture_resources=True)
        self._activations.append(activation)
        with activation:
            self._check()
            self.record.observed()
            self._started = True
            if action == 8:
                audit = self.owner.host_abi[1]
                if arg == 3:
                    audit('os.chmod', fd, 0o500, -1)
                elif arg == 4:
                    audit('fcntl.fcntl', fd, 1033, 15)
                elif arg == 5:
                    audit('fcntl.fcntl', fd, 1034, None)
                else:
                    raise ExecutableCaptureUnknown('invalid admitted audit operand')
                return 0
            if action == 9:
                return self.owner.host_abi[2]()
            if action == 10:
                previous = ctypes.get_errno()
                try:
                    ctypes.set_errno(arg)
                    self.owner.host_abi[3](OSError)
                finally:
                    ctypes.set_errno(previous)
                failure = ExecutableCaptureUnknown('errno constructor unexpectedly returned')
                self.record.failed(failure)
                raise failure
            if action == 11:
                if arg == 1:
                    raise SelfhostBuildRejected('E_HIA_SELFHOST_CAPTURE',
                                                'short executable capture')
                if arg == 2:
                    raise SelfhostBuildRejected(
                        'E_HIA_SELFHOST_CAPTURE',
                        'kernel seal or captured executable readback failed')
                raise ExecutableCaptureUnknown('invalid admitted capture-refusal reason')
            raise ExecutableCaptureUnknown('invalid mechanical host operand')

    def _drive(self, event=0, sequence=0, action=0, result=0, error=0):
        while True:
            fields = self._step(event, sequence, action, result, error)
            if fields[2] == 2:
                if fields[5] > 2147483647 or fields[9] != 0:
                    raise ExecutableCaptureUnknown('invalid captured descriptor transfer')
                value = (fields[5], struct.unpack_from('<Q', self.state, 80)[0])
                self._check()
                return value
            if fields[2] == 3:
                if not 1 <= fields[9] <= 2:
                    raise ExecutableCaptureUnknown('invalid capture exception receipt')
                selected = self._errors[fields[9]]
                if selected is None or sys.exception() is not selected:
                    raise ExecutableCaptureUnknown('capture exception identity differs')
                self._known_error = selected
                self._check()
                raise
            self._started = False
            try:
                result = (self._raw_effect(fields) if fields[4] <= 7
                          else self._host_effect(fields))
            except BaseException as failure:
                if self.record.loss is not None:
                    self.record.propagate(failure, ExecutableCaptureUnknown, (ValueError, OSError))
                    raise
                self._check()
                if not self._started:
                    raise
                handle = fields[9] + 1
                if handle > 2:
                    raise ExecutableCaptureUnknown('too many capture exception outcomes')
                self._errors[handle] = failure
                # Executed in the actual except domain. A failing close has the
                # real primary exception as context; no traceback is cleared.
                return self._drive(2, fields[3], fields[4], error=handle)
            event, sequence, action, error = 1, fields[3], fields[4], 0

    def _confirm(self):
        for activation in self._activations:
            activation.prepare_acknowledgement()
        self._check()
        self.record.confirmed(terminal=True)
        for activation in self._activations:
            activation.acknowledged()

    def finish(self):
        # Reject reused/foreign workspaces before entering any cleanup region.
        self._check()
        if self.used:
            raise ExecutableCaptureUnknown('capture workspace is single-use')
        self.used = True
        try:
            with self.record.foreign(observation=False):
                self.owner.check()
                self._check()
                value = self._drive()
            self._confirm()
            return value
        except BaseException as failure:
            if self._known_error is failure and self.record.loss is None:
                try:
                    self._confirm()
                except BaseException as acknowledgement_failure:
                    self.record.failed(acknowledgement_failure)
                    for activation in self._activations:
                        activation.failed(acknowledgement_failure)
                    raise
                raise
            self.record.failed(failure)
            for activation in self._activations:
                activation.failed(failure)
            self.record.propagate(failure, ExecutableCaptureUnknown, (ValueError, OSError))
            raise
        finally:
            if self.record.terminal and self.record.loss is None:
                for activation in self._activations:
                    activation.recover_acknowledged_resources()
            self.record.retire()
