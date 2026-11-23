"""The original Agent evaluation control graph, driven by an admitted HIA image.

HIA owns branch/iteration order, correctness/completeness/budget flags, outcome
precedence, exact-int deadlines and permission to perform each foreign effect.
Python retains opaque objects, the original runner/Store/clock providers and
object protocols. Integer true division to binary64 and binary64 comparison
use the pinned Agent identity image in the native Store profile. The hosted
interoperability route preserves CPython behavior for its unrestricted operands.
No retained evaluation body is invoked by this adapter.
"""
from __future__ import annotations

import ctypes
from .hia_agent_identity_native import DECLARED_OBSERVATION, NATIVE_OBSERVATION, REFERENCE_OBSERVATION
from .hia_agent_store import _native_agent_identity, uses_native_store
from .hia_native_delivery import DeliveryRecord, request_rejections
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import operator
import os
from pathlib import Path
import struct
import subprocess
import threading

from .hia_evaluation_protocol import PORT, PORTS, OUTCOMES
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_service_context_native import NativeServiceContextImage, _INTEROP, MATH_MAGIC
from .hia_store_lifecycle_native import _regular_bytes

SOURCE = _source_resource_path('examples/hia_bootstrap/evaluation.hepta')
SCHEMA = 'hepta.hia.evaluation-native.v1'
SELECTOR = 'HEPTA_HIA_EVALUATION_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HEVAREQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HEVARSP1', 'little')
STATE_BYTES = 128
OUTPUT_BYTES = 112
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()


class EvaluationUnknown(RuntimeError):
    """An evaluation observation is unconfirmed; no retry or implicit refund."""


_WORKLOAD_REFUSALS = {
    1: ('E_HIA_ABI', 'workload names an unavailable public entry'),
    2: ('E_HIA_ARGUMENTS', 'call arguments do not have the exact declared scalar types'),
    3: ('E_HIA_ABI', 'borrowed entry is absent from the frozen invocation profile'),
    4: ('E_HIA_ARGUMENTS', 'borrowed arguments require a byte snapshot'),
    5: ('E_HIA_ARGUMENTS', 'buffer bytes must be bounded canonical lowercase hex'),
    6: ('E_HIA_ARGUMENTS', 'buffer fill requires exact bounded integer length and byte'),
    7: ('E_HIA_ARGUMENTS', 'buffer snapshot has missing or unknown fields'),
    8: ('E_HIA_BUFFER_EXTENT', 'snapshot exceeds the frozen wrapper extent'),
    9: ('E_HIA_BUFFER_BUDGET', 'frozen workload exceeds 32 MiB of external byte snapshots'),
    10: ('E_HIA_ARGUMENTS', 'call does not match the frozen public ABI'),
}


def _run_native_evaluate_planner(planner, *parts):
    from .hia_scalar_reference_native import sealed_reference_bytes

    with sealed_reference_bytes(*parts) as source:
        try:
            result = subprocess.run(['/proc/self/fd/' + str(planner)], stdin=source, pass_fds=(planner,),
                                    env={'PATH': ''}, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvaluationUnknown('installed HIA Evaluate planner could not be observed') from error
    reply = result.stdout
    if (result.returncode or result.stderr or len(reply) < 16
            or struct.unpack_from('<Q', reply)[0] != len(reply) - 8):
        raise EvaluationUnknown('installed HIA Evaluate planner did not return an admitted packet')
    return reply[8:]


def _admit_native_workload(executable, signatures, raw, workload):
    """Send exact retained bytes to the installed HIA planner, not a Python validator."""
    from .hia_agent_store import reject, wire
    from .hia_scalar_reference_native import sealed_reference_bytes

    with sealed_reference_bytes(executable) as planner:
        reply = _run_native_evaluate_planner(planner, b'[', wire(signatures), b',', raw, b']')
    if len(reply) < 24 or not reply.startswith(b'HIAEVW01'):
        raise EvaluationUnknown('installed HIA workload planner packet identity differs')
    size = len(reply)
    status, count = struct.unpack_from('<2Q', reply, 8)
    cases = len(workload['cases'])
    if status:
        refusal = _WORKLOAD_REFUSALS.get(status)
        if refusal is None or size != 24 or count >= cases:
            raise EvaluationUnknown('installed HIA workload refusal differs from its issued case')
        reject(*refusal)
    if count != cases or size != 48 + 64 * count:
        raise EvaluationUnknown('installed HIA workload planner omitted an issued case')
    total, warmup, repetitions = struct.unpack_from('<3Q', reply, 24)
    if (total > 32 * 1024 * 1024 or warmup != workload['warmup_iterations']
            or repetitions != workload['repetitions']):
        raise EvaluationUnknown('installed HIA workload planner scope differs from the admitted workload')


def _project_native_evaluate_request(executable, catalog, arguments):
    from .hia_agent_store import decode_data, wire
    from .hia_scalar_reference_native import sealed_reference_bytes

    source = wire([catalog, arguments])
    with sealed_reference_bytes(executable) as planner:
        reply = _run_native_evaluate_planner(planner, source)
    if len(reply) < 128 or not reply.startswith(b'HIAEVQ01'):
        raise EvaluationUnknown('installed HIA Evaluate request did not issue retained dependencies')
    count, = struct.unpack_from('<Q', reply, 8)
    if not 1 <= count <= 16 or len(reply) != 112 + 16 * count:
        raise EvaluationUnknown('installed HIA Evaluate dependency count differs')

    spans = []
    for at, size in struct.iter_unpack('<2Q', reply[16:]):
        if not 0 <= at < at + size <= len(source):
            raise EvaluationUnknown('installed HIA Evaluate dependency is outside the admitted request')
        spans.append(source[at:at + size])
    if b'[' + b','.join(spans[6:]) + b']' != spans[5]:
        raise EvaluationUnknown('installed HIA Evaluate receipt order differs')
    keys = ('context', 'baseline_artifact', 'candidate_artifact', 'build_receipt',
            'request_key', 'verification_receipts')
    return {'catalog_sha256': catalog, **dict(zip(keys, map(decode_data, spans[:6]), strict=True))}


def _authorize_native_evaluate(executable, baseline, candidate, pinned, actual):
    from .hia_agent_store import wire
    from .hia_scalar_reference_native import sealed_reference_bytes

    fields = (wire(baseline['output_kind']), wire(candidate['output_kind']),
              wire(baseline['signatures']), wire(candidate['signatures']),
              b'' if pinned is None else pinned.encode('ascii'), actual.encode('ascii'))
    frame = struct.pack('<8s5Q', b'HIAEVA01', *(len(field) for field in fields[:-1]))
    with sealed_reference_bytes(executable) as planner:
        reply = _run_native_evaluate_planner(planner, frame, *fields)
    if len(reply) != 16 or not reply.startswith(b'HIAEVA02'):
        raise EvaluationUnknown('installed HIA Evaluate authority reply differs')
    flags, = struct.unpack_from('<Q', reply, 8)
    if flags not in (0, 1, 3, 7, 15, 31):
        raise EvaluationUnknown('installed HIA Evaluate authority refused its observation')
    return flags


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise EvaluationUnknown('evaluation custody belongs to its creator process')
    return _CUSTODY_LOCK


class NativeEvaluation(NativeHiaJsonImage):
    # The same representation-only six-argument arithmetic transport. The
    # corresponding HIA integer functions are part of this image, not an
    # undeclared companion image or an implicit SERVICE_CONTEXT selection.
    arithmetic = NativeServiceContextImage.arithmetic


@lru_cache(maxsize=3)
def _mapped_evaluation(raw, digest, source_digest):
    image = NativeEvaluation(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_evaluation(manifest_path):
    if not manifest_path:
        raise ValueError('evaluation selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeEvaluation)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid evaluation manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('evaluation image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('evaluation source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('evaluation image identity mismatch')
    if selected is None:
        selected = _mapped_evaluation(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeEvaluation or selected.image_sha256 != value['image_sha256']:
        raise ValueError('evaluation selection differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('evaluation selection changed during admission')
    return selected


@dataclass(frozen=True)
class EvaluationReceipt:
    port: int
    sequence: int
    phase: int
    index: int
    arm: int
    flags: int
    outcome: int
    failed: int


class EvaluationFrame:
    def __init__(self, image, service, args, *, namespace=None):
        if type(image) is not NativeEvaluation:
            raise TypeError('evaluation requires an admitted native image')
        # The original method imports these providers once on every invocation.
        # Keep later calls/patches observable; do not latch a process-wide copy.
        from .hia_agent_runner import run_native_batch, run_reference_batch
        from .hia_agent_buffers import validate_cases
        if namespace is None:
            from . import hia_agent_service
            namespace = vars(hia_agent_service)
        self.image, self.service, self.namespace = image, service, namespace
        self.run_native_batch, self.run_reference_batch = run_native_batch, run_reference_batch
        self.validate_cases = validate_cases
        self.data = {'args': args}
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = self.finished = self.unconfirmed = self.native_failed = False
        self.effect_started = False
        self._delivery = DeliveryRecord(self)
        try:
            with _custody_lock():
                # Reserve growable custody before the first effect. There is no
                # new frame-count quota or service-wide exclusion policy.
                _FRAME_CUSTODY[id(self)] = self
        except BaseException:
            self._delivery.retire()
            raise
        try:
            self.call(0)
        except BaseException:
            self._release()
            self._delivery.retire()
            raise

    def _release(self):
        with _custody_lock():
            _FRAME_CUSTODY.pop(id(self), None)

    def call(self, event, observation=0):
        if self.fenced or self.finished or os.getpid() != self.creator or threading.get_ident() != self.thread:
            raise EvaluationUnknown('evaluation frame cannot be resumed or inherited')
        if self._delivery.loss is not None:
            self.fenced = self.native_failed = self.unconfirmed = True
        self._delivery.check(EvaluationUnknown)
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, 0, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            self._delivery.enter_native()
            code = self.image._entry(source, len(raw), output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16):
                raise EvaluationUnknown('evaluation continuation return is unconfirmed')
            words = struct.unpack('<14Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw)
            expected_sequence = 1 if event == 0 else sequence if event == 1 else sequence + 1
            expected_phases = (1, 4) if event == 2 else (2,) if event == 1 else (5,) if event == 3 else (1,)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:10] != (state[3], state[4], state[5], state[8], state[9], state[2], state[11], state[12])
                    or words[10:12] != self.identity or state[6:8] != self.identity
                    or words[12:14] != (0, 0) or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] > 1 or words[7] > 7 or words[8] > 6 or words[9] > 1):
                raise EvaluationUnknown('evaluation receipt differs from the actual issued state')
            self.receipt = EvaluationReceipt(*words[2:10])
            self._delivery.confirmed(terminal=words[4] in (4, 5))
            return self.receipt
        except BaseException as error:
            self._delivery.failed(error)
            self.fenced = self.native_failed = True
            self.unconfirmed = self.effect_started
            # A transport failure is not a confirmed foreign rejection. The
            # original request wrapper catches ValueError/OSError subclasses;
            # allowing one through here could durably complete an unknown
            # effect. Preserve process-control BaseException signals while
            # keeping every ordinary native failure outside that catch set.
            if isinstance(error, Exception) and not isinstance(error, EvaluationUnknown):
                raise EvaluationUnknown('evaluation continuation observation failed') from error
            raise

    def finish(self):
        try:
            if (not self._delivery.current() or self._delivery.loss is not None
                    or self._delivery.terminal or self._delivery.retired):
                # The original owner guard determines a foreign PID/thread's
                # exception and refusal point before any ambient activation.
                return self._finish()
            # Keep implicit foreign object release/lookup between issued ports
            # on this actual invocation too. The individual effect scopes still
            # identify the precise pending observation; this ambient scope does
            # not invent an ACK obligation.
            with self._delivery.foreign(observation=False):
                return self._finish()
        except BaseException as error:
            self._delivery.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = self.unconfirmed = True
                self._delivery.propagate(error, EvaluationUnknown, request_rejections())
            raise
        finally:
            self._delivery.retire()

    def _finish(self):
        if self.finished:
            raise EvaluationUnknown('evaluation frame already completed')
        while True:
            if self.receipt.phase != 1:
                self.fenced = True
                raise EvaluationUnknown('evaluation effect is not newly issued')
            self.call(1)
            self.effect_started = self.unconfirmed = True
            try:
                with self._delivery.foreign():
                    observed = self.effect(self.receipt.port)
            except BaseException as error:
                if self.native_failed or self._delivery.loss is not None:
                    self.fenced = self.unconfirmed = True
                    self._delivery.propagate(error, EvaluationUnknown, request_rejections())
                    raise
                self.call(3)
                if self.receipt.phase != 5:
                    self.fenced = True
                    raise EvaluationUnknown('evaluation exception was not propagated')
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

    def _math(self, operation, left, right=0):
        self.data['math_left'], self.data['math_right'] = left, right
        try:
            value = self.image.arithmetic(operation, left, right)
        except BaseException as error:
            if self._delivery.loss is None:
                raise
            self.native_failed = True
            if isinstance(error, Exception) and not isinstance(error, EvaluationUnknown):
                raise EvaluationUnknown('evaluation arithmetic observation failed') from error
            raise
        if value is _INTEROP:
            # A private replacement numeric object uses its original protocol;
            # it is not silently narrowed to an integer or a new language domain.
            foreign = (operator.add, operator.sub, operator.mul, operator.floordiv,
                       operator.gt, operator.le, operator.ne, lambda a, b: max(0, a))
            value = foreign[operation - 1](left, right)
        self.data.pop('math_left')
        self.data.pop('math_right')
        return value

    def _remaining_total_ms(self):
        remaining = self._math(2, self.data['context_deadline'], self.namespace['time'].time_ns())
        return self._math(8, self._math(4, remaining, 1_000_000))

    def _run(self, cases, warmup, repetitions):
        d, api = self.data, self.namespace
        data, metadata = ((d['baseline_bytes'], d['baseline_meta']),
                          (d['candidate_bytes'], d['candidate_meta']))[self.receipt.arm]
        planner = d.get('workload_planner')
        options = {} if planner is None else {'_evaluate_planner': planner}
        if 'admission' in d:
            options['_evaluate_terminal'] = True
        return d['budget_claim'].run(self.run_native_batch, data, metadata['signatures'], cases,
            now=api['time'].monotonic_ns(), total_ms=self._remaining_total_ms(),
            warmup=int(warmup), repetitions=int(repetitions),
            memory_bytes=api['uint64'](d['context']['budget']['max_memory_bytes'], 'max_memory_bytes'), **options)

    def effect(self, port):
        """One fixed foreign operation; only HIA chooses the next port."""
        if not 1 <= port <= len(PORTS):
            raise EvaluationUnknown('evaluation issued an unknown foreign port')
        name = PORTS[port - 1]
        d, s, api = self.data, self.service, self.namespace
        args = d['args']
        label = ('baseline', 'candidate')[self.receipt.arm]
        index = self.receipt.index
        if name == 'start':
            d['started'] = api['time'].monotonic_ns()
            d['native_store'] = uses_native_store(s.store)
            d['identity'] = _native_agent_identity() if d['native_store'] else None
            if d['native_store']:
                from .hia_native_helpers import pinned_evaluate_request_executable

                request = pinned_evaluate_request_executable()
                if request is not None:
                    d['args'] = _project_native_evaluate_request(request, s.catalog_sha256, args)
        elif name == 'context':
            d['context'] = s._context(args['context'])
        elif name == 'baseline':
            d['baseline_bytes'], d['baseline_meta'], d['baseline_program'] = s._native(args['baseline_artifact'], args['context'])
        elif name == 'candidate':
            d['candidate_bytes'], d['candidate_meta'], d['candidate_program'] = s._native(args['candidate_artifact'], args['context'])
        elif name == 'build_receipt':
            d['built'] = s._build_receipt(args['build_receipt'], args['context'], args['candidate_artifact'])
            if d['native_store']:
                from .hia_native_helpers import pinned_evaluate_authority_executable

                authority = pinned_evaluate_authority_executable()
                if authority is not None:
                    d['admission'] = _authorize_native_evaluate(
                        authority, d['baseline_meta'], d['candidate_meta'],
                        d['context']['baseline_core_sha256'], d['baseline_program'].sha256)
        elif name == 'baseline_not_shared':
            if 'admission' in d:
                return int((d['admission'] & 1) == 0)
            return int(bool(d['baseline_meta']['output_kind'] != 'shared'))
        elif name == 'candidate_not_shared':
            if 'admission' in d:
                return int((d['admission'] & 2) == 0)
            return int(bool(d['candidate_meta']['output_kind'] != 'shared'))
        elif name == 'abi_equal':
            if 'admission' in d:
                return int(bool(d['admission'] & 4))
            return int(not bool(d['baseline_meta']['signatures'] != d['candidate_meta']['signatures']))
        elif name == 'baseline_pinned':
            if 'admission' in d:
                return int(bool(d['admission'] & 8))
            return int(d['context']['baseline_core_sha256'] is not None)
        elif name == 'baseline_equal':
            if 'admission' in d:
                return int(bool(d['admission'] & 16))
            return int(not bool(d['context']['baseline_core_sha256'] != d['baseline_program'].sha256))
        elif name == 'claims':
            d['objective'] = s._required_claims(d['context'], args['candidate_artifact'],
                                                args['verification_receipts'], d['baseline_program'].sha256)
        elif name == 'workload':
            if d['native_store']:
                d['workload'], d['workload_metadata'], d['workload_wire'] = s.store.get_json_with_wire(
                    d['context']['workload'])
            else:
                d['workload'], d['workload_metadata'] = s.store.get_json(d['context']['workload'])
        elif name == 'validate_workload':
            if d['native_store']:
                from .hia_agent_payload_schema_native import WORKLOAD_ROLE
                from .hia_native_helpers import pinned_evaluate_case_executable

                workload_wire = d.pop('workload_wire')
                s._validate_payload(d['workload'], workload_wire, api['WORKLOAD_SCHEMA'],
                                    'workload', WORKLOAD_ROLE)
                d['workload_planner'] = pinned_evaluate_case_executable()
                if d['workload_planner'] is not None:
                    d['workload_wire'] = workload_wire
            else:
                api['validate'](d['workload'], api['WORKLOAD_SCHEMA'], 'workload')
        elif name == 'validate_cases':
            signatures = d['baseline_meta']['signatures']
            planner = d.get('workload_planner')
            if planner is None:
                self.validate_cases(signatures, d['workload']['cases'])
            else:
                _admit_native_workload(planner, signatures, d.pop('workload_wire'), d['workload'])
        elif name == 'exports_init':
            d['export_iterator'] = iter(d['context'].get('foreign_buffer_exports', []))
            d['export_values'] = []
        elif name == 'exports_next':
            return self._next('export_iterator', 'export_value')
        elif name == 'exports_append':
            d['export_values'].append(tuple(d['export_value']))
        elif name == 'exports_finish':
            d['exports'] = tuple(d.pop('export_values'))
            d.pop('export_iterator')
            d.pop('export_value', None)
        elif name == 'collections':
            d['observations'], d['normal'], d['trapping'] = [], [], []
        elif name == 'reference_started':
            d['reference_started'] = api['time'].monotonic_ns()
        elif name == 'deadline_row':
            if d['native_store']:
                d['context_row'] = s.store.context_created(args['context']['id'])
            else:
                d['context_row'] = s.store.db.execute('SELECT created_ns FROM contexts WHERE id=?',
                                                     (args['context']['id'],)).fetchone()
        elif name == 'deadline':
            created = int(d['context_row']['created_ns'])
            budget = self._math(3, d['context']['budget']['max_total_wall_ms'], 1_000_000)
            d['context_deadline'] = self._math(1, created, budget)
        elif name == 'references_init':
            d['references'] = {}
        elif name == 'reference_run':
            program = (d['baseline_program'], d['candidate_program'])[self.receipt.arm]
            options = {'_evaluate_terminal': True} if 'admission' in d else {}
            d['reference'] = self.run_reference_batch(program, d['workload']['cases'],
                timeout_ms=self._remaining_total_ms(),
                memory_bytes=api['uint64'](d['context']['budget']['max_memory_bytes'], 'max_memory_bytes'),
                foreign_buffer_exports=d['exports'], **options)
            d['references'][label] = d['reference']
        elif name == 'reference_returned':
            return int(not bool(d['reference']['status'] != 'returned'))
        elif name == 'reference_complete':
            return int(bool(d['reference']['report']['complete']))
        elif name == 'reference_budget':
            return int(bool(d['reference']['status'] == 'budget_exceeded'))
        elif name == 'reference_report_present':
            return int(d['reference']['report'] is not None)
        elif name == 'reference_rows_init':
            d['reference_row_iterator'] = iter(d['reference']['report']['observations'])
        elif name == 'reference_rows_next':
            return self._next('reference_row_iterator', 'reference_row')
        elif name == 'reference_row_budget':
            return int(bool(d['reference_row']['status'] == 'budget_exceeded'))
        elif name == 'cases_init':
            d['case_iterator'] = iter(d['workload']['cases'])
        elif name == 'case_next':
            return self._next('case_iterator', 'case')
        elif name == 'case_expired':
            return int(bool(self._math(6, self._remaining_total_ms(), 0)))
        elif name == 'case_references':
            d['expected'] = d['references']['baseline']['report']['observations'][index]
            d['candidate_reference'] = d['references']['candidate']['report']['observations'][index]
            d['row'] = {'index': index, 'function': d['case']['function'], 'arguments': d['case']['arguments'],
                        'baseline_vm': d['expected'], 'candidate_vm': d['candidate_reference']}
            d['observations'].append(d['row'])
        elif name == 'case_budget':
            return int('budget_exceeded' in {d['expected']['status'], d['candidate_reference']['status']})
        elif name == 'expected_value':
            d['expected_value'] = api['_value_observation'](d['expected'])
        elif name == 'declared_present':
            return int('expected' in d['case'])
        elif name == 'declared_buffers':
            return int('buffers' in d['case']['expected'])
        elif name == 'declared_with_buffers':
            d['declared_scope'] = d['expected_value']
        elif name == 'declared_without_init':
            d['declared_scope'] = {}
            d['declared_iterator'] = iter(d['expected_value'].items())
        elif name == 'declared_without_next':
            return self._next('declared_iterator', 'declared_item')
        elif name == 'declared_key_buffers':
            return int(not bool(d['declared_item'][0] != 'buffers'))
        elif name == 'declared_insert':
            key, value = d['declared_item']
            d['declared_scope'][key] = value
        elif name == 'declared_equal':
            if d['identity'] is not None:
                return int(d['identity'].observation_agreement(
                    d['expected'], d['case']['expected'], mode=DECLARED_OBSERVATION))
            return int(not bool(d['case']['expected'] != d['declared_scope']))
        elif name == 'observables_equal':
            if d['identity'] is not None:
                return int(d['identity'].observation_agreement(
                    d['expected'], d['candidate_reference'], mode=REFERENCE_OBSERVATION))
            left = {'value': api['_value_observation'](d['expected']), 'first_trap': d['expected'].get('trap_code'),
                    'resources': d['expected']['ledger']['resources']}
            right = {'value': api['_value_observation'](d['candidate_reference']),
                     'first_trap': d['candidate_reference'].get('trap_code'),
                     'resources': d['candidate_reference']['ledger']['resources']}
            return int(not bool(left != right))
        elif name == 'prepared':
            d['prepared'] = {'function': d['case']['function'], 'arguments': d['case']['arguments'],
                             'expected': d['expected_value']}
        elif name == 'expected_trapped':
            return int(bool(d['expected']['status'] == 'trapped'))
        elif name == 'append_trap':
            d['trapping'].append((index, d['prepared']))
        elif name == 'append_normal':
            d['normal'].append((index, d['prepared']))
        elif name == 'reference_done':
            d['reference_ns'] = self._math(2, api['time'].monotonic_ns(), d['reference_started'])
        elif name == 'native_started':
            d['runs'], d['native_started'] = {}, api['time'].monotonic_ns()
        elif name == 'owner':
            d['owner'] = api['digest']({'tool': 'hia_evaluate', 'key': args['request_key']})
        elif name == 'claim':
            d['budget_claim'] = s.store.execution_budgets.claim(args['context']['id'], d['owner'],
                d['context']['budget']['max_native_wall_ms'], d['native_started'])
        elif name == 'arm_init':
            d['runs'][label] = {'normal': None, 'traps': [], 'total_native_ns': '0'}
        elif name == 'normal_present':
            return int(bool(d['normal']))
        elif name == 'normal_cases_init':
            d['normal_case_iterator'] = iter(d['normal'])
            d['normal_cases'] = []
        elif name == 'normal_cases_next':
            return self._next('normal_case_iterator', 'normal_case_pair')
        elif name == 'normal_cases_append':
            _index, case = d['normal_case_pair']
            d['normal_cases'].append(case)
        elif name == 'normal_run':
            d['outcome'] = self._run(d['normal_cases'], d['workload']['warmup_iterations'], d['workload']['repetitions'])
        elif name == 'normal_store':
            d['runs'][label]['normal'] = d['outcome']
        elif name == 'normal_returned':
            return int(not bool(d['outcome']['status'] != 'returned'))
        elif name == 'normal_budget':
            return int(bool(d['outcome']['status'] == 'budget_exceeded'))
        elif name == 'normal_report':
            d['report'] = d['outcome']['report']
        elif name == 'normal_completed_differs':
            return int(bool(self._math(7, d['report']['completed_cases'], len(d['normal']))))
        elif name == 'normal_observations_differ':
            return int(bool(self._math(7, len(d['report']['observations']), len(d['normal']))))
        elif name == 'normal_total':
            d['runs'][label]['total_native_ns'] = d['report']['total_native_ns']
        elif name == 'normal_observations_init':
            d['normal_observation_iterator'] = iter(zip(d['normal'], d['report']['observations']))
        elif name == 'normal_observations_next':
            return self._next('normal_observation_iterator', 'normal_observation_pair')
        elif name == 'normal_value':
            (d['normal_index'], d['normal_case']), d['observed'] = d['normal_observation_pair']
            d['value'] = api['_value_observation'](d['observed'])
        elif name == 'normal_observation_store':
            d['observations'][d['normal_index']][label + '_native'] = d['observed']
        elif name == 'normal_mismatch':
            return int(bool(d['observed']['mismatch']))
        elif name == 'normal_value_equal':
            if d['identity'] is not None:
                return int(d['identity'].observation_agreement(
                    d['observed'], d['normal_case']['expected'], mode=NATIVE_OBSERVATION))
            return int(not bool(d['value'] != d['normal_case']['expected']))
        elif name == 'traps_init':
            d['trap_iterator'] = iter(d['trapping'])
        elif name == 'trap_next':
            return self._next('trap_iterator', 'trap_pair')
        elif name == 'trap_run':
            d['trap_index'], d['trap_case'] = d['trap_pair']
            d['outcome'] = self._run([d['trap_case']], 0, 1)
        elif name == 'trap_store':
            d['runs'][label]['traps'].append({'index': d['trap_index'], **d['outcome']})
            d['observations'][d['trap_index']][label + '_native'] = {
                'status': d['outcome']['status'], 'returncode': d['outcome']['returncode']}
        elif name == 'trap_has_buffers':
            return int('buffers' in d['trap_case']['expected'])
        elif name == 'trap_buffer_store':
            d['actual_buffers'] = d['outcome'].get('buffer_snapshots', [{}])[0].get('buffers')
            d['observations'][d['trap_index']][label + '_native']['buffers'] = d['actual_buffers']
        elif name == 'trap_buffers_equal':
            return int(not bool(d['actual_buffers'] != d['trap_case']['expected']['buffers']))
        elif name == 'trap_is_trapped':
            return int(not bool(d['outcome']['status'] != 'trapped'))
        elif name == 'trap_terminal_failure':
            return int(d['outcome']['status'] in {'budget_exceeded', 'faulted', 'invalid_report'})
        elif name == 'trap_is_budget':
            return int(bool(d['outcome']['status'] == 'budget_exceeded'))
        elif name == 'claim_complete':
            d['budget_claim'].complete()
        elif name == 'native_ns':
            d['native_ns'] = d['budget_claim'].native_ns
        elif name == 'complete_count':
            return int(not bool(self._math(7, len(d['observations']), len(d['workload']['cases']))))
        elif name == 'complete_rows_init':
            d['complete_row_iterator'] = iter(d['observations'])
        elif name == 'complete_rows_next':
            return self._next('complete_row_iterator', 'complete_row')
        elif name == 'complete_row_baseline':
            return int('baseline_native' in d['complete_row'])
        elif name == 'complete_row_candidate':
            return int('candidate_native' in d['complete_row'])
        elif name == 'metric_artifact':
            return int(bool(d['objective']['metric'] == 'artifact_bytes'))
        elif name == 'measure_artifact':
            d['before'], d['after'] = len(d['baseline_bytes']), len(d['candidate_bytes'])
        elif name == 'measure_native':
            d['before'] = int(d['runs'].get('baseline', {}).get('total_native_ns', '0'))
            d['after'] = int(d['runs'].get('candidate', {}).get('total_native_ns', '0'))
        elif name == 'before_nonzero':
            return int(bool(self._math(7, d['before'], 0)))
        elif name == 'ratio':
            if d['identity'] is not None:
                # Get only the ratio and threshold observation. The enclosing
                # HIA continuation still chooses the final evaluation outcome.
                d['ratio'], decision = d['identity'].evaluation_measurement(
                    d['before'], d['after'], d['objective']['min_improvement_ratio'],
                    budget_exceeded=False, correct=True, complete=True, latency=False, trapping=False)
                d['meets_threshold'] = decision == 'improved'
            else:
                d['ratio'] = self._math(2, d['before'], d['after']) / d['before']
        elif name == 'ratio_zero':
            d['ratio'] = 0.0
        elif name == 'metric_latency':
            return int(bool(d['objective']['metric'] == 'latency_ns'))
        elif name == 'traps_present':
            return int(bool(d['trapping']))
        elif name == 'after_smaller':
            return int(bool(self._math(5, d['before'], d['after'])))
        elif name == 'ratio_threshold':
            if d['identity'] is not None:
                return int(d['meets_threshold'])
            return int(bool(d['ratio'] >= d['objective']['min_improvement_ratio']))
        elif name == 'after_greater':
            return int(bool(self._math(5, d['after'], d['before'])))
        elif name == 'measurements':
            if d['identity'] is None:
                d['measurements'] = s.store.json({'schema': 'hepta.hia.agent.measurements.v1', 'context': args['context'],
                    'workload': d['context']['workload'], 'objective': d['context']['objective'],
                    'baseline_artifact': args['baseline_artifact'], 'candidate_artifact': args['candidate_artifact'],
                    'metric': d['objective']['metric'], 'baseline_value': str(d['before']), 'candidate_value': str(d['after']),
                    'improvement_ratio': d['ratio'], 'reference_wall_ns': str(d['reference_ns']),
                    'planned_cases': len(d['workload']['cases']), 'observations': d['observations'], 'native_runs': d['runs'],
                    'reference_runs': d['references'],
                    'native_correctness_scope': 'frozen workload return/trap behavior and all external snapshot bytes; VM first-trap/resource observations recorded separately',
                    'universal_equivalence_or_native_refinement_proved': False,
                    'measurement_scope': 'same host and immutable workload, baseline then candidate; call latency includes ctypes FFI overhead; snapshot reset/hash outside call timing is included in subprocess wall cost',
                    'outcome': OUTCOMES[self.receipt.outcome], 'planned_workload_complete': bool(self.receipt.flags & 2)}, 'measurements')
            else:
                raw = d['identity'].measurement_record(
                    args, d['context'], before=d['before'], after=d['after'], ratio=d['ratio'],
                    scope=self._measurement_scope(d['runs']), metric=d['objective']['metric'],
                    native_runs=d['runs'], observations=d['observations'],
                    outcome=OUTCOMES[self.receipt.outcome], planned_cases=len(d['workload']['cases']),
                    complete=bool(self.receipt.flags & 2), reference_runs=d['references'],
                    reference_ns=d['reference_ns'])
                d['measurements'] = s.store.put(raw, 'measurements')
        elif name == 'costs':
            d['costs'] = s._cost_ledger(d['context'], self._math(2, api['time'].monotonic_ns(), d['started']), d['native_ns'])
        elif name == 'ledger':
            from .hia_agent_service import _retain_cost_ledger
            d['ledger'] = _retain_cost_ledger(s.store, d['costs'])
        elif name == 'receipt':
            if d['identity'] is None:
                d['evaluation_receipt'] = s.store.json({'schema': 'hepta.hia.agent.evaluation.v1', 'context': args['context'],
                    'installation': s.identities, 'baseline_artifact': args['baseline_artifact'],
                    'candidate_artifact': args['candidate_artifact'], 'baseline_core_sha256': d['baseline_program'].sha256,
                    'candidate_core_sha256': d['candidate_program'].sha256, 'build_receipt': args['build_receipt'],
                    'verification_receipts': args['verification_receipts'], 'report_complete': True,
                    'planned_workload_complete': bool(self.receipt.flags & 2), 'termination_confirmed': True,
                    'outcome': OUTCOMES[self.receipt.outcome], 'measurements': d['measurements'], 'full_cost_ledger': d['ledger'],
                    'net_optimization_benefit_proved': False, 'adopted': False}, 'evaluation-receipt')
            else:
                raw = d['identity'].evaluation_record(args, d['baseline_program'].sha256,
                    d['candidate_program'].sha256, s.identities, d['measurements'], d['ledger'],
                    OUTCOMES[self.receipt.outcome], bool(self.receipt.flags & 2))
                d['evaluation_receipt'] = s.store.put(raw, 'evaluation-receipt')
        elif name == 'result':
            if d['identity'] is None:
                d['result'] = {'baseline_artifact': args['baseline_artifact'], 'candidate_artifact': args['candidate_artifact'],
                    'evaluation_receipt': d['evaluation_receipt'], 'report_complete': True,
                    'planned_workload_complete': bool(self.receipt.flags & 2), 'termination_confirmed': True,
                    'outcome': OUTCOMES[self.receipt.outcome], 'measurements': d['measurements'],
                    'full_cost_ledger': d['ledger'], 'adopted': False}
            else:
                d['result'] = d['identity'].evaluation_result(args, d['evaluation_receipt'],
                    d['measurements'], d['ledger'], OUTCOMES[self.receipt.outcome], bool(self.receipt.flags & 2))
        elif name == 'reject_profile':
            api['reject']('E_HIA_EXECUTION_PROFILE', 'evaluation requires retained direct shared images', 'execution')
        elif name == 'reject_abi':
            api['reject']('E_HIA_ABI', 'baseline and candidate frozen public ABI differ', 'execution')
        elif name == 'reject_baseline':
            api['reject']('E_HIA_BASELINE', 'evaluation baseline differs from the frozen Core snapshot', 'execution')
        elif name == 'reject_expected':
            api['reject']('E_HIA_WORKLOAD_EXPECTATION',
                'declared case expectation differs from baseline Core at index ' + str(index), 'execution')
        elif name == 'reject_report':
            api['reject']('E_HIA_NATIVE_REPORT', 'native report did not account for every planned case', 'execution')
        else:
            raise EvaluationUnknown('evaluation object port is not implemented')
        return 0

    @staticmethod
    def _measurement_scope(runs):
        outcomes = [result for run in runs.values() for result in (run['normal'], *run['traps'])
                    if result is not None]
        prefix = 'same host and immutable workload, baseline then candidate; '
        snapshot = 'snapshot reset/hash outside call timing is included in subprocess wall cost'
        if outcomes and all(result.get('direct_call_executable_sha256') for result in outcomes):
            scopes = {run['normal']['report']['timing_scope'] for run in runs.values()
                      if run['normal'] and run['normal']['report'] is not None}
            return '; '.join((prefix + snapshot, *sorted(scopes)))
        return prefix + 'call latency includes ctypes FFI overhead; ' + snapshot


def unconfirmed_evaluation_count():
    with _custody_lock():
        return sum(frame.unconfirmed for frame in _FRAME_CUSTODY.values() if frame.creator == os.getpid())
