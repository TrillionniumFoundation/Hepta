"""A disposable scalar / owned-byte-snapshot native runner.

HIA tools pass only reverified retained images and server-derived signatures.
Every child has an address-space/CPU limit, a wall deadline, its own process
group, and Linux parent-death SIGKILL. No native program runs in the worker.
"""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
from hashlib import sha256
from io import BytesIO
import json
import math
import mmap
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import sys
import tempfile
import time

from .hia_agent_store import AgentRejected, _native_agent_identity, reject, stable_read, wire
from .hia_agent_buffers import (PROFILE as BUFFER_PROFILE, buffer_bytes,
                               buffer_observation, validate_arguments, validate_cases)
from .hia_native_byte_abi import LOANS
from .hia_program_tools import HIAEditRejected

_REPORT_LIMIT = 2 << 20
_REPORT_TOO_LARGE = 65
_ROW_START = 16 << 10
_REPORT_BUDGET_ERRORS = frozenset({
    'JSON input exceeds node/byte budget',
    'JSON container exceeds queued-node/byte budget',
    'JSON integer exceeds byte budget',
    'JSON string exceeds byte budget before encoding',
    'JSON key exceeds numeric byte budget',
    'JSON key exceeds byte budget',
    'JSON encoding exceeds byte budget',
})


_CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16,
    "u16": ctypes.c_uint16, "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
    "i64": ctypes.c_int64, "u64": ctypes.c_uint64, "isize": ctypes.c_int64,
    "usize": ctypes.c_uint64, "bool": ctypes.c_uint8}


def _reference_batch_receipt(artifact_hash, cases, observations, warmup, repetitions,
                             evaluator, standalone, owned):
    report = {"schema": "hepta.hia.agent.reference-observation.v1",
        "artifact_sha256": artifact_hash,
        "complete": len(observations) == len(cases) and
            all(row["status"] != "budget_exceeded" for row in observations),
        "planned_cases": len(cases), "completed_cases": len(observations),
        "warmup": warmup, "repetitions": repetitions,
        "observations": observations, "native_code_executed": False}
    if evaluator is not None:
        report["reference_evaluator_sha256"] = evaluator.image_sha256
    if standalone is not None:
        report["reference_executable_sha256"], report["reference_standalone_calls"] = standalone
    if owned is not None:
        report["owned_reference_executable_sha256"], report["owned_reference_standalone_calls"] = owned
    return report


def _child_setup(parent_pid, memory_bytes, cpu_seconds):
    # Runs after exec, never in a fork preexec hook: consumer threads cannot
    # deadlock on a lock inherited from another thread. Checking PPID after
    # prctl also closes parent death before this fixed runner's initialization.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        os._exit(125)
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # RLIMIT_CORE=0 alone does not suppress a piped Linux core_pattern handler.
    # Real UD2 traps must be observed within the existing deadline, without a
    # crash collector retaining native input/output mappings after termination.
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        os._exit(125)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))


def _cancel_runner(proc, *, has_reference_child):
    if has_reference_child:
        # Let the coordinator reap its observer before it exits. Killing both
        # at once can orphan a zombie inside the owned process group.
        proc.terminate()
        try:
            return proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return proc.communicate(timeout=5)


def _end_reference_runner(_signal, _frame):
    raise SystemExit(124)


def _observation_wire(row, available):
    if available < 0:
        return None
    cap = min(available, _ROW_START)
    while True:
        try:
            return wire(row, maximum=cap)
        except HIAEditRejected as error:
            if str(error).removeprefix('E_HIA_EDIT: ') not in _REPORT_BUDGET_ERRORS:
                raise
            if cap == available:
                return None
            cap = min(available, cap * 2)


def _write_child_report(report, stream):
    """Preserve the canonical receipt without an 8 MiB serializer workspace."""
    envelope = wire({**report, 'observations': []}, maximum=_ROW_START)
    before, marker, after = envelope.partition(b'"observations":[')
    if not marker or not after.startswith(b']') or marker in after:
        raise ValueError('native report envelope has no unique observation sequence')
    remaining = _REPORT_LIMIT - len(envelope) - 1  # Include the final newline.
    stream.write(before + marker)
    for index, row in enumerate(report['observations']):
        separator = b',' if index else b''
        row_bytes = _observation_wire(row, remaining - len(separator))
        if row_bytes is None:
            return _REPORT_TOO_LARGE
        stream.write(separator + row_bytes)
        remaining -= len(row_bytes) + len(separator)
    stream.write(after + b'\n')
    return 0


def _snapshot_fd(record, custody):
    fd = os.open(record['path'], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    custody.callback(os.close, fd)
    return fd


class _EvaluateCall:
    """Retain one HIA-issued case plan until its native owner has finished."""

    def __init__(self, planner, signature, case, deadline):
        from .hia_evaluation_native import EvaluationUnknown, _run_native_evaluate_planner

        self.invoke = _run_native_evaluate_planner
        self.planner = planner
        self.deadline = deadline
        self.source = b'[' + wire({case['function']: signature}) + b',' + wire(case) + b']'
        self.plan = self.invoke(planner, self.source, deadline=deadline)
        if len(self.plan) < 80 or not self.plan.startswith(b'HIAEVC01'):
            raise EvaluationUnknown('installed HIA Evaluate case plan identity differs')
        status, count, _return_role, _bytes, loans = struct.unpack_from('<5Q', self.plan, 8)
        if status or count > 128 or loans > 8 or len(self.plan) != 80 + 48 * count:
            raise EvaluationUnknown('installed HIA Evaluate case plan differs from its admitted scope')
        self.count, self.loans = count, loans

    def snapshots(self):
        from .hia_evaluation_native import EvaluationUnknown

        for argument in range(self.count):
            role, size = struct.unpack_from('<2Q', self.plan, 80 + 48 * argument)
            if role == 0:
                continue
            frame = struct.pack('<8s2Q', b'HIAEVB01', argument, len(self.plan))
            material = self.invoke(self.planner, frame, self.plan, self.source, deadline=self.deadline)
            binding = struct.pack('<8s3Q', b'HIAEVS01', argument, role, size)
            if (role not in (1, 2) or not material.startswith(binding)
                    or len(material) != 32 + max(1, size)
                    or size == 0 and material[32:] != b'\0'):
                raise EvaluationUnknown('installed HIA Evaluate snapshot differs from its issued extent')
            yield argument, 'readbuf' if role == 1 else 'mutbuf', material[32:32 + size]

    def bind(self, memory, cpu, artifact, artifact_bytes, warmup, repetitions, descriptors):
        from .hia_evaluation_native import EvaluationUnknown

        if len(descriptors) != self.loans:
            raise EvaluationUnknown('installed HIA Evaluate loan custody differs from its issued plan')
        frame = struct.pack('<8s9Q', b'HIAEVR01', os.getpid(), memory, cpu, artifact, artifact_bytes,
                            warmup, repetitions, self.loans, len(self.plan))
        loans = struct.pack(f'<{self.loans}Q', *descriptors)
        result = self.invoke(self.planner, frame, loans, self.plan, self.source, deadline=self.deadline)
        if len(result) < 105 or not result.startswith(b'HIADRX02'):
            raise EvaluationUnknown('installed HIA Evaluate runner packet identity differs')
        return result


def _direct_call_transport(signature, case, files, artifact, artifact_size, runner, custody,
                           memory_bytes, cpu_seconds, protocol, warmup, repetitions, prepare, planned=None):
    """Give the pinned HIA runner sealed code and only its per-call backing files."""
    command = ['/proc/self/fd/' + str(runner)]
    if planned is not None:
        loans = tuple(_snapshot_fd(record, custody) for record in files)
        payload = planned.bind(memory_bytes, cpu_seconds, artifact, artifact_size, warmup, repetitions, loans)
        return command, payload, {'pass_fds': (artifact, runner, *loans), 'env': {'PATH': ''}}
    descriptors = [artifact, runner]
    records = {row['argument']: row for row in files}
    arguments = []
    for index, (typ, value) in enumerate(zip(signature['params'], case['arguments'])):
        if typ not in LOANS:
            arguments.append((0, int(value) % (1 << 64), 0))
            continue
        record = records[index]
        fd = _snapshot_fd(record, custody)
        descriptors.append(fd)
        arguments.append((1 if typ == 'readbuf' else 2, fd, record['byte_length']))
    function = case['function'].encode('ascii')
    payload = prepare(protocol, function, arguments, parent=os.getpid(), memory=memory_bytes, cpu=cpu_seconds,
                      artifact=artifact, artifact_bytes=artifact_size, borrowed=signature.get('abi') == BUFFER_PROFILE,
                      returns=signature['returns'], expected='expected' in case, warmup=warmup, repetitions=repetitions)
    return command, payload, {'pass_fds': tuple(descriptors), 'env': {'PATH': ''}}


def _reference_direct_call_request(protocol, function, arguments, *, parent, memory, cpu,
                                   artifact, artifact_bytes, borrowed, returns, expected, warmup, repetitions):
    from .hia_opcodes import WIDTHS

    words, loans = [], []
    for role, value, size in arguments:
        if role == 0:
            words.append(value)
        else:
            loans.extend((len(words), value, size))
            if protocol >= 2:
                loans.append(int(role == 1))
            words.extend((0, size))
    magic = b'HIADRX02' if protocol >= 2 else b'HIADRX01'
    payload = struct.pack('<8s8Q', magic, parent, memory, cpu, artifact, artifact_bytes,
                          len(words), len(loans) // (4 if protocol >= 2 else 3), len(function))
    if protocol >= 2:
        bits = (64 if borrowed else
                WIDTHS.get(returns[0], 8 if returns == ['bool'] else 0) if returns else 0)
        payload += struct.pack('<4Q', warmup, repetitions, int(expected), (1 << bits) - 1)
    return payload + struct.pack(f'<{len(words) + len(loans)}Q', *words, *loans) + function


def _run_owned_process(command, payload, *, cwd, timeout, has_reference_child=False, **options):
    proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True, **options)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout, stderr = _cancel_runner(proc, has_reference_child=has_reference_child)
    except BaseException:
        _cancel_runner(proc, has_reference_child=has_reference_child)
        raise
    # Never claim a complete outcome while an owned process group exists.
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return proc.returncode, stdout, stderr, timed_out
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    reject("E_HIA_TERMINATION_UNKNOWN", "native process-group termination is not confirmed",
           "execution", retry_action="observe_original")


class _ReferenceStopped(Exception):
    def __init__(self, returncode, stderr, timed_out):
        self.result = returncode, b'', stderr, timed_out


class _IsolatedReference:
    """An already selected HIA image, one isolated native process per invocation."""
    direct_only = True

    def __init__(self, fd, memory_bytes, cpu_seconds, deadline, target=None, supervisor=None):
        self.fd = fd
        self.target = target
        self.supervisor = supervisor
        self.memory_bytes = memory_bytes
        self.cpu_seconds = cpu_seconds
        self.deadline = deadline
        self.calls = 0

    def remaining(self):
        return (self.deadline - time.monotonic_ns()) / 1_000_000_000

    def run(self, payload):
        timeout = self.remaining()
        if timeout <= 0:
            raise _ReferenceStopped(0 if self.calls else None, b'', True)
        descriptors = (self.fd,) if self.target is None else (self.fd, self.target)
        root = Path(__file__).resolve().parent.parent
        if self.supervisor is None:
            command = ['/proc/self/fd/' + str(self.fd), str(os.getpid()),
                       str(self.memory_bytes), str(self.cpu_seconds)]
            if self.target is not None:
                command.append(str(self.target))
            returncode, stdout, stderr, timed_out = _run_owned_process(
                command, payload, cwd=root, timeout=timeout, pass_fds=descriptors, env={'PATH': ''})
        else:
            returncode, stdout, stderr, timed_out = _observe_native_direct_owner(
                ['/proc/self/fd/' + str(self.supervisor)], payload, cwd=root, deadline=self.deadline,
                pass_fds=(self.supervisor, *descriptors), env={'PATH': ''},
                reference=(self.fd, self.memory_bytes, self.cpu_seconds, self.target or 0))
        if self.target is not None and returncode == 3 and not timed_out and not stdout and not stderr:
            self.calls += 1
            return None
        if timed_out or returncode != 0 or stderr:
            raise _ReferenceStopped(returncode or 125, stderr, timed_out)
        self.calls += 1
        return stdout


def _direct_reference_program(artifact_bytes, cases, exports, *, owned=False):
    """Admit complete closed wire programs before allowing an in-worker observer."""
    from .hia_agent_buffers import normalize_exports
    from .hia_opcodes import RESOURCES
    from .hia_program import scalar_value_valid, verify_program
    from .hia_program_tools import decode_json
    from .hia_scalar_reference_wire import MAX_PACKET_BYTES, selected_program_wire
    try:
        program = verify_program(decode_json(artifact_bytes))
        functions = {fn['name']: fn for fn in program.as_dict()['functions']}
        entries = program.scalar_entrypoints
        exports = normalize_exports(exports, program)
        borrowed = dict(exports)
        admitted = []
        for case in cases:
            name, arguments = case['function'], case['arguments']
            if (type(name) is not str or name not in entries and name not in borrowed
                    or type(arguments) not in (list, tuple)):
                return None
            function = functions[name]
            kinds = tuple(param['type'] for param in function['params'])
            arguments = tuple(value.copy() if type(value) is dict else value for value in arguments)
            suffix_bytes = 8 * len(arguments)
            loans = sum(kind in LOANS for kind in kinds)
            if name in borrowed:
                extent = validate_arguments({'params': kinds, 'abi': BUFFER_PROFILE,
                                             'max_buffer_bytes': borrowed[name]}, arguments)
                suffix_bytes += 8 + 24 * loans + extent
            elif len(kinds) != len(arguments) or not all(
                    scalar_value_valid(value, kind) for kind, value in zip(kinds, arguments)):
                return None
            packed = selected_program_wire(program.canonical_bytes, name, allow_resources=True)
            if packed is None:
                return None
            if packed[4] or loans:
                if not owned or any(kind in RESOURCES for kind in packed[3]):
                    return None
                suffix_bytes += 16  # Heap limit and allocation-injection index.
            if len(packed[0]) + suffix_bytes > MAX_PACKET_BYTES:
                return None
            admitted.append({'function': name, 'arguments': arguments})
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return None
    return program, admitted, exports


def _run_reference_direct(admitted, artifact_hash, executable, owned, evaluator,
                          memory_bytes, timeout_ms, warmup, repetitions, owned_capable):
    from .hia_agent_service import _vm_observation
    from .hia_native_helpers import pinned_direct_call_executable, pinned_direct_call_protocol
    from .hia_scalar_reference_native import sealed_reference_bytes, use_direct_reference

    program, cases, exports = admitted
    observations = []
    with ExitStack() as custody:
        fd = custody.enter_context(sealed_reference_bytes(executable[0]))
        supervisor = None
        if pinned_direct_call_protocol() >= 5:
            owner = pinned_direct_call_executable()
            if owner is None:
                reject("E_HIA_TERMINATION_UNKNOWN", "native reference owner is missing", "execution",
                       retry_action="observe_original")
            supervisor = custody.enter_context(sealed_reference_bytes(owner[0]))
        cpu_seconds = max(1, math.ceil(timeout_ms / 1000))
        deadline = time.monotonic_ns() + math.ceil(timeout_ms * 1_000_000)
        runner = _IsolatedReference(fd, memory_bytes, cpu_seconds, deadline, supervisor=supervisor)
        owned_runner = None
        if owned_capable:
            target = custody.enter_context(sealed_reference_bytes(owned[0]))
            owned_runner = _IsolatedReference(fd, memory_bytes, cpu_seconds, deadline,
                                              target=target, supervisor=supervisor)
        try:
            with use_direct_reference(evaluator, runner, owned_runner):
                for case in cases:
                    observation = _vm_observation(program, case, foreign_buffer_exports=exports)
                    observations.append(observation)
                    if observation['status'] == 'budget_exceeded':
                        break
        except _ReferenceStopped as stopped:
            returncode, stdout, stderr, timed_out = stopped.result
            return (0 if returncode is None and observations else returncode), stdout, stderr, timed_out
        report = _reference_batch_receipt(artifact_hash, cases, observations, warmup, repetitions,
            evaluator, (executable[1], runner.calls), (owned[1], owned_runner.calls if owned_runner else 0)
            if owned is not None else None)
        stream = BytesIO()
        status = _write_child_report(report, stream)
        if runner.remaining() <= 0:
            return 0 if observations else None, b'', b'', True
    return status, stream.getvalue(), b'', False


def _run_direct_cases(artifact_bytes, executable, signatures, cases, snapshot_files, cwd,
                      memory_bytes, deadline, protocol, warmup, repetitions, plans=None):
    from .hia_evaluation_native import EvaluationPlanningExpired
    from .hia_scalar_reference_native import sealed_reference_bytes

    native = _native_agent_identity()
    check_capture = _reference_direct_capture if native is None else native.direct_call_capture
    prepare = _reference_direct_call_request if native is None else native.direct_call_request
    receipts, stdout, stderr = [], bytearray(), bytearray()
    returncode, timed_out = None, False
    with (sealed_reference_bytes(artifact_bytes) as artifact, sealed_reference_bytes(executable) as runner):
        for index, (case, files) in enumerate(zip(cases, snapshot_files, strict=True)):
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                timed_out = True
                break
            cpu_seconds = (remaining + 999_999_999) // 1_000_000_000
            with ExitStack() as descriptors:
                try:
                    command, payload, options = _direct_call_transport(signatures[case['function']], case, files,
                        artifact, len(artifact_bytes), runner, descriptors, memory_bytes, cpu_seconds,
                        protocol, warmup, repetitions, prepare, plans[index] if plans is not None else None)
                except EvaluationPlanningExpired:
                    timed_out = True
                    break
                if plans is not None and time.monotonic_ns() >= deadline:
                    timed_out = True
                    break
                if protocol >= 4:
                    child_code, out, err, timed_out = _observe_native_direct_owner(
                        command, payload, cwd=cwd, deadline=deadline, **options)
                    if child_code is not None:
                        returncode = child_code
                else:
                    returncode, out, err, timed_out = _run_owned_process(command, payload, cwd=cwd,
                        timeout=max(0, (deadline - time.monotonic_ns()) / 1_000_000_000), **options)
            stdout.extend(out)
            stderr.extend(err)
            decision = check_capture(protocol, returncode, timed_out, len(stdout), len(stderr), _REPORT_LIMIT, out)
            if decision != 1:
                if decision == 2:
                    returncode = _REPORT_TOO_LARGE
                break
            receipts.append(out)
    return returncode, stdout, stderr, timed_out, receipts


def _observe_native_direct_owner(command, payload, *, cwd, deadline, pass_fds, env, reference=None):
    read_status, write_status = os.pipe2(os.O_CLOEXEC)
    try:
        with ExitStack() as custody:
            custody.callback(os.close, write_status)
            request = struct.pack('<8s3Q', b'HIADRS01', os.getpid(), deadline, write_status)
            if reference is None:
                arguments = [*command, '--supervise']
                payload = request + payload
            else:
                from .hia_scalar_reference_native import sealed_reference_bytes

                control = custody.enter_context(sealed_reference_bytes(request + struct.pack('<4Q', *reference)))
                arguments = [*command, '--supervise-at', str(control)]
                pass_fds = (*pass_fds, control)
            # The native owner enforces the exact absolute deadline. The
            # transport grace is only for delivering its already reaped status.
            timeout = max(0, (deadline - time.monotonic_ns()) / 1_000_000_000) + 1
            owner_code, stdout, stderr, timed_out = _run_owned_process(
                arguments, payload, cwd=cwd, timeout=timeout,
                pass_fds=(*pass_fds, write_status), env=env, has_reference_child=True)
        receipt = os.read(read_status, 25)
    finally:
        os.close(read_status)
    if owner_code != 0 or timed_out or len(receipt) != 24:
        reject("E_HIA_TERMINATION_UNKNOWN", "native direct process ownership is not confirmed",
               "execution", retry_action="observe_original")
    magic, code, stopped = struct.unpack('<8sqQ', receipt)
    if magic == b'HIADRT01' and code == -256 and stopped == 1 and not stdout and not stderr:
        return None, b'', b'', True
    if magic != b'HIADRT01' or not -64 <= code <= 255 or stopped not in (0, 1):
        reject("E_HIA_TERMINATION_UNKNOWN", "invalid native direct process receipt",
               "execution", retry_action="observe_original")
    return code, stdout, stderr, bool(stopped)


def _reference_direct_capture(protocol, returncode, timed_out, stdout_size, stderr_size, limit, raw):
    if timed_out or returncode != 0 or stdout_size > limit or stderr_size > 65536:
        return 0
    expect = (32, b'HIADRR02') if protocol >= 2 else (24, b'HIADRR01')
    return 1 if (len(raw), raw[:8]) == expect else 2


def _direct_observation(raw, signature, case, external, protocol, decode_receipt):
    borrowed = signature.get('abi') == BUFFER_PROFILE
    observation, duration, variation = decode_receipt(raw, protocol, signature['returns'], borrowed=borrowed)
    if borrowed:
        observation['buffers'] = [row for row, _initial_unchanged in external]
    changed_readonly = any(row['kind'] == 'readbuf' and not unchanged for row, unchanged in external)
    mismatch = bool(variation) or changed_readonly or 'expected' in case and case['expected'] != observation
    return {**observation, 'mismatch': mismatch, 'elapsed_ns': str(duration)}


def _reference_direct_receipt(raw, protocol, returns, *, borrowed):
    from .hia_opcodes import WIDTHS

    if len(raw) != (32 if protocol >= 2 else 24):
        raise ValueError('direct HIA call returned an invalid receipt extent')
    magic, value, duration = struct.unpack_from('<8sQQ', raw)
    variation = struct.unpack_from('<Q', raw, 24)[0] if protocol >= 2 else 0
    if magic != (b'HIADRR02' if protocol >= 2 else b'HIADRR01') or variation > 1:
        raise ValueError('direct HIA call returned an invalid receipt identity')
    if borrowed:
        status, value = value >> 32, value & 0xffffffff
        if status > 4:
            raise ValueError('direct HIA call returned an invalid borrowed-byte ABI status')
        observation = ({'status': 'abi_rejected', 'abi_status': status} if status else
                       {'status': 'returned', 'values': [value]})
    elif not returns or returns == ['unit']:
        observation = {'status': 'returned', 'values': [None] if returns else []}
    elif returns == ['bool']:
        observation = {'status': 'returned', 'values': [bool(value & 255)]}
    else:
        typ = returns[0]
        width = WIDTHS[typ]
        value %= 1 << width
        if typ.startswith('i') and value >= 1 << (width - 1):
            value -= 1 << width
        observation = {'status': 'returned', 'values': [value]}
    return observation, duration, variation


def _direct_call_report(receipts, signatures, submissions, snapshots, initial_digests,
                        artifact_hash, executable_hash, protocol, warmup, repetitions):
    native = _native_agent_identity()
    decode_receipt = _reference_direct_receipt if native is None else native.direct_call_receipt
    observations = []
    for index, (raw, case, snapshot) in enumerate(zip(receipts, submissions, snapshots, strict=True)):
        external = [(row, row['sha256'] == initial_digests.get((index, row['argument'])))
                    for row in snapshot['buffers']]
        observations.append(_direct_observation(raw, signatures[case['function']], case, external,
                                                protocol, decode_receipt))
    cases = len(submissions)
    return {'schema': 'hepta.hia.agent.native-observation.v1', 'artifact_sha256': artifact_hash,
            'complete': True, 'planned_cases': cases, 'completed_cases': cases, 'warmup': warmup,
            'repetitions': repetitions, 'measured_calls': repetitions * cases,
            'total_native_ns': str(sum(int(row['elapsed_ns']) for row in observations)),
            'observations': observations, 'direct_call_executable_sha256': executable_hash,
            'timing_scope': 'native SysV calls measured inside standalone HIA processes; snapshot reset and hashing outside call timing'}


def _reference_runner_terminal(returncode, timed_out, stdout_size, stderr_size, limit):
    if stdout_size > limit or stderr_size > 65536 or returncode == _REPORT_TOO_LARGE:
        return 'invalid_report'
    if timed_out or returncode == -signal.SIGXCPU:
        return 'budget_exceeded'
    if returncode == -signal.SIGABRT:
        return 'trapped'
    return 'faulted' if returncode != 0 else None


def run_native_batch(artifact_bytes, signatures, cases, *, warmup=0, repetitions=1,
                     timeout_ms=30000, memory_bytes=256 * 1024 * 1024, _mode="native",
                     foreign_buffer_exports=(), capture_buffers=False, _evaluate_planner=None,
                     _evaluate_terminal=False):
    if sys.platform != "linux" or not 64 * 1024 * 1024 <= memory_bytes <= 4 * 1024 * 1024 * 1024:
        reject("E_HIA_EXECUTION_PROFILE", "native execution requires Linux and 64 MiB..4 GiB address-space budget")
    if timeout_ms <= 0:
        return {"status": "budget_exceeded", "termination_confirmed": True,
                "started": False, "wall_ns": "0", "returncode": None, "report": None}
    classify = _reference_runner_terminal
    if _evaluate_terminal:
        identity = _native_agent_identity()
        if identity is None:
            from .hia_evaluation_native import EvaluationUnknown

            raise EvaluationUnknown('installed HIA Evaluate terminal authority is missing')
        classify = identity.runner_terminal
    if _mode == "native" and _evaluate_planner is None:
        validate_cases(signatures, cases)
    if capture_buffers and len(cases) != 1:
        reject("E_HIA_BUFFER_CAPTURE", "buffer capture requires one owned synchronous invocation")
    artifact_hash = sha256(artifact_bytes).hexdigest()
    started = time.monotonic_ns()
    from .hia_evaluation_native import EvaluationPlanningExpired
    from .hia_native_helpers import (
        pinned_direct_call_executable, pinned_direct_call_protocol, pinned_owned_reference_executable,
        pinned_reference_executable,
    )
    from .hia_scalar_reference_native import (
        ISOLATED_OWNED_MARKER, sealed_reference_bytes, selected_scalar_reference,
    )
    reference_evaluator = selected_scalar_reference() if _mode == "reference" else None
    executables = []
    if reference_evaluator is not None:
        executables = (
            ('reference_executable', 'reference_standalone_calls', pinned_reference_executable()),
            ('owned_reference_executable', 'owned_reference_standalone_calls', pinned_owned_reference_executable()),
        )
    isolated_reference = None
    if executables and executables[0][2] is not None and 1 <= len(cases) <= 512:
        scalar_executable, owned_executable = (binding for _, _, binding in executables)
        version = reference_evaluator.isolated_standalone_version(scalar_executable[0])
        owned_admitted = owned_executable is not None and owned_executable[0].startswith(b'\x7fELF')
        owned_capable = version >= 2 and owned_admitted and ISOLATED_OWNED_MARKER in owned_executable[0][:4096]
        if version and (owned_executable is None or owned_admitted):
            isolated_reference = _direct_reference_program(
                artifact_bytes, cases, foreign_buffer_exports, owned=owned_capable)
    direct_protocol = pinned_direct_call_protocol() if _mode == 'native' else 1
    one_call = warmup == 0 and repetitions == 1
    supported_repeat = direct_protocol >= 2 and 0 <= warmup <= 100 and 1 <= repetitions <= 10000
    supported_cases = len(cases) == 1 or direct_protocol >= 3 and 1 <= len(cases) <= 512
    direct_call = (pinned_direct_call_executable()
                   if _mode == 'native' and supported_cases and (one_call or supported_repeat) else None)
    if _evaluate_planner is not None and (direct_call is None or direct_protocol != 5):
        from .hia_evaluation_native import EvaluationUnknown

        raise EvaluationUnknown('installed HIA Evaluate planner requires the pinned native call owner')
    deadline = started + math.ceil(timeout_ms * 1_000_000) if direct_call is not None else None
    has_reference_child = any(executable is not None for _, _, executable in executables)
    with (tempfile.TemporaryDirectory(prefix="hia-agent-run-") as directory,
          ExitStack() as custody):
        artifact = Path(directory) / "program.so"
        if direct_call is None and isolated_reference is None:
            with artifact.open("xb") as stream:
                stream.write(artifact_bytes)
            artifact.chmod(0o400)
        planner = None if _evaluate_planner is None else custody.enter_context(sealed_reference_bytes(_evaluate_planner))
        plans = None if planner is None else []
        snapshot_files, initial_digests = [], {}
        for index, case in enumerate(cases):
            files = []
            if _mode == "native":
                signature = signatures[case["function"]]
                try:
                    if planner is None:
                        snapshots = ((i, typ, buffer_bytes(value)) for i, (typ, value) in
                                     enumerate(zip(signature["params"], case["arguments"])) if typ in LOANS)
                    else:
                        plan = _EvaluateCall(planner, signature, case, deadline)
                        plans.append(plan)
                        snapshots = plan.snapshots()
                    for argument, typ, data in snapshots:
                        if direct_call is not None and typ == 'readbuf':
                            initial_digests[index, argument] = sha256(data).hexdigest()
                        path = Path(directory) / ("buffer-" + str(index) + "-" + str(argument))
                        with path.open("xb") as stream:
                            stream.write(data if data else b"\0")
                        path.chmod(0o600)
                        files.append({"argument": argument, "kind": typ, "byte_length": len(data), "path": str(path)})
                except EvaluationPlanningExpired:
                    return {"status": "budget_exceeded", "termination_confirmed": True, "started": False,
                            "wall_ns": str(time.monotonic_ns() - started), "returncode": None, "report": None}
            snapshot_files.append(files)
        request = {"artifact": str(artifact), "artifact_sha256": artifact_hash,
                   "artifact_bytes": len(artifact_bytes),
                   "signatures": signatures, "cases": cases,
                   "warmup": warmup, "repetitions": repetitions, "mode": _mode,
                   "foreign_buffer_exports": [list(pair) for pair in foreign_buffer_exports],
                   "snapshot_files": snapshot_files}
        process_options = {}
        if reference_evaluator is not None and isolated_reference is None:
            fd = custody.enter_context(reference_evaluator.sealed_descriptor())
            request["scalar_reference"] = {"fd": fd, "sha256": reference_evaluator.image_sha256}
            process_options["pass_fds"] = (fd,)
        for name, _, executable in executables:
            if executable is None or isolated_reference is not None:
                continue
            executable_bytes, digest = executable
            fd = custody.enter_context(sealed_reference_bytes(executable_bytes))
            request[name] = {"fd": fd, "sha256": digest}
            process_options["pass_fds"] += (fd,)
        runner_root = Path(__file__).resolve().parent.parent
        if isolated_reference is not None:
            returncode, stdout, stderr, timed_out = _run_reference_direct(
                isolated_reference, artifact_hash, scalar_executable, owned_executable,
                reference_evaluator, memory_bytes, timeout_ms, warmup, repetitions, owned_capable)
        elif direct_call is not None:
            returncode, stdout, stderr, timed_out, direct_receipts = _run_direct_cases(
                artifact_bytes, direct_call[0], signatures, cases, snapshot_files, runner_root,
                memory_bytes, deadline, direct_protocol, warmup, repetitions, plans)
        else:
            payload = wire(request)
            cpu_seconds = max(1, math.ceil(timeout_ms / 1000))
            command = [sys.executable, "-B", "-E", "-s", "-m", "hepta.hia_agent_runner",
                       str(os.getpid()), str(memory_bytes), str(cpu_seconds)]
            returncode, stdout, stderr, timed_out = _run_owned_process(command, payload, cwd=runner_root,
                timeout=timeout_ms / 1000, has_reference_child=has_reference_child, **process_options)
        # Read parent-created backing files only after terminal ownership is
        # confirmed. A trap must not hide writes that happened before it.
        snapshots, captured = [], []
        for index, files in enumerate(snapshot_files):
            observed = []
            for record in files:
                size = record["byte_length"]
                data = stable_read(record["path"], max(1, size))
                if len(data) != max(1, size):
                    reject("E_HIA_NATIVE_REPORT", "owned external buffer extent changed")
                data = data[:size]
                observation = buffer_observation(record["argument"], record["kind"], data)
                observed.append(observation)
                if capture_buffers:
                    captured.append({**observation, "data": data})
            snapshots.append({"case": index, "buffers": observed})
    status = classify(returncode, timed_out, len(stdout), len(stderr), _REPORT_LIMIT)
    report = None
    if status is None:
        try:
            if direct_call is not None:
                report = _direct_call_report(direct_receipts, signatures, cases, snapshots, initial_digests,
                                             artifact_hash, direct_call[1], direct_protocol, warmup, repetitions)
            else:
                report = json.loads(stdout)
            if (type(report) is not dict or report.get("schema") != "hepta.hia.agent." + _mode + "-observation.v1"
                    or report.get("artifact_sha256") != artifact_hash
                    or report.get("planned_cases") != len(cases)
                    or report.get("repetitions") != repetitions
                    or report.get("warmup") != warmup
                    or type(report.get("complete")) is not bool
                    or _mode == "native" and report.get("complete") is not True):
                raise ValueError("native report identity differs")
            if _mode == "native":
                rows = report.get("observations")
                if type(rows) is not list or len(rows) != len(cases):
                    raise ValueError("native observation count differs")
                for row, snapshot in zip(rows, snapshots):
                    if snapshot["buffers"] and row.get("buffers") != snapshot["buffers"]:
                        raise ValueError("native external byte report differs from owned post-exit snapshot")
            if (reference_evaluator is not None and
                    report.get("reference_evaluator_sha256") != reference_evaluator.image_sha256):
                raise ValueError("reference evaluator identity differs")
            for name, calls_key, executable in executables:
                if executable is None:
                    continue
                calls = report.get(calls_key)
                if (report.get(name + '_sha256') != executable[1]
                        or type(calls) is not int or not 0 <= calls <= len(cases)):
                    raise ValueError("standalone reference report identity differs")
        except (ValueError, UnicodeError):
            status, report = "invalid_report", None
        else:
            status = "returned"
    result = {"status": status, "termination_confirmed": True, "started": returncode is not None,
            "wall_ns": str(time.monotonic_ns() - started), "returncode": returncode,
            "stdout_sha256": sha256(stdout).hexdigest(), "stderr_sha256": sha256(stderr).hexdigest(),
            "report": report}
    if direct_call is not None:
        result['direct_call_executable_sha256'] = direct_call[1]
    if any(snapshot["buffers"] for snapshot in snapshots):
        result["buffer_snapshots"] = snapshots
    if capture_buffers:
        result["captured_buffers"] = captured
    return result


def run_reference_batch(program, cases, *, timeout_ms, memory_bytes, foreign_buffer_exports=(),
                        _evaluate_terminal=False):
    """Run the existing VM under the same disposable process/deadline owner."""
    options = {'_evaluate_terminal': True} if _evaluate_terminal else {}
    return run_native_batch(program.canonical_bytes, {}, cases, timeout_ms=timeout_ms,
                            memory_bytes=memory_bytes, _mode="reference", foreign_buffer_exports=foreign_buffer_exports,
                            **options)


def main():
    if len(sys.argv) != 4:
        return 2
    _child_setup(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        return 2
    request = json.loads(raw)
    artifact = request["artifact"]
    extent = request.get("artifact_bytes")
    limit = 64 * 1024 * 1024
    if extent is not None:
        if type(extent) is not int or not 0 <= extent <= limit:
            return 2
        limit = extent
    data = stable_read(artifact, limit)
    if extent is not None and len(data) != extent:
        return 3
    if sha256(data).hexdigest() != request["artifact_sha256"]:
        return 3
    if request.get("mode") == "reference":
        if "reference_executable" in request or "owned_reference_executable" in request:
            signal.signal(signal.SIGTERM, _end_reference_runner)
        from .hia_agent_service import _vm_observation
        from .hia_program import verify_program
        from .hia_program_tools import decode_json
        from .hia_scalar_reference_native import (
            child_owned_reference, child_scalar_reference, child_standalone_reference,
        )
        program = verify_program(decode_json(data))
        observations = []
        with (child_scalar_reference(request.get("scalar_reference")) as scalar_reference,
              child_standalone_reference(request.get("reference_executable"), scalar_reference) as standalone,
              child_owned_reference(request.get("owned_reference_executable")) as owned):
            for case in request["cases"]:
                observation = _vm_observation(program, case,
                    foreign_buffer_exports=tuple(map(tuple, request["foreign_buffer_exports"])))
                observations.append(observation)
                if observation["status"] == "budget_exceeded":
                    break
        result = _reference_batch_receipt(request["artifact_sha256"], request["cases"], observations,
            request["warmup"], request["repetitions"], scalar_reference,
            (standalone.digest, standalone.calls) if standalone is not None else None,
            (owned.digest, owned.calls) if owned is not None else None)
        return _write_child_report(result, sys.stdout.buffer)
    if request.get("mode") != "native":
        return 2
    validate_cases(request["signatures"], request["cases"])
    # Load the exact opened inode via procfs, not a pathname that can be
    # replaced between hashing and dlopen. The fd stays live until process exit.
    fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if sha256(stream.read()).hexdigest() != request["artifact_sha256"]:
            return 3
        library = ctypes.CDLL("/proc/self/fd/" + str(stream.fileno()), mode=os.RTLD_LOCAL | os.RTLD_NOW)
        functions = {}
        for name, sig in request["signatures"].items():
            fn = getattr(library, name)
            fn.argtypes = [ctype for typ in sig["params"] for ctype in
                           ([ctypes.c_void_p, ctypes.c_uint64] if typ in LOANS else [_CTYPES[typ]])]
            fn.restype = (ctypes.c_uint64 if sig.get("abi") == BUFFER_PROFILE else
                          _CTYPES[sig["returns"][0]] if sig["returns"] and sig["returns"] != ["unit"] else None)
            functions[name] = fn
        observations, total_ns, calls = [], 0, 0
        for case_index, case in enumerate(request["cases"]):
            fn = functions[case["function"]]
            signature = request["signatures"][case["function"]]
            returns = signature["returns"]
            borrowed = signature.get("abi") == BUFFER_PROFILE
            mappings, arguments = [], []
            file_map = {row["argument"]: row for row in request["snapshot_files"][case_index]}
            for index, (typ, argument) in enumerate(zip(signature["params"], case["arguments"])):
                if typ not in LOANS:
                    arguments.append(argument)
                    continue
                initial = buffer_bytes(argument)
                record = file_map[index]
                if record["kind"] != typ or record["byte_length"] != len(initial):
                    return 3
                fd = os.open(record["path"], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    if os.fstat(fd).st_size != max(1, len(initial)):
                        return 3
                    mapping = mmap.mmap(fd, max(1, len(initial)), flags=mmap.MAP_SHARED,
                                        prot=mmap.PROT_READ | mmap.PROT_WRITE)
                finally:
                    os.close(fd)
                address = ctypes.addressof(ctypes.c_ubyte.from_buffer(mapping))
                mappings.append((index, typ, initial, mapping))
                arguments.extend((address, len(initial)))
            observation = None
            mismatch = False
            elapsed = 0
            for iteration in range(request["warmup"] + request["repetitions"]):
                for _index, _typ, initial, mapping in mappings:
                    mapping[:len(initial)] = initial
                start = time.perf_counter_ns()
                value = fn(*arguments)
                end = time.perf_counter_ns()
                abi_status = value >> 32 if borrowed else 0
                if borrowed:
                    value &= 0xffffffff
                elif returns == ["bool"]:
                    value = bool(value)
                values = [value] if returns else []
                observation = ({"status": "abi_rejected", "abi_status": abi_status} if abi_status else
                               {"status": "returned", "values": values})
                if borrowed:
                    observation["buffers"] = [buffer_observation(index, typ, mapping[:len(initial)])
                        for index, typ, initial, mapping in mappings]
                    if any(typ == "readbuf" and mapping[:len(initial)] != initial
                           for _index, typ, initial, mapping in mappings):
                        mismatch = True
                if "expected" in case and observation != case["expected"]:
                    mismatch = True
                if iteration >= request["warmup"]:
                    elapsed += end - start
                    calls += 1
            total_ns += elapsed
            observations.append({**observation, "mismatch": mismatch,
                                 "elapsed_ns": str(elapsed)})
            for _index, _typ, _initial, mapping in mappings:
                mapping.close()
        result = {"schema": "hepta.hia.agent.native-observation.v1",
            "artifact_sha256": request["artifact_sha256"], "complete": True,
            "planned_cases": len(request["cases"]), "completed_cases": len(observations),
            "warmup": request["warmup"], "repetitions": request["repetitions"],
            "measured_calls": calls, "total_native_ns": str(total_ns),
            "observations": observations, "timing_scope": "ctypes call including FFI overhead; snapshot reset and complete-byte hashing outside call timing, inside subprocess wall cost"}
        return _write_child_report(result, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
