"""Finite LLVM native execution probe for already-verified HIA byte trace.

A test-only backend over the *observed, externally specified* byte-action
trace, not a Hepta source compiler or executable ownership SSA. Each native
load/store/free corresponds to a previously validated Resource IR path and
typed byte action. Not an attestation of source or LLVM semantic refinement.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile

from .hia_byte_trace import _CLAIMS as _BYTE_CLAIMS, replay_byte_memory_path


class HIANativeByteProbeRejected(ValueError):
    pass


def _reject(reason: str):
    raise HIANativeByteProbeRejected("E_HIA_NATIVE_BYTE: " + reason)


def _expect_fields(obj: object, fields: set[str], context: str) -> dict:
    if type(obj) is not dict or set(obj) != fields:
        _reject(context + " has unknown or missing fields")
    return obj


def _safe_u(value: object, bits: int, context: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        _reject(context + " is outside exact unsigned range")
    return value


def _render_native_byte_trace(witness: dict) -> tuple[str, int]:
    """Generate LLVM from replayed observations, never from unverified graph.

    The result is an executable *specialized trace*, with conditional runtime
    read checks and real libc allocator calls. It is not a general backend for
    dynamic Hepta buffer sizes or branches. Keep calls visible with noinline /
    optnone and accesses volatile; production optimizations are out of scope.
    """
    if (type(witness) is not dict or witness.get("schema") != "hepta.hia-byte-memory-trace.v0"
            or witness.get("status") != "finite_external_byte_actions_over_verified_resource_path"
            or type(witness.get("claims")) is not dict
            or set(witness["claims"]) != set(_BYTE_CLAIMS)
            or any(witness["claims"][name] is not expected for name, expected in _BYTE_CLAIMS.items())
            or witness.get("external_allocation_extents_and_memory_actions") is not True):
        _reject("unknown/unqualified byte witness or promoted proof")
    # A hash checks byte identity, never the source/compiler's authenticity.
    import json
    raw = {key: value for key, value in witness.items() if key != "trace_sha256"}
    try:
        wire = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise HIANativeByteProbeRejected("E_HIA_NATIVE_BYTE: malformed witness JSON") from exc
    if (len(wire) > 8 * 1024 * 1024 or type(witness.get("trace_sha256")) is not str
            or witness["trace_sha256"] != sha256(wire).hexdigest()):
        _reject("byte trace changed since its source-independent replay")
    events = witness.get("memory_observations")
    if type(events) is not list or len(events) > 10000:
        _reject("invalid bounded memory event collection")
    ptrs: set[int] = set()
    sizes: dict[int, int] = {}
    active: set[int] = set()
    lines = ['target triple = "x86_64-unknown-linux-gnu"',
             'declare ptr @calloc(i64, i64)', 'declare void @free(ptr)',
             'declare void @abort() noreturn',
             'define i64 @hia_byte_trace() noinline optnone {', 'entry:',
             '  %seed = add i64 0, 1469598103934665603']
    cursor = 'seed'
    checks = 0
    expected = 1469598103934665603
    alloc_count = free_count = 0
    token = 0
    latest_token = 0
    for i, event in enumerate(events):
        if type(event) is not dict or type(event.get('kind')) is not str:
            _reject('malformed native memory event')
        kind = event['kind']
        _safe_u(event.get('memory_token'), 32, 'memory token')
        if event['memory_token'] < latest_token:
            _reject('memory effect token regressed')
        latest_token = event['memory_token']
        if kind == 'alloc':
            _expect_fields(event, {'block', 'kind', 'slot', 'allocation', 'bytes', 'memory_token'}, 'alloc')
            n = _safe_u(event['bytes'], 13, 'allocation bytes')
            aid = _safe_u(event['allocation'], 16, 'allocation id')
            if n > 4096 or aid in ptrs or aid != alloc_count + 1:
                _reject('invalid allocation identity or extent')
            alloc_count += 1
            ptrs.add(aid)
            active.add(aid)
            sizes[aid] = n
            lines.append(f'  %p{aid} = call ptr @calloc(i64 1, i64 {max(n,1)})')
            lines.append(f'  %ok{i} = icmp ne ptr %p{aid}, null')
            lines.append(f'  br i1 %ok{i}, label %after{i}, label %fail{i}')
            lines.append(f'fail{i}:')
            lines.append('  call void @abort()')
            lines.append('  unreachable')
            lines.append(f'after{i}:')
            token += 1
        elif kind in {'read', 'write'}:
            mandatory = {'block', 'kind', 'allocation', 'index', 'value', 'memory_token'}
            _expect_fields(event, mandatory, kind)
            aid = _safe_u(event['allocation'], 16, 'access allocation')
            index = _safe_u(event['index'], 13, 'access index')
            value = _safe_u(event['value'], 8, 'byte value')
            if aid not in active or index >= sizes[aid]:
                _reject('native read/write requires a live in-bounds buffer')
            lines.append(f'  %a{i} = getelementptr i8, ptr %p{aid}, i64 {index}')
            if kind == 'write':
                lines.append(f'  store volatile i8 {value}, ptr %a{i}, align 1')
                token += 1
            else:
                lines.append(f'  %v{i} = load volatile i8, ptr %a{i}, align 1')
                lines.append(f'  %eq{i} = icmp eq i8 %v{i}, {value}')
                lines.append(f'  br i1 %eq{i}, label %after{i}, label %fail{i}')
                lines.append(f'fail{i}:')
                lines.append('  call void @abort()')
                lines.append('  unreachable')
                lines.append(f'after{i}:')
                checks += 1
            # Runtime value contributes to a checksum, rather than returning
            # a compile-time constant that could hide a bad byte load.
            src = f'%v{i}' if kind == 'read' else str(value)
            lines.append(f'  %wide{i} = zext i8 {src} to i64' if kind == 'read'
                         else f'  %wide{i} = add i64 0, {value}')
            lines.append(f'  %xor{i} = xor i64 %{cursor}, %wide{i}')
            lines.append(f'  %hash{i} = mul i64 %xor{i}, 1099511628211')
            cursor = f'hash{i}'
            expected = ((expected ^ value) * 1099511628211) % (1 << 64)
        elif kind == 'drop':
            _expect_fields(event, {'block', 'kind', 'slot', 'allocation', 'memory_token'}, 'drop')
            aid = _safe_u(event['allocation'], 16, 'drop allocation')
            if aid not in active:
                _reject('double free or unmatched allocation')
            active.remove(aid)
            lines.append(f'  call void @free(ptr %p{aid})')
            free_count += 1
            token += 1
        elif kind in {'move', 'borrow', 'end_borrow'}:
            required = ({'block', 'kind', 'src', 'dest', 'memory_token'} if kind == 'move' else
                        {'block', 'kind', 'loan', 'allocation', 'mode', 'memory_token'} if kind == 'borrow' else
                        {'block', 'kind', 'loan', 'memory_token'})
            _expect_fields(event, required, kind)
        else:
            _reject('unrecognized native byte trace instruction')
        if event['memory_token'] != token:
            _reject('computed memory token disagrees with replayed effects')
    if (active or alloc_count != free_count or checks > 10000
            or token != witness.get('memory_token_final')
            or alloc_count != witness.get('allocation_count')
            or free_count != witness.get('free_count')):
        _reject('unbalanced ownership or effect inventory')
    lines.extend([f'  ret i64 %{cursor}', '}', ''])
    wire = '\n'.join(lines)
    if len(wire.encode()) > 2_000_000:
        _reject('native LLVM module exceeds bounded budget')
    return wire, expected


def compile_native_byte_trace(graph: dict, verified: dict, function_name: str, *,
                              inputs: dict[str, bool], actions: tuple[dict, ...],
                              output: str | Path, clang: str = 'clang', fuel: int = 4096) -> dict:
    """Compile one replayed finite byte trace to an actual host x86-64 ELF .so.

    Staged output never overwrites. This is a native test oracle, not a native
    Hepta release gate, target-independent ABI, or physically executed device.
    """
    dest = Path(os.path.abspath(output))
    if (platform.system() != 'Linux' or platform.machine().lower() not in {'x86_64', 'amd64'} or not dest.parent.is_dir()
            or dest.exists() or dest.is_symlink() or type(clang) is not str or not clang
            or not isinstance(fuel, int) or type(fuel) is not int):
        _reject('unsupported host, output, clang identity or fuel')
    trace = replay_byte_memory_path(graph, verified, function_name,
                                    inputs=inputs, actions=actions, fuel=fuel)
    ir, expected = _render_native_byte_trace(trace)
    with tempfile.TemporaryDirectory(prefix='.hia-byte-native-', dir=dest.parent) as directory:
        stage = Path(directory)
        source = stage / 'candidate.ll'
        library = stage / 'candidate.so'
        source.write_text(ir, encoding='utf-8')
        try:
            p = subprocess.run([clang, '-x', 'ir', '-shared', '-fPIC', '-O0', '-Werror',
                                str(source), '-o', str(library)], capture_output=True,
                               timeout=45, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HIANativeByteProbeRejected('E_HIA_NATIVE_BYTE: real Clang invocation failed') from exc
        if p.returncode or not library.is_file() or library.is_symlink():
            _reject('Clang rejected native byte trace: ' + p.stderr[:2000].decode(errors='replace'))
        data = library.read_bytes()
        if (len(data) < 64 or data[:4] != b'\x7fELF' or data[4] != 2
                or struct.unpack_from('<H', data, 16)[0] != 3
                or struct.unpack_from('<H', data, 18)[0] != 62):
            _reject('native output is not x86-64 ELF64 shared object')
        # Hard-link refuses to overwrite an existing path. A same-user hostile
        # editor or filesystem crash can still interfere; these are not solved.
        os.link(library, dest)
        if dest.read_bytes() != data:
            try:
                if dest.exists() and dest.samefile(library):
                    dest.unlink()
            finally:
                _reject('published native bytes differ from staged output')
    return {'schema': 'hepta.hia-native-byte-probe.v0',
            'status': 'synthetic_finite_byte_trace_native_compiled_not_source_refinement',
            'ok': True, 'output': str(dest), 'artifact_sha256': sha256(data).hexdigest(),
            'artifact_bytes': len(data), 'llvm_ir_sha256': sha256(ir.encode()).hexdigest(),
            'byte_trace_sha256': trace['trace_sha256'], 'expected_hash_u64': expected,
            'claims': {'native_trace_compiled': True, 'source_to_ir_refinement_proved': False,
                       'native_backend_refinement_proved': False,
                       'cpp_or_c_abi_qualified': False, 'whole_language_soundness_proved': False,
                       'physical_target_executed': False}}
