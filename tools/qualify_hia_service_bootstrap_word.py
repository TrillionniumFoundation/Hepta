"""Actual controls for the separate Bootstrap word profile.

Existing packet controls and the complete original 270-helper matrix are
retained. Native compilation here is explicitly development-only; no source
freeze, cold, complete finite, release or whole-stack result is inferred.
"""
from __future__ import annotations

import argparse
import ast
import ctypes
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import resource
import signal
import struct
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from tools import generate_hia_service_bootstrap_word as word
from tests.test_hia_service_bootstrap_fixed_words import (
    FIXTURE_SHA256, ORIGINAL_HIA_SHA256, PACKET_IDS, _author, _restore_helpers)
from tools.qualify_hia_fixed_word_access import FIXTURE, helper_documents
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, _Machine, _Owner, _View
from hepta.hia_program_runtime_prepared import prepare_runtime_program

LIMITS = (4_000_000, 16 << 20, None, 128)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def controller_sources():
    from tools import generate_hia_service_bootstrap as original
    fixed = (ROOT / word.REFERENCE_SOURCE).read_bytes()
    current = (ROOT / word.SOURCE_NAME).read_bytes()
    reference = render_assembly(_author(_restore_helpers(original.source_program()))).encode()
    if sha256(reference).hexdigest() != ORIGINAL_HIA_SHA256:
        raise ValueError('complete original loop controller differs')
    if (fixed != render_assembly(original.document()).encode()
            or current != render_assembly(word.document()).encode()):
        raise ValueError('complete reference or word source is stale')
    return {'original_loop': reference, 'retained_fixed': fixed, 'word': current}


class VMImage:
    """An explicitly labelled VM callback, never a native qualification image."""
    def __init__(self, raw):
        self.program = prepare_runtime_program(assemble_program(raw))
        self.steps = []

    def _entry(self, source, size, output, capacity, state, extent):
        inputs = tuple(ctypes.string_at(value, count)
                       for value, count in ((source, size), (output, capacity), (state, extent)))
        owners = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate(inputs)]
        machine = _Machine(self.program, *LIMITS)
        result = machine.invoke(machine.functions['f0'],
                                [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != inputs[0]:
            raise AssertionError('VM callback changed its read-only request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        self.steps.append(machine.steps)
        return result


def packet_comparisons(sources, native_images=None):
    from tests.hia_service_bootstrap_controls import packet_controls
    from hepta.hia_service_bootstrap_native import SOURCE
    if SOURCE.read_bytes() != sources['word']:
        raise ValueError('actual adapter does not select the word source')
    observations, baseline, steps = {}, None, {}
    engines = {name + '_VM': VMImage(raw) for name, raw in sources.items()}
    if native_images is not None:
        engines.update({name + '_native': image for name, image in native_images.items()})
    for name, image in engines.items():
        value = packet_controls(image)
        rows = value['records']
        if tuple(row['label'] for row in rows) != PACKET_IDS or len(rows) != 22:
            raise AssertionError('original complete packet inventory changed')
        if baseline is None:
            baseline = rows
        elif rows != baseline:
            raise AssertionError('complete packet results differ across engines: ' + name)
        # Original controls call one supplied ABI and the selected independent VM.
        # Label the supplied callback accurately instead of calling a VM native.
        observations[name] = [{'case': row['label'], 'sizes': row['sizes'],
            'before': row['before'], 'supplied_code': row['native_code'],
            'selected_VM_code': row['VM_code'], 'supplied_buffers': row['native'],
            'selected_VM_buffers': row['VM']} for row in rows]
        if isinstance(image, VMImage):
            steps[name] = image.steps
    return {'packet_ids': list(PACKET_IDS), 'packets_per_engine': 22,
            'supplied_engines': list(engines), 'rows': observations,
            'VM_steps': steps, 'actual_native_executed': native_images is not None,
            'full_buffers_and_original_canaries_equal': True}


def helper_programs():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('independent complete word fixture differs')
    old, names = helper_documents('execution-budget')
    if set(names) != set(word.HELPERS) or len(names) != 3:
        raise ValueError('original helper inventory differs')
    nodes = {node.name: node for node in ast.parse(word.source_program()).body}
    source = '\n\n'.join(ast.unparse(nodes[name]) for name in names) + '\n'
    from tools.generate_hia_cold_document import document
    current = document(source, 'fixed_word_helpers', builder_type=word.WordContextBuilder)
    return {'reference': old['reference'], 'word': current}, names


def helper_cases(names):
    for size in (0, 1, 7, 8, 9, 15, 16, 17, 24):
        raw = bytes((index * 37 + 19) & 255 for index in range(size))
        for index in (0, 1, 2, 1 << 61, (1 << 61) + 1, (1 << 64) - 1):
            for name in names:
                for value in ((0, (1 << 64) - 1, 0x8172635445362718)
                              if name == 'set' else (None,)):
                    yield name, raw, index, value


def helper_vm(program, function, name, raw, index, value):
    owner = _Owner(-1, bytearray(raw))
    view = _View(owner, name != 'read_word')
    arguments = [view, index] + ([] if value is None else [value])
    machine = _Machine(program, 1_000_000, 1 << 20, None, 128)
    try:
        outcome = {'kind': 'returned', 'values': machine.invoke(function, arguments)}
    except HIAProgramTrap as error:
        outcome = {'kind': 'trap', 'code': error.code, 'message': str(error)}
    return {'outcome': outcome, 'complete_buffer': bytes(owner.data).hex(),
            'owner_active': owner.active, 'view_active': view.active,
            'view_mutable': view.mutable, 'resources': machine.resources()}


class NativeHelper:
    def __init__(self, raw):
        self.mapping = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.mapping.write(raw)
        self.pointer = ctypes.addressof(ctypes.c_ubyte.from_buffer(self.mapping))
        # Use the ordinary three-view/u32-status root. The complete u64
        # helper result is written by HIA into a separate metadata view.
        arguments = [ctypes.c_void_p, ctypes.c_uint64] * 3
        self.entry = ctypes.CFUNCTYPE(ctypes.c_uint32, *arguments)(self.pointer)

    def invoke(self, raw, index, value):
        guard = bytes(range(32))
        metadata = struct.pack('<3Q', index, 0 if value is None else value, 0x53454e54494e454c)
        shared = mmap.mmap(-1, len(raw) + 96)
        shared[:] = guard + raw + guard + metadata + bytes(8)
        base = ctypes.addressof(ctypes.c_ubyte.from_buffer(shared))
        pointer = base + 32
        pid = os.fork()
        if pid == 0:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            # RLIMIT_CORE alone does not stop a piped host crash collector.
            # Disable dumpability only in this owned negative-test child and
            # read it back before executing the intentionally trapping image.
            prctl = ctypes.CDLL(None, use_errno=True).prctl
            prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
            prctl.restype = ctypes.c_int
            if prctl(4, 0, 0, 0, 0) != 0 or prctl(3, 0, 0, 0, 0) != 0:
                os._exit(126)
            struct.pack_into('<Q', shared, len(raw) + 88, 1)
            arguments = [pointer, len(raw), pointer, len(raw), base + len(raw) + 64, 24]
            result = self.entry(*arguments)
            os._exit(0 if result == 0 else 2)
        end = time.monotonic() + 3
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() >= end:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise AssertionError('native helper failed its independent three-second control deadline')
            time.sleep(0.001)
        final = bytes(shared)
        shared.close()
        if struct.unpack_from('<Q', final, len(raw) + 88)[0] != 1:
            raise AssertionError('isolated native child did not confirm dumpability disabled')
        if (final[:32] != guard or final[32 + len(raw):64 + len(raw)] != guard
                or final[len(raw) + 64:len(raw) + 80] != metadata[:16]):
            raise AssertionError('native helper crossed its declared view or changed its input words')
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
            outcome = {'kind': 'returned', 'values': [struct.unpack_from('<Q', final, len(raw) + 80)[0]]}
        elif os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGILL:
            outcome = {'kind': 'trap', 'signal': 'SIGILL'}
        else:
            raise AssertionError(('unexpected native helper terminal', status))
        return {'outcome': outcome, 'complete_buffer': final[32:32 + len(raw)].hex(),
                'full_canaries_unchanged': True, 'isolated_child_dumpable': False}


def helper_comparisons(native=None):
    documents, names = helper_programs()
    checked = {key: prepare_runtime_program(verify_program(doc)) for key, doc in documents.items()}
    rows = []
    for name, raw, index, value in helper_cases(names):
        observed = {key: helper_vm(checked[key], checked[key].as_dict()['functions'][names.index(name)],
                                   name, raw, index, value) for key in documents}
        if observed['reference'] != observed['word']:
            raise AssertionError(('complete helper VM outcome differs', name, raw, index, value, observed))
        row = {'function': name, 'before': raw.hex(), 'index': index, 'value': value,
               'VM': observed}
        if native is not None:
            actual = {key: native[key][name].invoke(raw, index, value) for key in documents}
            if actual['reference'] != actual['word']:
                raise AssertionError(('complete native partial-buffer outcome differs', row, actual))
            vm, machine = observed['reference'], actual['reference']
            if vm['complete_buffer'] != machine['complete_buffer']:
                raise AssertionError(('native and VM full helper buffer differs', row, actual))
            if vm['outcome']['kind'] == 'returned':
                if vm['outcome'] != machine['outcome']:
                    raise AssertionError(('native and VM helper value differs', row, actual))
            elif (vm['outcome']['code'] != 'bounds'
                  or machine['outcome'] != {'kind': 'trap', 'signal': 'SIGILL'}):
                raise AssertionError(('native and VM trap control differs', row, actual))
            row['native'] = actual
        rows.append(row)
    if len(rows) != 270:
        raise AssertionError('complete original 270-helper matrix was changed')
    return rows


def compile_helpers(output, compiler):
    from tools.qualify_hia_selfhost import compile_stage
    from tools.generate_hia_cold_document import document
    documents, names = helper_programs()
    fixture = json.loads(FIXTURE.read_bytes())['components']['execution-budget']['helpers']
    current_nodes = {node.name: node for node in ast.parse(word.source_program()).body}
    images, receipts = {}, {}
    for key, doc in documents.items():
        images[key], receipts[key] = {}, {}
        for index, name in enumerate(names):
            argument = 's' if name == 'read_word' else 'o'
            call = name + '(' + argument + ', index' + (', value' if name == 'set' else '') + ')'
            wrapper = ('def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
                       '    index = word_load(w, 0)\n'
                       '    value = word_load(w, 8)\n'
                       '    result = ' + call + '\n'
                       '    word_store(w, 16, result)\n'
                       '    return 0\n\n')
            helper = fixture[name] if key == 'reference' else ast.unparse(current_nodes[name]) + '\n'
            one = document(wrapper + helper, 'bootstrap_word_helper',
                           builder_type=word.WordContextBuilder)
            # Only an ordinary six-argument entry is added. The actual helper
            # IR body remains identical to the independently compared program.
            expected = {**doc['functions'][index], 'name': 'f1'}
            if one['functions'][1] != expected:
                raise AssertionError(('helper changed while adding its native ABI wrapper', key, name))
            raw = render_assembly(one).encode()
            path, receipt = compile_stage(output, key + '_' + name, compiler, raw)
            images[key][name] = NativeHelper(path.read_bytes())
            receipts[key][name] = receipt
    return images, receipts


def alias_comparisons(sources, native_images=None):
    from hepta import hia_service_bootstrap_protocol as p
    programs = {key: prepare_runtime_program(assemble_program(raw)) for key, raw in sources.items()}
    requests = struct.pack('<16Q', p.REQUEST_MAGIC, p.INITIALIZE, 0, 0, 0, p.CLOSE, 17, 23, *([0] * 8))
    rows = []
    # Same 128/96/192-byte views, including unaligned output/state overlap and
    # request/output alias. The entire shared backing, not just slices, is read.
    for source_at, output_at, state_at in ((0, 256, 256), (0, 257, 256),
            (0, 263, 256), (0, 272, 256), (0, 352, 256), (0, 400, 256),
            (0, 0, 256), (0, 1, 256), (0, 7, 256), (0, 64, 256)):
        raw = bytearray(576)
        raw[source_at:source_at + 128] = requests
        raw[512:] = bytes(range(64))
        positions = ((source_at, 128), (output_at, 96), (state_at, 192))
        observed = {}
        for key, program in programs.items():
            backing = bytearray(raw)
            owners = [_Owner(index + 1, memoryview(backing)[at:at + size])
                      for index, (at, size) in enumerate(positions)]
            machine = _Machine(program, *LIMITS)
            value = machine.invoke(machine.functions['f0'],
                                   [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
            observed[key + '_VM'] = (value, bytes(backing).hex())
        if native_images is not None:
            for key, image in native_images.items():
                backing = ctypes.create_string_buffer(bytes(raw), len(raw))
                base = ctypes.addressof(backing)
                value = image._entry(base + source_at, 128, base + output_at, 96, base + state_at, 192)
                observed[key + '_native'] = (value, backing.raw.hex())
        if len({(value, raw0) for value, raw0 in observed.values()}) != 1:
            raise AssertionError(('shared-backing alias outcome differs', positions, observed))
        if any(bytes.fromhex(raw0)[512:] != bytes(range(64)) for _, raw0 in observed.values()):
            raise AssertionError('alias control crossed the entire allocation')
        rows.append({'positions': positions, 'before': bytes(raw).hex(), 'observations': observed})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--development-compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('independent controls require all original assertions')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    compiler = args.development_compiler.read_bytes()
    sources = controller_sources()
    captured = {name: (ROOT / name).read_bytes() for name in (
        word.REFERENCE_AUTHOR, word.REFERENCE_SOURCE, word.PROTOCOL, word.SOURCE_NAME,
        'tools/generate_hia_service_bootstrap_word.py', 'tools/qualify_hia_service_bootstrap_word.py',
        'tests/hia_service_bootstrap_controls.py', 'tests/test_hia_service_bootstrap_fixed_words.py',
        'hepta/hia_program_runtime.py', 'hepta/hia_service_bootstrap_native.py')}
    from tools.qualify_hia_selfhost import compile_stage
    from tools.build_hia_service_bootstrap import build
    from hepta.hia_service_bootstrap_native import NativeServiceBootstrap, installed_service_bootstrap
    started = time.monotonic()
    images, receipts = {}, {}
    for name in ('original_loop', 'retained_fixed'):
        path, receipt = compile_stage(args.output, name, args.development_compiler, sources[name])
        images[name] = NativeServiceBootstrap(path.read_bytes(), receipt['produced_sha256'])
        receipts[name] = receipt
    manifest = build(args.output / 'current-component', args.development_compiler, development=True)
    images['word'] = installed_service_bootstrap(str(manifest))
    receipts['word'] = json.loads((manifest.parent / 'build.json').read_bytes())
    helpers, helper_receipts = compile_helpers(args.output, args.development_compiler)
    helper_rows = helper_comparisons(helpers)
    packets = packet_comparisons(sources, images)
    aliases = alias_comparisons(sources, images)
    from tests.hia_service_bootstrap_observer import Backend
    from tests.hia_bootstrap_current_dispatch import current_dispatch_controls
    from tools.hia_bootstrap_source_history import SOURCE, code_bindings
    from tools.read_hia_service_bootstrap import _read_current_dispatch_control
    current = current_dispatch_controls(Backend('native', manifest), 'native')
    _read_current_dispatch_control(current, code_bindings((ROOT / SOURCE).read_bytes()), 'native')
    artifacts = {'helpers.json': helper_rows, 'packets.json': packets, 'aliases.json': aliases,
                 'current-dispatch.json': current, 'compile-receipts.json': receipts,
                 'helper-compile-receipts.json': helper_receipts}
    pins = {}
    for name, value in artifacts.items():
        raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        (args.output / name).write_bytes(raw); pins[name] = pin(raw)
    if args.development_compiler.read_bytes() != compiler or any(
            (ROOT / name).read_bytes() != raw for name, raw in captured.items()):
        raise ValueError('complete physical sources or compiler changed')
    report = {'schema': 'hepta.hia.bootstrap-word-qualification.v1',
        'scope': 'DEVELOPMENT_NATIVE_AND_VM_COMPONENT_ONLY',
        'status': 'PASS_COMPONENT_ONLY', 'seconds': time.monotonic() - started,
        'compiler': pin(compiler), 'sources': {name: pin(raw) for name, raw in sources.items()},
        'source_before': {name: pin(raw) for name, raw in captured.items()},
        'source_after': {name: pin((ROOT / name).read_bytes()) for name in captured},
        'complete_original_helper_rows': len(helper_rows),
        'native_helper_calls': len(helper_rows) * 2,
        'all_isolated_native_children_dumpability_read_back_false': all(
            row['native'][key]['isolated_child_dumpable'] is False
            for row in helper_rows for key in ('reference', 'word')),
        'original_packet_rows_per_engine': 22,
        'actual_native_packet_engines': 3, 'VM_packet_engines': 3,
        'shared_backing_alias_rows': len(aliases), 'alias_engines': 6,
        'current_native_init_combinations': 8, 'current_native_program_cases': 12,
        'artifacts': pins, 'current_manifest': str(manifest.resolve()),
        'source_unchanged': True, 'original_finite_qualified': False,
        'matching_source_cold_qualified': False, 'whole_native_stack_qualified': False}
    (args.output / 'qualification.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
