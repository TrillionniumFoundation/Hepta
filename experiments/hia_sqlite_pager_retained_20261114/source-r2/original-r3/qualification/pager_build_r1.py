"""Two original B3 compiles, three fixed assembly objects, one HIA ELF call.

Future execution occurs only inside Root's one frozen 180+3 owner. HIA compiler
20-wall/10-CPU/1MiB input/output/workspace gates are inherited unchanged. Complete
SQLite engines are external, already closed reference supplies, never built here.
The final executable comes ONLY from actual HIA output, not the Python readback.
"""
from __future__ import annotations
import ctypes
import hashlib
import importlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

import pager_common_r1 as common
import pager_support_r1 as support
from pager_generation_r1 import generate
from pager_elf_readback_r1 import inspect_link
from pager_link_buffer_trace_r1 import (
    CANARY, CANARY_BYTE, CAPACITIES, MAX_EXPANDED, retain, inspect, initial_piece)
from pager_audit_stream_r3 import PhysicalBudget

ROOT = Path(__file__).resolve().parent.parent
AS_SOURCES = (
    ('start', 'inputs/native/pager_start_r4.S'),
    ('os', 'inputs/native/pager_os_once_r2.S'),
    ('wrapper', 'inputs/native/pager_image_wrapper.S'),
)
OBJECT_LIMIT = 1 << 20
FILE_LIMIT = 4 << 20

def _assemble(request, output, objects_root, label, source_name, incbin_pin):
    directory = output/label
    directory.mkdir(mode=0o700)
    source = ROOT/source_name
    source_pin, _ = common.read(source, OBJECT_LIMIT)
    common.require(source_pin == request['inputs'][source_name], 'fixed assembly source')
    inputs = {str(source): source_pin}
    if label == 'wrapper':
        inputs[incbin_pin['path']] = incbin_pin
    argv = [request['system_binaries']['as'], '--64', '--fatal-warnings',
            '-o', str(directory/'object.o'), str(source)]
    q = {
        'schema': 'hia.sqlite-pager.assembly-object-request.v1',
        'label': label, 'assembler': request['system_binaries']['as'],
        'source_path': str(source), 'source_inputs': inputs,
        'output': str(directory), 'cwd': str(objects_root), 'argv': argv,
        'environment': {'LANG': 'C', 'LC_ALL': 'C', 'PATH': '', 'TZ': 'UTC'},
        'wall_seconds': 20, 'cpu_seconds': 10, 'max_object_bytes': OBJECT_LIMIT}
    qpin = common.create(directory/'REQUEST.json', q)
    command = [sys.executable, '-I', '-S', '-B',
               str(ROOT/'qualification/pager_asm_child_r1.py'),
               str(directory/'REQUEST.json'), qpin['sha256']]
    invocation = {'argv': command, 'cwd': str(ROOT),
                  'env': request['environment'], 'wall_seconds': 20,
                  'attempted': False, 'returncode': None, 'exception': None}
    started = time.monotonic_ns()
    try:
        invocation['attempted'] = True
        with (directory/'child.stdout.log').open('xb', buffering=0) as stdout, (
                directory/'child.stderr.log').open('xb', buffering=0) as stderr:
            child = subprocess.run(command, cwd=ROOT, env=request['environment'],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                close_fds=True, timeout=20)
        invocation['returncode'] = child.returncode
    except BaseException as exc:
        invocation['exception'] = type(exc).__name__+': '+str(exc)[:1024]
        raise
    finally:
        invocation['elapsed_ns'] = time.monotonic_ns()-started
        common.create(directory/'INVOCATION.json', invocation)
    common.require(invocation['returncode'] == 0 and invocation['exception'] is None
                   and invocation['elapsed_ns'] <= 20000000000,
                   'one bounded assembly invocation failed')
    report_pin, report = support.read_json(directory/'COMPILE.json', 1 << 20)
    common.require(report['schema'] == 'hia.sqlite-pager.assembly-object.v1'
        and report['status'] == 'ONE_BOOTSTRAP_OBJECT_COMPILED_ONLY'
        and report['request'] == qpin and report['argv'] == argv
        and report['cwd'] == q['cwd'] and report['environment'] == q['environment']
        and report['attempted'] is True and type(report['returncode']) is int
        and report['returncode'] == 0 and report['timed_out'] is False
        and report['exception'] is None and type(report['elapsed_ns']) is int
        and 0 <= report['elapsed_ns'] <= 20000000000
        and report['inputs_before'] == report['inputs_after'] == inputs
        and report['limits'] == {'wall_seconds': 20, 'cpu_seconds': 10,
             'address_bytes': 256 << 20, 'stack_bytes': 8 << 20,
             'file_bytes': OBJECT_LIMIT, 'core_bytes': 0},
        'complete assembly request/raw result/budget identity')
    pin, body = common.read(directory/'object.o', OBJECT_LIMIT)
    common.require(pin == report['object'], 'actual assembled object pin')
    return {'label': label, 'request': qpin, 'receipt': report_pin,
            'object': pin, 'invocation': invocation}, body

def _piece(view):
    return lambda offset, count: bytes(view[offset:offset+count])

def _one_link(request, output, linker_pin, objects, pager_pin, budget):
    output.mkdir(mode=0o700)
    pager_pin_read, pager_body = common.read(pager_pin['path'], 1 << 20)
    common.require(pager_pin_read == pager_pin, 'exact whole B3 Pager image')
    body = bytearray()
    import struct
    body.extend(struct.pack('<4Q', int.from_bytes(b'HIAPGLK2', 'little'), 3, 6, 0))
    body.extend(b'_start')
    for record, raw in objects:
        common.require(len(raw) <= OBJECT_LIMIT and
                       hashlib.sha256(raw).hexdigest() == record['object']['sha256'],
                       'exact object packet inputs')
        body.extend(struct.pack('<Q', len(raw)))
        body.extend(raw)
    packet = bytes(body)
    common.require(len(packet) <= CAPACITIES['input'], 'three complete object packet')
    packet_pin = common.create(output/'packet.bin', packet, raw=True)
    module = importlib.import_module('hepta.hia_json_preflight_native')
    compiler_pin, compiler_body = common.read(linker_pin['path'], 1 << 20)
    common.require(compiler_pin == linker_pin, 'exact new HIA linker image')
    codec = module.NativeHiaJsonImage(compiler_body, compiler_pin['sha256'])
    entry = codec._entry
    maps_before = support.loaded_file_maps(request, {}, codec, entry, entry,
                                          compiler_pin, output/'mapping-before')
    capacities = {'input': len(packet), 'output': CAPACITIES['output'],
                  'workspace': CAPACITIES['workspace']}
    allocations = {}
    addresses = {}
    for role, size in capacities.items():
        allocation = bytearray(size+2*CANARY)
        allocation[:CANARY] = bytes([CANARY_BYTE])*CANARY
        allocation[-CANARY:] = bytes([CANARY_BYTE])*CANARY
        if role == 'input':
            allocation[CANARY:CANARY+size] = packet
        allocations[role] = allocation
        addresses[role] = ctypes.addressof(
            (ctypes.c_ubyte*len(allocation)).from_buffer(allocation))+CANARY
    regions = [(addresses[r]-CANARY, addresses[r]+capacities[r]+CANARY)
               for r in capacities]
    common.require(all(a1 <= b0 or b1 <= a0 for i, (a0, a1) in enumerate(regions)
                       for b0, b1 in regions[i+1:]), 'three distinct owned allocations')
    traces = {}
    for role, size in capacities.items():
        root = output/('PRE-'+role)
        retain(root, phase='PRE', role=role, logical_bytes=size,
               allocation=allocations[role], budget=budget)
        traces['PRE-'+role] = inspect(root, phase='PRE', role=role,
            logical_bytes=size, expected_piece=initial_piece(role, packet, size),
            budget_token=budget.token)
    common.create(output/'CALL-INTENT.json', {
        'schema': 'hia.sqlite-pager.one-HIA-ELF-call.v1',
        'expected_calls': 1, 'image': compiler_pin, 'packet': packet_pin,
        'addresses': addresses, 'capacities': capacities,
        'pre_traces': traces, 'maps_before': maps_before,
        'physical_budget_token': budget.token,
        'expanded_buffer_bound': MAX_EXPANDED,
        'compiler_gate_unchanged': {'wall_seconds': 20, 'cpu_seconds': 10,
                                   'capacity': 1 << 20, 'workspace': 1 << 20}})
    # All PRE parts/indexes are already fsync'd and independently decoded.
    # No reference executable is used as a fallback for this call.
    call = {'attempted': True, 'returned': False, 'result_u64': None,
            'exception': None, 'elapsed_ns': None}
    started = time.monotonic_ns()
    try:
        result = entry(addresses['input'], capacities['input'],
                       addresses['output'], capacities['output'],
                       addresses['workspace'], capacities['workspace'])
        call['returned'] = True
        call['result_u64'] = result
    except BaseException as exc:
        call['exception'] = type(exc).__name__+': '+str(exc)[:1024]
    finally:
        call['elapsed_ns'] = time.monotonic_ns()-started
        common.create(output/'CALL-RETURN.json', call)
    # Preserve ALL full actual POST buffers before checking status/canaries/ELF.
    for role, size in capacities.items():
        retain(output/('POST-'+role), phase='POST', role=role, logical_bytes=size,
               allocation=allocations[role], budget=budget)
    for role, size in capacities.items():
        traces['POST-'+role] = inspect(output/('POST-'+role), phase='POST',
            role=role, logical_bytes=size, expected_piece=_piece(allocations[role]),
            budget_token=budget.token)
    maps_after = support.loaded_file_maps(request, {}, codec, entry, entry,
                                         compiler_pin, output/'mapping-after')
    common.require(call['returned'] is True and call['exception'] is None
                   and type(call['result_u64']) is int
                   and 0 < call['result_u64'] <= FILE_LIMIT,
                   'actual HIA linker returned bounded executable bytes')
    common.require(all(a[:CANARY] == bytes([CANARY_BYTE])*CANARY and
                       a[-CANARY:] == bytes([CANARY_BYTE])*CANARY
                       for a in allocations.values()), 'all six linker canaries')
    common.require(allocations['input'][CANARY:-CANARY] == packet,
                   'whole linker input unchanged')
    common.require(maps_before['image_binding']['address'] ==
                   maps_after['image_binding']['address']
                   and maps_before['image_binding']['image'] ==
                       maps_after['image_binding']['image'],
                   'same exact HIA code mapping before/after one call')
    size = call['result_u64']
    common.require(not any(allocations['output'][CANARY+size:-CANARY]),
                   'complete unused output tail unchanged')
    actual_elf = bytes(allocations['output'][CANARY:CANARY+size])
    path = output/'pager-owner.elf'
    common.create(path, actual_elf, raw=True)
    os.chmod(path, 0o700)
    layout = inspect_link([r['object']['path'] for r, _ in objects], path, pager_body)
    pin, verified = common.read(path, FILE_LIMIT)
    common.require(pin == layout['actual'] and verified == actual_elf,
                   'only the actual native HIA result becomes the executable')
    raw_bytes = sum(value['raw_bytes'] for value in traces.values())
    physical_bytes = sum(value['physical_bytes'] for value in traces.values())
    common.require(raw_bytes <= MAX_EXPANDED and len(traces) == 6,
                   'complete six-buffer bounded evidence')
    report = {
        'schema': 'hia.sqlite-pager.one-linker-call-readback.v1',
        'status': 'ONE_ACTUAL_HIA_ELF_LINK_PASS_ONLY', 'call': call,
        'image': compiler_pin, 'packet': packet_pin, 'traces': traces,
        'raw_bytes': raw_bytes, 'physical_bytes': physical_bytes,
        'maps_before': maps_before, 'maps_after': maps_after, 'ELF': layout,
        'host_ELF_fallback': False}
    common.create(output/'LINK-REPORT.json', report)
    # No additional native mapping survives into the independent Pager cases.
    codec._mapping.close()
    return pin, layout, report

def build(request, output, *, budget):
    """The caller supplies the ONE shared trace budget used again by cases."""
    common.require(type(budget) is PhysicalBudget and
                   budget.token == request['trace_budget_token'],
                   'one request-wide trace budget')
    output = Path(output)
    output.mkdir(mode=0o700)
    generated = generate(request, output/'generation')
    compiler_custody = support.inspect_compiler_inputs()
    qualifier = importlib.import_module('tools.qualify_hia_selfhost')
    common.require(qualifier.NATIVE_OBSERVER is None and
                   qualifier.NATIVE_LINKED_OBSERVER is None
                   and qualifier.CAPACITY == 1 << 20,
                   'original direct 20-wall B3 compile entry')
    compiled = {}
    try:
        common.require(resource.getrlimit(resource.RLIMIT_FSIZE) ==
                       (4 << 20, 16 << 20),
                       'worker soft4MiB; original B3 child hard16MiB inheritance')
        for label in ('pager', 'linker'):
            directory = output/('B3-'+label)
            directory.mkdir(mode=0o700)
            assembly = generated[label]['assembly']
            pin, body = common.read(assembly['path'], 1 << 20)
            common.require(pin == assembly, 'exact generated source before compiler')
            qualifier.compile_stage(directory, label, ROOT/'compiler-inputs/B3.image.bin', body)
            compiled[label] = support.inspect_new_compile(directory, request, label, assembly['path'])
            common.require(common.read(assembly['path'], 1 << 20)[0] == assembly,
                           'generated source unchanged by compiler')
    finally:
        # Both success and failure close the compiler-only hard-limit window.
        # The original child, 20-wall/10-CPU/1MiB ABI and seven files are unchanged.
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 4 << 20))
    common.require(resource.getrlimit(resource.RLIMIT_FSIZE) ==
                   (4 << 20, 4 << 20),
                   'native/trace hard4MiB before objects, linker and scenarios')
    objects_root = output/'objects'
    objects_root.mkdir(mode=0o700)
    pager_pin = compiled['pager']['pins']['pager.image.bin']
    _, pager_bytes = common.read(pager_pin['path'], 1 << 20)
    incbin_pin = common.create(objects_root/'pager_read_owner.image.bin', pager_bytes, raw=True)
    common.require(incbin_pin['sha256'] == pager_pin['sha256']
                   and incbin_pin['bytes'] == pager_pin['bytes'], 'whole incbin copy')
    assembled = []
    for label, source_name in AS_SOURCES:
        assembled.append(_assemble(request, objects_root, objects_root,
                                   label, source_name, incbin_pin))
    linker_pin = compiled['linker']['pins']['linker.image.bin']
    before_link_physical = budget.used
    executable, layout, link = _one_link(request, output/'HIA-link', linker_pin,
                                         assembled, pager_pin, budget)
    common.require(budget.reserved == 0
                   and budget.used-before_link_physical == link['physical_bytes'],
                   'complete shared linker physical charge')
    report = {'schema': 'hia.sqlite-pager.fixed-build.v1',
              'status': 'PAGER_BUILD_PASS_ONLY', 'generation': generated,
              'historical_compiler': compiler_custody, 'B3_compiles': compiled,
              'assembly_objects': [record for record, _ in assembled],
              'link': link, 'executable': executable,
              'bootstrap_assembly_not_final_all_HIA': True,
              'SQLite_reference_builds_executed_here': 0}
    common.create(output/'BUILD-REPORT.json', report)
    return executable, layout, report
