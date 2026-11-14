"""Differential controls for the budget and journal fixed-word expansions.

The frozen fixture contains only the five original helpers. Rebuilding a
reference preserves every other current function. Development compilation is
explicit: these comparisons never supply matching-source cold qualification.
"""
from __future__ import annotations

import argparse
import ast
import copy
import ctypes
from hashlib import sha256
import importlib
import json
from pathlib import Path
import statistics
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FIXTURE = ROOT / 'tests/fixtures/hia_fixed_word_reference_a7710b5.json'
GENERATORS = {'execution-budget': 'tools.generate_hia_execution_budget',
              'agent-journal': 'tools.generate_hia_agent_journal'}


def digest(raw):
    return sha256(raw).hexdigest()


def function_document(node, names, signatures, total):
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg
    builder = Builder(node, names, signatures, total)
    builder.statements(node.body)
    function = {'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
        'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
        'entry': 'b0', 'blocks': builder.blocks}
    # These fixed helpers have no user-function calls or external dependencies.
    assert {call.func.id for call in ast.walk(node) if isinstance(call, ast.Call)} <= {'byte', 'store', 'length'}
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'fixed_word_reference',
                                  'functions': [function]})['functions'][0]


def helper_documents(component):
    """Small programs for independent return, bounds and partial-write tests."""
    from tools.generate_hia_selfhost import total_scalar_functions
    fixture = json.loads(FIXTURE.read_bytes())['components'][component]
    generator = importlib.import_module(GENERATORS[component])
    current = {node.name: node for node in ast.parse(generator.source_program()).body}
    names = {name: 'f' + str(index) for index, name in enumerate(fixture['helpers'])}
    sets = {'current': [current[name] for name in names],
            'reference': [ast.parse(fixture['helpers'][name]).body[0] for name in names]}
    documents = {}
    for key, nodes in sets.items():
        signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                      for node in nodes}
        total = total_scalar_functions(nodes)
        documents[key] = {'schema': 'hepta.hia.program.v8', 'module': 'fixed_word_helpers',
            'functions': [function_document(node, names, signatures, total) for node in nodes]}
    return documents, list(names)


def helper_comparisons(component):
    if sys.flags.optimize:
        raise ValueError('fixed-word differential controls require enabled assertions')
    from hepta.hia_program import verify_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap
    documents, names = helper_documents(component)
    checked = {key: verify_program(value) for key, value in documents.items()}
    def invoke(key, name, raw, index, value):
        owner = _Owner(-1, bytearray(raw))
        arguments = [_View(owner, name != 'read_word'), index]
        if value is not None:
            arguments.append(value)
        machine = _Machine(checked[key], 1000000, 1 << 20, None, 128)
        try:
            outcome = ('returned', machine.invoke(documents[key]['functions'][names.index(name)], arguments))
        except HIAProgramTrap as error:
            outcome = ('trap', error.code)
        return outcome, bytes(owner.data)
    count = 0
    for size in (0, 1, 7, 8, 9, 15, 16, 17, 24):
        raw = bytes((index * 37 + 19) & 255 for index in range(size))
        indices = ((0, 1, 2, 1 << 61, (1 << 61) + 1, (1 << 64) - 1)
                   if component == 'execution-budget' else
                   (0, 1, 4088, 4095, 4096, 4096 - size, 4097 - size, (1 << 64) - 1))
        for index in indices:
            for name in names:
                values = (0, (1 << 64) - 1, 0x8172635445362718) if name in {'set', 'hash_put'} else (None,)
                for value in values:
                    before = invoke('reference', name, raw, index, value)
                    after = invoke('current', name, raw, index, value)
                    assert before == after, (name, size, index, value, before, after)
                    count += 1
    return count


def full_documents(component):
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_selfhost import total_scalar_functions
    fixture = json.loads(FIXTURE.read_bytes())['components'][component]
    generator = importlib.import_module(GENERATORS[component])
    nodes = ast.parse(generator.source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    current = generator.document()
    current_raw = render_assembly(current).encode()
    assert current_raw == (ROOT / fixture['original_assembly_path']).read_bytes(), 'generated source is stale'
    reference = copy.deepcopy(current)
    indices = [index for index, node in enumerate(nodes) if node.name in fixture['helpers']]
    total = total_scalar_functions(nodes)
    for index in indices:
        node = ast.parse(fixture['helpers'][nodes[index].name]).body[0]
        reference['functions'][index] = function_document(node, names, signatures, total)
    assert all(a == b for index, (a, b) in enumerate(zip(current['functions'], reference['functions']))
               if index not in indices)
    return {'reference': render_assembly(reference).encode(), 'current': current_raw}, fixture


class Comparison:
    def __init__(self, sources, images):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = {key: assemble_program(raw) for key, raw in sources.items()}
        self.images, self.observations = images, []

    def vm(self, key, frame):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = [_Owner(-index - 1, bytearray(raw)) for index, raw in enumerate(frame)]
        machine = _Machine(self.checked[key], 100000000, 64 << 20, None, 128)
        entry = self.checked[key].as_dict()['functions'][0]
        returned = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True),
                                          _View(owners[2], True)])[0]
        assert bytes(owners[0].data) == frame[0]
        return returned, bytes(owners[1].data), bytes(owners[2].data)

    def native(self, key, frame):
        canary = bytes(range(64))
        buffers = [ctypes.create_string_buffer(raw + canary, len(raw) + len(canary)) for raw in frame]
        returned = self.images[key]._entry(buffers[0], len(frame[0]), buffers[1], len(frame[1]),
                                           buffers[2], len(frame[2]))
        assert buffers[0].raw == frame[0] + canary
        assert all(buffer.raw[len(raw):] == canary for buffer, raw in zip(buffers, frame))
        return returned, buffers[1].raw[:len(frame[1])], buffers[2].raw[:len(frame[2])]

    def case(self, label, frame, *, native_only=False):
        engines = [('reference-native', self.native, 'reference'), ('current-native', self.native, 'current')]
        if not native_only:
            engines += [('reference-VM', self.vm, 'reference'), ('current-VM', self.vm, 'current')]
        expected = None
        for name, invoke, key in engines:
            actual = invoke(key, frame)
            if expected is None:
                expected = actual
            assert actual == expected, (label, name, actual[0], expected[0])
        self.observations.append({'case': label, 'engines': [row[0] for row in engines],
            'returned': expected[0], 'input_bytes': len(frame[0]), 'output_bytes': len(frame[1]),
            'work_bytes': len(frame[2]), 'input_sha256': digest(frame[0]),
            'complete_output_sha256': digest(expected[1]), 'complete_work_sha256': digest(expected[2]),
            'all_bytes_equal': True, 'native_input_and_canaries_unchanged': True})
        return expected


def budget_cases(compare):
    from hepta.hia_execution_budget_native import STATE_BYTES, OUTPUT_BYTES
    from tests.test_hia_execution_budget_native import packet, row_packet, witnesses, CONTEXT, OWNER
    output = b'\xcd' * OUTPUT_BYTES
    class Engine:
        def __init__(self, label):
            self.state, self.count, self.label = bytes(STATE_BYTES), 0, label
        def call(self, raw):
            result = compare.case(self.label + '-' + str(self.count), (raw, output, self.state))
            self.count += 1; self.state = result[2]
            return result[0], result[1][:result[0]], result[2]
    engine = Engine('claim-run-complete')
    rows = witnesses(engine); assert len(rows) == 16
    frozen_state = engine.state
    engine.call(packet(90))
    scenarios = {
        'create-missing': [packet(0, values=(0, 0, 0, len(CONTEXT), 0), payload=CONTEXT),
                           packet(1, 1, (1,)), row_packet(2, None, None)],
        'observe-largest-decimal': [packet(0, values=(2, 0, 0, len(CONTEXT), 0), payload=CONTEXT),
                                    row_packet(1, b'9' * 4300, None)],
        'noncanonical-cost': [rows[0][0], packet(1, 1, (1,)), row_packet(2, b'00', None)],
        'wrong-owner': [rows[0][0], packet(1, 1, (1,)), row_packet(2, b'1', OWNER)]}
    for label, packets in scenarios.items():
        engine = Engine(label)
        for raw in packets:
            engine.call(raw)
    invalid = [b'', b'x' * 127, b'x' * 4701, bytes(128), packet(90, identity=(12, 17)),
        packet(90, connection=(31, 38)), packet(90, values=(0, 0, 0, 0, 0, 1)),
        packet(90, payload=b'x'), packet(123, 16)]
    for number, raw in enumerate(invalid):
        compare.case('invalid-packet-' + str(number), (raw, output, frozen_state))
    for offset in (0, 7, 17 * 8, 31 * 8, 256, 4824, 9136, STATE_BYTES - 1):
        state = bytearray(frozen_state); state[offset] ^= 0x80
        result = compare.case('corrupt-state-' + str(offset), (packet(90), output, bytes(state)))
        assert result[2] == bytes(state) and struct.unpack_from('<Q', result[1], 8)[0] == 2
    return (packet(90), output, frozen_state)


def journal_frame(stage, raw=b'', state=bytes(512), *, foreign=b'', profile=False):
    from hepta.hia_agent_journal_native import buffer_sizes, PRIVATE_BYTES
    output, work = buffer_sizes(0 if stage == 10 else len(raw))
    scratch = bytearray(work + len(foreign))
    base = len(scratch) - PRIVATE_BYTES
    scratch[base:base + 512] = state
    scratch[base - len(foreign):base] = foreign
    struct.pack_into('<2Q', scratch, 0, stage, sys.get_int_max_str_digits())
    struct.pack_into('<2Q', scratch, base + 336, len(foreign), profile)
    return raw, bytes(output), bytes(scratch)


def journal_cases(compare):
    from hepta.hia_agent_journal_native import HEADER_OFFSET, MAGIC, PRIVATE_BYTES
    def state_of(result):
        return result[1][HEADER_OFFSET:HEADER_OFFSET + 512]
    requests = [b'{"tool":"hia_describe","arguments":{}}',
        b'{"tool":"unknown","arguments":{"request_key":"a"}}',
        b'{"tool":"hia_artifact","arguments":{"request_key":"a","number":1.25}}',
        '{"arguments":{"request_key":"雪","number":-0.0},"tool":"hia_read"}'.encode(),
        b'{"tool":[],"arguments":{}}', b'{"tool":"hia_resource_read","arguments":{}}',
        b'{"tool":"hia_describe","arguments":{"x":1,"x":2}}', b'{"tool":', b'\xff']
    for index, raw in enumerate(requests):
        compare.case('prepare-' + str(index), journal_frame(0, raw))
    prepared = compare.case('lookup-prepare', journal_frame(0, requests[2]))
    assert prepared[0] == 2
    reserved = compare.case('lookup-missing', journal_frame(1, b'null', state_of(prepared)))
    assert reserved[0] == 3
    acknowledged = compare.case('reservation-ack', journal_frame(2, state=state_of(reserved)))
    assert acknowledged[0] == 1
    effect = compare.case('effect-admission', journal_frame(5, state=state_of(acknowledged)))
    response = b'{"status":"completed","result":{"number":1.25}}'
    compare.case('terminal-response', journal_frame(8, response, state_of(effect)))
    raw = b'{"digest":"' + state_of(prepared)[64:128] + b'","state":"completed"}'
    cached = compare.case('lookup-completed', journal_frame(1, raw, state_of(prepared)))
    assert cached[0] == 4
    compare.case('cached-response', journal_frame(3, response, state_of(cached)))
    conflict = b'{"digest":"' + b'0' * 64 + b'","state":"running"}'
    compare.case('lookup-conflict', journal_frame(1, conflict, state_of(prepared)))
    for size in (0, 1, 55, 56, 63, 64):
        result = compare.case('catalog-refusal-' + str(size), journal_frame(9, b'x' * size))
        assert result[0] == 11 and struct.unpack_from('<Q', state_of(result), 56)[0] == 7
    malformed = bytearray(512); struct.pack_into('<2Q', malformed, 0, MAGIC, 1)
    result = compare.case('catalog-phase-before-hash', journal_frame(9, b'x' * 64, bytes(malformed)))
    assert result[0] == 0xfffffffd
    result = compare.case('catalog-oversize', journal_frame(9, b'x' * ((8 << 20) + 1)))
    assert result[0] == 0xfffffffd
    catalog = (ROOT / 'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
    # Real full catalog bytes run through both original native images. The VM
    # cases above cover the same SHA helpers at both padding boundaries; do not
    # claim that a short VM case executed the complete installed catalog.
    for label, raw in (('actual-catalog', catalog), ('changed-catalog', catalog[:-1] + bytes([catalog[-1] ^ 1]))):
        frame = journal_frame(9, raw)
        result = compare.case(label, frame, native_only=True)
        at = len(frame[2]) - 4096 + 1088
        assert result[2][at:at + 32] == sha256(raw).digest()
        assert result[0] == (12 if label == 'actual-catalog' else 11)
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=GENERATORS, required=True)
    parser.add_argument('--development-compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('fixed-word differential controls require enabled assertions')
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    sources, fixture = full_documents(args.component)
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_execution_budget_native import NativeExecutionBudgetImage
    from hepta.hia_agent_journal_native import NativeAgentJournal
    image_type = NativeAgentJournal if args.component == 'agent-journal' else NativeExecutionBudgetImage
    compiler_raw = args.development_compiler.read_bytes()
    images, image_hashes = {}, {}
    for key, raw in sources.items():
        (args.output / (key + '.hepta')).write_bytes(raw)
        path, receipt = compile_stage(args.output, key, args.development_compiler, raw)
        image_hashes[key] = receipt['produced_sha256']
        images[key] = image_type(path.read_bytes(), image_hashes[key])
    assert args.development_compiler.read_bytes() == compiler_raw
    compare = Comparison(sources, images)
    timing_input = journal_cases(compare) if args.component == 'agent-journal' else budget_cases(compare)
    helpers = helper_comparisons(args.component)
    timings = {'reference': [], 'current': []}
    repetitions = 10 if args.component == 'agent-journal' else 1000
    for round_number in range(5):
        for key in (('reference', 'current') if round_number % 2 == 0 else ('current', 'reference')):
            begin = time.perf_counter_ns()
            for _ in range(repetitions):
                if args.component == 'agent-journal':
                    images[key].bind_catalog(timing_input)
                else:
                    compare.native(key, timing_input)
            timings[key].append((time.perf_counter_ns() - begin) / 1e9)
    result = {'schema': 'hepta.hia.fixed-word-differential.v1', 'component': args.component,
        'scope': 'DEVELOPMENT_DIFFERENTIAL_NOT_MATCHING_SOURCE_COLD_OR_WHOLE_NATIVE_COMPLETION',
        'passed': True, 'command': sys.argv, 'python': sys.version, 'seconds': time.monotonic() - started,
        'reference_fixture_sha256': digest(FIXTURE.read_bytes()), 'reference_origin': json.loads(FIXTURE.read_bytes())['origin_commit'],
        'source_sha256': {key: digest(raw) for key, raw in sources.items()},
        'reference_matches_original_assembly': digest(sources['reference']) == fixture['original_assembly_sha256'],
        'all_non_word_assembly_functions_equal': True, 'changed_functions': list(fixture['helpers']),
        'compiler_sha256': digest(compiler_raw), 'image_sha256': image_hashes,
        'helper_return_trap_partial_buffer_comparisons': helpers, 'observations': compare.observations,
        'four_way_full_buffer_cases': sum(len(row['engines']) == 4 for row in compare.observations),
        'native_only_full_catalog_cases': sum(len(row['engines']) == 2 for row in compare.observations),
        'timing_repetitions_per_sample': repetitions, 'native_seconds': timings,
        'median_native_speedup': statistics.median(timings['reference']) / statistics.median(timings['current']),
        'matching_current_source_cold_qualified': False, 'whole_native_delivery_qualified': False}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'observations'}, indent=2), flush=True)


if __name__ == '__main__':
    main()
