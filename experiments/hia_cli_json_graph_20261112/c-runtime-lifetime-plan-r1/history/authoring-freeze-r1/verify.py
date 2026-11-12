"""Independent joins of actual compile, case, trace and raw owner originals."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct

from common import require, read_file, pin
from original_current_compiler import json_original, COMPILER_LIMITS, RECEIPT_ADDITIONS
from support import closed_owner, natural_owner, ROOT
from case_contract import (RUNTIME_IDS, LIFETIME_IDS, RAW_LEAF_ONLY_IDS,
                           EXPECTED_HIA_RETURNS, EXPECTED_C_PUMP_CALLS,
                           NORMAL_EFFECTS, YIELD_EFFECTS, ERROR_TWO_STACK_EFFECTS)

ELF_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
ELF_PROGRAM = struct.Struct('<IIQQQQQQ')
ELF_SECTION = struct.Struct('<IIQQQQIIQQ')
ELF_SYMBOL = struct.Struct('<IBBHQQ')


def original(path, maximum=4 << 20):
    raw, record = read_file(path, maximum)
    return json_original(raw), record, raw


def c_image(policy, work):
    path = work / 'c-build/cli-json.so'
    raw, actual = read_file(path, 1 << 20)
    require(len(raw) >= ELF_HEADER.size, 'C shared library ELF header is missing')
    fields = ELF_HEADER.unpack_from(raw)
    ident, kind, machine, version, entry, ph_at, sh_at, flags, eh_size, ph_size, ph_count, sh_size, sh_count, sh_names = fields
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and kind == 3 and machine == 62
            and version == 1 and entry == 0 and eh_size == ELF_HEADER.size
            and ph_size == ELF_PROGRAM.size and sh_size == ELF_SECTION.size
            and ph_count > 0 and sh_count > 0 and sh_names < sh_count,
            'actual C shared-library profile differs')
    def span(offset, count):
        require(0 <= offset <= len(raw) and 0 <= count <= len(raw) - offset, 'C ELF extent exceeds actual bytes')
        return raw[offset:offset + count]
    span(ph_at, ph_size * ph_count); span(sh_at, sh_size * sh_count)
    programs = [ELF_PROGRAM.unpack_from(raw, ph_at + i * ph_size) for i in range(ph_count)]
    require(not any(row[0] == 1 and row[1] & 3 == 3 for row in programs),
            'actual C image has a writable-executable load segment')
    sections = [ELF_SECTION.unpack_from(raw, sh_at + i * sh_size) for i in range(sh_count)]
    exports = {}
    needed = []
    for section in sections:
        name, section_type, section_flags, address, offset, size, link, info, alignment, stride = section
        if section_type in (14, 15):
            require(size == 0, 'unexpected automatic C initializer/finalizer')
        if section_type == 6:
            require(stride == 16 and size % 16 == 0, 'malformed C dynamic table')
            for at in range(offset, offset + size, 16):
                tag, value = struct.unpack('<qQ', span(at, 16))
                if tag == 1:
                    needed.append(value)
        if section_type != 11:
            continue
        require(stride == ELF_SYMBOL.size and size % stride == 0 and link < len(sections),
                'malformed C dynamic symbol table')
        strings_section = sections[link]
        strings = span(strings_section[4], strings_section[5])
        for at in range(offset, offset + size, stride):
            name_offset, symbol_info, visibility, section_index, value, extent = ELF_SYMBOL.unpack(span(at, stride))
            require(name_offset < len(strings), 'C symbol name exceeds its table')
            end = strings.find(b'\0', name_offset)
            require(end >= 0, 'C symbol name is unterminated')
            name = strings[name_offset:end].decode('ascii', 'strict')
            if section_index and symbol_info & 15 == 2 and name.startswith('hia_cli_json_'):
                require(name not in exports, 'duplicate actual C exported function')
                exports[name] = {'value': value, 'bytes': extent, 'section': section_index}
    require(needed == [], 'the explicit -nostdlib C link unexpectedly added a dynamic dependency')
    require(set(policy['c_required_exports']) <= set(exports), 'actual C leaf/pump/binder export is missing')
    deps_raw, deps_pin = read_file(work / 'c-build/cli-json.d', 1 << 20)
    text = deps_raw.decode().replace('\\\n', ' ')
    require(': ' in text, 'actual compiler dependency record is absent')
    target, remainder = text.split(': ', 1)
    require(target == str(path), 'actual compiler dependency target differs')
    dependencies = remainder.split()
    require(dependencies and all('\\' not in name for name in dependencies),
            'unexpected escaped or absent dependency path')
    system, system_pin, _ = original(ROOT / policy['system_manifest']['path'], 8 << 20)
    admitted_system = {row['physical_path'] for row in system['files']}
    admitted_source = {str(ROOT / 'source' / row['path']) for row in policy['source_files']}
    observed = []
    for name in dependencies:
        p = Path(name)
        require(p.is_absolute(), 'relative actual C dependency is inadmissible')
        resolved = str(p.resolve(strict=True))
        require(resolved in admitted_system or resolved in admitted_source,
                'actual compiler read an undeclared source/header: ' + name)
        observed.append({'lexical': name, 'physical': resolved})
    require(str(ROOT / 'source/hepta/hia_cli_json_cpython.c') in dependencies,
            'actual C source is absent from the compiler dependency record')
    return {'schema': 'hia.cli-json.C-build-byte-join.v1', 'status': 'ACTUAL_C_IMAGE_ADMITTED_PENDING_LOAD',
            'image': actual, 'exports': exports, 'dependencies': observed, 'dependency_record': deps_pin,
            'no_dynamic_needed_libraries': True, 'no_automatic_initializers': True,
            'runtime_loaded': False, 'body_qualified': False}


def hia_image(policy, work):
    build = work / 'hia-build'
    names = ('input.bin', 'output.bin', 'request.json', 'stdout.log', 'stderr.log', 'receipt.json', 'image.bin')
    values = {name: read_file(build / ('cli-lifetime.' + name), 1 << 20) for name in names}
    request = json_original(values['request.json'][0])
    child = json_original(values['stdout.log'][0])
    receipt = json_original(values['receipt.json'][0])
    report, report_pin, _ = original(build / 'REPORT.json')
    source, source_pin = read_file(ROOT / policy['lifetime_source']['path'], 1 << 20)
    compiler = Path(policy['compiler_origin_root']) / policy['compiler']['path']
    require(report['status'] == 'ORIGINAL_COMPILE_RETURNED_PENDING_INDEPENDENT_JOIN'
            and report['compile_stage_attempts'] == 1 and report.get('error') is None
            and report['returned_receipt'] == receipt
            and set(RECEIPT_ADDITIONS) <= set(receipt)
            and {k: v for k, v in receipt.items() if k not in RECEIPT_ADDITIONS} == child,
            'whole original child stdout/receipt/wrapper projection differs')
    image = values['image.bin'][0]
    require(receipt['status'] == 'returned' and receipt['abi_status'] == 0
            and type(receipt['core_u32']) is int and 0 < receipt['core_u32'] <= 1 << 20
            and receipt['core_u32'] == receipt['produced_bytes'] == len(image)
            and receipt['source_unchanged'] is True and receipt['limits'] == COMPILER_LIMITS
            and receipt['forbidden_compiler_modules_loaded'] == [], 'original HIA compiler refused or changed limits')
    require(receipt['image_sha256'] == receipt['artifact_sha256'] == policy['compiler']['sha256']
            and receipt['source_sha256'] == receipt['input_sha256'] == source_pin['sha256']
            == policy['lifetime_source']['sha256']
            and receipt['produced_sha256'] == values['image.bin'][1]['sha256']
            and values['input.bin'][0] == source and receipt['input_bytes'] == len(source)
            and len(values['output.bin'][0]) == 1 << 20
            and values['output.bin'][0][:len(image)] == image
            and values['output.bin'][1]['sha256'] == receipt['output_sha256']
            and values['stderr.log'][0] == b'', 'actual complete HIA input/output/image binding differs')
    require(request == {'format': 'flat-x86-64', 'image': str(compiler),
            'image_sha256': policy['compiler']['sha256'], 'source': str(build / 'cli-lifetime.input.bin'),
            'source_sha256': source_pin['sha256'], 'output': str(build / 'cli-lifetime.output.bin'),
            'capacity': 1 << 20, 'workspace_size': 1 << 20, 'workspace_fill': 0},
            'actual original compiler child request differs')
    return {'schema': 'hia.cli-json.lifetime-compile-byte-join.v1', 'status': 'ACTUAL_HIA_IMAGE_BOUND',
            'originals': {key: value[1] for key, value in values.items()}, 'receipt': receipt,
            'report': report_pin, 'image': values['image.bin'][1], 'source': source_pin,
            'compiler': pin(compiler, 1 << 20), 'fresh_cold': False}


def finite_cases(policy, policy_sha256, work, kind, dso, image=None):
    output = work / kind
    report, report_pin, _ = original(output / 'REPORT.json', 2 << 20)
    expected = list(RUNTIME_IDS if kind == 'runtime' else LIFETIME_IDS)
    require(report['schema'] == 'hia.cli-json.C-runtime-lifetime-finite.v1'
            and report['kind'] == kind and report['status'] == 'FINITE_' + kind.upper() + '_PASS'
            and report['expected_ids'] == report['loaded_ids'] == report['executed_ids'] == expected
            and len(report['outcomes']) == len(expected) and report['errors'] == []
            and report['policy_sha256'] == policy_sha256
            and report['dso_sha256'] == dso['image']['sha256']
            and report['original17_executed'] is False and report['original46_executed'] is False
            and report['body_driver_qualified'] is False and report['declared_child_seconds'] == 5,
            'complete finite case population or actual result differs')
    verified = []
    native_calls = pump_calls = 0
    for index, (case_id, row) in enumerate(zip(expected, report['outcomes'])):
        individual, individual_pin, _ = original(output / (case_id + '.json'))
        require(individual == row and row['id'] == case_id and row['status'] == 'PASS'
                and type(row['hia_entry_calls']) is int, 'actual individual case original differs')
        if kind == 'runtime':
            require(row['hia_entry_calls'] == 0, 'runtime-only admission executed a HIA entry')
        else:
            require(row['hia_entry_calls'] == EXPECTED_HIA_RETURNS[index]
                    and type(row['c_pump_calls']) is int and row['c_pump_calls'] == EXPECTED_C_PUMP_CALLS[index]
                    and row['raw_leaf_only'] is (case_id in RAW_LEAF_ONLY_IDS),
                    'real entry/negative/raw-leaf accounting differs')
            counted_native = 0
            for run in row.get('runs', []):
                trace_raw, trace_pin = read_file(Path(run['trace']['path']), 1 << 20)
                request_raw, request_pin = read_file(Path(run['request']['path']), 512)
                state_raw, state_pin = read_file(Path(run['state']['path']), 512)
                require(trace_pin == run['trace'] and request_pin == run['request'] and state_pin == run['state'],
                        'actual returned request/state/trace bytes changed')
                require(len(request_raw) == len(state_raw) == 512 and len(trace_raw) % 256 == 0,
                        'finite binary original extent differs')
                request = struct.unpack('<64Q', request_raw)
                trace = [struct.unpack_from('<32Q', trace_raw, at) for at in range(0, len(trace_raw), 256)]
                receipt = run['receipt']
                require(list(request) == receipt['raw_request_words'] and request[3] == 2
                        and request[21] == request[22] and request[23] == request[24]
                        and request[25] == request[26] and request[27] == len(trace)
                        and request[27] + request[28] == request[22] + request[24]
                        and request[30] == request[41] == request[42] == 0
                        and all(word == 0 for word in request[43:]),
                        'actual C terminal/return counters differ')
                counted_native += request[22]
                if run['complete_trace_required']:
                    native = [r for r in trace if r[0] == 1]
                    leaves = [r for r in trace if r[0] == 2]
                    require(request[28] == 0 and len(native) == request[22]
                            and len(leaves) == request[24] and len(native) == len(leaves) + 1
                            and [r[0] for r in trace] == [1, 2] * len(leaves) + [1]
                            and [r[3] for r in leaves] == list(range(1, len(leaves) + 1))
                            and [r[4] for r in leaves] == run['observed_effects']
                            and all(r[1] == 0 and r[10] == 2 for r in leaves)
                            and all(r[1] == 2 for r in native[:-1])
                            and native[-1][1] == request[20], 'complete actual leaf/native trace differs')
                    expected_effects = (YIELD_EFFECTS if request[13] == 2 else
                                        ERROR_TWO_STACK_EFFECTS if request[13] == 1 else NORMAL_EFFECTS)
                    require(run['observed_effects'] == list(expected_effects),
                            'actual HIA-selected effect sequence differs')
                else:
                    require(case_id == LIFETIME_IDS[6] and request[27] == 1 and request[28] == 10
                            and row['full_trace_qualified'] is False and row['negative_observer_control'] is True,
                            'incomplete trace was hidden or promoted to full qualification')
            require(counted_native == row['hia_entry_calls'], 'case actual request native denominator differs')
            if case_id == LIFETIME_IDS[7]:
                raw_request, _ = read_file(output / (case_id + '.request.bin'), 512)
                raw_state, _ = read_file(output / (case_id + '.state.bin'), 512)
                require(len(raw_request) == len(raw_state) == 512
                        and list(struct.unpack('<64Q', raw_request)) == row['request']
                        and all(row['request'][at] == 0 for at in range(18, 64))
                        and raw_state[8] == 1 and row['retained_to_process_exit'] is True,
                        'preentry refusal original bytes/retained ownership differ')
            native_calls += row['hia_entry_calls']; pump_calls += row['c_pump_calls']
        verified.append({'id': case_id, 'original': individual_pin})
    if kind == 'lifetime':
        require(report['image_sha256'] == image['image']['sha256']
                and native_calls == report['hia_entry_calls'] == sum(EXPECTED_HIA_RETURNS)
                and pump_calls == report['c_pump_calls'] == sum(EXPECTED_C_PUMP_CALLS)
                and report['quarantined_owners_retained_to_process_exit'] == 2,
                'complete actual lifetime population/entry/quarantine sum differs')
    else:
        require(report['image_sha256'] is None and report['hia_entry_calls'] == report['c_pump_calls'] == 0,
                'runtime-only child inherited a native result')
    return {'schema': 'hia.cli-json.independent-finite-case-join.v1', 'status': 'EXACT_FINITE_ORIGINALS_PASS',
            'kind': kind, 'report': report_pin, 'ids': expected, 'individual_originals': verified,
            'hia_entry_returns': native_calls, 'c_pump_calls_including_refusals': pump_calls,
            'full_graph_or_evaluator_equivalence': False}
