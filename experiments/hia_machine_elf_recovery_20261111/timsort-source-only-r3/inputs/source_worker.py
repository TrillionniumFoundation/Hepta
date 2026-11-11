"""Generate one candidate source and verify Core/caps; never run a native image."""
from hashlib import sha1, sha256
import ast
import json
import os
from pathlib import Path
import sys
import traceback

from common import ROOT, GENERATED, LIMITS, OVERLAYS, checked_config, create, require, wire

config = checked_config()
source = ROOT / 'source'
report = {
    'schema': 'hepta.hia.machine-elf.sort-source-generation.v1',
    'status': 'HOLD', 'scope': 'SOURCE_GENERATION_AND_CORE_ROUNDTRIP_ONLY',
    'native_compilation_executed': False, 'product_tests_executed': False,
    'matching_current_cold': False, 'whole_writer_qualified': False,
    'whole_native_delivery_qualified': False, 'original_limits': LIMITS,
    'syntax_checked': [], 'roundtrip': False,
}
try:
    for relative in OVERLAYS:
        raw = (source / relative).read_bytes()
        ast.parse(raw, filename=str(source / relative))
        report['syntax_checked'].append(relative)
    for name in ('complete_comparison_trajectories.py', 'oracle-608.py.txt'):
        ast.parse((ROOT / 'control' / name).read_bytes(), filename=str(ROOT / 'control' / name))
        report['syntax_checked'].append('control/' + name)
    cases = json.loads((ROOT / 'control' / 'complete_comparison_trajectory_inputs.json').read_bytes())
    require(len(cases['cases']) == 122 and len({row['id'] for row in cases['cases']}) == 122,
            'frozen full comparison input denominator differs')
    report['comparison_input_count'] = 122
    report['comparison_inputs_executed'] = False
    sys.path.insert(0, str(source))
    from tools.generate_hia_machine_elf import document
    from hepta.hia_agent_assembly import render_assembly, assemble_program
    value = document()
    document_raw = wire(value)
    report['core_document'] = create(ROOT / 'generated-document.json', document_raw)
    raw = render_assembly(value).encode('utf-8')
    report['generated_source'] = create(ROOT / 'generated-machine-elf.hiaasm', raw)
    report['generated_source']['git_blob_sha1'] = sha1(
        b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    functions = []
    for function in value['functions']:
        values = list(function['params'])
        edge_counts = []
        block_parameter_counts = []
        for block in function['blocks']:
            values.extend(block['params'])
            block_parameter_counts.append(len(block['params']))
            for operation in block['ops']:
                values.extend(operation['out'])
            term = block['term']
            if term['op'] == 'jump':
                edge_counts.append(len(term['args']))
            elif term['op'] == 'branch':
                edge_counts.extend((len(term['then']['args']), len(term['else']['args'])))
        unique_names = {item['name'] for item in values}
        # Compiler capacity is the number of distinct SSA names, not the
        # greatest decimal suffix. Sparse numbering remains only diagnostic.
        numeric_indices = [int(name[1:]) for name in unique_names
                           if type(name) is str and name.startswith('v')
                           and name[1:].isascii() and name[1:].isdecimal()]
        functions.append({
            'name': function['name'], 'blocks': len(function['blocks']),
            'ops': sum(len(block['ops']) for block in function['blocks']),
            'unique_ssa_names': len(unique_names),
            'function_parameters': len(function['params']),
            'max_block_parameters': max(block_parameter_counts, default=0),
            'max_edge_arguments': max(edge_counts, default=0),
            'largest_numeric_ssa_index_diagnostic': max(numeric_indices, default=None),
        })
    measurements = {
        'source_bytes': len(raw), 'lines': len(raw.splitlines()), 'functions': len(functions),
        'blocks': sum(row['blocks'] for row in functions),
        'max_blocks_per_function': max((row['blocks'] for row in functions), default=0),
        'ops': sum(row['ops'] for row in functions),
        'max_unique_ssa_names_per_function': max((row['unique_ssa_names'] for row in functions), default=0),
        'max_function_parameters': max((row['function_parameters'] for row in functions), default=0),
        'max_block_parameters': max((row['max_block_parameters'] for row in functions), default=0),
        'max_edge_arguments': max((row['max_edge_arguments'] for row in functions), default=0),
    }
    report.update(measurements=measurements, functions=functions)
    report['roundtrip'] = assemble_program(raw).as_dict() == value
    require(report['roundtrip'], 'complete generated Core roundtrip differs')
    require(measurements['functions'] == config['expected_generated_functions']
            and all(measurements[name] <= bound for name, bound in LIMITS.items()),
            'original authoring cap exceeded or expected function count differs')
    temporary = source / (GENERATED + '.timsort-new')
    create(temporary, raw, 0o644)
    os.replace(temporary, source / GENERATED)
    report['status'] = 'SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
except BaseException:
    report['error'] = traceback.format_exc()
finally:
    create(ROOT / 'source-generation-report.json', wire(report))
    print(json.dumps({'status': report['status'], 'scope': report['scope'],
                      'measurements': report.get('measurements'), 'error': report.get('error')}),
          flush=True)
raise SystemExit(0 if report['status'] == 'SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED' else 1)
