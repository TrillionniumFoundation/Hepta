"""Future finite Pager generation with the unchanged nine Core compiler caps.

Only the frozen outer owner may call generate(). This source does not import
the candidate at module load, run a VM, compile, or run a Pager. The generated
Core and assembly are retained BEFORE the caps are applied, including failure.
"""
from __future__ import annotations
import ast
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys

import pager_common_r1 as common

ROOT = Path(__file__).resolve().parent.parent
PARTS = ('pager_owner_lock_source_r3', 'pager_owner_page_source',
         'pager_owner_common_source_r2')
AUTHORS = (
    ('pager', 'generate_hia_sqlite_pager_retained_owner_r1'),
    ('linker', 'generate_hia_pager_elf_linker'),
)
CAPS = {
    'assembly_bytes': 1 << 20, 'assembly_split_newline_items': 16384,
    'functions': 128, 'total_blocks': 1536,
    'operations_including_terminators': 8192,
    'blocks_per_function': 256, 'function_parameters': 16,
    'all_argument_or_parameter_lists': 16, 'maximum_ssa_id': 2047,
}

def checked_module(name, request):
    path = ROOT/'inputs/tools'/(name+'.py')
    pin, raw = common.read(path, 1 << 20)
    expected = request['inputs'][str(path.relative_to(ROOT))]
    common.require(pin == expected, 'exact frozen author identity')
    ast.parse(raw.decode('utf-8'), filename=str(path))
    full_name = 'tools.'+name
    common.require(full_name not in sys.modules, 'author loaded before stage')
    spec = importlib.util.spec_from_file_location(full_name, path)
    common.require(spec is not None and spec.loader is not None, 'author loader')
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    common.require(common.read(path)[0] == pin, 'author changed while imported')
    return module, pin

def checked_retained_source(request):
    path = ROOT/'inputs/tools/sqlite_pager_retained_owner.hia'
    pin, raw = common.read(path, 1 << 20)
    common.require(pin == request['inputs'][str(path.relative_to(ROOT))]
        and len(raw) == 6223
        and hashlib.sha256(raw).hexdigest() ==
            '3c9ec1a7e570c27bdf879c1d88f810bb1dd9598800c36c0a9b144d9f16ede7f9',
        'exact frozen retained HIA source identity')
    return pin, raw

def cap_values(document, assembly):
    functions = document['functions']
    common.require(type(functions) is list and functions, 'Core function vector')
    blocks = [block for fn in functions for block in fn['blocks']]
    widths = []
    registers = []
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ('args', 'params') and isinstance(item, list):
                    widths.append(len(item))
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value.startswith('v') and value[1:].isdigit():
            registers.append(int(value[1:]))
    walk(document)
    common.require(registers, 'Core SSA namespace empty')
    values = {
        'assembly_bytes': len(assembly),
        'assembly_split_newline_items': len(assembly.decode('utf-8').split('\n')),
        'functions': len(functions), 'total_blocks': len(blocks),
        'operations_including_terminators': sum(len(b['ops'])+1 for b in blocks),
        'blocks_per_function': max(len(fn['blocks']) for fn in functions),
        'function_parameters': max(len(fn['params']) for fn in functions),
        'all_argument_or_parameter_lists': max(widths, default=0),
        'maximum_ssa_id': max(registers),
    }
    common.require(all(type(value) is int and value <= CAPS[name]
                       for name, value in values.items()),
                   'unchanged original nine compiler caps')
    common.require(all(len(fn['returns']) == 1 for fn in functions),
                   'original single-result function ABI')
    entry = functions[0]
    common.require(entry['name'] == 'f0'
                   and [p['type'] for p in entry['params']] ==
                       ['readbuf', 'mutbuf', 'mutbuf']
                   and entry['returns'] == ['u32'],
                   'original B3 physical entry types 6,7,7 -> u32')
    return values

def generate(request, output):
    output = Path(output)
    output.mkdir(mode=0o700)
    common.require(request['original_caps'] == CAPS, 'frozen unchanged caps')
    retained_before, retained_raw = checked_retained_source(request)
    source = Path(request['source_root'])
    sys.path.insert(0, str(source))
    assembly_module = importlib.import_module('hepta.hia_agent_assembly')
    # Import the existing parent namespace before installing the three exact
    # new author-only modules. No product execution is hidden in generation.
    importlib.import_module('tools.generate_hia_selfhost')
    modules = {}
    authors = {}
    for name in PARTS:
        modules[name], authors[name] = checked_module(name, request)
    results = {}
    for label, name in AUTHORS:
        author, author_pin = checked_module(name, request)
        document = author.document()
        core_raw = common.wire(document)
        assembly = assembly_module.render_assembly(document).encode('utf-8')
        # Full attempted products survive a later cap/roundtrip failure.
        common.require(len(core_raw) <= 4 << 20, 'original 4MiB physical file cap')
        core_pin = common.create(output/(label+'.core.json'), core_raw, raw=True)
        asm_pin = common.create(output/(label+'.hiaasm'), assembly, raw=True)
        values = cap_values(document, assembly)
        reconstructed = assembly_module.assemble_program(assembly.decode('utf-8'))
        common.require(reconstructed.as_dict() == document,
                       'complete independent assembly-to-Core roundtrip')
        common.require(assembly_module.render_assembly(reconstructed.as_dict()) ==
                       assembly.decode('utf-8'), 'canonical assembly roundtrip')
        results[label] = {
            'author': author_pin, 'core': core_pin, 'assembly': asm_pin,
            'caps': values, 'cap_limits': CAPS, 'native_or_VM_executed': False}
        common.create(output/(label+'.GENERATION.json'), results[label])
    retained_after, retained_after_raw = checked_retained_source(request)
    common.require(retained_after == retained_before and retained_after_raw == retained_raw,
                   'retained HIA source changed during complete generation')
    common.require(set(results) == {'pager', 'linker'}, 'exact two author stages')
    common.create(output/'GENERATION.json', {
        'schema': 'hia.sqlite-pager.finite-generation.v1',
        'status': 'TWO_CORE_ASSEMBLY_CAPS_PASS_ONLY',
        'parts': authors, 'programs': results,
        'retained_hia_source': {'before': retained_before, 'after': retained_after},
        'native_or_VM_executed': False})
    return results
