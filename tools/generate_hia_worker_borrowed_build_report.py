"""Render the native Borrowed ABI receipt from independently measured values."""
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_native_byte_abi import PROFILE
from hepta.hia_program_native import CORE_SCHEMAS, SUPPORTED_OPCODES, TARGET
from tools.generate_hia_agent_identity import receipt_template, source_program as identity_source
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_shared_build_report import IMPORTS
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_inspection_request import POLICY as INSPECTION

SOURCE = Path('examples/hia_bootstrap/worker_borrowed_build_report.hepta')
MAGIC = int.from_bytes(b'HIAWBR01', 'little')
OBJECT_FACTS = ('artifact_bytes', 'artifact_sha256', 'binary_inventory', 'core_sha256',
                'exports', 'foreign_buffer_exports', 'function_frames', 'implementation_sha256',
                'input_sha256', 'kind', 'machine_plan_sha256', 'machine_text_bytes',
                'machine_text_sha256', 'object_sha256', 'toolchain')
CLAIMS = {name: False for name in (
    'assembler_used', 'backend_refinement_proved', 'c_codegen_used', 'external_linker_used',
    'fallback_used', 'llvm_codegen_used', 'llvm_ir_used', 'native_execution_qualified',
    'rust_codegen_used', 'rust_reference_required', 'source_ast_required', 'whole_language_soundness_proved',
)}
CLAIMS.update(direct_machine_code=True, foreign_buffer_entrypoints_exposed=True,
              self_hosted=True, standalone_core_reverified=True)
CONTRACT = {
    **dict.fromkeys(OBJECT_FACTS, '__fragment__'),
    'build_host': {'byteorder': 'little', 'long_bits': 64, 'machine': 'x86_64', 'pointer_bits': 64,
                   'size_t_bits': 64, 'system': 'Linux'},
    'claims': CLAIMS,
    'external_abi': 'SysV AMD64 scalar C functions plus explicit synchronous borrowed-byte pointer/length entrypoints',
    'flags': [], 'implicit_profitability_optimizer_used': False, 'ok': True,
    'parent_death_guarded_linker': False, 'profile': PROFILE,
    'runtime_assumptions': [
        'Linux x86-64 LP64 runtime and ordinary C scalar ABI',
        'calloc/malloc return null or fresh nonaliasing allocations; calloc initializes every byte',
        'free releases a live allocation; libc memory functions implement their standard byte semantics',
        'abort terminates execution; traps do not promise cleanup',
        'linker, loader, libc and host hardware are trusted; native execution has no VM step/heap/call quotas',
        'foreign caller supplies live, correctly sized allocations for the synchronous call',
        'mutable foreign ranges are exclusive and read-only ranges are not concurrently mutated',
        'numeric guards do not prove allocation provenance or pointer liveness',
    ],
    'schema': 'hepta.hia.program.direct-native.v1', 'status': 'native_emitted_not_executed',
    'supported_core_schemas': sorted(CORE_SCHEMAS), 'supported_opcodes': sorted(SUPPORTED_OPCODES),
    'target': TARGET,
}
ABI = {
    'claims': {'backend_refinement_proven': False, 'binary_abi_observed': True,
               'native_execution_proven': False, 'whole_language_memory_safety_proven': False},
    'dynamic_exports': '__fragment__', 'format': 'ELF64', 'kind': 'ET_DYN', 'machine': 62,
    'schema': 'hepta.elf-shared-abi.v1', 'source_exports_rechecked': True,
    'unresolved_imports': '__fragment__',
}
POLICY = r'''
# All dynamic report fragments are separately checked on sealed Core, object,
# shared artifact and exact executable identities before the renderer runs.
def build_report(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(s) > 1048576 or input_word(s, 0) != MAGIC:
        return 4294967293
    mode = input_word(s, 8)
    if mode == 3:
        if length(s) != 24 or length(o) < 512 or input_word(s, 16) >= MASK_LIMIT:
            return 4294967293
        return import_list(o, input_word(s, 16))
    size = render_build(s, o, mode, 0)
    if size >= 4294967292:
        return size
    return render_build(s, o, mode, 1)

def render_build(s:readbuf, o:mutbuf, mode:u64, emit:u64) -> u64:
    if mode == 1:
        return borrowed_report(s, o, emit)
    if mode == 2:
        return shared_inventory(s, o, emit)
    return 4294967293
'''


def compact_template(record):
    return json.dumps(record, sort_keys=True, separators=(',', ':')).replace('"__fragment__"', '{}')


def import_list():
    lines = ['def import_list(o:mutbuf, mask:u64) -> u64:', '    store(o, 0, 91)', '    at = 1']
    for index, name in enumerate(IMPORTS):
        lines.extend((f'    if mask & {1 << index} != 0:', '        if at != 1:',
                      '            store(o, at, 44)', '            at = at + 1'))
        raw = f'"{name}"'.encode('ascii')
        for offset in range(0, len(raw), 8):
            part = raw[offset:offset + 8]
            lines.append(f'        at = receipt_literal(o, at, {int.from_bytes(part, "little")}, {len(part)}, 1)')
    lines.extend(('    store(o, at, 93)', '    return at + 1'))
    return '\n'.join(lines)


def program():
    identity = identity_source()
    return '\n'.join((
        POLICY.replace('MAGIC', str(MAGIC)).replace('MASK_LIMIT', str(1 << len(IMPORTS))),
        receipt_template('borrowed_report', compact_template(CONTRACT)),
        receipt_template('shared_inventory', compact_template(ABI)), import_list(),
        function(INSPECTION, 'input_word'),
        *(function(identity, name).replace('read_word(', 'input_word(')
          for name in ('receipt_fragment_size', 'receipt_literal', 'receipt_fragment')),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
