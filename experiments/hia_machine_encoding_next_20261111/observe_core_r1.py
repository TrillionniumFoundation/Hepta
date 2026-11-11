"""Independent Core-VM byte comparisons for the experimental HIA encoder."""
from __future__ import annotations

from collections import Counter
import ctypes
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_machine_x64 import Code
from hepta.hia_program_runtime import _Machine, _Owner, _View

HERE = Path(__file__).resolve().parent


def load_bridge():
    spec = importlib.util.spec_from_file_location('experimental_machine_encoding_bridge', HERE / 'native_encoding_bridge.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cases():
    rows = []
    def add(name, operations, **options):
        rows.append({'id': name, 'operations': operations, 'options': options})
    instructions = [
        ('align', [32]), ('mov_rr', ['r15', 'r12']),
        ('load', ['r15', 'rsp', -(1 << 31)]), ('store', ['r12', (1 << 31) - 1, 'r9']),
        ('lea', ['r10', 'r12', -17]), ('load_u8', ['r9', 'rsp', 0]),
        ('store_u8', ['r12', 17, 'rsi']),
        *[(op, ['r9', 'r15']) for op in ('add', 'sub', 'and_', 'or_', 'xor', 'cmp', 'test', 'imul', 'imul_rr')],
        *[(op, ['r15']) for op in ('mul', 'imul_full', 'div', 'idiv', 'neg', 'bitnot', 'push', 'pop')],
        *[(op, []) for op in ('cqo', 'ret', 'leave', 'ud2')],
        ('setcc', ['ne', 'r11']), ('cmov', ['e', 'r10', 'r9']),
        ('shift_imm', ['sar', 'r9', 63]), ('shift_cl', ['shr', 'r10']),
        ('shl', ['r10', 0]), ('shr', ['r11', 17]), ('sar', ['r12', 'cl']),
    ]
    for swapped in (False, True):
        options = {'scratch_registers': {'r10': 'r11', 'r11': 'r10'}} if swapped else {}
        for index, instruction in enumerate(instructions):
            add(f'public-{int(swapped)}-{index}', [instruction], **options)
    for compact in (False, True):
        options = {'move_immediate': 'mov32_if_exact' if compact else 'movabs',
                   'alu_immediate': 'imm8_if_exact' if compact else 'imm32'}
        for index, value in enumerate((-(1 << 63), -1, 0, (1 << 32) - 1, 1 << 32, (1 << 64) - 1)):
            add(f'move-{int(compact)}-{index}', [('mov_imm', ['r9', value])], **options)
        for op in ('add', 'or', 'and', 'sub', 'xor', 'cmp'):
            for value in (-129, -128, 127, 128):
                add(f'alu-{int(compact)}-{op}-{value}', [('alu_imm', [op, 'r11', value])], **options)
    for condition in ('o', 'no', 'c', 'nc', 'z', 'nz', 'na', 'nbe', 's', 'ns', 'pe', 'po', 'nge', 'nl', 'ng', 'nle'):
        add('condition-' + condition, [('setcc', [condition, 'r15']), ('cmov', [condition, 'r8', 'r9'])])
    add('labels-calls-rel32', [('label', ['start']), ('jmp', ['end']), ('call', ['calloc']),
        ('jcc', ['ne', 'start']), ('label', ['end']), ('ret', [])])
    bad = [
        ('mov_rr', ['rax', 'eax']), ('mov_imm', ['rax', True]),
        ('mov_imm', ['rax', 1 << 64]), ('load', ['rax', 'r12', 1 << 31]),
        ('shift', ['shl', 'rax', 64]), ('alu_imm', ['bad', 'unknown', True]),
        ('jcc', ['unsupported', 'x']), ('cmov', ['e', 'rax', '[rcx]']),
        ('call', ['puts;system']), ('jmp', ['']), ('align', [True]),
    ]
    for index, operation in enumerate(bad):
        add('refusal-' + str(index), [operation])
    add('unresolved-label', [('jmp', ['missing'])])
    return rows


def observe(factory, row):
    value = factory(**row['options'])
    result = {'exception': None}
    try:
        for name, arguments in row['operations']:
            getattr(value, name)(*arguments)
        raw, relocations = value.finalize()
        result['final'] = {'bytes': raw.hex(), 'relocations': relocations}
        if value.finalize() != (raw, relocations):
            raise AssertionError('repeated finalize differs')
    except Exception as exc:
        result['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
    result.update(data=value.data.hex(), labels=dict(value.labels), fixups=list(value.fixups),
                  relocations=[dict(item) for item in value.relocations])
    return result


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = HERE / 'source-r1/machine_encoding.hiaasm'
    paths = [source, HERE / 'generate_machine_encoding.py', HERE / 'native_encoding_bridge.py', Path(__file__)]
    before = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in paths}
    report = {'schema': 'hepta.hia.machine-encoding.core-observation.v1',
              'scope': 'INDEPENDENT_CORE_VM_NOT_NATIVE_OR_COLD', 'status': 'STARTED',
              'source_before': before, 'cases': [], 'entries': [], 'python': sys.version}
    start = time.monotonic()
    try:
        bridge = load_bridge()
        program = assemble_program(source.read_bytes())
        function = program.as_dict()['functions'][0]
        def entry(source_ptr, source_size, output_ptr, output_size, workspace_ptr, workspace_size):
            packet = ctypes.string_at(source_ptr, source_size)
            previous_output = ctypes.string_at(output_ptr, output_size)
            previous_workspace = ctypes.string_at(workspace_ptr, workspace_size)
            owners = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(previous_output)),
                      _Owner(-3, bytearray(previous_workspace))]
            machine = _Machine(program, 4_000_000, 16 << 20, None, 128)
            status = machine.invoke(function, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            if bytes(owners[0].data) != packet:
                raise AssertionError('Core VM changed input packet')
            for pointer, owner in ((output_ptr, owners[1]), (workspace_ptr, owners[2])):
                ctypes.memmove(pointer, bytes(owner.data), len(owner.data))
            report['entries'].append({'packet_hex': packet.hex(), 'status': status,
                'output_before_hex': previous_output.hex(), 'output_after_hex': bytes(owners[1].data).hex(),
                'workspace_before_hex': previous_workspace.hex(), 'workspace_after_hex': bytes(owners[2].data).hex(),
                'resources': machine.resources()})
            return status
        encoding = bridge.NativeMachineEncoding.__new__(bridge.NativeMachineEncoding)
        encoding._entry = entry
        encoding.calls = Counter()
        candidate = bridge.selected_code_class(encoding)
        for row in cases():
            original = observe(Code, row)
            actual = observe(candidate, row)
            report['cases'].append({**row, 'reference': original, 'candidate': actual, 'equal': actual == original})
            if actual != original:
                raise AssertionError('complete Code observation differs: ' + row['id'])
        report['commands_observed'] = dict(encoding.calls)
        if set(encoding.calls) != set(bridge.COMMANDS):
            raise AssertionError('not every declared packing command was observed')
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
    report['source_after'] = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in paths}
    report['source_stable'] = report['source_after'] == before
    if not report['source_stable']:
        report['status'] = 'FAIL'
    report['seconds'] = time.monotonic() - start
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('schema', 'scope', 'status', 'seconds', 'source_stable')} |
        {'cases': len(report['cases']), 'entries': len(report['entries']), 'commands': len(report.get('commands_observed', {})),
         'exception': report.get('exception')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
