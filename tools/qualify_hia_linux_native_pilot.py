#!/usr/bin/env python3
"""Matched host pilot of real Linux/HIA objects, explicitly not a kernel result."""
from __future__ import annotations

import argparse
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
import platform
import re
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_linux_kernel import build_kernel_object, require
from hepta.hia_program_source import lower_source
from tools import qualify_hia_linux_baseline as base
from tools import qualify_hia_linux_component as component

PLAN = ROOT / 'benchmarks/hia_linux_kernel/NATIVE_PILOT.json'
ASSETS = ROOT / 'examples/hia_linux_kernel'


def put(path, value):
    component.write(path, value)
    return component.binding(path)


def clean_command(record):
    return (type(record) is dict and record.get('timed_out') is False
            and base.process_group_outcome_admissible(record))


def validate_observation(value, expected, cases):
    required = set(expected) | {'comparisons', 'wall_ns', 'cpu_ns', 'has_popcnt'}
    require(type(value) is dict and set(value) == required, 'exact observation fields required')
    require(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()),
            'native trial denominator/output differs')
    require(type(value['has_popcnt']) is bool, 'actual POPCNT observation must be boolean')
    require(expected['arm'] != 3 or value['has_popcnt'] is True,
            'hardware POPCNT arm requires observed CPU support')
    require(type(value['comparisons']) is int and value['comparisons'] == cases*(4 if value['has_popcnt'] else 3)
            and type(value['wall_ns']) is int and value['wall_ns'] > 0
            and type(value['cpu_ns']) is int and value['cpu_ns'] > 0,
            'native clocks/comparisons invalid')


def run(args):
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), 'new output outside checkout required')
    require(args.cpu in os.sched_getaffinity(0), 'explicit allowed CPU required')
    output.mkdir(parents=True)
    start = time.monotonic_ns()
    plan = json.loads(PLAN.read_bytes())
    orders = list(itertools.permutations(range(len(plan['arms']))))
    require(plan['blocks'] == len(orders) == 24, 'frozen balanced order required')
    cells = [{'block': b, 'position': p, 'arm': plan['arms'][a], 'arm_id': a, 'status': 'NOT_RUN'}
             for b, order in enumerate(orders) for p, a in enumerate(order)]
    report = {'schema': 'hepta.hia.linux-native-pilot-result.v1', 'status': 'FAIL',
              'scope': plan['scope'], 'cells': cells, 'plan': component.binding(PLAN),
              'claims': {'kernel_built': False, 'kernel_booted': False, 'whole_kernel_rewritten': False,
                         'global_comparison_completed': False, 'ndu_gain_established': False},
              'ndu_calls': 0, 'shared_host': True, 'frequency_locked': False,
              'production_activation': False, 'memory_performance': 'NOT_MEASURED',
              'host': {'platform': platform.platform(), 'allowed_cpus': sorted(os.sched_getaffinity(0)),
                       'selected_cpu': args.cpu}, 'commands': []}
    tool_bindings = {name: component.binding(getattr(args, name)) for name in ('clang', 'objdump')}
    report['tools_before'] = tool_bindings
    child_environment = {key: value for key, value in os.environ.items()
                         if key in {'PATH', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR'}}
    report['child_environment'] = child_environment
    runner = base.CommandRunner(output, child_environment)
    try:
        before = component.source_identity(args.expected_head)
        report['source_before'] = before
        report['runner'] = component.binding(__file__)
        raw = args.upstream.read_bytes()
        require(sha256(raw).hexdigest() == plan['upstream_sha256'], 'frozen upstream assembly hash mismatch')
        put(output / 'upstream-hweight.S', raw)
        report['upstream'] = {'input': component.binding(args.upstream), 'commit': plan['upstream_commit'],
                              'path': plan['upstream_path']}
        put(output / 'profile.config', plan['profile_config'])
        program = lower_source((ASSETS / 'hweight32.hepta').read_text())
        report['core'] = put(output / 'hweight32.core.json', program.as_dict())
        report['hia_object'] = build_kernel_object(program, output / 'hia.o',
            config=plan['profile_config'].encode(), clang=str(args.clang), objdump=str(args.objdump),
            command_log=report['commands'])
        report['arithmetic'] = component.prove_arithmetic(program, output)
        require(report['arithmetic']['status'] == 'PASS', 'independent all-u32 arithmetic proof failed')
        # These explicit host stubs do not pretend to be the Linux preprocessor.
        headers = output / 'include'
        put(headers / 'linux/export.h', '#define EXPORT_SYMBOL(n)\n')
        put(headers / 'linux/linkage.h',
            '#define SYM_FUNC_START(n) .globl n; .type n,@function; .p2align 4; n:\n'
            '#define SYM_FUNC_END(n) .size n,.-n\n#define RET jmp __x86_return_thunk\n')
        put(headers / 'linux/objtool.h', '#define ANNOTATE_NOENDBR\n')
        put(headers / 'asm/asm.h', '#define __ASM_SIZE(x,y) x##q\n#define __ASM_REG(x) r##x\n')
        bridge = '#include <linux/linkage.h>\n#include <linux/objtool.h>\n.text\n' + component.WRAPPER.replace(
            '__sw_hweight32', 'hia_bridge_hweight32') + '\n.section .note.GNU-stack,"",@progbits\n'
        put(output / 'bridge.S', bridge)
        put(output / 'hardware.c', 'unsigned hardware_popcnt(unsigned w) {return __builtin_popcount(w);}\n')
        common = [str(args.clang), '-O2', '-fno-lto', '-fno-builtin', '-fno-pie', '-mno-red-zone',
                  '-mgeneral-regs-only', '-mno-popcnt', '-mfunction-return=thunk-extern', '-fcf-protection=branch']
        def command(name, argv):
            return runner.run(name, [str(x) for x in argv], timeout=60)
        command('stock-assembly', [*common, '-I', headers, '-DCONFIG_X86_64=1', '-c', output/'upstream-hweight.S', '-o', output/'stock.o'])
        command('bridge', [*common, '-I', headers, '-c', output/'bridge.S', '-o', output/'bridge.o'])
        for name, target in [('stock', '__sw_hweight32'), ('hybrid', 'hia_bridge_hweight32')]:
            command(name+'-abi', [*common, '-I', headers, '-Dhia_hweight_abi_probe='+name+'_abi_probe',
                '-D__sw_hweight32='+target, '-c', ASSETS/'abi_probe.S', '-o', output/(name+'-abi.o')])
        command('hardware-popcnt', [*common, '-mpopcnt', '-c', output/'hardware.c', '-o', output/'hardware.o'])
        exe = output / 'pilot'
        def link(object_path, target, name):
            command(name, [*common, '-no-pie', ASSETS/'native_pilot.c', output/'stock.o', object_path,
                output/'bridge.o', output/'stock-abi.o', output/'hybrid-abi.o', output/'hardware.o',
                ASSETS/'host_return_thunk.S', '-o', target])
        link(output/'hia.o', exe, 'link')
        report['executable'] = component.binding(exe)
        inspection = command('inspect-linked-executable', [args.objdump, '-dr', exe])
        disassembly = Path(inspection['stdout']['path']).read_text()
        def body(name):
            match = re.search(r'<' + re.escape(name) + r'>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)', disassembly, re.S)
            require(match is not None, 'missing linked body: ' + name)
            return match.group(1)
        require(re.search(r'\bcallq?\b.*<hia_sw_hweight32>', body('hia_bridge_hweight32')) is not None,
                'preserving bridge does not call the actual HIA body')
        require(re.search(r'\bpopcnt[lq]?\b', body('hardware_popcnt')) is not None,
                'hardware control has no actual POPCNT instruction')
        require(all(re.search(r'\bpopcnt[lq]?\b', body(name)) is None
                    for name in ('__sw_hweight32', 'hia_sw_hweight32')),
                'software/HIA control unexpectedly uses hardware POPCNT')
        report['linked_route_inspection'] = {'status': 'PASS', 'command_receipt': inspection}
        wrong = lower_source('module wrong; export "C" fn hia_sw_hweight32(w:u32)->u32 effects {} {return 0;}')
        report['wrong_object'] = build_kernel_object(wrong, output/'wrong.o',
            config=plan['profile_config'].encode(), clang=str(args.clang), objdump=str(args.objdump),
            command_log=report['commands'])
        link(output/'wrong.o', output/'wrong-pilot', 'link-wrong-body')
        negative = runner.run('reject-wrong-body', [str(output/'wrong-pilot'), '0', '1', str(args.cpu)],
                              timeout=30, check=False)
        negative_value = json.loads(Path(negative['stdout']['path']).read_bytes())
        require(negative['exit_code'] == 1 and clean_command(negative)
                and negative_value.get('status') == 'FAIL'
                and type(negative_value.get('failures')) is int and negative_value['failures'] > 0,
                'the actual pilot driver must reject the wrong HIA body before timing')
        report['negative_control'] = {'status': 'EXPECTED_FAILURE', 'command_receipt': negative,
                                      'observation': negative_value}
        artifacts = [p for p in output.rglob('*') if p.is_file() and 'commands' not in p.parts]
        report['build_inputs_and_artifacts'] = {str(p.relative_to(output)): component.binding(p) for p in artifacts}
        input_digest = component.expected_digest()
        expected_sum = sum(value.bit_count() for value in component.inputs()) * plan['cycles_per_trial']
        for cell in cells:
            cell['status'] = 'FAIL'
            record = runner.run('trial-%02d-%d' % (cell['block'], cell['position']),
                [str(exe), str(cell['arm_id']), str(plan['cycles_per_trial']), str(args.cpu)], timeout=30, check=False)
            cell['command_receipt'] = record
            value = json.loads(Path(record['stdout']['path']).read_bytes())
            cell['observation'] = value
            if clean_command(record) and record['exit_code'] == 77 and cell['arm_id'] == 3 and value == {'status': 'NOT_RUN_UNSUPPORTED_CPU', 'arm': 3}:
                cell['status'] = 'NOT_RUN_UNSUPPORTED_CPU'
                continue
            cell['status'] = 'FAIL'
            require(type(record['exit_code']) is int and record['exit_code'] == 0 and clean_command(record), 'actual native trial failed')
            expected = {'arm': cell['arm_id'], 'cases': plan['cases'], 'cycles': plan['cycles_per_trial'],
                        'calls': plan['cases']*plan['cycles_per_trial'], 'input_digest': input_digest,
                        'sum': expected_sum, 'failures': 0, 'abi_checks': 64, 'status': 'PASS', 'cpu': args.cpu}
            validate_observation(value, expected, plan['cases'])
            cell['status'] = 'PASS'
        summary = {}
        for arm in plan['arms']:
            rows = [c for c in cells if c['arm'] == arm and c['status'] == 'PASS']
            summary[arm] = {'planned': 24, 'passed': len(rows)}
            if rows:
                summary[arm].update(wall_ns_per_call_median=statistics.median(c['observation']['wall_ns']/c['observation']['calls'] for c in rows),
                    cpu_ns_per_call_median=statistics.median(c['observation']['cpu_ns']/c['observation']['calls'] for c in rows))
        ratios = []
        for block in range(24):
            group = {c['arm']: c['observation'] for c in cells if c['block'] == block and c['status'] == 'PASS'}
            ratios.append(group['hia-preserving-bridge']['wall_ns']/group['linux-software-asm']['wall_ns'])
        report['summary'] = summary
        report['bridge_over_stock_paired_ratios'] = ratios
        report['bridge_over_stock_paired_ratio_median'] = statistics.median(ratios)
        report['source_after'] = component.source_identity(args.expected_head)
        require(before == report['source_after'], 'execution source changed')
        require(component.binding(exe) == report['executable'], 'timed executable changed')
        require({name: component.binding(getattr(args, name)) for name in tool_bindings} == tool_bindings,
                'native tool bytes changed')
        require(all(component.binding(item['path']) == item for item in report['build_inputs_and_artifacts'].values()),
                'bound build inputs/artifacts changed')
        require(component.binding(PLAN) == report['plan'] and component.binding(__file__) == report['runner'],
                'pilot plan or runner changed')
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        report['lifecycle_commands'] = runner.records
        report['outer_wall_ns'] = time.monotonic_ns() - start
        report['cost_rule'] = 'Outer includes all setup, proof, compilation, child startup/checks and trials; do not add nested times again.'
        put(output / 'RESULT.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'upstream', 'clang', 'objdump'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--cpu', type=int, required=True)
    args = parser.parse_args()
    args.clang, args.objdump = args.clang.resolve(strict=True), args.objdump.resolve(strict=True)
    # A single explicit environment is shared by helper/compiler and driver children.
    environment = {key: value for key, value in os.environ.items()
                   if key in {'PATH', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR'}}
    environment.update(LC_ALL='C', LANG='C', TZ='UTC')
    os.environ.clear()
    os.environ.update(environment)
    report = run(args)
    print(json.dumps({k: report[k] for k in ('status', 'scope', 'claims')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
