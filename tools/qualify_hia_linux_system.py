#!/usr/bin/env python3
"""Build one registered control/hybrid Linux image and replay its real TCG boot.

Run the two arms into separate new output directories, with the same completed
stock receipt and formal component preparation. These are correctness runs on a
shared host, not paired performance measurements or a whole-kernel rewrite.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import qualify_hia_linux_baseline as base
from tools import qualify_hia_linux_component as component_tool


require = base.require
KINDS = {'control': 'instrumented_linux_control', 'hybrid': 'hybrid_linux_hia_component'}


def checked_binding(record):
    require(isinstance(record, dict) and all(key in record for key in ('path', 'bytes', 'sha256')),
            'complete file binding required')
    actual = base.identity(record['path'])
    require(actual == {key: record[key] for key in actual}, 'bound file changed: ' + record['path'])
    return Path(record['path'])


def single_option(command, flag):
    require(command.count(flag) == 1 and command.index(flag) + 1 < len(command), 'unique option required: ' + flag)
    return command[command.index(flag) + 1]


def validate_stock(stock):
    require(stock.get('status') == stock.get('build_status') == stock.get('boot_status') == 'PASS',
            'completed stock build and boot are required')
    require(stock.get('image_kind') == 'stock_linux' and stock.get('linux_source_unchanged') is True,
            'unchanged stock source evidence required')
    require(stock.get('source_archive_sha256') == base.ARCHIVE_SHA256, 'wrong stock upstream')
    for key in ('config', 'kernel_image', 'vmlinux', 'guest_init', 'initramfs', 'compiler'):
        checked_binding(stock[key])
    checked_binding(stock['qemu'])
    checked_binding(stock['qemu']['bios'])
    command = stock['boot']['command_receipt']
    for key in ('stdout', 'stderr'):
        checked_binding(command[key])
    require(single_option(command['argv'], '-kernel') == stock['kernel_image']['path'], 'stock boot image mismatch')
    require(single_option(command['argv'], '-initrd') == stock['initramfs']['path'], 'stock boot initramfs mismatch')
    verdict = base.parse_guest_serial(Path(command['stdout']['path']).read_text(errors='strict'),
                                     stock['run_id'], command['exit_code'], command['timed_out'])
    require(verdict['status'] == 'PASS' and verdict['guest_tests'] == stock['guest_tests'], 'stock raw boot replay failed')
    require(base.sha(Path(base.__file__)) == stock['source_before']['wrapper']['sha256'], 'stock runner bytes changed')
    require(base.sha(ROOT / 'experiments/hia_linux_kernel_20261106/guest_init.c') ==
            stock['source_before']['guest_source']['sha256'], 'stock guest source bytes changed')
    return verdict


def overlay_expected_inventory(before, manifest):
    expected = {item['path']: dict(item) for item in before}
    require(len(expected) == len(before), 'duplicate upstream inventory entries')
    visited = set()
    for item in manifest['files']:
        name = item['relative_path']
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name and name not in visited,
                'unsafe/duplicate overlay path')
        visited.add(name)
        old = expected.get(name)
        require((old['sha256'] if old else None) == item['before_sha256'], 'overlay before-image mismatch')
        require(old is None or old['type'] == 'file', 'overlay may not replace a symlink')
        checked_binding(item['after'])
        expected[name] = {'path': name, 'type': 'file', 'bytes': item['after']['bytes'], 'sha256': item['after']['sha256']}
    return sorted(expected.values(), key=lambda item: item['path'])


def require_independent_inodes(original, copied, entries):
    original, copied = Path(original).resolve(), Path(copied).resolve()
    require(original != copied and not copied.is_relative_to(original), 'independent source copy required')
    for entry in entries:
        if entry['type'] != 'file':
            continue
        left, right = (original / entry['path']).stat(), (copied / entry['path']).stat()
        require((left.st_dev, left.st_ino) != (right.st_dev, right.st_ino), 'hardlinked source copy refused: ' + entry['path'])


def validate_component_observation(text, arm, prepared):
    rows = []
    for line in text.splitlines():
        if component_tool.PREFIX in line:
            rows.append(json.loads(line.split(component_tool.PREFIX, 1)[1]))
    require(len(rows) == 1, 'exactly one complete component kernel observation is required')
    expected = {'arm': arm,
                'core_sha256': prepared['artifact']['core_sha256'] if arm == 'hybrid' else '0' * 64,
                'object_sha256': prepared['artifact']['sha256'] if arm == 'hybrid' else '0' * 64,
                'direct_calls': component_tool.CALLS, 'natural_calls': component_tool.CALLS,
                'abi_calls': 32, 'popcnt': 0, 'failures': 0,
                'result_digest': component_tool.expected_digest()}
    require(isinstance(rows[0], dict) and rows[0].keys() == expected.keys()
            and all(type(rows[0][key]) is type(value) for key, value in expected.items()),
            'component observation field types differ')
    require(rows[0] == expected, 'component/ABI/oracle/CPU-route observation differs')
    return {'status': 'PASS', 'observation': rows[0], 'whole_kernel_rewrite': False,
            'scope': 'registered_driver_calls_not_a_whole_system_hotpath_counter'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', choices=tuple(KINDS), required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--component', type=Path, required=True)
    parser.add_argument('--linux-source', type=Path, required=True)
    parser.add_argument('--tool-sysroot', type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=3)
    parser.add_argument('--build-timeout', type=int, default=7200)
    parser.add_argument('--boot-timeout', type=int, default=180)
    args = parser.parse_args(argv)
    require(re.fullmatch('[a-f0-9]{40}', args.expected_head), 'exact execution source SHA required')
    require(1 <= args.jobs <= 64 and args.build_timeout > 0 and args.boot_timeout > 0, 'finite positive budget required')
    source, output = args.linux_source.resolve(), args.output.resolve()
    for protected in (ROOT, source, args.baseline.resolve().parent, args.component.resolve().parent):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output), 'output overlaps immutable inputs')
    output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    result = {'schema': 'hepta.hia.linux.component-system-arm.v1', 'arm': args.arm,
              'image_kind': KINDS[args.arm], 'status': 'FAIL', 'build_status': 'NOT_RUN', 'boot_status': 'NOT_RUN',
              'component_status': 'NOT_RUN', 'started_at_utc': base.utc(), 'source_commit': args.expected_head,
              'whole_kernel_rewrite': False, 'global_linux_qualification': False, 'performance_comparison': False,
              'shared_host_correctness_run': True, 'production_activation': False, 'ndu_calls': 0,
              'active_compile_units': None, 'fallback_c_units': None,
              'hia_compiled_units': 0, 'guest_tests': {'total': len(base.CHECK_IDS), 'passed': 0,
                                                   'failed': 0, 'skipped': 0, 'not_run': len(base.CHECK_IDS)}}
    runner, code_before, before, patched_before, copied = None, None, None, None, None
    try:
        code_before = base.source_identity(args.expected_head)
        result['source_before'] = code_before
        result['system_runner'] = base.identity(__file__)
        stock = json.loads(args.baseline.read_bytes())
        validate_stock(stock)
        result['stock_baseline'] = base.identity(args.baseline)
        result['stock_execution_source_commit'] = stock['source_commit']
        prepared = json.loads(args.component.read_bytes())
        require(prepared.get('status') == 'PASS' and prepared.get('formal_evidence') is True,
                'formal prepared component required')
        require(prepared['implementation_source']['commit'] == args.expected_head
                and prepared['implementation_source']['development_only'] is False,
                'component and system source freeze differ')
        require(prepared['source']['configuration']['sha256'] == stock['config_sha256'], 'prepared component config differs from stock')
        require(prepared['artifact']['compiler_version'].splitlines()[0] == stock['compiler']['version'], 'component compiler differs from stock')
        checked_binding(prepared['source']['configuration'])
        checked_binding(prepared['artifact'])
        result['prepared_component'] = base.identity(args.component)
        overlays = {}
        for arm in KINDS:
            overlays[arm] = json.loads(checked_binding(prepared['overlays'][arm]).read_bytes())
        for name in ('arch/x86/lib/hia_component_selftest.c', 'arch/x86/lib/hia_abi_probe.S'):
            left = next(item for item in overlays['control']['files'] if item['relative_path'] == name)
            right = next(item for item in overlays['hybrid']['files'] if item['relative_path'] == name)
            require(left['after']['sha256'] == right['after']['sha256'], 'paired test algorithm or ABI probe differs')
        manifest = overlays[args.arm]
        require(manifest['arm'] == args.arm and manifest['configuration_sha256'] == stock['config_sha256'], 'overlay identity mismatch')
        original_inventory = checked_binding(stock['linux_source_inventory'])
        before = json.loads(gzip.decompress(original_inventory.read_bytes()))
        require(base.inventory_tree(source) == before, 'pristine source differs from completed stock')
        llvm = Path(stock['compiler']['path']).parent
        for tool in stock['llvm_tools'].values():
            checked_binding(tool)
        env = base.build_environment(llvm, args.tool_sysroot)
        stock_environment = Path(args.baseline).parent / 'build-environment.json'
        require(json.loads(stock_environment.read_bytes()) == env, 'compiler environment differs from stock')
        result['build_environment'] = base.identity(stock_environment)
        result['compiler'], result['llvm_tools'], result['qemu'] = stock['compiler'], stock['llvm_tools'], stock['qemu']
        runner = base.CommandRunner(output, env)
        copied = output / 'linux-source'
        runner.run('copy-pristine-source', ['cp', '--reflink=auto', '-a', source, copied], timeout=300)
        require_independent_inodes(source, copied, before)
        require(base.inventory_tree(copied) == before, 'source copy bytes differ before overlay')
        patched_before = overlay_expected_inventory(before, manifest)
        for item in manifest['files']:
            target = copied / item['relative_path']
            require(target.parent.resolve().is_relative_to(copied), 'overlay parent escapes copied tree')
        applied_path = output / 'APPLIED.json'
        runner.run('apply-registered-overlay', [sys.executable, '-B', ROOT / 'tools/qualify_hia_linux_component.py',
                                              'apply', '--component', args.component, '--arm', args.arm,
                                              '--source-copy', copied, '--receipt', applied_path])
        require(base.inventory_tree(copied) == patched_before, 'overlay changed unregistered source bytes')
        result['applied'] = base.identity(applied_path)
        result['source_copy'] = str(copied)
        result['source_overlay_manifest'] = prepared['overlays'][args.arm]
        result['source_copy_before_inventory'] = base.write_gzip_json(output / 'source-copy-before.json.gz', patched_before)
        build = output / 'build'
        build.mkdir()
        shutil.copyfile(stock['config']['path'], build / '.config')
        make = ['make', '-C', str(copied), 'O=' + str(build), 'ARCH=x86_64', 'LLVM=' + str(llvm) + '/', 'V=1']
        runner.run('olddefconfig', [*make, 'olddefconfig'])
        require(base.sha(build / '.config') == stock['config_sha256'], 'paired final kernel configuration differs')
        shutil.copyfile(build / '.config', output / 'exact.config')
        result['config'], result['config_sha256'] = base.identity(output / 'exact.config'), stock['config_sha256']
        result['kernel_version'] = stock['kernel_version']
        result['source_archive_sha256'] = stock['source_archive_sha256']
        result['build_status'] = 'FAIL'
        build_record = runner.run('full-kbuild', [*make, '-j' + str(args.jobs), 'vmlinux', 'bzImage', 'modules'],
                                  timeout=args.build_timeout)
        diagnostics = []
        for stream in ('stdout', 'stderr'):
            with Path(build_record[stream]['path']).open(errors='replace') as lines:
                diagnostics.extend(line.strip() for line in lines if re.search(r'\bobjtool:', line))
        result['objtool_diagnostics'] = diagnostics
        require(not diagnostics, 'objtool diagnostics require review; no bypass admitted')
        require(base.sha(build / '.config') == stock['config_sha256'], 'Kbuild changed paired config')
        result['kbuild_command_status'] = 'PASS'
        result['kernel_image'], result['vmlinux'] = base.identity(build / 'arch/x86/boot/bzImage'), base.identity(build / 'vmlinux')
        full_path = output / 'compile_commands.json'
        runner.run('compile-database', [sys.executable, '-B', copied / 'scripts/clang-tools/gen_compile_commands.py',
                                       '-d', build, '-o', full_path, '-a', llvm / 'llvm-ar'])
        database = json.loads(full_path.read_bytes())
        require(isinstance(database, list) and database, 'actual full compilation database required')
        result['original_compile_commands'], result['original_compile_commands_sha256'] = base.identity(full_path), base.sha(full_path)
        metadata, coverage = base.collect_build_inventory(copied, build, output, database)
        result['build_inventory'] = metadata
        indices = [row['index'] for row in coverage['compile_commands'] if row['role'] == 'kernel_target_c']
        require(indices, 'positive target C compilation denominator required')
        target_path = output / 'target-compile_commands.json'
        base.write_json(target_path, [database[index] for index in indices])
        result['target_compile_indices'] = indices
        result['compile_commands'], result['compile_commands_sha256'] = base.identity(target_path), base.sha(target_path)
        result['active_compile_units'] = result['fallback_c_units'] = len(indices)
        result['active_compile_units_scope'] = 'kernel-target C commands; the component replaces one ASM symbol, not a complete C translation unit'
        runner.run('linked-symbols', [llvm / 'llvm-nm', '--defined-only', '--extern-only', build / 'vmlinux'])
        if args.arm == 'hybrid':
            result['hia_build_object'] = base.identity(build / 'arch/x86/lib/hia_hweight.o')
            result['linked_hia_route'] = component_tool.verify_linked_route(prepared, build / 'vmlinux', build / 'arch/x86/lib/hia_hweight.o')
            result['hia_compiled_units'] = 1
            result['hia_compiled_units_scope'] = 'one authored scalar-body object via registered Kbuild rule, independently linked-byte checked'
        result['build_status'] = 'PASS'
        result['guest_init'], result['initramfs'] = stock['guest_init'], stock['initramfs']
        result['run_id'] = hashlib.sha256((str(output) + base.utc()).encode()).hexdigest()[:24]
        stock_argv = stock['boot']['command_receipt']['argv']
        command = base.qemu_command(stock['qemu']['path'], single_option(stock_argv, '-L'), stock['qemu']['bios']['path'],
                                    result['kernel_image']['path'], stock['initramfs']['path'], result['run_id'], stock['kernel_version'])
        rec = runner.run('boot-' + args.arm + '-kernel-tcg', command, timeout=args.boot_timeout, check=False)
        serial = Path(rec['stdout']['path']).read_text(errors='strict')
        verdict = base.parse_guest_serial(serial, result['run_id'], rec['exit_code'], rec['timed_out'])
        result['boot'], result['boot_status'], result['guest_tests'] = {**verdict, 'command_receipt': rec}, verdict['status'], verdict['guest_tests']
        require(verdict['status'] == 'PASS', 'common real boot smoke failed')
        observation = validate_component_observation(serial, args.arm, prepared)
        result['component_observation'] = observation
        after = base.inventory_tree(copied)
        result['source_copy_after_inventory'] = base.write_gzip_json(output / 'source-copy-after.json.gz', after)
        result['source_copy_unchanged_after_registered_overlay'] = after == patched_before
        require(after == patched_before, 'source copy changed during build/boot')
        result['stock_source_unchanged'] = base.inventory_tree(source) == before
        require(result['stock_source_unchanged'], 'original stock source changed')
        result['source_after'] = base.source_identity(args.expected_head)
        require(result['source_after'] == code_before, 'execution source changed')
        result['commands'] = runner.records
        boot_report_path = output / 'BOOT_REPORT.json'
        boot_report = {**result, 'status': 'PASS', 'stage': 'build_and_common_boot_passed_component_readback_pending',
                       'component_status': 'NOT_RUN'}
        base.write_json(boot_report_path, boot_report)
        result['boot_report'] = base.identity(boot_report_path)
        if args.arm == 'hybrid':
            readback_path = output / 'COMPONENT_READBACK.json'
            component_result = component_tool.readback(
                args.component, readback_path, serial_log=rec['stdout']['path'], kernel_image=result['kernel_image']['path'],
                vmlinux=result['vmlinux']['path'], build_object=result['hia_build_object']['path'],
                boot_report=str(boot_report_path), applied=str(applied_path), kernel_config=result['config']['path'])
            result['component_readback'] = base.identity(readback_path)
            require(component_result['status'] == 'PASS' and component_result['guest_gate']['status'] == 'PASS', 'hybrid native/guest readback failed')
        result['component_status'], result['status'] = 'PASS', 'PASS'
        result['stage'] = 'registered_control_or_hybrid_image_built_booted_and_read_back'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if copied is not None and copied.exists() and patched_before is not None and 'source_copy_after_inventory' not in result:
            try:
                after = base.inventory_tree(copied)
                result['source_copy_after_inventory'] = base.write_gzip_json(output / 'source-copy-after.json.gz', after)
                result['source_copy_unchanged_after_registered_overlay'] = after == patched_before
                if after != patched_before:
                    result['status'] = 'FAIL'
                    result['source_copy_error'] = 'source copy changed during build/boot'
            except Exception as error:
                result['status'], result['source_copy_error'] = 'FAIL', str(error)
        if before is not None and 'stock_source_unchanged' not in result:
            try:
                result['stock_source_unchanged'] = base.inventory_tree(source) == before
                if not result['stock_source_unchanged']:
                    result['status'] = 'FAIL'
            except Exception as error:
                result['status'], result['stock_source_error'] = 'FAIL', str(error)
        if code_before is not None and 'source_after' not in result:
            try:
                result['source_after'] = base.source_identity(args.expected_head)
                require(result['source_after'] == code_before, 'execution source changed')
            except Exception as error:
                result['status'], result['source_after_error'] = 'FAIL', str(error)
        result['commands'] = runner.records if runner else []
        result['completed_at_utc'] = base.utc()
        result['elapsed_ns'] = time.monotonic_ns() - start
        base.write_json(output / 'RESULT.json', result)
        print(json.dumps({'result': str(output / 'RESULT.json'), 'arm': args.arm, 'status': result['status'],
                          'build_status': result['build_status'], 'boot_status': result['boot_status'],
                          'whole_kernel_rewrite': False}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
