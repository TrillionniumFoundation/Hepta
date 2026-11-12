"""New v83 source-only integration controls; no compiler or native test entry.

This sparse local worktree verifies its entire declared source closure. The
remote capsule separately verifies all physical files of the published tree.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha1, sha256
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import time
import traceback
import unittest


GENERATED = ('docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
             'docs/HIA_SELFHOST_CORE_SUPPORT.json')


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('declared source is not a regular independent file: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_mode, before.st_size,
        before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
        after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError('source changed during read: ' + str(path))
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}


def declared_names(source):
    parsed = ast.parse((source / 'tools/hia_selfhost_contract.py').read_bytes())
    assignments = [node for node in parsed.body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'SOURCE_FILES'
                           for t in node.targets)]
    if len(assignments) != 1:
        raise RuntimeError('ambiguous source declaration')
    names = ast.literal_eval(assignments[0].value)
    if type(names) is not tuple or not all(type(x) is str for x in names):
        raise RuntimeError('source declaration is not a literal string tuple')
    return sorted(set(names) | set(GENERATED) | {
        p.relative_to(source).as_posix() for p in (source / 'hepta').rglob('*.py')})


def identifiers(node):
    if isinstance(node, unittest.TestSuite):
        return [name for child in node for name in identifiers(child)]
    return [node.id()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--classes', type=Path, required=True)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.core-unpack-v83-source-controls.v1', 'status': 'HOLD',
              'product_native_executed': False, 'cold_executed': False,
              'installed_executed': False, 'complete116_executed': False,
              'complete_physical_checkout_claimed': False,
              'scope': 'DECLARED_SOURCE_CLOSURE_AND_ORIGINAL54_PLUS_NEW2_SOURCE_METHODS',
              'commands': [], 'idempotence_commands': [], 'errors': []}
    started = time.monotonic()
    names = declared_names(args.source)
    before = {name: pin(args.source / name) for name in names}
    (args.evidence / 'source-before.json').write_bytes(wire(before))
    derived = None
    def capture(name, value):
        (args.evidence / name).write_bytes(wire(value))
    def command(label, command, records):
        at = time.monotonic()
        out = args.evidence / (label + '.stdout.log')
        err = args.evidence / (label + '.stderr.log')
        with out.open('xb') as stdout, err.open('xb') as stderr:
            result = subprocess.run(command, cwd=args.source, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr)
        row = {'label': label, 'command': command, 'returncode': result.returncode,
               'seconds': time.monotonic() - at, 'stdout': pin(out), 'stderr': pin(err)}
        records.append(row)
        if result.returncode:
            raise RuntimeError('source command failed: ' + label)
    try:
        for p in sorted(args.inputs.rglob('*')):
            if p.is_file():
                name = p.relative_to(args.inputs).as_posix()
                if pin(p) != pin(args.source / name):
                    raise RuntimeError('frozen overlay input differs: ' + name)
        workflow = (args.source / '.github/workflows/hia-core.yml').read_text()
        components = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
        ledger = json.loads((args.source / 'docs/HIA_COMPILER_OWNER_QUALIFICATION_GATES.json').read_bytes())
        if components != ledger['generator_order'] or not (len(components) == len(set(components)) == 61):
            raise RuntimeError('fixed complete generator sequence differs')
        if len(components) != 61 or components[-2:] != ['bounded_read', 'core_unpack']:
            raise RuntimeError('legacy prefix plus bounded and UNPACK sequence differs')
        report['generator_commands'] = []
        for index, component in enumerate(components):
            command('generator-%02d-%s' % (index, component),
                    [sys.executable, '-B', '-m', 'tools.generate_hia_' + component],
                    report['generator_commands'])
        if {name: pin(args.source / name) for name in names} != before:
            raise RuntimeError('actual HIA regeneration changed a frozen source input')
        report['all61_generators_exact_byte_stable'] = True
        for label, argv in (
            ('contract-before', ['tools/generate_hia_selfhost_contract.py']),
            ('coverage', ['tests/test_hia_selfhost_language_coverage.py', '--generate-inventory']),
            ('contract-after', ['tools/generate_hia_selfhost_contract.py']),
            ('contract-check', ['tools/generate_hia_selfhost_contract.py', '--check']),
        ):
            command(label, [sys.executable, '-I', '-S', '-B', *argv], report['commands'])
        if declared_names(args.source) != names:
            raise RuntimeError('declared source set changed during derivation')
        derived = {name: pin(args.source / name) for name in names}
        changed = sorted(name for name in names if before[name] != derived[name])
        if not set(changed) <= set(GENERATED):
            raise RuntimeError('derivation changed undeclared output: ' + str(changed))
        report['changed_derivation_paths'] = changed
        capture('source-derived.json', derived)
        for name in GENERATED:
            (args.evidence / Path(name).name).write_bytes((args.source / name).read_bytes())
        for index, argv in enumerate((
            ['tests/test_hia_selfhost_language_coverage.py', '--generate-inventory'],
            ['tools/generate_hia_selfhost_contract.py'],
            ['tools/generate_hia_selfhost_contract.py', '--check'],
        )):
            command('idempotence-%02d' % index, [sys.executable, '-I', '-S', '-B', *argv],
                    report['idempotence_commands'])
        if {name: pin(args.source / name) for name in names} != derived:
            raise RuntimeError('the exact remote three-command regeneration is not idempotent')
        report['exact_remote_three_commands_idempotent'] = True
        sys.path.insert(0, str(args.source))
        from tools.hia_selfhost_contract import validate_contract
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_core_lowering_selection import ABI_SOURCE, checked_abi, source_names
        contract = validate_contract()
        if contract['profile'] != 'selfhost-core-linux-x86_64-v83-native-core-unpack-bounded-read-interned-scans-development':
            raise RuntimeError('actual independent UNPACK profile differs')
        if len(source_names(checked_abi((args.source / ABI_SOURCE).read_bytes()))) != 39:
            raise RuntimeError('original Core39 denominator changed')
        if len(NATIVE_SOURCE_FILES) != 92:
            raise RuntimeError('bounded/Core/UNPACK complete resource union differs')
        report['source_identity_files'] = len(contract['source_identity']['files'])
        report['native_source_resources'] = len(NATIVE_SOURCE_FILES)
        classes = json.loads(args.classes.read_bytes())
        expected = json.loads(args.expected.read_bytes())
        if len(classes) != 8 or not (len(expected) == len(set(expected)) == 56):
            raise RuntimeError('fixed source-only denominator differs')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(classes)
        loaded, executed = identifiers(suite), []
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                executed.append(test.id())
                super().startTest(test)
        result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
        anomalies = {name: getattr(result, name) for name in
                     ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses')}
        report.update(expected_ids=expected, loaded_ids=loaded, executed_ids=executed,
                      tests_run=result.testsRun, loader_errors=loader.errors,
                      anomaly_counts={name: len(value) for name, value in anomalies.items()},
                      anomaly_details={name: [str(item) for item in value]
                                       for name, value in anomalies.items()})
        if not (expected == loaded == executed and len(expected) == result.testsRun == 56
                and not loader.errors and not any(anomalies.values())):
            raise RuntimeError('complete original54 plus new2 source methods did not pass')
        report['status'] = 'SOURCE_ONLY_56_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['errors'].append(traceback.format_exc())
        traceback.print_exc()
    finally:
        try:
            after = {name: pin(args.source / name) for name in names}
            capture('source-after.json', after)
            report['source_stable_after_derivation'] = derived is not None and after == derived
            if not report['source_stable_after_derivation']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'; report['errors'].append(traceback.format_exc())
        report['declared_source_files_including_contract'] = len(names)
        report['seconds'] = time.monotonic() - started
        capture('report.json', report)
    print(json.dumps({name: report.get(name) for name in
                     ('status', 'seconds', 'tests_run', 'anomaly_counts', 'errors')}, sort_keys=True))
    return 0 if report['status'] == 'SOURCE_ONLY_56_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
