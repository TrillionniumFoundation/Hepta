"""Run the exact v67 generators and focused source controls with raw custody.

This is a source-only development control. It cannot certify a cold or native
caller run, a full Git checkout, or whole native delivery.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
import traceback
import unittest
import zipfile


GROUPS = (
    'tests.test_hia_integrated_workflow',
    'tests.test_hia_json_wire_native.WireSourceTests',
    'tests.test_hia_worker_report_native.WorkerReportSourceTests',
    'tests.test_hia_machine_plan_native.MachinePlanSourceTests',
    'tests.test_hia_machine_encoding_native.MachineEncodingSourceTests',
    'tests.test_hia_selfhost_linked_observer.LinkedObserverSourceTests',
    'tests.test_hia_cli_native.CliSourceTests',
    'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests',
    'tests.test_hia_selfhost_contract',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--preexecution-commit', required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    out = args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.chdir(root)
    sys.path.insert(0, str(root))
    sys.dont_write_bytecode = True
    from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, file_digests
    names = sorted(set(file_digests(root)) | {
        CONTRACT_PATH, 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'})
    started = time.monotonic()

    def snapshot():
        result = {}
        for name in names:
            path = root / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('source is not regular: ' + name)
            raw = path.read_bytes()
            result[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                            'mode': stat.S_IMODE(info.st_mode)}
        return result

    def save(name, data):
        (out / name).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')

    before = snapshot()
    save('source-before.json', before)
    archive_path = out / 'executed-source.zip'
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | before[name]['mode']) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (root / name).read_bytes())
    with zipfile.ZipFile(archive_path) as archive:
        assert sorted(archive.namelist()) == names
        for item in archive.infolist():
            raw = archive.read(item)
            assert len(raw) == before[item.filename]['bytes']
            assert hashlib.sha256(raw).hexdigest() == before[item.filename]['sha256']
            assert stat.S_IMODE(item.external_attr >> 16) == before[item.filename]['mode']
    result = {
        'schema': 'hepta.hia.v67.focused-source-controls.v1',
        'scope': 'SOURCE_ONLY_NOT_COLD_OR_FULL', 'status': 'HOLD',
        'preexecution_commit': args.preexecution_commit,
        'materialization_is_full_git_checkout': False,
        'profile': PROFILE, 'python': sys.version, 'python_executable': sys.executable,
        'platform': platform.platform(), 'groups': GROUPS,
        'declared_source_files': len(file_digests(root)),
        'executed_source_archive': {'path': archive_path.name,
            'members': len(names), 'bytes': archive_path.stat().st_size,
            'sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            'every_member_bytes_hash_and_mode_read_back': True},
        'commands': [], 'loaded_ids': [], 'executed_ids': [],
        'loader_errors': [], 'failures': [], 'errors': [], 'skipped': [],
        'expectedFailures': [], 'unexpectedSuccesses': [],
        'cold_or_native_caller_qualification_executed': False,
        'historical_results_relabelled': False,
        'whole_native_delivery_qualified': False,
    }
    try:
        workflow = (root / '.github/workflows/hia-core.yml').read_text()
        selected = re.findall(r'for component in ([^\n]+); do', workflow)
        assert len(selected) == 1
        generators = selected[0].split()
        assert len(generators) == len(set(generators)) == 53
        result['generators'] = generators
        commands = [[sys.executable, '-B', '-m', 'tools.generate_hia_' + name]
                    for name in generators]
        commands += [[sys.executable, '-B', 'tools/check_hia_core_only.py'],
                     [sys.executable, '-B', 'tools/generate_hia_selfhost_contract.py', '--check'],
                     [sys.executable, '-B', 'tests/test_hia_selfhost_language_coverage.py', '--generate-inventory']]
        for index, argv in enumerate(commands):
            then = time.monotonic()
            process = subprocess.run(argv, cwd=root, capture_output=True, check=False,
                                     env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            prefix = f'command-{index:02}'
            (out / (prefix + '.stdout')).write_bytes(process.stdout)
            (out / (prefix + '.stderr')).write_bytes(process.stderr)
            result['commands'].append({'argv': argv, 'returncode': process.returncode,
                'seconds': time.monotonic() - then, 'stdout': prefix + '.stdout',
                'stderr': prefix + '.stderr', 'stdout_sha256': hashlib.sha256(process.stdout).hexdigest(),
                'stderr_sha256': hashlib.sha256(process.stderr).hexdigest()})
            save('progress.json', result)
            if process.returncode:
                raise RuntimeError('source command failed: ' + repr(argv))
            if snapshot() != before:
                raise RuntimeError('generator or source command changed frozen declared bytes')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(GROUPS)

        def ids(item):
            if isinstance(item, unittest.TestSuite):
                return [name for child in item for name in ids(child)]
            return [item.id()]

        result['loaded_ids'] = ids(suite)
        result['loader_errors'] = list(loader.errors)
        class RetainedResult(unittest.TextTestResult):
            def startTest(self, test):
                result['executed_ids'].append(test.id())
                super().startTest(test)
        with (out / 'unittest.log').open('x') as stream:
            observed = unittest.TextTestRunner(stream=stream, verbosity=2,
                                               resultclass=RetainedResult).run(suite)
        result['tests_run'] = observed.testsRun
        for name in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            entries = getattr(observed, name)
            result[name] = [([entry[0].id(), entry[1]] if isinstance(entry, tuple)
                             else entry.id()) for entry in entries]
        complete = bool(result['loaded_ids']) and len(set(result['loaded_ids'])) == len(result['loaded_ids'])
        complete = complete and result['loaded_ids'] == result['executed_ids']
        complete = complete and observed.testsRun == len(result['loaded_ids'])
        result['strict_pass'] = bool(complete and observed.wasSuccessful()
            and not loader.errors and all(not result[key] for key in
                ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses')))
    except BaseException:
        result['exception'] = traceback.format_exc()
        result['strict_pass'] = False
    finally:
        try:
            after = snapshot()
            save('source-after.json', after)
            result['source_preserved'] = after == before
        except BaseException:
            result['source_preserved'] = False
            result['source_after_exception'] = traceback.format_exc()
        result['status'] = 'PASS' if result.get('strict_pass') and result['source_preserved'] else 'HOLD'
        result['seconds'] = time.monotonic() - started
        result['finished_utc'] = datetime.now(timezone.utc).isoformat()
        save('report.json', result)
    print(json.dumps({key: result.get(key) for key in
        ('status', 'tests_run', 'seconds', 'source_preserved', 'declared_source_files', 'exception')}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
