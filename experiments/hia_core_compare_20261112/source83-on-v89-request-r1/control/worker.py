"""Execute the frozen generators, derivations and complete source controls."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, content, pin, request, require, runtime, save, snapshot


def main():
    policy = request()
    source, folder = Path(policy['source_root']), Path(policy['evidence_root']) / 'evidence'
    folder.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'schema': 'hepta.hia.core-compare-integration-source-run.v1', 'status': 'HOLD',
        'scope': 'LOCAL_EXACT_PARTIAL_SOURCE_GENERATION_AND_SOURCE_VM_CONTROLS_ONLY',
        'base_commit': policy['base_commit'], 'base_tree': policy['base_tree'],
        'actual_git_HEAD_claimed': False, 'runtime': runtime(policy['runtime']),
        'original61_prefix': policy['generator_names'][:61], 'generator_count': len(policy['generator_names']),
        'expected_ids': policy['expected_ids'], 'commands': [], 'allowed_derived_changes': policy['allowed_derived_changes'],
        'native_executed': False, 'complete18_executed': False, 'complete116_executed': False,
        'cold_executed': False, 'installed_executed': False, 'remote_triggered': False}
    before = snapshot(source)
    save(folder / 'source-before.json', before)
    derived = None
    def execute(label, operation, *arguments):
        command = [policy['runtime']['path'], '-I', '-S', '-B', str(HERE / 'control/child.py'), operation, *arguments]
        environment = dict(os.environ)
        environment['HEPTA_COMPARE_SOURCE_CHILD_REPORT'] = str(folder / (label + '.report.json'))
        row = {'label': label, 'command': command, 'started_monotonic_ns': time.monotonic_ns()}
        report['commands'].append(row)
        with (folder / (label + '.stdout.log')).open('xb') as stdout, \
             (folder / (label + '.stderr.log')).open('xb') as stderr:
            result = subprocess.run(command, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr)
        row.update(returncode=result.returncode, ended_monotonic_ns=time.monotonic_ns(),
                   stdout=pin(folder / (label + '.stdout.log')), stderr=pin(folder / (label + '.stderr.log')))
        result_path = folder / ('source-tests.json' if operation == 'tests' else label + '.report.json')
        row['report'] = pin(result_path)
        observed = json.loads(result_path.read_bytes())
        require(result.returncode == 0 and observed.get('status') == 'SOURCE_CHILD_PASS'
                and observed.get('native_or_compiler_or_process_attempts') == [],
                'frozen source child failed: ' + label)
        return observed
    try:
        require(content(before) == policy['source_files'], 'frozen physical source pins differ')
        for index, name in enumerate(policy['generator_names']):
            execute('generator-' + format(index + 1, '02d') + '-' + name, 'module', 'tools.generate_hia_' + name)
        after_generators = snapshot(source)
        save(folder / 'source-after-generators.json', after_generators)
        require(content(after_generators) == content(before), 'canonical HIA source regeneration changed a frozen byte or mode')
        for index, (name, arguments) in enumerate(policy['derivations']):
            execute('derive-' + str(index + 1), 'script', name, *arguments)
        derived = snapshot(source)
        save(folder / 'source-derived.json', derived)
        old, new = ({row['relative_path']: row for row in content(rows)} for rows in (before, derived))
        require(set(old) == set(new), 'source derivation added or removed a physical file')
        changed = [name for name in old if old[name] != new[name]]
        require(set(changed) <= set(policy['allowed_derived_changes']), 'source derivation changed an unapproved file')
        report['actual_derived_changes'] = changed
        for name in policy['allowed_derived_changes']:
            target = folder / ('derived-' + Path(name).name)
            with target.open('xb') as stream:
                stream.write((source / name).read_bytes())
        # The already generated exact bytes must then remain idempotent.
        for index, (name, arguments) in enumerate(policy['derivations']):
            execute('idempotence-' + str(index + 1), 'script', name, *arguments)
        require(content(snapshot(source)) == content(derived), 'derived contract/inventory is not idempotent')
        observed = execute('source-tests', 'tests')
        require(observed['expected_ids'] == observed['loaded_ids'] == observed['executed_ids'] == policy['expected_ids'],
                'complete source test IDs differ at final readback')
        require(content(snapshot(source)) == content(derived), 'source changed during source-only tests')
        report['tests'] = observed
        report['status'] = 'SOURCE_INTEGRATION_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            after = snapshot(source)
            save(folder / 'source-after.json', after)
            report['final_source_content'] = content(after)
            report['source_preserved_after_derivation'] = derived is not None and content(after) == content(derived)
            if report['status'] == 'SOURCE_INTEGRATION_PASS' and not report['source_preserved_after_derivation']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save(folder / 'report.json', report)
        save(folder / 'ORIGINALS.json', [pin(path) for path in sorted(folder.rglob('*')) if path.is_file()])
    print(json.dumps({key: report.get(key) for key in ('scope', 'status', 'seconds', 'actual_derived_changes', 'error')}, sort_keys=True))
    return 0 if report['status'] == 'SOURCE_INTEGRATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
