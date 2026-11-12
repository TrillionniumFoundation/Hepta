"""Run one frozen, source-only permission control under the original180/3 owner."""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import natural_owner, pin, read_file, require, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw, _ = read_file(args.request, 262144)
    require(sha256(raw).hexdigest() == args.sha256, 'source-control request differs')
    request = json.loads(raw)
    require(request['schema'] == 'hepta.hia.numeric-runtime-source-preexec.v1', 'source request schema differs')
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and list(sys.version_info[:3]) == [3, 12, 14]
            and str(Path(sys.executable).resolve()) == request['python'], 'source runtime differs')

    def inputs():
        result = []
        for row in request['source_files']:
            actual = pin(ROOT / row['path'], row['size'])
            require((actual['size'], actual['sha256'], actual['mode'])
                    == (row['size'], row['sha256'], row['mode']), 'source input differs')
            result.append(actual)
        return result

    before = inputs()
    output = Path(request['output_root'])
    require(output == Path('/tmp/hia-core-numeric-runtime-permissions-r1'), 'fixed source-control output differs')
    output.mkdir(mode=0o700)
    save(output / 'source-before.json', before)
    terminal = {'schema': 'hepta.hia.numeric-runtime-source-terminal.v1', 'status': 'HOLD',
                'native_executed': False, 'compiler_executed': False,
                'numeric_finite_request_executed': False}
    try:
        owner_path = ROOT / 'compiler-source/tools/hia_selfhost_process_owner.py'
        spec = importlib.util.spec_from_file_location('numeric_runtime_permission_owner', owner_path)
        owner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = owner
        spec.loader.exec_module(owner)
        command = [request['python'], '-I', '-S', '-B', str(CONTROL / 'source_permissions.py'),
                   '--evidence', str(output / 'checks')]
        save(output / 'command.json', {'command': command, 'cwd': str(ROOT),
             'qualification_seconds': 180, 'cleanup_seconds': 3})
        wrapper = owner.run_owned(command, cwd=ROOT, env=dict(os.environ),
            stdout_path=output / 'child.stdout.log', stderr_path=output / 'child.stderr.log',
            receipt_path=output / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
        save(output / 'owner-wrapper.json', wrapper)
        original, _ = read_file(output / 'lifecycle.json', 1048576)
        life = natural_owner(wrapper, original)
        report_raw, _ = read_file(output / 'checks/report.json', 1048576)
        report = json.loads(report_raw)
        require(report['status'] == 'SOURCE_CONTROLS_PASS'
                and report['loaded_ids'] == request['expected_ids'] == report['executed_ids']
                and report['tests_run'] == 6 and not any(report['anomalies'].values())
                and report['source_before'] == report['source_after'], 'six source controls did not pass')
        terminal.update(status='SOURCE_PERMISSION_CONTROLS_PASS', owner=life,
                        report_sha256=sha256(report_raw).hexdigest(), actual_tests=6)
    except BaseException:
        terminal['status'] = 'HOLD'
        terminal['error'] = traceback.format_exc()
    finally:
        try:
            after = inputs()
            save(output / 'source-after.json', after)
            terminal['source_preserved'] = before == after
            if before != after:
                terminal['status'] = 'HOLD'
        except BaseException:
            terminal['status'] = 'HOLD'
            terminal['preservation_error'] = traceback.format_exc()
        save(output / 'FINAL.json', terminal)
    print(json.dumps({'status': terminal['status'], 'output': str(output)}))
    return 0 if terminal['status'] == 'SOURCE_PERMISSION_CONTROLS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
