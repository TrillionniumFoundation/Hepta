"""Nonaccepting timing of already materialized, byte-bound nocode sources.

Preparation time is EXCLUDED from this diagnostic and never represented as a
qualifying full run. No result from this command authorizes an optimization.
The unchanged acceptance collector enforces 60 seconds/process, 2 seconds for
cleanup, bounded raw streams, and a 540-second launch window. There are at most
11 invocations and no retries or old modules. All evidence is retained on fail.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import time
from types import SimpleNamespace

from tools import core_seven_nocode_sources as n
from tools import core_seven_acceptance_capture as capture
from tools import core_seven_relocation_acceptance_plan as contract
from tools import diagnose_core_seven_certificate as old
from tools.check_guarded_slice_lean import require


SCHEMA = 'hepta.hia.seven-data-nocode-timing-diagnostic.v1'
LEAN_SHA256 = '92c3d35b5bfaa5e0fea413a775d504cf46cd95e1345df61c2274f76779e7e023'


def read_regular(path, maximum):
    with open(path, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= maximum,
                'bounded unique regular file')
        data = stream.read(maximum + 1)
    require(len(data) == st.st_size and not path.is_symlink(), 'complete non-symlink file')
    return data


def write_new(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(data) <= contract.BUDGETS['metadata'], 'bounded diagnostic record')
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def diagnose(lean, directory):
    started = time.monotonic_ns()
    root = Path(directory).resolve(strict=True)
    executable = Path(lean).resolve(strict=True)
    require(n.digest(read_regular(executable, 32 * 1024 * 1024)) == LEAN_SHA256,
            'pinned Lean 4.19.0 executable')
    raw_manifest = read_regular(root / 'nocode-manifest.json', n.MAX_MANIFEST)
    manifest = json.loads(raw_manifest)
    require(n.encode(manifest).encode() == raw_manifest and
            manifest['schema'] == n.SCHEMA and manifest['protocol'] == n.PROTOCOL,
            'canonical source-only manifest')
    require(manifest['source_only'] is True and manifest['acceptance_eligible'] is False and
            manifest['authority'] == 'DENY_ALL', 'diagnostic cannot upgrade source proposal')
    require(tuple(row['name'] for row in manifest['stages']) == n.seven.NAMES and
            tuple(row['inventory_count'] for row in manifest['stages']) == n.COUNTS,
            'fixed eleven-stage source inventory')
    expected_files = {'nocode-manifest.json'} | {
        'HiaSyntaxResearch/' + name + '.lean' for name in n.seven.NAMES}
    require({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()} == expected_files,
            'fresh diagnostic directory, no old modules or evidence')
    sources, stages = {}, []
    for row in manifest['stages']:
        path = root / (row['module_name'].replace('.', '/') + '.lean')
        require(str(path.relative_to(root)) == 'HiaSyntaxResearch/' + row['name'] + '.lean',
                'closed module path')
        raw = read_regular(path, n.MAX_SOURCE)
        require(len(raw) == row['source_bytes'] and n.digest(raw) == row['source_sha256'],
                'actual source bytes bind manifest')
        text = raw.decode('utf-8')
        names = n.seven._qualified_prints(text)
        require(len(names) == len(set(names)) == row['inventory_count'] and
                n.digest(n.encode(sorted(names)).encode()) == row['inventory_sha256'],
                'actual complete theorem-print inventory')
        sources[path] = raw
        stages.append(SimpleNamespace(name=row['name'], module_name=row['module_name'],
                                      source=text, expected_theorems=frozenset(names)))
    require(sum(map(len, sources.values())) <= n.MAX_TOTAL_SOURCE, 'aggregate source budget')
    record = dict(schema=SCHEMA, diagnostic_only=True, acceptance_eligible=False,
                  preparation_time_included=False, source_manifest_sha256=n.digest(raw_manifest),
                  lean_sha256=LEAN_SHA256, source_inverse_replayed_here=False,
                  kernel_core_syntax_connection_checked=False, actual_core_bridge_proved=False,
                  python_exporter_refinement_proved=False, body_prefix_refinement_proved=False,
                  all_edge_transfer_proved=False, **n.seven.facts.DENY,
                  stages=[], status='incomplete', invocation_count=0,
                  obligations=manifest['obligations'])
    write_new(root / 'diagnostic.started.json', record)
    env = dict(os.environ, LEAN_PATH=str(root), LEAN_SYSROOT=str(executable.parent.parent))
    env.pop('LEAN_SRC_PATH', None)
    raw_used, module_used = 0, 0
    for stage in stages:
        if time.monotonic_ns() >= started + contract.BUDGETS['launch_ns']:
            record['error_code'] = 'launch_deadline'
            break
        require(all(read_regular(p, n.MAX_SOURCE) == raw for p, raw in sources.items()),
                'sources remain byte-identical before launch')
        module = root / (stage.module_name.replace('.', '/') + '.olean')
        source = root / (stage.module_name.replace('.', '/') + '.lean')
        argv = [str(executable), '--root=' + str(root), '-o', str(module), str(source)]
        result = capture.capture(argv, cwd=str(root), env=env,
                                 stdout_path=root / (stage.name + '.stdout'),
                                 stderr_path=root / (stage.name + '.stderr'),
                                 raw_remaining=contract.RAW_GLOBAL - raw_used,
                                 launch_deadline_ns=started + contract.BUDGETS['launch_ns'])
        record['invocation_count'] += int(result['process']['spawned'])
        row = dict(name=stage.name, argv=argv, **result)
        raw_used += sum(v['bytes'] for v in result['logs'].values())
        if result['error_code'] is None:
            try:
                contract.validate_process(result['process'], success=True)
                out = read_regular(root / (stage.name + '.stdout'), contract.BUDGETS['raw_stage'])
                err = read_regular(root / (stage.name + '.stderr'), contract.BUDGETS['raw_stage'])
                inventory = old._inventory(out, err, stage)
                module_raw = read_regular(module, contract.BUDGETS['module'])
                require(bool(module_raw), 'nonempty newly emitted module')
                module_used += len(module_raw)
                require(module_used <= contract.BUDGETS['modules'], 'aggregate module budget')
                row.update(subjects=len(stage.expected_theorems),
                           inventory_sha256=contract.commitment(inventory),
                           module_sha256=n.digest(module_raw), module_bytes=len(module_raw))
            except (OSError, ValueError, UnicodeError) as error:
                row['error_code'] = 'verification_failed'
                row['verification_error'] = str(error)
        record['stages'].append(row)
        write_new(root / (stage.name + '.diagnostic.json'), row)
        print(json.dumps({'name':stage.name, 'error_code':row['error_code'],
                          'subjects':row.get('subjects', 0),
                          'elapsed_ns':row['process']['elapsed_ns']}, sort_keys=True), flush=True)
        if row['error_code'] is not None:
            record['error_code'] = row['error_code']
            break
    require(all(read_regular(p, n.MAX_SOURCE) == raw for p, raw in sources.items()),
            'sources remain byte-identical after all invocations')
    record.update(status='diagnostic_completed' if len(record['stages']) == 11 and
                  all(r['error_code'] is None for r in record['stages']) else 'diagnostic_failed',
                  elapsed_ns=time.monotonic_ns() - started, raw_bytes=raw_used, module_bytes=module_used)
    write_new(root / 'diagnostic.result.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True)
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    result = diagnose(args.lean, args.directory)
    print(json.dumps({k:v for k,v in result.items() if k != 'stages'}, sort_keys=True))
    return 0 if result['status'] == 'diagnostic_completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
