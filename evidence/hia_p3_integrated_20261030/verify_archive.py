#!/usr/bin/env python3
"""Bounded offline byte/receipt replay. No extraction, native execution or imports from the archive."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

HEAD = '50c4067399989e7194028576c38c0e783b78cf06'

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def c_oracle(arguments, refusal):
    count, left, right = arguments
    if count > 8:
        result, attempts, allocations = -259, 0, 0
    elif count == 0:
        result, attempts, allocations = 0, 0, 0
    elif refusal:
        result, attempts, allocations = -256 - refusal, refusal, refusal - 1
    else:
        result, attempts, allocations = 0, 2, 2
        for index in range(count):
            a, b = (left >> (8 * index)) & 255, (right >> (8 * index)) & 255
            if a != b or a == 0:
                result = a - b
                break
    return dict(result=result, attempts=attempts, allocations=allocations, frees=allocations, live=0)

def cpp_inputs(payload):
    rows = []
    for line in payload.decode().splitlines():
        match = re.fullmatch(r'\{(.*)\},', line)
        if match:
            row = json.loads('[' + match.group(1) + ']')
            require(len(row) == 3 and type(row[0]) is str and type(row[1]) is int and type(row[2]) is int,
                    'malformed retained C++ input')
            rows.append(row)
    require(len(rows) == 98, 'C++ input denominator differs')
    return rows

def cpp_oracle(inputs):
    rows = []
    for index, (text, offset, replacement) in enumerate(inputs):
        status, result = 0, 9223372036854775807
        try:
            parsed = json.loads(text)
            if type(parsed) is not dict or type(parsed.get('values')) is not list:
                raise ValueError('domain')
            values = parsed['values']
            if len(values) > 64 or any(type(value) is not int or abs(value) > 1000000 for value in values):
                raise ValueError('domain')
            if not 0 <= offset < len(values) or abs(replacement) > 1000000:
                raise ValueError('domain')
            values[offset] = replacement
            result = sum(values)
        except (ValueError, TypeError):
            status = 3
        rows.append(dict(id=index, direct_status=status, direct_value=result,
                         hepta_status=status, hepta_value=result, live_delta=0))
    return rows

def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / 'MANIFEST.json').read_text())
    encoded = (directory / 'executions.tar.xz.base64').read_bytes()
    require(len(encoded) <= 128 * 1024 * 1024, 'encoded archive exceeds bound')
    raw = base64.b64decode(b''.join(encoded.splitlines()), validate=True)
    require(len(raw) == manifest['archive_bytes'] <= 96 * 1024 * 1024 and sha(raw) == manifest['archive_sha256'], 'archive identity differs')
    inventory = {row['path']: row for row in manifest['members']}
    require(len(inventory) == len(manifest['members']) <= 2000, 'duplicate or excessive members')
    members, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                    and member.name in inventory and member.name not in members, 'unsafe or unexpected archive member')
            row = inventory[member.name]
            require(type(row['bytes']) is int and 0 <= member.size == row['bytes'] <= 64 * 1024 * 1024, 'member size differs')
            total += member.size
            require(total <= 256 * 1024 * 1024, 'archive expansion exceeds bound')
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == member.size and sha(data) == row['sha256'], 'member bytes differ')
            members[member.name] = data
    require(set(members) == set(inventory), 'archive inventory incomplete')

    def obj(name):
        return json.loads(members[name])

    def recorded_path(path):
        path = PurePosixPath(path)
        for original, prefix in sorted(manifest['roots'].items(), key=lambda item: -len(item[0])):
            try:
                relative = path.relative_to(PurePosixPath(original))
            except ValueError:
                continue
            return prefix + '/' + str(relative)
        raise ValueError('recorded path outside retained execution roots: ' + str(path))

    def retained_identity(row):
        data = members[recorded_path(row['path'])]
        require(len(data) == row['bytes'] and sha(data) == row['sha256'], 'retained file identity differs')

    plan = obj('launches/PLAN.json')
    require(plan['source_head'] == HEAD and plan['same_matrix'] is True and plan['new_holdout'] is False, 'scope or source relabelled')
    require(plan['human_effort'] is None and plan['complete_development_effort'] is None, 'unknown effort changed')
    require(sha(members['launches/launch.py']) == plan['launcher']['sha256'], 'launcher differs from preregistered bytes')
    for relative, expected in plan['frozen_inputs']['source_bindings'].items():
        data = members['source/' + HEAD + '/' + relative]
        require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'source snapshot differs')
    for name, expected in plan['frozen_inputs']['historical_evidence_unchanged'].items():
        require(sha(members['historical/' + name]) == expected['sha256'], 'historical record changed')
    historical = obj('historical/SUMMARY.json')
    require(historical['baseline_source_commit'] == '46534e04ec874bd5681b9f38914e210c2ef813be'
            and historical['maintenance_source_commit'] == 'f82d016e08431bf9c16d12a613bfab6151103d8a', 'historical sources relabelled')
    launch_results = []
    for ordinal, stage in enumerate(('musl125', 'musl126', 'cpp'), 1):
        prefix = f'launches/{ordinal:02d}-{stage}-attempt-'
        names = sorted(name for name in members if name.startswith(prefix) and name.endswith('/launch.json'))
        require(names, 'stage attempt missing')
        for name in names:
            launch = obj(name)
            require(launch['plan']['sha256'] == sha(members['launches/PLAN.json']) and launch['stage'] == stage, 'launch plan identity differs')
            require(type(launch['outer_wall_ns']) is int and launch['outer_wall_ns'] >= 0, 'outer attempt cost missing')
            require(launch['same_matrix'] is True and launch['new_holdout'] is False, 'attempt scope differs')
            for stream in ('stdout', 'stderr'):
                if stream in launch:
                    retained_identity(launch[stream])
            for row in launch.get('retained_output_files', []):
                retained_identity(row)
        launch = obj(names[-1])
        require(launch['status'] == 'completed' and launch['returncode'] == 0 and launch['process_launched'] is True,
                'stage did not complete')
        require(launch['inputs_before'] == launch['inputs_after'] == plan['frozen_inputs'], 'source/tool drift')
        require(launch['argv'] == plan['stages'][stage]['argv'] and launch['timeout_seconds'] == plan['stages'][stage]['timeout_seconds'], 'launch command or timeout changed')
        require(launch['child_environment'] == plan['child_environment'], 'child environment changed')
        launch_results.append({'stage': stage, 'outer_wall_ns': launch['outer_wall_ns'], 'attempts': len(names)})

    musl, inputs = {}, []
    for prefix, version in (('baseline', '1.2.5'), ('maintenance/successor', '1.2.6')):
        report = obj(prefix + '/qualification.json')
        require(report['ok'] is True and report['source_commit'] == HEAD and report['upstream']['version'] == version, 'musl source/result differs')
        for row in report['retained_files']:
            retained_identity(row)
        for relative, digest in report['source_bindings'].items():
            require(sha(members['source/' + HEAD + '/' + relative]) == digest, 'musl source binding differs')
        processes = [json.loads(line) for line in members[prefix + '/processes.jsonl'].splitlines()]
        require([{key: value for key, value in process.items() if key not in ('stdout', 'stderr')} for process in processes]
                == report['commands'], 'musl raw process ledger differs')
        cases = obj(prefix + '/input-cases.json')
        inputs.append(cases)
        require(len(cases) == 386, 'musl input matrix differs')
        observations = [json.loads(line) for line in members[prefix + '/observations.jsonl'].splitlines()]
        seen, used = set(), set()
        for row in observations:
            key = row['case'], row['refuse_at']
            require(key not in seen and 0 <= key[0] < 386 and key[1] in (0, 1, 2), 'musl matrix cell duplicated/unplanned')
            seen.add(key)
            require({name: row[name] for name in ('case', 'category', 'arguments', 'expected')} == cases[key[0]], 'musl input changed')
            expected = c_oracle(row['arguments'], row['refuse_at'])
            require(row['resource_expected'] == expected and set(row['native']) == {'original_c_native', 'hia_llvm_native'}, 'musl oracle/route differs')
            for route, observation in row['native'].items():
                index = observation['command_index']
                require(index not in used, 'native process reused')
                used.add(index)
                process = processes[index]
                require(process['stage'] == 'native_observation' and process['returncode'] == 0
                        and PurePosixPath(process['argv'][0]).name == route
                        and process['argv'][1:] == list(map(str, [*row['arguments'], row['refuse_at']]))
                        and process['wall_ns'] == observation['wall_ns']
                        and json.loads(process['stdout']) == observation['observed'] == expected, 'musl native receipt differs')
            vm = row['vm']['observed']
            stats = vm['resources']
            require(vm['result'] == expected['result'] and stats['live_owners'] == stats['live_bytes'] == stats['live_local_loans'] == 0
                    and stats['loans_started'] == stats['loans_ended']
                    and stats['owners_created'] == stats['owners_dropped']
                    and all(stats[a] == expected[b] for a, b in (('allocation_attempts', 'attempts'), ('allocations', 'allocations'), ('frees', 'frees'))), 'musl VM resource/result differs')
        require(len(seen) == len(observations) == report['completed_cases'] == 1158
                and len(used) == report['native_observations'] == 2316 and report['vm_observations'] == 1158
                and sum(row['stage'] == 'native_observation' for row in processes) == 2316, 'musl denominator differs')
        require(sha(members[prefix + '/capture/program.hia.json']) == report['migration']['program_sha256'], 'musl Core differs')
        release = members['archives/musl-1.2.5.tar.gz' if version == '1.2.5' else 'acquisition/musl-1.2.6.tar.gz']
        require(sha(release) == report['upstream']['release_archive']['sha256'], 'official archive identity differs')
        with tarfile.open(fileobj=io.BytesIO(release), mode='r:gz') as archive:
            for row in report['upstream']['files']:
                require(archive.extractfile('musl-' + version + '/' + row['upstream_path']).read()
                        == members[prefix + '/project/' + row['local_path']], 'upstream component bytes changed')
        musl[version] = {'cases': len(seen), 'native_observations': len(used), 'vm_observations': len(observations)}
    require(inputs[0] == inputs[1] and members['baseline/capture/program.hia.json'] == members['maintenance/successor/capture/program.hia.json'], 'maintenance matrix/Core changed')
    update = obj('maintenance/update.json')
    require(update['ok'] is True and update['baseline']['source_commit'] == update['successor']['source_commit'] == HEAD, 'maintenance source/result differs')

    report = obj('cpp-upgrade/report.json')
    require(report['ok'] is True and report['claims']['foreign_library_rewritten'] is False
            and report['claims']['foreign_memory_safety_proved'] is False
            and report['claims']['total_development_cost_measured'] is False, 'C++ status/scope differs')
    for relative, digest in report['inputs'].items():
        require(sha(members['source/' + HEAD + '/' + relative]) == digest, 'C++ source binding differs')

    def cpp_process(row, expected_code=None):
        require(row['status'] == 'exited' and row['executable_unchanged'] is True and row['seconds'] >= 0, 'C++ process did not exit with bound identity/cost')
        if expected_code is not None:
            require(row['exit_code'] == expected_code, 'C++ exit code differs')
        for stream in ('stdout', 'stderr'):
            data = members[recorded_path(row[stream + '_path'])]
            require(sha(data) == row[stream + '_sha256']
                    and base64.b64decode(row[stream + '_bytes_base64'], validate=True) == data
                    and data.decode(errors='replace') == row[stream], 'C++ raw stream differs')
        if row['argv'][0].startswith(manifest['cpp_original_root']):
            require(sha(members[recorded_path(row['argv'][0])]) == row['executable_sha256'], 'C++ executed artifact identity differs')

    cpp, cpp_case_inputs, terminations = {}, [], []
    for row, version in zip(report['versions'], ('3.11.3', '3.12.0')):
        require(row['version'] == version and row['status'] == 'passed', 'C++ version result differs')
        prefix = 'cpp-upgrade/work/' + version
        case_inputs = cpp_inputs(members[prefix + '/cases.hpp'])
        cpp_case_inputs.append(case_inputs)
        for name, expected in row['artifacts'].items():
            data = members[prefix + '/' + name]
            require(len(data) == expected['bytes'] and sha(data) == expected['sha256'], 'C++ native/generated artifact differs')
        for process in row['processes']:
            cpp_process(process)
        cpp_process(row['execution_process'], 0)
        observed = json.loads(row['execution_process']['stdout'])
        require(observed == row['execution'] and observed['cases'] == cpp_oracle(case_inputs)
                and observed['version'] == version and observed['pointer_guards'] == 2
                and observed['ordinary_live_delta'] == 0, 'C++ native cases/guards/lifetime differs')
        calibrated = json.loads(row['calibration']['process']['stdout'])
        cpp_process(row['calibration']['process'], 0)
        sites = calibrated['allocation_sites']
        require(type(sites) is int and 0 < sites < 128 and calibrated == row['calibration']['observation']
                == {'version': version, 'allocation_sites': sites, 'value': 9, 'live_delta': 0}
                and observed['allocation_sites'] == sites, 'actual C++ calibration differs')
        faults = row['allocation_failures']
        require(len(faults) == sites and [fault['site'] for fault in faults] == list(range(1, sites + 1)), 'C++ fault denominator differs')
        recovered = terminated = 0
        for fault in faults:
            process = fault['process']
            require(process['argv'][1:] == [str(fault['site'])], 'C++ fault invocation differs')
            if fault['status'] == 'caught_and_recovered':
                cpp_process(process, 0)
                expected = {'site': fault['site'], 'status': 3, 'output_preserved': True, 'live_delta': 0, 'recovered_value': 9}
                require(fault['observation'] == json.loads(process['stdout']) == expected and fault['recovery_qualified'] is True, 'C++ recovery observation differs')
                recovered += 1
            else:
                cpp_process(process, -6)
                require(fault['status'] == 'foreign_noexcept_termination' and 'std::bad_alloc' in process['stderr']
                        and fault['observation'] is None and fault['recovery_qualified'] is False, 'foreign termination credited as recovery')
                terminated += 1
                terminations.append({'version': version, 'site': fault['site'], 'seconds': process['seconds']})
        require(row['all_allocation_failure_paths_recovered'] is (terminated == 0), 'C++ recovery summary differs')
        require(row['headers_before']['files'] == row['headers_after']['files'], 'C++ header identity drift')
        generated = row['generated_identity']
        require(sha(members[prefix + '/bridge/bridge.cpp'].decode().replace(row['directory'], '<VERSION_DIRECTORY>').encode())
                == generated['normalized_cpp_sha256'], 'generated C++ identity differs')
        for name in ('bridge.h', 'bridge.hepta', 'contract.json'):
            require(sha(members[prefix + '/bridge/' + name]) == generated[name], 'generated boundary identity differs')
        symbols = sorted(line.split()[-1] for line in row['symbol_process']['stdout'].splitlines()
                         if line.split() and line.split()[-1].startswith('hepta_cpp_json_upgrade_'))
        require(symbols == row['c_symbols'] and len(symbols) == 5, 'observed C ABI export symbols differ')
        cpp[version] = {'cases': len(case_inputs), 'actual_allocation_sites': sites,
            'caught_and_recovered': recovered, 'foreign_noexcept_termination': terminated,
            'all_allocation_failure_paths_recovered': terminated == 0}
    require(cpp_case_inputs[0] == cpp_case_inputs[1] and report['versions'][0]['generated_identity'] == report['versions'][1]['generated_identity']
            and report['versions'][0]['c_symbols'] == report['versions'][1]['c_symbols'], 'C++ upgrade ABI/inputs differ')
    require(report['upgrade']['source_files_patched'] == [] and report['upgrade']['source_lines_changed'] == 0
            and report['upgrade']['contract_changes'] == report['upgrade']['hepta_caller_changes'] == 0
            and report['upgrade']['human_review_hours'] is None and report['upgrade']['agent_tokens'] is None, 'C++ maintenance/effort claim differs')
    for process in report['processes'] + report['negative_controls']['processes']:
        cpp_process(process)
    controls = report['negative_controls']
    require(controls['status'] == 'passed' and controls['incompatible_signature']['report']['ok'] is False
            and controls['incompatible_signature']['output_published'] is False, 'C++ signature negative control missing')
    wrong = controls['wrong_implementation']
    cpp_process(wrong['execution_process'], 2)
    require(wrong['execution_process']['stderr'] == 'allocation calibration call\n'
            and wrong['first_mismatch']['hepta_value'] == wrong['first_mismatch']['direct_value'] + 1, 'compiled wrong-implementation control missing')
    summary = json.loads((directory / 'SUMMARY.json').read_text())
    require(sha((directory / 'SUMMARY.json').read_bytes()) == manifest['summary_sha256'], 'visible summary differs')
    require(summary['source_head'] == HEAD and summary['same_matrix'] is True and summary['new_holdout'] is False
            and summary['cpp']['all_allocation_failure_paths_recovered'] is False
            and summary['cpp']['foreign_noexcept_terminations'] == len(terminations) == 6, 'visible scope/recovery denominator differs')
    return {'ok': True, 'archive_members': len(members), 'archive_bytes': len(raw), 'uncompressed_member_bytes': total,
            'source_head': HEAD, 'source_files_rehashed': len(plan['frozen_inputs']['source_bindings']),
            'musl': musl, 'cpp': cpp, 'unrecovered_terminations': terminations,
            'launches': launch_results, 'historical_files_unchanged': len(plan['frozen_inputs']['historical_evidence_unchanged']),
            'artifacts_executed': False, 'source_or_backend_all_input_proof': False,
            'claim': 'retained-byte and finite receipt consistency; no rerun, authentication, physical execution proof, or general migration qualification'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2, sort_keys=True))
