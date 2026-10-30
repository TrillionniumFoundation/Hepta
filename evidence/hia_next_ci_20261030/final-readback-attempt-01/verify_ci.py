#!/usr/bin/env python3
"""Bounded, offline CI artifact audit; never extract or execute ZIP contents."""
import argparse
from collections import Counter
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import zipfile

ZIP_LIMIT = 4 * 1024**2
MEMBER_LIMIT = 8 * 1024**2
TOTAL_LIMIT = 32 * 1024**2
MEMBER_COUNT_LIMIT = 64
ROOT = '_temp/hepta-integrated/'
GATES = ('actual_tools_and_linux_seals', 'ranking_bridge_identity',
         'recursive_bridge_identity', 'finite_bridge_identity',
         'stream_bridge_identity', 'rust_resource_crate', 'full_regression',
         'merge_and_profile_coverage')
FALSE_QUALIFICATION_CLAIMS = ('global_optimality_established',
    'scientific_incremental_advantage_established', 'whole_language_soundness_proved',
    'historical_evidence_reused_as_current', 'historical_performance_denominators_combined',
    'standalone_performance_campaigns_replayed', 'six_stages_closed')
FALSE_SAFETY_CLAIMS = ('absolute_resource_safety_proved', 'core_to_native_refinement_proved',
    'general_concurrent_memory_safety_proved', 'global_optimality_proved',
    'native_process_memory_bound_proved', 'rust_performance_superiority_proved',
    'source_to_core_refinement_proved', 'whole_language_soundness_proved')
BRIDGE_SOURCES = {'ranking': 'd3c2d760eca5065fc966820379c35c6e8d56e855',
    'recursive': '2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b',
    'finite': '4b6391e116949af0c7e59776baead67271856bdb',
    'stream': 'c4a1bbed3a39beba43a6abf1a18b6f75c5725c21'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def bounded_read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                'input must be a bounded regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size <= maximum and
                all(getattr(before, k) == getattr(after, k) for k in
                    ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
                'input changed during bounded read')
        return raw
    finally:
        os.close(fd)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    require(len(raw) <= MEMBER_LIMIT, 'JSON byte bound')
    return json.loads(raw, object_pairs_hook=unique_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def safe(name):
    require(type(name) is str and 0 < len(name) <= 512 and
            not name.startswith('/') and '\\' not in name and ':' not in name and
            str(PurePosixPath(name)) == name and
            all(p not in ('', '.', '..') for p in name.split('/')) and
            all(ord(c) >= 32 for c in name), 'unsafe member path')


def load_zip(path, pin):
    raw = bounded_read(path, ZIP_LIMIT)
    require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'pinned ZIP identity differs')
    members, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= MEMBER_COUNT_LIMIT and len(infos) == pin['members'], 'ZIP member count')
        for info in infos:
            safe(info.filename)
            require(info.filename not in members and not info.is_dir() and
                    stat.S_ISREG(info.external_attr >> 16) and not info.flag_bits & 1 and
                    info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                    0 <= info.file_size <= MEMBER_LIMIT and 0 <= info.compress_size <= ZIP_LIMIT,
                    'duplicate, encrypted, linked, special or oversized ZIP member')
            total += info.file_size
            require(total <= TOTAL_LIMIT, 'ZIP aggregate expansion bound')
            with archive.open(info, 'r') as stream:
                payload = stream.read(info.file_size + 1)
            require(len(payload) == info.file_size, 'ZIP expanded member size differs')
            members[info.filename] = payload
    require(total == pin['payload_bytes'], 'ZIP payload denominator differs')
    return members


def validate_manifest(members, entry):
    rows = entry['members']
    require(type(rows) is list and len(rows) == len(members), 'manifest denominator')
    expected = {}
    for row in rows:
        safe(row['path'])
        require(row['path'] not in expected, 'duplicate manifest path')
        expected[row['path']] = row
    require(set(expected) == set(members), 'manifest member set differs')
    for name, raw in members.items():
        require(expected[name]['bytes'] == len(raw) and expected[name]['sha256'] == sha(raw),
                'manifest bytes differ: ' + name)


def verify_acquisition(root, pin):
    documents = {}
    for role in ('run_api', 'artifacts_api', 'download'):
        item = pin['acquisition'][role]
        safe(item['file'])
        raw = bounded_read(root / item['file'], 256 * 1024)
        require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'acquisition receipt differs')
        documents[role] = parse(raw)
    run = documents['run_api']
    require(run['id'] == pin['run_id'] and run['status'] == 'completed' and run['conclusion'] == 'success' and
            run['head_sha'] == run['head_commit']['id'] == pin['head'] and
            run['head_commit']['tree_id'] == pin['tree'] and
            run['repository']['id'] == 1432132756 and run['repository']['full_name'] == 'TrillionniumFoundation/Hepta' and
            run['html_url'] == 'https://github.com/TrillionniumFoundation/Hepta/actions/runs/' + str(pin['run_id']),
            'official run identity/status differs')
    artifacts = [a for a in documents['artifacts_api']['artifacts'] if a['id'] == pin['artifact_id']]
    require(len(artifacts) == 1, 'official artifact identity missing/duplicated')
    artifact = artifacts[0]
    require(artifact['digest'] == 'sha256:' + pin['sha256'] and artifact['size_in_bytes'] == pin['bytes'] and
            artifact['name'] == 'hepta-integrated-evidence-' + pin['head'] and artifact['expired'] is False and
            artifact['workflow_run']['id'] == pin['run_id'] and artifact['workflow_run']['head_sha'] == pin['head'],
            'official artifact digest/run binding differs')
    download = documents['download']
    require(download['file'] == Path(pin['file']).name and download['bytes'] == pin['bytes'] and
            download['sha256'] == pin['sha256'] and download['artifact_executed'] is False and
            type(download['download_wall_ns']) is int and download['download_wall_ns'] >= 0,
            'download receipt differs')
    return {'official_run_status': 'completed', 'official_run_conclusion': 'success',
            'official_artifact_digest_matched': True, 'official_head_commit_tree_matched': True,
            'official_run_url': run['html_url'], 'download_wall_ns': download['download_wall_ns'],
            'api_documents_are_retained_receipts_not_new_network_attestation': True}


def python_log(log, expected):
    # unittest may print a method docstring and a tested CLI's diagnostics
    # between the header and its final status. Keep each entire method span.
    footer = list(re.finditer(r'^Ran (\d+) tests? in ([0-9.]+)s\n\nOK\n?\Z', log, re.M))
    require(len(footer) == 1 and int(footer[0][1]) == expected, 'Python final footer differs')
    headers = list(re.finditer(r'^(test[A-Za-z0-9_]+) \(((?:tests\.)?test_[A-Za-z0-9_.]+)\)(?= |\n|$)', log, re.M))
    require(len(headers) == expected and len({h[2] for h in headers}) == expected,
            'Python unique method denominator differs')
    records = []
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else log.rfind('\n---', 0, footer[0].start())
        require(end > header.end() and header[1] == header[2].rsplit('.', 1)[-1], 'Python method identity')
        span = log[header.end():end].strip()
        require(span.endswith('... ok') or span.endswith('\nok') or span == '... ok',
                'Python method lacks successful terminal status: ' + header[2])
        records.append(header[2])
    return records, float(footer[0][2])


def rust_log(execution, expected, binaries):
    log = execution['stdout']
    starts = list(re.finditer(r'^running (\d+) tests?\n', log, re.M))
    footer_pattern = re.compile(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; '
        r'(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$', re.M)
    all_footers = list(footer_pattern.finditer(log))
    require(len(starts) == len(all_footers) == binaries, 'Rust per-binary footer denominator')
    records, total = [], 0
    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(log)
        section = log[start.end():end]
        footers = list(footer_pattern.finditer(section))
        require(len(footers) == 1, 'missing or extra Rust binary footer')
        footer = footers[0]
        methods = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$', section, re.M)
        number = int(start[1])
        require(int(footer[1]) == number == len(methods) == len(set(methods)) and
                all(int(footer[k]) == 0 for k in (2, 3, 4, 5)) and
                not section[footer.end():].strip(), 'Rust binary count/status differs')
        records.append({'index': index, 'tests': number, 'method_ids_sha256': sha(canonical(methods)),
                        'footer_seconds': float(footer[6])})
        total += number
    launches = re.findall(r'^\s+(?:Running .+|Doc-tests .+)$', execution['stderr'], re.M)
    require(total == expected and len(launches) == binaries, 'Rust binary launch/footer total differs')
    return records


def test_execution(gate, expected, kind):
    execution = gate['execution']
    require(gate['passed'] is True and execution['returncode'] == 0 and
            type(execution['seconds']) in (int, float) and math.isfinite(execution['seconds']) and
            execution['seconds'] > 0 and gate['tests_run'] == expected and
            gate['failures'] == gate['skipped'] == 0, kind + ' gate failed')
    if kind == 'Python':
        require(gate['errors'] == 0, 'Python errors')
    else:
        require(gate['filtered_out'] == gate['measured'] == 0, 'Rust omitted tests')
    return execution


def verify_run(pin, members):
    get = lambda name: parse(members[name])
    q = get(ROOT + 'qualification.json')
    plan = get(ROOT + 'frozen-plan.json')
    source = q['source_before']
    require(q['schema'] == 'hepta.hia.integrated-contract-qualification.v2' and
            q['ok'] is True and q['status'] == 'bounded_integrated_contracts_passed' and
            q['full_regression_requested'] is True, 'qualification incomplete')
    require(source == q['source_after'] and q['source_unchanged'] is True and
            source['status'] == '' and source['head'] == pin['head'] and source['tree'] == pin['tree'] and
            len(source['files']) == pin['tracked_files'] and
            q['external_inventory_before'] == q['external_inventory_after'] and
            q['external_inputs_unchanged'] is True and
            len(q['external_inventory_before']) == pin['external_files'], 'source or external identity differs')
    require(plan['source_head'] == pin['head'] and plan['source_tree'] == pin['tree'] and
            plan['native_identity_gates'] == list(GATES[:5]) and
            plan['configured_environment'] == q['configured_environment'], 'frozen plan differs')
    for claim in FALSE_QUALIFICATION_CLAIMS:
        holder = plan if claim == 'historical_performance_denominators_combined' else q
        require(holder[claim] is False, 'unsupported qualification claim: ' + claim)
    workflow = get('Hepta/Hepta/artifacts/workflow-source.json')
    require(workflow['schema'] == 'hepta.workflow-source.v1' and workflow['qualification_profile'] == 'integrated' and
            all(workflow[k] == pin['head'] for k in ('expected_head_sha', 'checkout_head_sha', 'event_sha')),
            'workflow head differs')
    gates = q['gates']
    require([g['name'] for g in gates] == list(GATES) and all(g['passed'] is True for g in gates), 'eight gates differ')
    for gate in gates:
        suffix = {'rust_resource_crate': 'rust_resource_crate-execution.json',
                  'full_regression': 'full_regression-execution.json',
                  'merge_and_profile_coverage': 'merge-and-profile-coverage.json'}.get(gate['name'], gate['name'] + '.json')
        require(get(ROOT + suffix) == gate, 'separate gate/qualification mismatch')
    tool_gate = gates[0]
    require(tool_gate['linux_seals'] == {'actual_bits': 15, 'actual_write_rejected_errno': 1,
            'exact_readback': True, 'required_bits': 15}, 'actual Linux seal observation')
    require(tool_gate['solver']['version'] == '4.15.4', 'solver pin')
    for name, tool in tool_gate['tools'].items():
        require(q['external_inventory_before'][tool['path']] == tool['sha256'] and
                get(ROOT + name + '-tool-probe.json') == tool, 'tool identity/probe binding')
    selected = get('Hepta/Hepta/artifacts/selected-rustc.json')
    require(selected['executable_sha256'] == tool_gate['tools']['rustc']['sha256'] and
            selected['host'] == 'x86_64-unknown-linux-gnu' and 'release: 1.90.0' in selected['version'], 'Rust host pin')
    bridge_records = {}
    for gate in gates[1:5]:
        profile = gate['name'].removesuffix('_bridge_identity')
        receipt_member = '_temp/' + gate['receipt'].split('/_temp/', 1)[1]
        receipt_sha = gate['identity']['build_receipt_sha256'] if profile == 'ranking' else gate['receipt_sha256']
        require(sha(members[receipt_member]) == receipt_sha == q['external_inventory_before'][gate['receipt']],
                'native build receipt binding')
        response, identity = gate['response'], gate['identity']
        if profile == 'ranking':
            require(identity['upstream_commit'] == response['upstream_commit'] == BRIDGE_SOURCES[profile] and
                    response['authority'] == 'ADVISORY_ONLY' and response['proves_program_safety'] is False and
                    response['global_optimality_established'] is False, 'ranking authority scope')
            binary_sha = identity['binary_sha256']
        else:
            require(identity['source_commit'] == BRIDGE_SOURCES[profile] and
                    identity['authority'] == response['authority'] == 'DENY_ALL' and
                    identity['safety_certificate'] is False and response['safety_certificate'] is False and
                    response['optimality_scope'] == 'bounded-supplied-candidate-paths-only', 'native authority scope')
            binary_sha = gate['binary_sha256']
        require(q['external_inventory_before'][gate['binary']] == binary_sha, 'native binary inventory binding')
        if profile == 'stream':
            session = gate['session_observation']
            require(session['closed_after_context'] is True and session['requests'] == 2 and
                    session['identity'] == identity and session['binary_sha256'] == binary_sha and
                    session['initial_full_digest_verified'] is True and session['safety_certificate'] is False,
                    'stream probe finalization')
        bridge_records[profile] = {'source': BRIDGE_SOURCES[profile], 'binary_sha256': binary_sha,
                                  'authority': response['authority'], 'synthetic_identity_probe_only': True}
    full = gates[6]
    full_execution = test_execution(full, pin['python_tests'], 'Python')
    methods, footer_seconds = python_log(full_execution['stderr'], pin['python_tests'])
    require(full_execution['argv'] == plan['commands'][1]['argv'], 'full test argv differs')
    rust = gates[5]
    rust_execution = test_execution(rust, pin['rust_tests'], 'Rust')
    require(rust_execution['argv'] == plan['commands'][0]['argv'] and rust['test_binaries'] == pin['rust_binaries'], 'Rust plan differs')
    binaries = rust_log(rust_execution, pin['rust_tests'], pin['rust_binaries'])
    coverage = gates[7]
    require(coverage['subsets_of_full_regression_only'] is True and coverage['missing_modules'] == [] and
            coverage['unique_method_records'] == coverage['verbose_method_records'] == len(methods) and
            set(coverage['groups']) == set(plan['critical_modules']) and
            len(coverage['groups']) == pin['critical_groups'], 'critical coverage shape')
    critical_methods, critical_modules = set(), set()
    for group, module_map in coverage['groups'].items():
        require(set(module_map) == set(plan['critical_modules'][group]), 'critical group modules differ')
        for module, recorded in module_map.items():
            actual = [method for method in methods if method.startswith(module + '.')]
            require(actual and len(recorded) == len(set(recorded)) and set(actual) == set(recorded),
                    'critical methods are not the exact full-run module subset')
            critical_modules.add(module)
            critical_methods.update(recorded)
    require(len(critical_modules) == pin['critical_modules'] and len(critical_methods) == pin['critical_methods'], 'critical denominator')
    safety = get('_temp/hepta-integrated-safety.json')
    contract = safety['contract']
    require(safety['schema'] == 'hepta.hia.safety-contract-qualification.v1' and safety['status'] == 'passed' and
            safety['source_before'] == safety['source_after'] and safety['source_stable'] is True and
            all(source['files'][path] == digest for path, digest in safety['source_before'].items()), 'safety source drift')
    for key in ('head_before', 'head_after'):
        require(safety[key] == {'argv': ['git', 'rev-parse', 'HEAD'], 'returncode': 0, 'stderr': '', 'stdout': pin['head'] + '\n'},
                'matrix source head differs')
    require(safety['status_before'] == {'argv': ['git', 'status', '--porcelain'], 'returncode': 0, 'stderr': '', 'stdout': ''},
            'matrix source not initially clean')
    require(sha(canonical(contract)) == pin['contract_sha256'] == safety['contract_sha256'] == safety['reviewed_contract_sha256'],
            'canonical reviewed contract differs')
    require(contract['schema'] == 'hepta.hia.safety-contract.v1' and len(contract['capabilities']) == len(safety['capabilities']) == pin['capabilities'],
            'capability denominator')
    selectors = set()
    for declared, observed in zip(contract['capabilities'], safety['capabilities']):
        require(declared['id'] == observed['id'] and declared['regression_selectors'] == observed['regression_selectors'] and
                declared['guarantee'] == observed['declared_contract'] and observed['regression_evidence_passed'] is True and
                observed['soundness_or_refinement_proof_established_by_this_run'] is False, 'capability scope/binding')
        selectors.update(declared['regression_selectors'])
    require(len({c['id'] for c in contract['capabilities']}) == pin['capabilities'] and
            len(selectors) == safety['expected_tests'] == safety['tests_run'] == pin['matrix_tests'] and
            selectors == set(safety['tests']), 'matrix selector denominator')
    matrix_methods, matrix_seconds = python_log(safety['log'], pin['matrix_tests'])
    require(set(matrix_methods) == selectors and all(row['status'] == 'passed' and type(row['wall_ns']) is int and row['wall_ns'] > 0
            for row in safety['tests'].values()) and {s.removeprefix('tests.') for s in selectors}.issubset(methods),
            'matrix test status/log/full-run subset')
    require(all(contract['unproved_claims'][key] is False and safety['claims'][key] is False for key in FALSE_SAFETY_CLAIMS) and
            safety['claims']['metadata_grants_admission'] is False and
            safety['claims']['all_selected_boundary_regressions_passed_without_skips'] is True and
            contract['authority']['external_receipts_grant_admission'] is False and contract['authority']['metadata_grants_admission'] is False and
            safety['environment']['complete_transitive_toolchain_or_sysroot_closure_proved'] is False, 'unsupported safety claim')
    final_line = members['_temp/hepta-integrated-safety.log'].decode().splitlines()[-1]
    require(parse(final_line.encode()) == {'status': 'passed', 'tests_run': pin['matrix_tests'],
            'expected_tests': pin['matrix_tests'], 'source_stable': True}, 'matrix outer log terminal record')
    timeline = [parse(line) for line in members['_temp/hepta-integrated.log'].splitlines()]
    require([r['gate'] for r in timeline if 'passed' in r] == list(GATES[:7]) and
            all(r['passed'] is True for r in timeline if 'passed' in r) and timeline[-1] == {
                'ok': True, 'status': 'bounded_integrated_contracts_passed', 'source_unchanged': True,
                'external_inputs_unchanged': True}, 'outer qualification timeline')
    return {'run_id': pin['run_id'], 'artifact_id': pin['artifact_id'], 'head': pin['head'], 'tree': pin['tree'],
        'archive_sha256': pin['sha256'], 'members_verified': len(members), 'payload_bytes_verified': sum(map(len, members.values())),
        'source_before_after_equal': True, 'tracked_source_files': pin['tracked_files'], 'external_files': pin['external_files'],
        'all_eight_gates_passed': True, 'python_tests': len(methods), 'python_unique_method_ids_sha256': sha(canonical(methods)),
        'python_footer_seconds': footer_seconds, 'python_process_seconds': full_execution['seconds'],
        'rust_tests': pin['rust_tests'], 'rust_binary_footers': binaries, 'rust_process_seconds': rust_execution['seconds'],
        'critical_groups': len(coverage['groups']), 'critical_modules': len(critical_modules), 'critical_methods': len(critical_methods),
        'critical_coverage_is_full_run_subset_not_additional_tests': True,
        'matrix_tests': len(selectors), 'matrix_capabilities': pin['capabilities'], 'matrix_contract_sha256': pin['contract_sha256'],
        'matrix_footer_seconds': matrix_seconds, 'matrix_wall_ns': safety['wall_ns'],
        'matrix_selectors_are_full_run_subset': True, 'bridges': bridge_records,
        'ci_pass_reclassifies_economic_or_model_trials': False, 'scientific_incremental_advantage_established': False,
        'whole_language_soundness_proved': False, 'global_optimality_proved': False,
        'source_files_and_tool_binaries_rehashed_locally_from_archive': False,
        'source_identity_scope': 'before/after recorded inventories and known head/tree; this ZIP does not bundle the source/tool installation',
        'all_unsupported_safety_claims_remain_false': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--pins', type=Path, required=True)
    parser.add_argument('--pins-sha256', required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic_ns()
    pins_raw = bounded_read(args.pins, 256 * 1024)
    manifest_raw = bounded_read(args.manifest, 256 * 1024)
    require(sha(pins_raw) == args.pins_sha256 and sha(manifest_raw) == args.manifest_sha256, 'external metadata pins differ')
    pins, manifest = parse(pins_raw), parse(manifest_raw)
    require(pins['schema'] == 'hepta.ci.artifact-pins.v1' and manifest['schema'] == 'hepta.ci.member-manifest.v1' and
            manifest['pins_sha256'] == sha(pins_raw), 'manifest/pins schema or binding')
    require(set(pins['runs']) == set(manifest['runs']) and 0 < len(pins['runs']) <= 3, 'run denominator')
    runs = {}
    for key, pin in pins['runs'].items():
        safe(pin['file'])
        acquisition = verify_acquisition(args.root, pin)
        members = load_zip(args.root / pin['file'], pin)
        validate_manifest(members, manifest['runs'][key])
        runs[key] = verify_run(pin, members)
        runs[key]['acquisition'] = acquisition
    result = {'schema': 'hepta.ci.offline-verification.v1', 'passed': True, 'runs': runs,
        'pins_sha256': sha(pins_raw), 'manifest_sha256': sha(manifest_raw),
        'latest_required_source': pins['latest_required_source'],
        'latest_required_source_verified': any(v['head'] == pins['latest_required_source'] for v in runs.values()),
        'historical_ci_is_not_current_ci': True, 'archive_code_extracted_or_executed': False,
        'network_or_credentials_used': False, 'new_test_or_model_runs': 0,
        'verification_wall_ns_before_encoding': time.monotonic_ns() - started}
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    main()
