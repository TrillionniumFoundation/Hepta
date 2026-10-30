#!/usr/bin/env python3
"""Bounded offline data audit. Never extract or execute archived code/images."""
import argparse
import base64
from collections import Counter
import hashlib
import io
from itertools import product
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import statistics
import tarfile
import time

ARCHIVE_SHA = 'e406e8826a7a98aab96232054757a14857b71020c9f5c5b154d170d2c74e7fa2'
MANIFEST_SHA = 'a3e7ea32a6ff607071f662a39f96bf0b9ba9c56ae3b30e1fd5b833945c8f5a00'
LABELS = ('baseline', 'guard_8', 'guard_10', 'guard_8_10')
ARMS = ('fixed', 'feedback-greedy', 'light-dp', 'native-ndu')
TRACE = [8, 8, 10, 10, 13, 8, 10, 13]
MAX_FILE = 8 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_MEMBERS = 5000
STREAM_SOURCE = 'c4a1bbed3a39beba43a6abf1a18b6f75c5725c21'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def bounded_regular_bytes(path, limit):
    """One bounded, no-follow read; hash and parse these identical bytes."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit,
                'input is not a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        stable = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(data) == before.st_size <= limit
                and all(getattr(before, key) == getattr(after, key) for key in stable),
                'input changed during bounded read')
        return data
    finally:
        os.close(descriptor)


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def parse(raw):
    require(len(raw) <= MAX_FILE, 'JSON byte bound')
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def safe(name):
    require(type(name) is str and 0 < len(name) <= 512, 'member name bound')
    require(not name.startswith('/') and '\\' not in name and ':' not in name
            and str(PurePosixPath(name)) == name
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and all(ord(char) >= 32 for char in name), 'unsafe member name')


def load(archive, manifest_path):
    # Both immutable external pins are checked BEFORE decompressing/parsing.
    archive_raw = bounded_regular_bytes(archive, 32 * 1024**2)
    manifest_raw = bounded_regular_bytes(manifest_path, 2 * 1024**2)
    require(sha(archive_raw) == ARCHIVE_SHA, 'archive SHA differs')
    require(sha(manifest_raw) == MANIFEST_SHA, 'manifest SHA differs')
    manifest = parse(manifest_raw)
    require(manifest['schema'] == 'hepta.hia.stb-ndu.evidence-archive.v1', 'manifest schema')
    require(manifest['archive']['sha256'] == ARCHIVE_SHA
            and manifest['archive']['bytes'] == len(archive_raw), 'archive binding')
    rows = manifest['members']
    require(type(rows) is list and 0 < len(rows) <= MAX_MEMBERS, 'member count bound')
    expected = {}
    for row in rows:
        safe(row['path'])
        require(row['path'] not in expected and type(row['bytes']) is int
                and 0 <= row['bytes'] <= MAX_FILE, 'duplicate or oversized manifest member')
        require(type(row['sha256']) is str and len(row['sha256']) == 64
                and all(c in '0123456789abcdef' for c in row['sha256']), 'bad member hash')
        expected[row['path']] = row
    total = sum(row['bytes'] for row in rows)
    require(total == manifest['payload_bytes'] <= MAX_TOTAL
            and len(rows) == manifest['member_count'], 'manifest denominator')
    # Bound the XZ dictionary and the complete expanded tar stream, including
    # metadata headers; a payload-only counter would not constrain long/PAX
    # headers. No expanded bytes are written to the filesystem.
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
    expanded = decoder.decompress(archive_raw, max_length=MAX_TOTAL + 1)
    require(len(expanded) <= MAX_TOTAL and decoder.eof and not decoder.unused_data,
            'expanded stream bound, truncated XZ or trailing compressed member')
    raw = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r|') as tar:
        for member in tar:
            safe(member.name)
            require(member.isfile() and not member.issym() and not member.islnk()
                    and member.name in expected and member.name not in raw,
                    'unknown, duplicate, linked or special archive member')
            require(0 <= member.size <= MAX_FILE and member.size == expected[member.name]['bytes'], 'member size')
            stream = tar.extractfile(member)  # Read bytes only; no filesystem extraction.
            data = stream.read(MAX_FILE + 1)
            require(len(data) == member.size and sha(data) == expected[member.name]['sha256'], 'member bytes differ')
            raw[member.name] = data
            require(len(raw) <= MAX_MEMBERS and sum(len(data) for data in raw.values()) <= MAX_TOTAL, 'expanded payload bounds')
    require(set(raw) == set(expected), 'archive member denominator differs')
    return manifest, raw


def require_source(root, report, raw, head):
    require(report['source_before'] == report['source_after'] and report['source_before']['head'] == head
            and report['identities_unchanged'] is True, 'source identity drift')
    for name, digest in report['source_before']['files'].items():
        require(sha(raw[root + '/source_snapshot/' + name]) == digest, 'source snapshot byte differs')
    for key in ('tools', 'solver', 'frontend_libraries'):
        require(report[key + '_before'] == report[key + '_after'], 'observed tool/solver/library drift')
    require(report['solver_before']['version'] == '4.15.4', 'solver pin')
    bridge = report['capture']['adapter']['call_closure_bridge']
    require(bridge['status'] == 'proved'
            and bridge['claims']['all_input_return_and_first_trap_equivalence'] is True
            and bridge['claims']['source_C_refinement_proved'] is False, 'captured call-closure scope')


def check_bank(root, report, raw, key, labels):
    bank = report[key]
    folder = 'bank' if key == 'bank' else 'baseline-bank'
    require(set(bank['candidates']) == set(labels), 'candidate bank denominator')
    calls = 0
    for label in labels:
        candidate = bank['candidates'][label]
        require(candidate['translation']['status'] == 'proved', 'scalar candidate proof')
        require(candidate['lowering']['claims']['selected_body_all_input_value_and_abort_equivalence'] is True,
                'selected LLVM value/abort check')
        require(candidate['compilation']['ok'] is True, 'actual compilation failed')
        require(sha(raw[root + '/' + folder + '/' + label + '.so']) == candidate['compilation']['artifact_sha256'],
                'native artifact bytes differ')
        require(sha(raw[root + '/' + folder + '/' + label + '.ll']) == candidate['compilation']['llvm_ir_sha256'],
                'LLVM bytes differ')
        differential = candidate['native_differential']
        require(differential['cases_executed'] == 64
                and differential['status'] == 'finite_native_observations_match_oracle_not_proved', 'native differential count')
        calls += differential['cases_executed']
    release = report[key + '_release']
    require(release['complete'] is True and release['pending_input_bytes'] == 0
            and release['pins_retained_for_uncertain_child'] is False
            and release['oracle_references']['closed'] is True
            and release['oracle_references']['retained_canonical_bytes'] == 0, 'bank/cache release incomplete')
    return calls


def reference(values, parameter, repetitions):
    require(parameter in (8, 10, 13) and repetitions == 4096 and len(values) == 4096, 'registered request shape')
    modulus, multiplier, block = 1 << 64, 1099511628211, 0
    for bits in values:
        require(type(bits) is int and 0 <= bits < 1 << 32, 'input word type/range')
        result = (bits if bits < 1 << 31 else bits - (1 << 32)) % parameter
        block = (block * multiplier + result) % modulus
    # Independently compose the repeated affine checksum transport.
    factor, addend, checksum, count = pow(multiplier, len(values), modulus), block, 0, repetitions
    while count:
        if count & 1:
            checksum = (checksum * factor + addend) % modulus
        addend, factor = (addend * factor + addend) % modulus, factor * factor % modulus
        count >>= 1
    return result, checksum


def check_delivery(folder, index, observed, values, report, raw, bank_key, nonces, references):
    stem = folder + '/' + str(index).zfill(4)
    plan, native = parse(raw[stem + '.plan.json']), parse(raw[stem + '.native.json'])
    retained_observation = parse(raw[stem + '.observation.json'])
    require(all(observed[key] == value for key, value in retained_observation.items()), 'observation/aggregate differs')
    require(native['status'] == 'completed' and native['execution_attempted'] is True
            and native['returncode'] == 0 and native['prefix']['complete'] is True
            and native['replay_permitted'] is False, 'native delivery incomplete or reused')
    require(plan['trace_sha256'] == native['trace_sha256'] == observed['trace_sha256']
            and plan['trace_sha256'] not in nonces, 'reused/mismatched trace nonce')
    nonces.add(plan['trace_sha256'])
    require(len(plan['requests']) == len(plan['expected']) == 1, 'one actual request required')
    ident, local_slot, mode, seed, parameter, actual_values, repeats = plan['requests'][0]
    require(ident == index and mode == 2 and seed == 0 and parameter == observed['parameter']
            and actual_values == values and repeats == 4096, 'registered input/request differs')
    bank = report[bank_key]
    # Request slots index this trace's loaded images, not the global bank.
    # prepare_trace normalizes bank indices through images.index(bank_index).
    require(type(plan['images']) is list and len(plan['images']) == 1
            and type(local_slot) is int and local_slot == 0, 'local image slot differs')
    bank_index = plan['images'][local_slot]
    require(type(bank_index) is int and 0 <= bank_index < len(bank['labels'])
            and bank['labels'][bank_index] == observed['target'], 'candidate identity differs')
    key = (sha(canonical(values)), parameter)
    if key not in references:
        references[key] = reference(values, parameter, repeats)
    state, checksum = references[key]
    require(plan['expected'] == [['returned', state, checksum]], 'independent mathematical reference differs')
    events = [parse(line) for line in base64.b64decode(native['raw_stdout_base64'], validate=True).splitlines()]
    require(events == native['prefix']['events'] and all(row['trace'] == plan['trace_sha256'] for row in events),
            'raw native stdout/prefix binding')
    results = [row for row in events if row['kind'] == 'result']
    require(len(results) == 1 and results == native['prefix']['completed_requests'], 'actual result denominator')
    result = results[0]
    require(result['calls'] == observed['calls'] == 16777216 and result['state'] == state
            and result['checksum'] == observed['checksum'] == checksum and result['repetitions'] == repeats
            and result['kernel_ns'] == observed['kernel_ns'] > 0
            and result['id'] == ident and result['candidate'] == local_slot
            and result['mode'] == mode and result['seed'] == seed and result['parameter'] == parameter,
            'actual calls/value/cost/request differ')
    require(events[-1]['kind'] == 'finish' and events[-1]['ok'] is True
            and events[-1]['acquired'] == events[-1]['closed'] == 1, 'native image release incomplete')
    inventory = native['loaded_inventory']
    require(len(inventory) == 1 and inventory[0]['candidate'] == observed['target']
            and inventory[0]['slot'] == local_slot and inventory[0]['bank_index'] == bank_index
            and inventory[0]['artifact_sha256'] == bank['candidates'][observed['target']]['compilation']['artifact_sha256'],
            'loaded image binding differs')
    return result['calls']


def estimates(calibration, prior, parameter):
    return {label: round(statistics.median([row['delivery_ns'] for row in prior
        if row['target'] == label and row['parameter'] == parameter]))
        if any(row['target'] == label and row['parameter'] == parameter for row in prior)
        else calibration['latency_ns'][str(parameter)][label] for label in LABELS}


def check_policies(root, report, raw):
    calibration, calls, nonces, references = report['calibration'], 0, set(), {}
    inputs = parse(raw[root + '/INPUTS.json'])
    for group in (-1, 0, 1, 2, 3):
        row = inputs[str(group)]
        require(row['sha256'] == sha(canonical(row['values'])), 'input vector hash')
        phase = 'training' if group == -1 else 'validation'
        generated = hashlib.shake_256(('hepta/stb-mod-eucl/ndu/v1/20261030/' + phase + '/' + str(group)).encode()).digest(16384)
        words = [int.from_bytes(generated[i:i + 4], 'little') for i in range(0, len(generated), 4)]
        words[:8] = [0, 1, 7, 8, 9, 2147483647, 2147483648, 4294967295]
        require(row['values'] == words, 'domain-separated input changed')
    require(len(calibration['rows']) == 24 and {(r['repetition'], r['parameter'], r['target']) for r in calibration['rows']} ==
            {(repeat, parameter, label) for repeat in range(2) for parameter in (8, 10, 13) for label in LABELS}, 'calibration denominator')
    for index, row in enumerate(calibration['rows']):
        calls += check_delivery(root + '/calibration', index, row, inputs['-1']['values'], report, raw, 'bank', nonces, references)
    for parameter in (8, 10, 13):
        for label in LABELS:
            expected = round(statistics.median(row['delivery_ns'] for row in calibration['rows']
                if row['parameter'] == parameter and row['target'] == label))
            require(calibration['latency_ns'][str(parameter)][label] == expected, 'calibration estimator differs')
    episodes = report['episodes']
    require(len(episodes) == 20 and {(r['group'], r['arm']) for r in episodes} ==
            {(group, arm) for group in range(4) for arm in (*ARMS, 'baseline-only')}, '20 group/arm denominator')
    native_audit = []
    for episode in episodes:
        group, arm = episode['group'], episode['arm']
        folder = root + '/group-' + str(group) + '-' + arm
        require(parse(raw[folder + '/EPISODE.json']) == episode and episode['complete'] is True
                and episode['wall_ns'] <= 120000000000 and len(episode['observations']) == 8, 'episode binding/budget')
        for index, observation in enumerate(episode['observations']):
            require(observation['epoch'] == index and observation['parameter'] == TRACE[index], 'trace/order differs')
            calls += check_delivery(folder, index, observation, inputs[str(group)]['values'], report, raw,
                'baseline_bank' if arm == 'baseline-only' else 'bank', nonces, references)
            prior = episode['observations'][:index]
            if arm in ('fixed', 'feedback-greedy'):
                costs = estimates(calibration, [] if arm == 'fixed' else prior, TRACE[index])
                require(observation['target'] == min(LABELS, key=lambda key: (costs[key], key)), 'fixed/feedback information rule')
            elif arm == 'baseline-only':
                require(observation['target'] == 'baseline', 'baseline control substituted a candidate')
            else:
                decision = episode['decisions'][index]
                require(parse(raw[folder + '/' + str(index).zfill(4) + '.decision.json']) == decision, 'decision byte/aggregate binding')
                model = decision['model']
                horizon = TRACE[index:index + 3]
                require(model['epoch'] == index and model['horizon'] == horizon
                        and model['costs'] == [estimates(calibration, prior, parameter) for parameter in horizon],
                        'planner sees unregistered/future/other-arm observations')
                choices = [(sum(cost[label] for cost, label in zip(model['costs'], labels)), labels)
                           for labels in product(LABELS, repeat=len(horizon))]
                feasible = [choice for choice in choices if choice[0] <= model['remaining_ns']]
                require(feasible, 'planner has no feasible supplied path')
                cost, labels = min(feasible)
                expected = {'targets': list(labels), 'cost_ns': cost, 'id': 'p-' + sha(canonical(labels))[:24]}
                require(decision['chosen'] == expected and observation['target'] == labels[0], 'same-model exhaustive optimum differs')
                if arm == 'native-ndu':
                    frame = folder + '/stream/' + str(index + 2).zfill(4)
                    request, envelope = parse(raw[frame + '.stdin']), parse(raw[frame + '.stdout'])
                    require(request == decision['request'] and envelope['response'] == decision['response']
                            and envelope['sequence'] == index + 1 and request['generation'] == index + 1,
                            'actual native frames/sequence differ')
                    require(len(request['candidates']) == 4**len(horizon) + 1
                            and request['candidates'][-1]['id'] == 'abstain', 'native supplied-path denominator')
                    require(envelope['authority'] == envelope['response']['authority'] == 'DENY_ALL'
                            and envelope['safety_certificate'] is False
                            and envelope['response']['safety_certificate'] is False, 'native authority scope')
                    native_audit.append({'group': group, 'epoch': index, 'native': decision['chosen'],
                        'same_model_dp': expected, 'same_choice': True, 'modeled_regret_ns': 0})
        if arm == 'native-ndu':
            session = episode['native_session']
            require(session['closed'] is True and session['process_exited'] is True and session['requests'] == 8
                    and session['identity']['source_commit'] == STREAM_SOURCE, 'native session cleanup/source')
    require(calls == 3087007744 and len(nonces) == 184 and len(native_audit) == 32, 'actual work/native decision denominator')
    return native_audit


def cost_analysis(report, audit):
    ledger = report['ledger'][:-1]
    require(report['ledger'][-1]['label'] == 'post-policy.analysis', 'last analysis stage missing')
    costs = Counter()
    end = None
    for row in ledger:
        require(row['status'] == 'completed' and type(row['wall_ns']) is int and row['wall_ns'] >= 0,
                'unknown/unclosed policy cost')
        require(end is None or row['started_monotonic_ns'] >= end, 'overlapping cost stages')
        end = row['started_monotonic_ns'] + row['wall_ns']
        costs[row['label']] += row['wall_ns']
    counts = Counter(row['label'] for row in ledger)
    required_once = ('source.before', 'solver.before', 'frontend_libraries.before', 'source.capture_and_bridge',
        'candidate.generate', 'candidate.prepare_bank', 'candidate.distinct_code', 'input.construct',
        'reference.prepare', 'calibration', 'baseline.prepare_bank', 'baseline.reference', 'bank.close',
        'baseline_bank.close', 'source_after', 'tools_after', 'solver_after', 'frontend_libraries_after')
    require(all(counts[label] == 1 for label in required_once)
            and all(counts['episode.' + arm] == 4 for arm in (*ARMS, 'baseline-only')),
            'required closed cost stage missing or duplicated; unknown costs are not zero')
    baseline_preparation = sum(costs[key] for key in ('baseline.prepare_bank', 'baseline.reference', 'baseline_bank.close'))
    search = sum(costs[key] for key in ('candidate.generate', 'candidate.prepare_bank', 'candidate.distinct_code',
                                      'reference.prepare', 'calibration', 'bank.close'))
    episode_cost = sum(costs['episode.' + arm] for arm in (*ARMS, 'baseline-only'))
    common = report['wall_ns_before_analysis_and_final_encoding'] - search - baseline_preparation - episode_cost
    require(common >= 0 and sum(costs.values()) <= report['wall_ns_before_analysis_and_final_encoding'], 'total cost consistency')
    totals = {arm: common + search + costs['episode.' + arm] for arm in ARMS}
    baseline = common + baseline_preparation + costs['episode.baseline-only']
    return {'standalone_measured_ns': totals, 'baseline_only_standalone_ns': baseline,
        'closed_policy_cost_ledger_sha256': sha(canonical(ledger)),
        'common_charged_once_per_arm_ns': common, 'complete_search_preparation_ns': search,
        'baseline_only_preparation_ns': baseline_preparation,
        'native_build_inclusive_ns': totals['native-ndu'] + report['historical_native_build_ns'],
        'historical_native_build_allocation_ns': report['historical_native_build_ns'],
        'same_model_audit': audit, 'candidate_cold_observed_net_gate': totals['fixed'] < baseline,
        'ndu_warm_observed_net_gate': all(totals['native-ndu'] < totals[arm] for arm in ARMS[:-1]),
        'ndu_build_inclusive_observed_net_gate': all(totals['native-ndu'] + report['historical_native_build_ns'] < totals[arm] for arm in ARMS[:-1]),
        'actual_kernel_calls': 3087007744}


def verify(archive, manifest_path):
    started = time.monotonic_ns()
    manifest, raw = load(archive, manifest_path)
    ndu = parse(raw['provenance/stream-identity.json'])
    require(sha(raw['provenance/stream-native.bin']) == ndu['binary_sha256']
            and ndu['identity']['source_commit'] == STREAM_SOURCE
            and ndu['build_cost']['wall_ns'] == 28548912666, 'original native identity/build allocation')
    require(sha(raw['provenance/stream-build-commands.json']) == ndu['command_evidence']['sha256'], 'build receipt bytes')
    summaries = {}
    for label, head, succeeded in (
        ('formal-failed-f7cc8721', 'f7cc87218a101b4b2c715e3fdd2e9d42a7f7fd8b', False),
        ('formal-revalidated-44e34b7a', '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304', True)):
        root = label + '/run'
        report, outer = parse(raw[root + '/RESULT.json']), parse(raw[label + '/EXECUTION.json'])
        require_source(root, report, raw, head)
        require(report['qualified'] is succeeded and outer['qualified_complete_observation'] is succeeded
                and outer['returncode'] == (0 if succeeded else 1) and outer['within_total_budget'] is True
                and outer['total_wall_ns_before_receipt_encoding'] <= 900000000000, 'formal state/budget reclassified')
        require(outer['result_identity']['sha256'] == sha(raw[root + '/RESULT.json'])
                and outer['source_before'] == outer['source_after']
                and outer['tools_before'] == outer['tools_after'], 'outer identity binding')
        require(report['protocol']['trace'] == TRACE and report['protocol']['arms'] == list(ARMS)
                and report['protocol']['expected_actual_kernel_calls'] == 3087007744
                and report['protocol']['previous_negative_results_replaced'] is False, 'frozen protocol changed')
        require(report['protocol_sha256'] == sha(raw[root + '/source_snapshot/experiments/hia_stb_ndu_20261030/PROTOCOL.json'])
                and report['historical_native_build_ns'] == ndu['build_cost']['wall_ns'], 'protocol/build allocation binding')
        require(report['performance_timing_qualified'] is False and report['source_C_refinement_proved'] is False
                and report['machine_code_refinement_proved'] is False, 'scope promoted to an unestablished proof')
        calls = check_bank(root, report, raw, 'bank', LABELS) + check_bank(root, report, raw, 'baseline_bank', ('baseline',))
        require(calls == report['preparation_native_calls']['total_calls'] == 320, 'additional preparation calls')
        require(len({row['code']['sha256'] for row in report['bank']['candidates'].values()}) == 4, 'native candidate bodies not distinct')
        audit = check_policies(root, report, raw)
        calculated = cost_analysis(report, audit)
        if succeeded:
            recorded = report['analysis']
            require(report['ledger'][-1]['status'] == 'completed' and 'analysis_error' not in report, 'fixed analysis did not complete')
        else:
            require(report['analysis_error'] == {'type': 'KeyError', 'message': "'wall_ns'"}
                    and report['ledger'][-1]['wall_ns'] == 145660, 'original analysis failure/cost lost')
            sidecar = parse(raw[label + '/OFFLINE_ANALYSIS_SIDECAR.json'])
            require(sidecar['original_result']['sha256'] == sha(raw[root + '/RESULT.json'])
                    and sidecar['original_qualified'] is False and sidecar['original_result_modified'] is False
                    and sidecar['new_economic_observations'] == 0, 'sidecar promoted failed run')
            recorded = sidecar['analysis']
        require(all(recorded[key] == value for key, value in calculated.items()), 'independent cost/decision audit differs')
        require(all(recorded[key] is False for key in ('new_native_build_performed',
            'same_model_algorithmic_improvement_established', 'candidate_opportunity_is_NDU_increment',
            'statistical_superiority_established')), 'performance/build scope changed')
        gates = [calculated[key] for key in ('candidate_cold_observed_net_gate', 'ndu_warm_observed_net_gate',
                                            'ndu_build_inclusive_observed_net_gate')]
        require(gates == [False, False, False], 'negative gates changed')
        summaries[label] = {'formal_qualified': succeeded, 'registered_delivery_calls': 3087007744,
            'preparation_differential_calls': 320, 'native_requests': 32, 'same_model_choices': 32,
            'same_model_modeled_regret_ns': 0, 'net_gates': gates,
            'standalone_measured_ns': calculated['standalone_measured_ns'],
            'baseline_only_standalone_ns': calculated['baseline_only_standalone_ns'],
            'native_build_inclusive_ns': calculated['native_build_inclusive_ns'],
            'outer_wall_ns': outer['total_wall_ns_before_receipt_encoding']}
    return {'schema': 'hepta.hia.stb-ndu.offline-verification.v1', 'passed': True,
        'archive_sha256': ARCHIVE_SHA, 'manifest_sha256': MANIFEST_SHA,
        'members_verified': len(raw), 'payload_bytes_verified': manifest['payload_bytes'],
        'runs': summaries, 'original_failed_run_retained': True,
        'code_extracted_or_executed': False, 'SMT_or_native_reexecuted': False,
        'hardware_or_general_performance_proof': False,
        'complete_human_development_cost_known': False,
        'verification_wall_ns_before_encoding': time.monotonic_ns() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.archive, args.manifest)
    if args.output:
        args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
