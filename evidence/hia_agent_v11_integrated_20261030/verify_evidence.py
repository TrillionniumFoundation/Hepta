#!/usr/bin/env python3
"""Bounded offline integrity/consistency review; never extract or execute archive data."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_MANIFEST = 8 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_CAPTURE = 128 * 1024 * 1024
PREFIX = 'p7-v11-20261030/'
SOURCE = '50c4067399989e7194028576c38c0e783b78cf06'
MODEL_SHA = '00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4'
MODEL_BYTES = 2740937888
HASH = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_file(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_name(name):
    require(type(name) is str and name.startswith(PREFIX) and '\\' not in name and '\x00' not in name,
            'invalid member name/prefix')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(part not in ('', '.', '..') for part in path.parts),
            'noncanonical or traversing member path')
    require(not name.endswith('.gguf'), 'model weights must not be bundled')


def verify(archive, manifest_path, archive_sha, manifest_sha):
    require(HASH.fullmatch(archive_sha) and HASH.fullmatch(manifest_sha), 'external hashes must be SHA256')
    require(manifest_path.stat().st_size <= MAX_MANIFEST, 'manifest size limit')
    require(archive.stat().st_size <= MAX_TOTAL, 'compressed archive size limit')
    require(digest_file(manifest_path) == manifest_sha, 'external manifest hash mismatch')
    require(digest_file(archive) == archive_sha, 'external archive hash mismatch')
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get('schema') == 'hepta.p7.evidence-manifest.v1', 'manifest schema')
    rows = manifest.get('entries')
    require(type(rows) is list and 0 < len(rows) <= MAX_MEMBERS, 'member count bound')
    expected = {}
    for row in rows:
        name, size, sha = row['name'], row['bytes'], row['sha256']
        safe_name(name)
        require(name not in expected and type(size) is int and 0 <= size <= MAX_FILE
                and type(sha) is str and HASH.fullmatch(sha), 'duplicate or invalid manifest entry')
        expected[name] = row
    require(sum(row['bytes'] for row in rows) <= MAX_TOTAL, 'total expanded byte bound')
    seen, captured, total, captured_bytes = set(), {}, 0, 0
    with tarfile.open(archive, mode='r|xz') as bundle:
        for member in bundle:
            safe_name(member.name)
            require(member.isfile() and not member.issym() and not member.islnk(), 'only regular files are permitted')
            require(member.name in expected and member.name not in seen, 'unexpected or duplicate member')
            row = expected[member.name]
            require(member.size == row['bytes'] and member.size <= MAX_FILE, 'member size mismatch')
            seen.add(member.name)
            total += member.size
            require(len(seen) <= MAX_MEMBERS and total <= MAX_TOTAL, 'expanded archive bound')
            capture = ('/source_snapshot/' not in member.name and
                       member.name.endswith(('.json', '.sse', '.stderr', '.stdout')))
            chunks, size, sha = [], 0, hashlib.sha256()
            with bundle.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    size += len(block)
                    require(size <= member.size, 'overlong member payload')
                    sha.update(block)
                    if capture:
                        captured_bytes += len(block)
                        require(captured_bytes <= MAX_CAPTURE, 'semantic capture memory bound')
                        chunks.append(block)
            require(size == row['bytes'] and sha.hexdigest() == row['sha256'], 'member bytes/hash mismatch')
            if capture:
                captured[member.name] = b''.join(chunks)
    require(seen == set(expected), 'manifest member denominator differs from archive')

    def data(relative):
        return json.loads(captured[PREFIX + relative])

    def text(relative):
        return captured[PREFIX + relative].decode()

    fresh = 'fresh/'
    summary = data(fresh + 'SUMMARY.json')
    capacity = data(fresh + 'capacity/CAPACITY.json')
    calibration = data(fresh + 'calibration/RESULT.json')
    capacity_exec = data(fresh + 'operations/CAPACITY_EXECUTION.json')
    calibration_exec = data(fresh + 'operations/CALIBRATION_EXECUTION.json')
    main_exec = data(fresh + 'operations/MAIN_EXECUTION.json')
    restore = data(fresh + 'operations/RESTORATION_ACQUISITION.json')
    cleanup = data(fresh + 'operations/CLEANUP.json')
    for execution in (capacity_exec, calibration_exec, main_exec):
        require(execution['source_commit'] == execution['source_commit_after'] == SOURCE
                and execution['source_clean_before'] is True and execution['source_clean_after'] is True,
                'stage source identity differs')
        require(type(execution['outer_wall_ns']) is int and execution['outer_wall_ns'] > 0, 'missing measured stage cost')
        require(execution['execution_attempt'] == 1 and execution['task_or_generation_parameters_modified'] is False,
                'execution/retry scope differs')
    require(cleanup['status'] == 'completed' and cleanup['source_unchanged'] and cleanup['protected_unchanged'],
            'cleanup identity preservation differs')
    require(restore['status'] == 'restored_exact_same_bytes' and restore['attempts'] == 1
            and restore['retry_enabled'] is False and restore['curl_returncode'] == 0
            and restore['verified_file']['bytes'] == MODEL_BYTES
            and restore['verified_file']['sha256'] == MODEL_SHA, 'restored model identity/attempt differs')
    require(capacity['complete'] is True and capacity_exec['returncode'] == 0
            and capacity['model_requests'] == 0 and len(capacity['rows']) == 19
            and all(row['passed'] is True and row['reference_is_model_answer'] is False for row in capacity['rows']),
            'capacity denominator or controls differ')
    cli = capacity['independent_cli_tokenizer']
    require(cli['calls'] == 95 and cli['all_matched'] is True and len(cli['retained_call_records']) == 95,
            'CLI tokenizer control denominator differs')
    for call in cli['retained_call_records']:
        relative = 'fresh/' + call['receipt_path'].split('/p7-v11-integrated-50c40673/', 1)[1]
        require(data(relative) == call and call['matched'] is True and call['returncode'] == 0
                and call['cli_token_ids'] == call['server_token_ids'], 'retained tokenizer call mismatch')
    require(sum(row['rendered_request_cli_checks'] for row in capacity['rows']) == 76, 'rendered request denominator')
    for report, phase in ((capacity, 'capacity'), (calibration, 'calibration')):
        require(report['source_commit'] == SOURCE and report['model']['sha256'] == MODEL_SHA
                and report['model']['bytes'] == MODEL_BYTES, 'report source/model pin differs')
        require(all(report[key] is True for key in ('source_unchanged', 'tools_unchanged', 'model_unchanged')),
                'final tool/source/model identity failed')
        for name, sha in report['source_bindings'].items():
            member = PREFIX + fresh + phase + '/source_snapshot/' + name
            require(member in expected and expected[member]['sha256'] == sha, 'source snapshot binding mismatch')
    require(capacity['tools'] == calibration['tools'] and capacity['source_bindings'] == calibration['source_bindings'],
            'calibration inherited different source/tools')
    cells = calibration['cells']
    require(len(cells) == 3 and calibration['status'] == 'all_cells_attempted'
            and calibration['valid_observation'] is True, 'fresh qualification was not completed')
    require(calibration['calibration_eligible'] is False and not all(cell['correct'] for cell in cells),
            'this bundle must retain the failed fresh qualification')
    attempts = [attempt for cell in cells for attempt in cell['attempts']]
    require(all(0 < len(cell['attempts']) <= 3 for cell in cells), 'attempt budget differs')
    require(calibration['complete_usage'] is True and all(type(a.get('usage')) is dict for a in attempts),
            'complete token accounting is required by this observed bundle')
    totals = {key: sum(a['usage'][key] for a in attempts) for key in ('input_tokens', 'output_tokens', 'total_tokens')}
    aggregate_keys = {'input_tokens': 'known_input_tokens', 'output_tokens': 'known_output_tokens', 'total_tokens': 'total_tokens'}
    require(all(calibration[aggregate_keys[key]] == value for key, value in totals.items()), 'aggregate token totals differ')
    usage_names = sorted(name for name in captured if name.startswith(PREFIX + fresh + 'calibration/engine-')
                         and re.search(r'/transport-[0-9]+\.usage\.json\Z', name))
    require(len(usage_names) == calibration['requests'] == calibration['responses'] == len(attempts),
            'raw generation count differs')
    raw_totals = dict(input_tokens=0, output_tokens=0, total_tokens=0)
    for name in usage_names:
        usage = json.loads(captured[name])
        stem = name.removesuffix('.usage.json')
        request = json.loads(captured[stem + '.request.json'])
        payload = request['payload']
        require(payload['n_predict'] == 1536 and payload['temperature'] == 0 and payload['seed'] == 0
                and payload['cache_prompt'] is False and payload['stream'] is True, 'generation budget/settings differ')
        raw = captured[stem + '.response.sse']
        events = [json.loads(line[5:].strip()) for line in raw.decode().splitlines() if line.startswith('data:')]
        require(events and events[-1].get('stop') is True and sum(e.get('stop') is True for e in events) == 1,
                'SSE final event missing or duplicated')
        tokens = [token for event in events for token in event.get('tokens', [])]
        final = events[-1]
        require(usage['complete'] is True and usage['unknown_output_tokens'] is False
                and usage['observed_output_token_ids'] == tokens
                and usage['response_bytes'] == len(raw) and usage['events'] == len(events)
                and usage['input_tokens'] == len(payload['prompt']) == final['tokens_evaluated']
                and usage['output_tokens'] == len(tokens) == final['tokens_predicted']
                and usage['total_tokens'] == usage['input_tokens'] + usage['output_tokens'], 'raw SSE/usage accounting differs')
        for key in raw_totals:
            raw_totals[key] += usage[key]
    require(raw_totals == totals, 'SSE totals disagree with attempt totals')
    require(main_exec['returncode'] != 0 and main_exec['stage'] == 'main'
            and 'validate_qualification' in text(fresh + 'operations/main.stderr'), 'actual main qualification refusal missing')
    require(not any(name.startswith(PREFIX + fresh + 'main/') for name in expected), 'unexpected main-stage artifacts')
    require(summary['main']['attempted_cells'] == 0 and summary['main']['generation_requests'] == 0
            and summary['main']['startup_refused'] is True, 'main scope was overstated')
    require(summary['historical_results_reused_as_fresh'] is False, 'historical qualification was inherited')
    return {'schema': 'hepta.p7.offline-verification.v1', 'passed': True,
            'archive_sha256': archive_sha, 'manifest_sha256': manifest_sha,
            'members_verified': len(seen), 'uncompressed_bytes_verified': total,
            'source_commit': SOURCE, 'capacity_rows': 19, 'independent_tokenizer_calls': 95,
            'rendered_request_checks': 76, 'fresh_qualification_tasks': len(cells),
            'fresh_qualification_correct': sum(cell['correct'] for cell in cells),
            'generation_requests': calibration['requests'], 'usage_totals_recomputed_from_sse': raw_totals,
            'main_cells': 0, 'main_startup_refusal_observed': True,
            'archive_extracted': False, 'archive_code_executed': False, 'network_used': False,
            'scope': 'Integrity and internal consistency of retained evidence; no independent inference/compiler re-execution or cryptographic attestation of past execution.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'refuse to overwrite verification report')
    result = verify(args.archive, args.manifest, args.archive_sha256, args.manifest_sha256)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
