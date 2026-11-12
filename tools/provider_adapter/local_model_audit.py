#!/usr/bin/env python3
"""Reconcile local service token-ID evidence with immutable study receipts.

This checks ledger consistency, not independent proof that a trusted host ran
particular model weights. Unreceived and unfinished inference stays visible.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

try:
    from .local_model_common import canonical, digest, file_digest, model_identity, regular, validate_lock, verify_assets
    from .local_model_service import service_identity, validate_request, render_prompt
except ImportError:
    from local_model_common import canonical, digest, file_digest, model_identity, regular, validate_lock, verify_assets
    from local_model_service import service_identity, validate_request, render_prompt


def read(path):
    path = regular(path)
    if path.stat().st_size > 64 * 1024**2:
        raise ValueError('E_LOCAL_AUDIT: oversized ledger record')
    return json.loads(path.read_bytes())


def checked_generation(request, response, service):
    identity = request['request_id']
    prefix = {'schema': 'hepta.local_generation.v1', 'service_sha256': service['service_sha256'],
              'model': request['request']['model'], 'request_id': identity,
              'request_sha256': digest(canonical(request['request']))}
    if (any(request.get(k) != value or response.get(k) != value for k, value in prefix.items())
            or request['request'].get('service_sha256') != service['service_sha256']
            or prefix['model'] not in service['models']):
        raise ValueError('E_LOCAL_AUDIT: generation/request identity mismatch')
    usage = response.get('usage')
    if usage is None:
        expected = {'rejected_pre_inference': False, 'inference_failed': True}
        if (response.get('status') not in expected
                or response.get('inference_started') is not expected[response['status']]
                or 'token_ids' in response):
            raise ValueError('E_LOCAL_AUDIT: unaccounted outcome misclassified')
        return None
    fields = {'input_tokens', 'output_tokens', 'total_tokens', 'input_ids_sha256', 'output_ids_sha256',
              'text_sha256', 'model_lock_sha256', 'service_sha256', 'elapsed_ns', 'finish_reason', 'request_sha256'}
    token_ids = response.get('token_ids')
    if (not isinstance(usage, dict) or set(usage) != fields
            or not isinstance(token_ids, dict) or set(token_ids) != {'input', 'output'}
            or any(not isinstance(ids, list) or any(type(v) is not int or not 0 <= v < 2**31 for v in ids)
                   for ids in token_ids.values())
            or not token_ids['input']
            or response.get('inference_started') is not True
            or response.get('status') not in {'completed', 'incomplete'}
            or not isinstance(response.get('text'), str)
            or any(type(usage[k]) is not int or usage[k] < 0
                   for k in ('input_tokens', 'output_tokens', 'total_tokens', 'elapsed_ns'))):
        raise ValueError('E_LOCAL_AUDIT: missing exact token IDs/counters')
    expected = {'input_tokens': len(token_ids['input']), 'output_tokens': len(token_ids['output']),
                'total_tokens': len(token_ids['input']) + len(token_ids['output']),
                'input_ids_sha256': digest(canonical(token_ids['input'])),
                'output_ids_sha256': digest(canonical(token_ids['output'])),
                'text_sha256': digest(response['text'].encode()),
                'model_lock_sha256': prefix['model']['revision'],
                'service_sha256': service['service_sha256'], 'request_sha256': prefix['request_sha256']}
    if (any(usage.get(k) != value for k, value in expected.items())
            or usage['finish_reason'] not in {'eos', 'length', 'deadline'}
            or (response['status'] == 'completed') != (usage['finish_reason'] == 'eos')):
        raise ValueError('E_LOCAL_AUDIT: token IDs/text/usage content drift')
    return usage


def check_tokenizer_response(tokenizer, lock, request, response):
    rendered = render_prompt(tokenizer, request['request']['messages'],
                             lock['generation'].get('prompt_format', 'tokenizer_chat_template'))
    inputs = tokenizer.encode(rendered, add_special_tokens=False)
    outputs = tokenizer.decode(response['token_ids']['output'], skip_special_tokens=True)
    if inputs != response['token_ids']['input'] or outputs != response['text']:
        raise ValueError('E_LOCAL_AUDIT: original tokenizer cannot reconstruct input IDs/output text')


def audit(evidence_dir, reports, *, model_directories=None):
    root = Path(evidence_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('E_LOCAL_AUDIT: regular evidence directory required')
    service = read(root / 'service.json')
    if (not isinstance(service, dict) or service.get('schema') != 'hepta.local_service.v1'
            or not isinstance(service.get('locks'), list) or not service['locks']):
        raise ValueError('E_LOCAL_AUDIT: exact service record required')
    locks = [validate_lock(lock) for lock in service['locks']]
    if (service.get('models') != [model_identity(lock) for lock in locks]
            or service.get('service_sha256') != service_identity(locks, service.get('runtime'))):
        raise ValueError('E_LOCAL_AUDIT: service/model/runtime identity drift')
    tokenizers = {}
    if model_directories is not None:
        if not isinstance(model_directories, list) or len(model_directories) != len(locks):
            raise ValueError('E_LOCAL_AUDIT: pair every model with its frozen asset directory')
        if (service['runtime'].get('engine_source_sha256') != file_digest(Path(__file__).with_name('local_model_service.py'))
                or service['runtime'].get('common_source_sha256') != file_digest(Path(__file__).with_name('local_model_common.py'))):
            raise ValueError('E_LOCAL_AUDIT: use the original frozen rendering/lock implementation')
        from transformers import AutoTokenizer
        for lock, directory in zip(locks, model_directories):
            verify_assets(lock, directory)
            tokenizers[lock['lock_sha256']] = AutoTokenizer.from_pretrained(
                str(directory), local_files_only=True, trust_remote_code=False)
    requests, responses, measured = {}, {}, {}
    for suffix, destination in (('.request.json', requests), ('.response.json', responses)):
        for path in sorted(root.glob('*' + suffix)):
            value = read(path)
            rid = value.get('request_id')
            if (not isinstance(rid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', rid)
                    or path.name != rid + suffix or rid in destination):
                raise ValueError('E_LOCAL_AUDIT: invalid/duplicate request identity')
            destination[rid] = value
    if set(responses) - set(requests):
        raise ValueError('E_LOCAL_AUDIT: response without original request')
    for request in requests.values():
        payload = validate_request(request.get('request'), service['service_sha256'], service['models'])
        if (request.get('schema') != 'hepta.local_generation.v1'
                or request.get('service_sha256') != service['service_sha256']
                or request.get('model') != payload['model']
                or request.get('request_sha256') != digest(canonical(payload))
                or request.get('inference_completed') is not False):
            raise ValueError('E_LOCAL_AUDIT: original request content drift')
    for rid, response in responses.items():
        usage = checked_generation(requests[rid], response, service)
        if usage is not None:
            measured[rid] = usage
            if tokenizers:
                lock = next(v for v in locks if v['lock_sha256'] == usage['model_lock_sha256'])
                check_tokenizer_response(tokenizers[lock['lock_sha256']], lock, requests[rid], response)
    owners, report_tokens = {}, 0
    for report in reports:
        if (not isinstance(report, dict) or report.get('schema') != 'hepta.crossfile_run.v1'
                or report.get('run_kind') != 'provider_adapter_run'
                or digest(canonical({k: v for k, v in report.items() if k != 'record_sha256'}))
                   != report.get('record_sha256')):
            raise ValueError('E_LOCAL_AUDIT: unsealed or non-provider report')
        usage = report.get('usage')
        if usage is None:
            continue
        receipts = usage.get('provider_calls')
        if not isinstance(receipts, list) or not receipts:
            raise ValueError('E_LOCAL_AUDIT: report usage without receipts')
        if any(type(usage.get(k)) is not int for k in ('input_tokens', 'output_tokens', 'total_tokens')):
            raise ValueError('E_LOCAL_AUDIT: invalid cumulative counter types')
        input_count = output_count = 0
        for receipt in receipts:
            rid = receipt.get('request_id')
            if rid not in measured or rid in owners:
                raise ValueError('E_LOCAL_AUDIT: missing/reused generation receipt')
            record = measured[rid]
            messages = requests[rid]['request']['messages']
            try:
                public = json.loads(messages[1]['content'])
                source_identity = digest(canonical({name: digest(source.encode())
                                         for name, source in sorted(public['files'].items())}))
                semantic = {'rust_plain': False, 'rust_semantic': True,
                            'hepta_plain': False, 'hepta_protocol': True}[report['arm']]
                expected_tools = ['read_file', 'check', 'public_test'] + (
                    ['query_nodes', 'replace_nodes'] if semantic else ['replace_files'])
                if (messages[1]['role'] != 'user' or public['task_id'] != report['task_id']
                        or public['language'] != report['language'] or public['budget'] != report['budget']
                        or source_identity != report['base_sha256'] or public['tools'] != expected_tools):
                    raise ValueError()
            except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                raise ValueError('E_LOCAL_AUDIT: receipt prompt belongs to another task/budget') from None
            if (receipt.get('raw_usage') != record or receipt.get('model') != report.get('model')
                    or receipt.get('model') != responses[rid]['model']
                    or receipt.get('input_tokens') != record['input_tokens']
                    or receipt.get('output_tokens') != record['output_tokens']):
                raise ValueError('E_LOCAL_AUDIT: report receipt differs from original generation')
            owners[rid] = report['record_sha256']
            input_count += record['input_tokens']; output_count += record['output_tokens']
        if (usage.get('input_tokens') != input_count or usage.get('output_tokens') != output_count
                or usage.get('total_tokens') != input_count + output_count):
            raise ValueError('E_LOCAL_AUDIT: cumulative report counters differ from receipts')
        report_tokens += input_count + output_count
    pending = sorted(set(requests) - set(responses))
    unknown = sorted(rid for rid, value in responses.items() if value.get('status') == 'inference_failed')
    unreceived = sorted(set(measured) - set(owners))
    result = {'schema': 'hepta.local_evidence_audit.v1', 'status': 'consistent_local_ledger',
              'service_sha256': service['service_sha256'], 'models': service['models'],
              'requests': len(requests), 'responses': len(responses),
              'measured_generations': len(measured), 'matched_report_receipts': len(owners),
              'known_service_input_tokens': sum(v['input_tokens'] for v in measured.values()),
              'known_service_output_tokens': sum(v['output_tokens'] for v in measured.values()),
              'known_service_total_tokens': sum(v['total_tokens'] for v in measured.values()),
              'known_report_total_tokens': report_tokens,
              'known_inference_wall_ns': sum(v['elapsed_ns'] for v in measured.values()),
              'pre_inference_rejections': sum(v.get('status') == 'rejected_pre_inference' for v in responses.values()),
              'pending_request_ids': pending, 'unknown_usage_request_ids': unknown,
              'measured_but_unreceived_request_ids': unreceived,
              'all_service_cost_received_by_reports': not (pending or unknown or unreceived),
              'frozen_tokenizer_reconstruction_verified': bool(tokenizers),
              'claims': {'independent_inference_attestation': False, 'billing_attestation': False,
                         'hepta_productivity_advantage_established': False}}
    return {**result, 'record_sha256': digest(canonical(result))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', required=True)
    parser.add_argument('--reports-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--model-dir', action='append', help='Optional exact assets for each service model, in service order')
    args = parser.parse_args(argv)
    reports = [read(p) for p in sorted(Path(args.reports_dir).glob('*.run.json'))]
    result = audit(args.evidence_dir, reports, model_directories=args.model_dir)
    with Path(args.output).open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'output': str(Path(args.output).resolve()), 'status': result['status'],
                      'matched_report_receipts': result['matched_report_receipts']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
