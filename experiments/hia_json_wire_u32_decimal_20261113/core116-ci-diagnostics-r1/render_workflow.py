"""Render reviewed transport YAML only after official artifact pins are frozen.

This authoring utility never calls GitHub, changes a ref, launches an owner, or
opens an artifact. Only the exact frozen diagnostic control policy can be rendered.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import re


PREFIX = 'experiments/hia_json_wire_u32_decimal_20261113/core116-ci-diagnostics-r1'
EXPECTED_LIMITS = {
    'controller_seconds': 900, 'cleanup_seconds': 3, 'transfer_seconds': 720,
    'maximum_original_bytes': 3 << 30, 'maximum_parts': 10,
    'part_bytes': 256 << 20, 'public_part_bytes': 320 << 20,
    'diagnostic_bytes_per_part': 2 << 20, 'document_bytes_per_part': 3 << 20,
    'private_metadata_reserve_bytes': 64 << 20,
    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
}



def require(value, message):
    if not value:
        raise ValueError(message)


def render(policy_raw, directory, template, control_commit):
    policy = json.loads(policy_raw)
    require(policy.get('status') == 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
            and policy.get('input_pins_frozen') is True,
            'actual official metadata is pending; no executable workflow can be rendered')
    require(policy.get('schema') == 'hia.actions.v92-ci-diagnostics-only-policy.v2'
            and policy.get('repository') == 'TrillionniumFoundation/Hepta'
            and policy.get('control_prefix') == PREFIX
            and policy.get('limits') == EXPECTED_LIMITS,
            'fixed transport policy differs')
    require(type(control_commit) is str and re.fullmatch('[0-9a-f]{40}', control_commit),
            'the read-back control commit is required')
    pin = policy['artifact']
    require(type(pin) is dict
            and all(type(pin.get(k)) is int and pin[k] > 0 for k in ('id', 'run_id', 'job_id'))
            and type(pin.get('run_attempt')) is int and pin['run_attempt'] == 1
            and type(pin.get('bytes')) is int and 0 < pin['bytes'] <= 3 << 30
            and type(pin.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256'])
            and all(type(pin.get(k)) is str and re.fullmatch('[0-9a-f]{40}', pin[k])
                    for k in ('checkout_commit', 'checkout_tree'))
            and pin.get('workflow_terminal') in ('success', 'failure', 'cancelled', 'timed_out'),
            'a completed official artifact identity is required')
    require(policy.get('parts') == [] and policy.get('partition_files_created') is False,
            'diagnostics-only request must not produce original ZIP partitions')
    require(set(policy.get('control_files', {})) == {
        'controller.py', 'worker.py', 'guardian.py', 'original_receiver.py', 'process_owner_impl.py', 'diagnostics.py'},
        'six exact control files are required')
    for name, expected in policy['control_files'].items():
        raw = (directory / name).read_bytes()
        require(len(raw) == expected['bytes'] and sha256(raw).hexdigest() == expected['sha256'],
                'actual control bytes do not match the frozen policy')
    require(template.count('CONTROL_COMMIT_PLACEHOLDER') == 4
            and template.count('POLICY_SHA256_PLACEHOLDER') == 3
            and 'UPLOAD_STEPS_PENDING_ACTUAL_COUNT' not in template,
            'fixed authoring template substitutions differ')
    text = template.replace('CONTROL_COMMIT_PLACEHOLDER', control_commit)
    text = text.replace('POLICY_SHA256_PLACEHOLDER', sha256(policy_raw).hexdigest())
    require('PLACEHOLDER' not in text and 'PENDING_ACTUAL' not in text,
            'a workflow placeholder remains')
    return text.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--control-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raw = args.policy.read_bytes()
    template = (args.policy.parent / 'workflow-template.yml').read_text()
    output = render(raw, args.policy.parent, template, args.control_commit)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    require(args.output.read_bytes() == output, 'new workflow authoring readback differs')
    print(json.dumps({'status': 'WORKFLOW_TEXT_CREATED_NOT_DISPATCHED', 'partition_files_created': False,
                      'bytes': len(output), 'sha256': sha256(output).hexdigest(),
                      'policy_sha256': sha256(raw).hexdigest(), 'control_commit': args.control_commit,
                      'artifact_id': json.loads(raw)['artifact']['id'], 'triggered': False}, sort_keys=True))


if __name__ == '__main__':
    main()
