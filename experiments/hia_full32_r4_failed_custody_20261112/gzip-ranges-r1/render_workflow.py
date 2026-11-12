"""Render reviewed transport YAML only after official artifact pins are frozen.

This authoring utility never calls GitHub, changes a ref, launches an owner, or
opens an artifact. The current draft policy is deliberately rejected.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import os
import re


PREFIX = 'experiments/hia_full32_r4_failed_custody_20261112/gzip-ranges-r1'
EXPECTED_LIMITS = {
    'controller_seconds': 900, 'cleanup_seconds': 3, 'transfer_seconds': 720,
    'maximum_original_bytes': 3 << 30, 'maximum_parts': 10,
    'part_bytes': 312 << 20, 'public_part_bytes': 320 << 20,
    'diagnostic_bytes_per_part': 2 << 20, 'document_bytes_per_part': 3 << 20,
    'private_metadata_reserve_bytes': 64 << 20,
    'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
    'compressed_part_bytes': 313 << 20,
    'small_original_bytes': 160 << 20, 'small_derived_bytes': 32 << 20,
    'small_public_bytes': 224 << 20, 'inner_stream_bytes': 16 << 30, 'outer_stream_bytes': 4 << 30,
}
UPLOAD = '''      - name: Preserve original ZIP range ORDINAL_PLACEHOLDER and complete small controls
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: hia-full32-r4-original-gzip-part-ORDINAL_PLACEHOLDER-${{ github.run_id }}-1
          path: '${{ runner.temp }}/hia-full32-r4-gzip-originals-public-r1/part-ORDINAL_PLACEHOLDER/'
          if-no-files-found: error
          include-hidden-files: false
          compression-level: 0
          retention-days: 14
          overwrite: false
'''


def require(value, message):
    if not value:
        raise ValueError(message)


def render(policy_raw, directory, template, control_commit):
    policy = json.loads(policy_raw)
    require(policy.get('status') == 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
            and policy.get('input_pins_frozen') is True,
            'actual official metadata is pending; no executable workflow can be rendered')
    require(policy.get('schema') == 'hia.actions.failed-full32-gzip-parts-policy.v1'
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
    parts = []
    offset = 0
    while offset < pin['bytes']:
        count = min(312 << 20, pin['bytes'] - offset)
        parts.append({'ordinal': len(parts), 'offset': offset, 'bytes': count,
                      'name': 'part-%02d.bin.gz' % len(parts)})
        offset += count
    require(1 <= len(parts) <= 10 and policy.get('parts') == parts
            and all(type(row.get(k)) is int for row in policy['parts']
                    for k in ('ordinal', 'offset', 'bytes')),
            'the complete deterministic partition must be frozen')
    require(set(policy.get('control_files', {})) == {
        'controller.py', 'worker.py', 'guardian.py', 'original_receiver.py', 'process_owner_impl.py', 'gzip_evidence.py'},
        'six exact control files are required')
    for name, expected in policy['control_files'].items():
        raw = (directory / name).read_bytes()
        require(len(raw) == expected['bytes'] and sha256(raw).hexdigest() == expected['sha256'],
                'actual control bytes do not match the frozen policy')
    require(template.count('CONTROL_COMMIT_PLACEHOLDER') == 4
            and template.count('POLICY_SHA256_PLACEHOLDER') == 3
            and template.count('UPLOAD_STEPS_PENDING_ACTUAL_COUNT') == 1,
            'fixed authoring template substitutions differ')
    text = template.replace('CONTROL_COMMIT_PLACEHOLDER', control_commit)
    text = text.replace('POLICY_SHA256_PLACEHOLDER', sha256(policy_raw).hexdigest())
    uploads = ''.join(UPLOAD.replace('ORDINAL_PLACEHOLDER', '%02d' % row['ordinal']) for row in parts)
    text = text.replace('UPLOAD_STEPS_PENDING_ACTUAL_COUNT\n', uploads)
    require('PLACEHOLDER' not in text and 'PENDING_ACTUAL' not in text,
            'a workflow placeholder remains')
    return text.encode(), parts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--control-commit', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    raw = args.policy.read_bytes()
    template = (args.policy.parent / 'workflow-template.yml').read_text()
    output, parts = render(raw, args.policy.parent, template, args.control_commit)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(output)
        stream.flush()
        os.fsync(stream.fileno())
    require(args.output.read_bytes() == output, 'new workflow authoring readback differs')
    print(json.dumps({'status': 'WORKFLOW_TEXT_CREATED_NOT_DISPATCHED', 'parts': len(parts),
                      'bytes': len(output), 'sha256': sha256(output).hexdigest(),
                      'policy_sha256': sha256(raw).hexdigest(), 'control_commit': args.control_commit,
                      'artifact_id': json.loads(raw)['artifact']['id'], 'triggered': False}, sort_keys=True))


if __name__ == '__main__':
    main()
