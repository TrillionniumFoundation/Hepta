"""Qualify exact named-source admission for the native job release members.

The shared fixture separately compiles every source, compares both retained and
ELF-embedded images, reverses source order, and refuses missing, mismatched or
extra roles. This component gate does not assert production job routing.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--seed', type=Path, required=True)
    parser.add_argument('--kit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve(strict=True)))
    from tools.qualify_hia_worker_install_sources import qualify
    report = qualify(
        args.source, args.seed, args.kit, args.output,
        specifications=(
            ('hia-job-launch', 'job_launch', 'job_launch_json', True),
            ('hia-job-observation', 'job_observation', 'job_observation_json', False),
            ('hia-job-entry', 'job_entry', 'sha256_stream', False),
            ('hia-job-cancel', 'job_cancel', 'job_observation_json', True),
            ('hia-job-submit', 'job_submit', ('job_submit_launch', 'job_submit_json'), True),
        ),
        schema='hepta.hia.job-source-qualification.v1',
        scope='NATIVE_JOB_RELEASE_MEMBER_COMPONENTS',
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
