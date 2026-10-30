"""Retain one evidence-tool invocation, output and cost without touching experiments."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or not args.name.replace('-', '').replace('_', '').isalnum():
        raise ValueError('exact operation name and argv required')
    here = Path(__file__).resolve().parent
    out = here / ('operation-' + args.name)
    out.mkdir()
    argv = args.command[1:] if args.command[0] == '--' else args.command
    start = time.monotonic_ns()
    receipt = {'schema': 'hepta.p7.evidence-tool-execution.v1',
               'argv': argv, 'cwd': str(here),
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'returncode': None, 'wall_ns': None,
               'experiment_rerun': False, 'source_or_protocol_modified': False}
    try:
        proc = subprocess.run(argv, cwd=here, capture_output=True, timeout=180)
        receipt['returncode'] = proc.returncode
        for name, raw in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            (out / name).write_bytes(raw)
            receipt[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    except BaseException as exc:
        receipt['error'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        receipt['wall_ns'] = time.monotonic_ns() - start
        (out / 'EXECUTION.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        print(json.dumps(receipt, sort_keys=True))
    return receipt['returncode']


if __name__ == '__main__':
    raise SystemExit(main())
