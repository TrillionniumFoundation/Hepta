"""Check the terminal renderer through the installed, independent ELF."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys

from hepta.hia_agent_contract import VERSION


LIMIT = 8 << 20
CATALOG, BACKEND, WORKER, HELPERS = (digit * 64 for digit in '2345')


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def frame(request, response, *, catalog=CATALOG, backend=BACKEND,
          helpers=None, digits=4300, flags=None):
    if flags is None:
        flags = int(helpers is not None)
    pins = (catalog + backend + WORKER + (helpers or '\0' * 64)).encode()
    return (struct.pack('<8s4Q', b'HIATRP01', len(request), len(response), digits, flags)
            + pins + request + response)


def check(executable: Path):
    def run(packet, status, expected=b'', *, extra_args=()):
        result = subprocess.run([executable, *extra_args], input=packet, env={'PATH': ''},
                                capture_output=True, timeout=30, check=False)
        actual = (result.returncode, result.stdout, result.stderr)
        if actual != (status, expected, b''):
            raise AssertionError((actual[0], actual[1][:400], actual[2], status, expected[:400]))

    request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_describe',
               'arguments': {'e': -0.0, 'χ': '𐐷'}, 'profile_sha256': '1' * 64,
               'catalog_sha256': CATALOG}
    request['request_sha256'] = sha256(wire(request)).hexdigest()
    raw = json.dumps(request).encode().replace(b'"request_sha256"', b'"request_\\u0073ha256"')
    complete = {'status': 'completed', 'result': {'z': -0.0, 'a': [1e22, '葡萄']},
                'contract_version': VERSION, 'request_id': 'native-1'}
    reject = {'status': 'rejected', 'error': {'code': 'E_HIA_REQUEST_CONFLICT'},
              'contract_version': VERSION, 'request_id': 'native-2'}
    report = {'schema': 'hia-agent-worker-report-v1', 'complete': True,
              'backend_sha256': BACKEND, 'worker_sha256': WORKER,
              **{key: request[key] for key in ('tool', 'profile_sha256',
                                              'catalog_sha256', 'request_sha256')}}
    for response in (complete, reject):
        body = json.dumps(response, ensure_ascii=True).encode()
        for helpers in (None, HELPERS):
            output = dict(report, response=response)
            if helpers:
                output['native_helpers_sha256'] = helpers
            run(frame(raw, body, helpers=helpers), 0, wire(output) + b'\n')

    body = wire(complete)
    for bad in (b'null', b'{', b'{"status":"completed",' + body[1:],
                wire(dict(complete, extra=True)), wire(dict(complete, result=[])),
                wire(dict(complete, request_id='')), wire(dict(complete, status='running')),
                wire(dict(complete, contract_version='other')), wire(dict(reject, status='completed'))):
        run(frame(raw, bad), 2)
    run(frame(raw, body, catalog='8' * 64), 2)
    run(frame(raw, body, backend='G' * 64), 2)
    run(frame(wire(dict(request, request_sha256='0' * 64)), body), 2)
    run(frame(raw, body, flags=1), 2)
    run(frame(raw, body, helpers=HELPERS, flags=0), 64)
    run(frame(raw, body, flags=2), 64)
    run(frame(raw, body, digits=639), 64)
    packet = frame(raw, body)
    for truncated in (packet[:295], packet[:300], packet[:-1], packet + b'\x00'):
        run(truncated, 64)
    run(packet, 64, extra_args=('unexpected',))
    oversized_header = packet[:16] + struct.pack('<Q', LIMIT + 1) + packet[24:296]
    run(oversized_header, 3)
    # The canonical body alone fits; its authenticated full report does not.
    big = wire(dict(complete, result={'a': ''}))
    big = big.replace(b'""', b'"' + b'a' * (LIMIT - len(big)) + b'"', 1)
    run(frame(raw, big), 3)
    print('installed worker terminal: completed and rejected reports byte-exact; malformed and over-budget inputs emit nothing')


if __name__ == '__main__':
    check(Path(sys.argv[1]))
