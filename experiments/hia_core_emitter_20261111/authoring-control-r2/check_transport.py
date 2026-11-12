"""Local syntax and standard-library transport check; do not execute authoring."""
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import sys
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parent
REQUEST_SHA = '011c137e305a473c89d1e24ff35edcd97404fca9b48fd5159cc215778594dca7'
BOOTSTRAP_SHA = 'cac71af96d1d0d0814220e561eeeb3ad540061a3c59cc35f987a3e4d3d3bbef6'
started = time.monotonic()
report = {'schema': 'hia.core-emitter-authoring-transport-check.v1', 'status': 'HOLD',
          'scope': 'ACTUAL_INTERPRETER_SYNTAX_AND_GZIP_TRANSPORT_ONLY',
          'remote_authoring_executed': False, 'project_imported': False,
          'HIA_generated': False, 'native_or_cold_executed': False,
          'python': sys.version, 'executable': sys.executable}
def require(value, message):
    if not value:
        raise AssertionError(message)
def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
try:
    raw = (ROOT / 'request.json').read_bytes()
    require(len(raw) == 999074 and sha256(raw).hexdigest() == REQUEST_SHA, 'request differs')
    bootstrap = (ROOT / 'bootstrap.py').read_bytes()
    require(sha256(bootstrap).hexdigest() == BOOTSTRAP_SHA, 'bootstrap differs')
    compile(bootstrap, 'bootstrap.py', 'exec')
    request = json.loads(raw)
    observed = {}
    for name, row in request['controls'].items():
        source = row['content'].encode()
        require(len(source) == row['size'] and sha256(source).hexdigest() == row['sha256'],
                'control source differs')
        compile(source, name, 'exec')
        observed[name] = {'size': len(source), 'sha256': sha256(source).hexdigest()}
    transport = request['source_transport']
    compressed = base64.b64decode(transport['content'], validate=True)
    require(len(compressed) == transport['gzip_size']
            and sha256(compressed).hexdigest() == transport['gzip_sha256'],
            'gzip input differs')
    decoder = zlib.decompressobj(wbits=31)
    expanded = decoder.decompress(compressed, transport['raw_size'] + 1)
    require(len(expanded) == transport['raw_size'] and decoder.eof
            and not decoder.unused_data and not decoder.unconsumed_tail
            and sha256(expanded).hexdigest() == transport['raw_sha256'],
            'independent Python gzip decode differs')
    inputs = json.loads(expanded)
    require(inputs['canonical_candidate'] == request['candidate_commit']
            and inputs['candidate_tree'] == request['candidate_tree']
            and len(inputs['delta']) == 67, 'source mapping differs')
    seen = set()
    for row in inputs['delta']:
        path = Path(row['path'])
        require(not path.is_absolute() and '..' not in path.parts and str(path) == row['path']
                and row['path'] not in seen and path.parts[0] != '.git', 'source path differs')
        seen.add(row['path'])
        value = row['content'].encode('utf-8')
        require(len(value) == row['size'] and sha256(value).hexdigest() == row['sha256']
                and blob(value) == row['git_blob_sha1'], 'source bytes differ')
    report.update(status='CONTROL_SYNTAX_AND_TRANSPORT_PASS', controls=observed,
                  bootstrap_sha256=BOOTSTRAP_SHA, request_sha256=REQUEST_SHA,
                  gzip_size=len(compressed), gzip_sha256=sha256(compressed).hexdigest(),
                  expanded_size=len(expanded), expanded_sha256=sha256(expanded).hexdigest(),
                  source_members=len(seen), source_bytes=sum(row['size'] for row in inputs['delta']),
                  candidate_commit=inputs['canonical_candidate'], candidate_tree=inputs['candidate_tree'])
except BaseException:
    report['error'] = traceback.format_exc()
finally:
    report['seconds'] = time.monotonic() - started
    with (ROOT / 'transport-check.json').open('xb') as stream:
        stream.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps(report, sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'CONTROL_SYNTAX_AND_TRANSPORT_PASS' else 1)
