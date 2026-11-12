"""Materialize one pinned, offline Emitter authoring request and exec its guardian."""
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import zlib

ROOT = Path('/home/qian-qi/he26coreemitter-authoring-r2')
REQUEST_SHA = '011c137e305a473c89d1e24ff35edcd97404fca9b48fd5159cc215778594dca7'
REQUEST_BYTES = 999074
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'
CONTROL_SHAS = {
    'guardian.py': 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'process_owner_impl.py': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'authoring.py': '01522f30bb5ada62e593c2dd4fbb982b493238545162339be13d6a49b7a457e7',
}
INPUT_RAW_SIZE = 2625127
INPUT_RAW_SHA = '31d6ad1cd0b1a4068b59237b7c33c6ba152cdf09382545ccfa4c3d2203fbf29c'
INPUT_GZIP_SIZE = 707760
INPUT_GZIP_SHA = 'a58fc4dc08caaef3781ec2a61a051822054e5541ef80ad640545867a02873f6e'

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(raw):
    return sha256(raw).hexdigest()

def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)

def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def original_regular(path):
    initial = path.lstat()
    require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1, 'nonregular original interpreter')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(signature(os.fstat(descriptor)) == signature(initial), 'interpreter changed before read')
        chunks, remaining = [], initial.st_size + 1
        while remaining:
            data = os.read(descriptor, min(1048576, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        raw = b''.join(chunks)
        require(len(raw) == initial.st_size and signature(os.fstat(descriptor)) == signature(initial)
                and signature(path.lstat()) == signature(initial), 'interpreter changed while read')
        return raw
    finally:
        os.close(descriptor)

raw = sys.stdin.buffer.read(1048577)
require(len(raw) == REQUEST_BYTES and digest(raw) == REQUEST_SHA, 'frozen request differs')
request = json.loads(raw)
require(request['schema'] == 'hia.core-emitter-remote-authoring-request.v1'
        and request['root'] == str(ROOT)
        and request['candidate_commit'] == '80ec04ae7489209b122c874531d194c67b30dfed'
        and request['candidate_tree'] == '963e980c2486e1f7c74fa42bc8132ef6b1b8b690'
        and request['scope'] == {'source_only': True, 'owner_seconds': 180, 'cleanup_seconds': 3,
                                'h_seconds': 240, 'native_compiler': False,
                                'product_tests': False, 'cold': False,
                                'old_v1_results_inherited': False},
        'authoring request interface differs')
# Reject inherited VCS/loader redirection before creating the new root.
# This does not claim to undo loader activity before Python started.
require(not any(value for name, value in os.environ.items()
                if name.startswith(('GIT_', 'LD_'))),
        'nonempty ambient Git or loader variables are outside the source-only profile')
actual_python = Path(sys.executable).resolve(strict=True)
require(sys.version_info[:3] == (3, 14, 4)
        and digest(original_regular(actual_python)) == PYTHON_SHA, 'original Python identity differs')
require(set(request['controls']) == set(CONTROL_SHAS), 'control inventory differs')
controls = {}
for name, expected in CONTROL_SHAS.items():
    row = request['controls'][name]
    value = row['content'].encode('utf-8')
    require(len(value) == row['size'] and digest(value) == row['sha256'] == expected,
            'pinned control bytes differ: ' + name)
    controls[name] = value
transport = request['source_transport']
require(transport['encoding'] == 'gzip-base64'
        and transport['raw_size'] == INPUT_RAW_SIZE and transport['raw_sha256'] == INPUT_RAW_SHA
        and transport['gzip_size'] == INPUT_GZIP_SIZE and transport['gzip_sha256'] == INPUT_GZIP_SHA,
        'source transport profile differs')
compressed = base64.b64decode(transport['content'], validate=True)
require(len(compressed) == INPUT_GZIP_SIZE and digest(compressed) == INPUT_GZIP_SHA,
        'compressed source transport identity differs')
decoder = zlib.decompressobj(wbits=31)
expanded = decoder.decompress(compressed, INPUT_RAW_SIZE + 1)
require(len(expanded) == INPUT_RAW_SIZE and decoder.eof and not decoder.unconsumed_tail
        and not decoder.unused_data and digest(expanded) == INPUT_RAW_SHA,
        'bounded source transport decode differs')
inputs = json.loads(expanded)
require(inputs['schema'] == 'hia.core-emitter-authoring-source-inputs.v1'
        and inputs['canonical_candidate'] == request['candidate_commit']
        and inputs['candidate_tree'] == request['candidate_tree']
        and inputs['candidate_leaf_count'] == 4023 and len(inputs['delta']) == 67,
        'expanded complete source interface differs')
os.umask(0o077)
ROOT.mkdir(mode=0o700)
control, guard = ROOT / 'control', ROOT / 'guard'
control.mkdir(mode=0o700)
guard.mkdir(mode=0o700)
identities = {str(actual_python): PYTHON_SHA}
for name, value in controls.items():
    destination = control / name
    create(destination, value)
    identities[str(destination)] = digest(value)
for name, value in (('launch-payload.original.json', raw), ('SOURCE-INPUTS.json', expanded),
                    ('source-inputs.json.gz', compressed)):
    destination = control / name
    create(destination, value)
    identities[str(destination)] = digest(value)
for name in tuple(os.environ):
    if name.startswith('HEPTA_HIA_') or name == 'PYTHONPATH':
        del os.environ[name]
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['PYTHONUNBUFFERED'] = '1'
configuration = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                 'command': [sys.executable, '-B', str(control / 'authoring.py'), '--root', str(ROOT)],
                 'cwd': str(ROOT), 'source_identities': identities}
configuration_raw = (json.dumps(configuration, sort_keys=True, indent=2) + '\n').encode()
configuration_path = guard / 'request.json'
create(configuration_path, configuration_raw)
print(json.dumps({'stage': 'CORE_EMITTER_AUTHORING_GUARDIAN_ONLY', 'root': str(ROOT),
                  'request_sha256': REQUEST_SHA, 'source_candidate': request['candidate_commit'],
                  'configuration_sha256': digest(configuration_raw),
                  'native_execution_requested': False}), flush=True)
os.execv(sys.executable, [sys.executable, '-B', str(control / 'guardian.py'),
         '--config', str(configuration_path), '--config-sha256', digest(configuration_raw),
         '--implementation', str(control / 'process_owner_impl.py')])
