"""Actual fresh-wheel worker evidence for the explicit v4 artifact capsule."""
from contextlib import closing, ExitStack
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import base64
import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import patch
import zipfile
from .hia_artifact_delivery_fixture import ROOT, encoded, clean_environment

WORKER = r'''
import importlib.abc,json,os,sys
from hashlib import sha256
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.') or name=='tests' or name.startswith('tests.'):
            raise AssertionError('installed D5 worker imported authoring/tests')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_store as store, hia_agent_service as api
from hepta import hia_store_artifact_profile_native as native
from hepta import hia_service_context_native as context, hia_agent_journal_native as journal
from hepta import artifact_publication_native as provider, hia_artifact_delivery as bridge
from hepta import hia_native_delivery as delivery
from hepta.hia_agent_worker import main
for module in (provider,bridge,delivery,native,context,journal):
    assert Path(module.__file__).resolve().is_relative_to(Path(installed).resolve()/'hepta')
counts={'startup':{'store':0,'context':0,'journal':0,'provider':0},
        'request':{'store':0,'context':0,'journal':0,'provider':0},
        'cleanup':{'store':0,'context':0,'journal':0,'provider':0},
        'provider_operations':[],'durable_puts':0,'lost_ack':0,'peer_losses':0,
        'swallowed':0,'close_attempts':0,'actual_db_close':0,
        'natural_admissions':{'startup':0,'request':0,'cleanup':0},
        'observer_extra_admissions':0}
phase='startup';armed=False;reported=False
def forbidden(*a,**k):raise AssertionError('installed D5 selected owner used retained policy')
for name in ('_put_reference','_json_reference','_ref_reference','_get_reference',
             '_get_json_reference','_resolve_uri_reference','_profile_reference','_check_profile_reference'):
    setattr(store.AgentStore,name,forbidden)
for name in tuple(store._STORE_ARTIFACT_PROFILE_REFERENCES):store._STORE_ARTIFACT_PROFILE_REFERENCES[name]=forbidden
api.HIAAgentService._reference_call=forbidden
api.HIAAgentService._context_reference=forbidden
api._NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE=forbidden
actual_call=api.HIAAgentService.call
def request_call(self,*args,**kwargs):
    global phase
    phase='request'
    try:return actual_call(self,*args,**kwargs)
    finally:phase='cleanup'
api.HIAAgentService.call=request_call
actual_close=store.AgentStore.close;actual_db_close=store._NATIVE_STORE_CLOSE_REFERENCE
def close(self):
    counts['close_attempts']+=1
    return actual_close(self)
def close_db(self):
    counts['actual_db_close']+=1
    return actual_db_close(self)
store.AgentStore.close=close;store.AgentStore._close_reference=close_db
store._NATIVE_STORE_CLOSE_REFERENCE=close_db
def emit():
    global reported
    assert not reported;reported=True
    custody=delivery.custody_snapshot()
    counts['lost_records']=sum(row['lost'] for row in custody)
    counts['pending_native_records']=sum(row['native_pending'] for row in custody)
    counts['Store_unknown_frames']=sum(frame.unconfirmed for frame in native._FRAME_CUSTODY.values())
    counts['module_sha256']={module.__name__:sha256(Path(module.__file__).read_bytes()).hexdigest()
                            for module in (provider,bridge,delivery,native,context,journal)}
    os.write(2,('D5_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
for kind,label in ((native.NativeStoreArtifactProfile,'store'),
                   (context.NativeServiceContextImage,'context'),(journal.NativeAgentJournal,'journal')):
    initializer=kind.__init__
    def image_init(self,*args,_initializer=initializer,_label=label,**kwargs):
        _initializer(self,*args,**kwargs);entry=self._entry
        def observed(source,size,output,capacity,state,extent):
            result=entry(source,size,output,capacity,state,extent)
            counts[phase][_label]+=1
            if _label=='context' and armed:
                counts['peer_losses']+=1
                raise ValueError('actual peer result lost during artifact process delivery')
            return result
        self._entry=observed
    kind.__init__=image_init
actual_admitted=provider._admitted_code;captured_admitted=None
def admitted(manifest):
    global captured_admitted
    value=actual_admitted(manifest)
    if captured_admitted is not None:assert value==captured_admitted
    captured_admitted=value
    counts['natural_admissions'][phase]+=1
    return value
provider._admitted_code=admitted
actual_run=provider.subprocess.run
def artifact_run(argv,**kwargs):
    global armed
    assert len(argv)==4 and argv[0].startswith('/proc/self/fd/')
    fd,=kwargs['pass_fds'];admitted_bytes=captured_admitted
    assert type(admitted_bytes) is bytes
    assert os.pread(fd,len(admitted_bytes)+1,0)==admitted_bytes
    result=actual_run(argv,**kwargs)
    counts[phase]['provider']+=1
    if phase=='request':
        counts['provider_operations'].append({'operation':argv[1],'exit':result.returncode,
            'stdin_sha256':sha256(kwargs['input']).hexdigest(),'stdout_hex':result.stdout.hex(),
            'stderr_hex':result.stderr.hex(),'sealed_sha256':sha256(admitted_bytes).hexdigest()})
    if phase=='request' and argv[1]=='store-put':
        assert result.returncode==0 and len(result.stderr)==128
        counts['durable_puts']+=1
        peer=context.installed_service_context(os.environ[context.SELECTOR])
        armed=mode in ('peer-swallow','peer-replace')
        try:
            try:assert peer.arithmetic(1,17,5)==22
            except context.ServiceContextUnknown:
                assert armed;counts['swallowed']+=1
                if mode=='peer-replace':raise OSError('foreign wrapper replaced actual peer loss')
        finally:armed=False
        if mode=='exit':emit();os._exit(73)
        if mode=='ack':
            counts['lost_ack']+=1
            return provider.subprocess.CompletedProcess(result.args,result.returncode,result.stdout,b'')
    return result
provider.subprocess.run=artifact_run
assert mode in ('normal','ack','peer-swallow','peer-replace','exit')
try:status=main(sys.argv[1:])
finally:
    if not reported:emit()
raise SystemExit(status)
'''

SCOPE_PROBE = r'''
import json,os,sys,threading
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
installed,capsule,capsule_sha,bundle,bundle_sha,manifest=sys.argv[1:]
sys.path.insert(0,installed)
from hepta import hia_native_helpers as helpers, artifact_publication_native as provider
from hepta import hia_artifact_delivery_worker as artifact
from hepta.hia_artifact_delivery import _CURRENT
rows=[];calls=[]
def forbidden(*a,**k):
    calls.append(1);raise AssertionError('custody refusal reached a child process')
provider.subprocess.run=forbidden
def reject(label,operation):
    try:operation()
    except (ValueError,OSError,TypeError,RuntimeError) as error:
        assert not isinstance(error,AssertionError)
        assert not calls and _CURRENT.get() is None
        rows.append({'name':label,'error_type':type(error).__name__,'error':str(error),'children':0})
    else:raise AssertionError(label+' unexpectedly accepted')
def invoke(admission=None):
    return provider.invoke_artifact_store(manifest,'store-hash',Path(installed),data=b'x',_admission=admission)
before=helpers._manifest_environment()
with helpers.native_helpers_scope():reject('unselected_scope',invoke)
with helpers.native_helpers_scope(bundle,bundle_sha):reject('v1_scope',invoke)
with helpers.native_helpers_scope(capsule,capsule_sha) as binding:
    owner=binding.artifact;assert provider._admitted_code(manifest)==owner.private
    reject('wrong_factory',lambda:helpers.pinned_bundle(manifest,artifact.ARTIFACT_SCHEMA,object))
    reject('wrong_path',lambda:helpers.pinned_bundle(capsule,artifact.ARTIFACT_SCHEMA,artifact.NativeArtifactExecutable))
    errors=[]
    def in_thread():
        try:owner.current_code()
        except ValueError as error:errors.append(str(error))
    thread=threading.Thread(target=in_thread);thread.start();thread.join(10)
    assert not thread.is_alive() and len(errors)==1
    rows.append({'name':'wrong_actual_thread','error':errors[0],'children':0})
    pid=os.fork()
    if pid==0:
        try:owner.current_code()
        except ValueError:os._exit(0)
        except BaseException:os._exit(2)
        os._exit(3)
    actual_pid,status=os.waitpid(pid,0)
    assert actual_pid==pid and os.waitstatus_to_exitcode(status)==0
    rows.append({'name':'wrong_actual_process','child_exit':0,'artifact_children':0})
    assert helpers.native_helpers_identity()=={'native_helpers_sha256':capsule_sha}
reject('owner_after_scope',owner.current_code)
assert helpers._manifest_environment()==before

# Both pre-existing multi-image binding types delegate artifact lookup to the
# exact same registry boundary. This is a registry-unit negative, not a claim
# to have built or admitted all of their separate executable profiles here.
from hepta.hia_worker_bundle import NativeWorkerBundleBinding
from hepta.hia_worker_scheduling_bundle import NativeWorkerSchedulingBinding
for kind in (NativeWorkerBundleBinding,NativeWorkerSchedulingBinding):
    legacy=object.__new__(kind);legacy.owner=(os.getpid(),threading.get_ident());legacy.bundles={}
    with patch.object(helpers,'_SCOPE_OWNER',legacy.owner),patch.object(helpers,'_ACTIVE',legacy):
        reject(kind.__name__+'_exact_registry_boundary',
               lambda:helpers.pinned_bundle(manifest,artifact.ARTIFACT_SCHEMA,artifact.NativeArtifactExecutable))

production=Path(installed)/'hepta'/'hia_artifact_delivery_protocol.py'
added=Path(installed)/'hepta'/'unlisted_d5_production.py'
original=production.read_bytes()
for name in ('added_module','deleted_module','changed_module'):
    with helpers.native_helpers_scope(capsule,capsule_sha) as binding:
        admission=provider.admit_artifact_store(manifest)
        try:
            if name=='added_module':added.write_bytes(b'UNLISTED=True\n')
            elif name=='deleted_module':production.unlink()
            else:production.write_bytes(original+b'\n')
            reject(name+'_fresh_public_call',invoke)
            reject(name+'_cached_call_local_admission',lambda:invoke(admission))
            reject(name+'_terminal_identity',helpers.native_helpers_identity)
        finally:
            if added.exists():added.unlink()
            production.write_bytes(original)
    assert production.read_bytes()==original and not added.exists()
for filename in (Path(manifest),Path(manifest).parent/'hia-artifact'):
    raw=filename.read_bytes()
    with helpers.native_helpers_scope(capsule,capsule_sha):
        admission=provider.admit_artifact_store(manifest)
        try:
            filename.write_bytes(raw+b'\n')
            reject(filename.name+'_fresh_public_call',invoke)
            reject(filename.name+'_cached_call_local_admission',lambda:invoke(admission))
            reject(filename.name+'_terminal_identity',helpers.native_helpers_identity)
        finally:filename.write_bytes(raw)
    assert filename.read_bytes()==raw
assert helpers._manifest_environment()==before and _CURRENT.get() is None and not calls
print(json.dumps({'schema':'hepta.hia.artifact-delivery-scope-observations.v1','status':'PASS',
    'rows':rows,'artifact_children':0,'source_restored':True,'selectors_restored':True,
    'old_v2_v3_scope':'exact existing registry unit boundary; profiles not built in this control'},sort_keys=True))
'''


def run(root, manifests):
    with ExitStack() as cleanup:
        result = _run(root, manifests, cleanup)
    (root / 'installed-observations.json').write_bytes(encoded(result) + b'\n')
    return result


def _run(root, manifests, cleanup):
    from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
    from tests.test_hia_agent_native_tools import AgentToolCase
    from hepta import hia_agent_service as api
    from hepta.hia_native_helpers import native_helpers_scope
    from hepta.hia_artifact_delivery_worker import SCHEMA, ABI
    staging = root / 'source'; staging.mkdir()
    shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
    for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    environment = dict(clean_environment(), PYTHONDONTWRITEBYTECODE='1')
    commands, command_starts = [], []
    commands_lock = threading.Lock()
    def execute(label, arguments, *, body=None, expected_code=0):
        argv = [sys.executable, '-B', *map(str, arguments)]
        started = time.monotonic()
        started_ns = time.monotonic_ns()
        with commands_lock:
            assert all(row['label'] != label for row in command_starts)
            command_starts.append({'label': label, 'argv': argv,
                'started_monotonic_ns': started_ns, 'thread_id': threading.get_ident()})
            (root / 'command-starts.json').write_bytes(encoded(command_starts) + b'\n')
        try:
            result = subprocess.run(argv, cwd=root, env=environment, input=body,
                                    capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            (root / (label + '.stdout')).write_bytes(error.stdout or b'')
            (root / (label + '.stderr')).write_bytes(error.stderr or b'')
            with commands_lock:
                commands.append({'label': label, 'argv': argv, 'exit_code': None,
                    'timed_out': True, 'timeout_seconds': 60,
                    'started_monotonic_ns': started_ns, 'finished_monotonic_ns': time.monotonic_ns(),
                    'elapsed_seconds': time.monotonic() - started,
                    'stdin_sha256': None if body is None else sha256(body).hexdigest(),
                    'stdout_sha256': sha256(error.stdout or b'').hexdigest(),
                    'stderr_sha256': sha256(error.stderr or b'').hexdigest()})
                (root / 'commands.json').write_bytes(encoded(commands) + b'\n')
            raise
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        with commands_lock:
            commands.append({'label': label, 'argv': argv, 'exit_code': result.returncode,
                'started_monotonic_ns': started_ns, 'finished_monotonic_ns': time.monotonic_ns(),
                'elapsed_seconds': time.monotonic() - started,
                'stdin_sha256': None if body is None else sha256(body).hexdigest(),
                'stdout_sha256': sha256(result.stdout).hexdigest(),
                'stderr_sha256': sha256(result.stderr).hexdigest()})
            (root / 'commands.json').write_bytes(encoded(commands) + b'\n')
        if expected_code is not None:
            assert result.returncode == expected_code, (label, result.stdout, result.stderr)
        return result
    execute('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                     '--wheel-dir', root / 'wheels', staging])
    wheel, = (root / 'wheels').glob('*.whl')
    installed = root / 'installed'
    execute('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                       '--target', installed, wheel])
    wheel_records = []
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        record_name, = [name for name in names if name.endswith('.dist-info/RECORD')]
        records = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        assert len(records) == len({row[0] for row in records})
        assert {row[0] for row in records} == set(names)
        for name, digest, extent in records:
            data = archive.read(name)
            if name == record_name:
                assert digest == extent == ''
            else:
                assert digest == 'sha256=' + base64.urlsafe_b64encode(sha256(data).digest()).rstrip(b'=').decode()
                assert int(extent) == len(data)
                assert (installed / name).read_bytes() == data
            wheel_records.append({'name': name, 'bytes': len(data), 'sha256': sha256(data).hexdigest()})
        for source in (ROOT / 'hepta').rglob('*.py'):
            name = source.relative_to(ROOT).as_posix()
            assert archive.read(name) == source.read_bytes()
    bundle = root / 'helpers-v1.json'
    selectors = {'store_artifact_profile': 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST',
                 'service_context': 'HEPTA_HIA_SERVICE_CONTEXT_MANIFEST',
                 'agent_journal': 'HEPTA_HIA_AGENT_JOURNAL_MANIFEST'}
    bundle.write_bytes(encoded({'schema': 'hepta.hia.native-helpers.v1', 'target': 'linux-x86_64-lp64',
        'abi': 'hia-byte-six-argument-v1', 'helpers': [{'selector': selector,
            'manifest_path': manifests[name], 'manifest_sha256': sha256(Path(manifests[name]).read_bytes()).hexdigest()}
            for name, selector in selectors.items()]}) + b'\n')
    bundle_sha = sha256(bundle.read_bytes()).hexdigest()
    capsule = root / 'artifact-v4.json'
    capsule.write_bytes(encoded({'schema': SCHEMA, 'target': 'linux-x86_64-lp64', 'abi': ABI,
        'helpers_bundle': str(bundle), 'helpers_bundle_sha256': bundle_sha,
        'artifact_manifest': manifests['artifact'],
        'artifact_manifest_sha256': sha256(Path(manifests['artifact']).read_bytes()).hexdigest()}) + b'\n')
    capsule_sha = sha256(capsule.read_bytes()).hexdigest()

    def read_counts(result):
        prefix = b'D5_COUNTS='
        rows = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
        assert len(rows) == 1, result.stderr
        return json.loads(rows[0])

    def tree_snapshot(directory):
        rows = {}
        for path in sorted((directory, *directory.rglob('*'))):
            info = path.lstat()
            row = {'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns}
            if stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
            else:
                assert stat.S_ISREG(info.st_mode), 'baseline is not an ordinary SQLite/CAS tree'
                raw = path.read_bytes()
                row.update(kind='file', bytes=len(raw), sha256=sha256(raw).hexdigest())
            rows[path.relative_to(directory).as_posix()] = row
        return rows

    baseline = AgentToolCase('runTest')
    with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(capsule), capsule_sha):
        baseline.setUp()
        cleanup.callback(baseline.tearDown)
    # Use the real selected preparation and the original argument constructor
    # once. Every independent clone retains the same first request-key value.
    baseline_arguments = baseline.session.arguments(context=False,
        artifact_profile=baseline.session.profiles['artifact'],
        source={'kind': 'utf8', 'text': ''})
    baseline_catalog = baseline.service.catalog_sha256
    baseline.service.close()
    try:
        baseline.service.store.db.execute('SELECT 1')
    except sqlite3.ProgrammingError:
        pass
    else:
        raise AssertionError('the real baseline SQLite connection is still open')
    database = baseline.state_root / 'state.sqlite3'
    # This controlled fixture has no other connections. Do not silently omit
    # a live or unresolved WAL namespace when establishing a closed template.
    assert not any(Path(str(database) + suffix).exists()
                   for suffix in ('-wal', '-shm', '-journal'))
    baseline_tree = tree_snapshot(baseline.state_root)
    baseline_files = tree_snapshot(baseline.files_root)
    baseline_info = database.stat()
    baseline_identity = (baseline_info.st_dev, baseline_info.st_ino)
    copies = []
    baseline_record = {'schema': 'hepta.hia.artifact-delivery-closed-baseline.v1',
        'real_selected_preparation_count': 1, 'actual_SQLite_connection_closed': True,
        'v4_capsule_sha256': capsule_sha, 'state_root': str(baseline.state_root),
        'files_root': str(baseline.files_root.resolve()), 'state_tree': baseline_tree,
        'state_tree_sha256': sha256(encoded(baseline_tree)).hexdigest(),
        'files_tree': baseline_files, 'database_identity': list(baseline_identity),
        'copies': copies}
    (root / 'closed-baseline.json').write_bytes(encoded(baseline_record) + b'\n')

    def finish_baseline():
        state_after, files_after = tree_snapshot(baseline.state_root), tree_snapshot(baseline.files_root)
        baseline_record['state_tree_unchanged'] = state_after == baseline_tree
        baseline_record['shared_files_root_unchanged'] = files_after == baseline_files
        baseline_record['state_tree_after'] = state_after
        baseline_record['files_tree_after'] = files_after
        (root / 'closed-baseline.json').write_bytes(encoded(baseline_record) + b'\n')
        assert state_after == baseline_tree and files_after == baseline_files
    cleanup.callback(finish_baseline)

    def prepare(label):
        temporary = tempfile.TemporaryDirectory(prefix='hia-artifact-delivery-case-')
        state_root = Path(temporary.name) / 'state'
        try:
            assert tree_snapshot(baseline.state_root) == baseline_tree
            assert tree_snapshot(baseline.files_root) == baseline_files
            shutil.copytree(baseline.state_root, state_root, copy_function=shutil.copy2)
            copied = tree_snapshot(state_root)
            assert copied == baseline_tree
            for name, row in baseline_tree.items():
                if row['kind'] == 'file':
                    assert (state_root / name).read_bytes() == (baseline.state_root / name).read_bytes()
            identity = (state_root / 'state.sqlite3').stat()
            identity = (identity.st_dev, identity.st_ino)
            assert identity != baseline_identity
            assert all(identity != tuple(item['database_identity']) for item in copies)
            assert tree_snapshot(baseline.state_root) == baseline_tree
        except BaseException:
            temporary.cleanup()
            raise
        case = SimpleNamespace(state_root=state_root, files_root=baseline.files_root,
                               tearDown=temporary.cleanup)
        cleanup.callback(temporary.cleanup)
        copies.append({'label': label, 'state_root': str(state_root),
            'files_root': str(case.files_root.resolve()), 'state_tree': copied,
            'state_tree_sha256': sha256(encoded(copied)).hexdigest(),
            'byte_identical_before_worker': True, 'database_identity': list(identity),
            'independent_database_inode': True})
        (root / 'closed-baseline.json').write_bytes(encoded(baseline_record) + b'\n')
        arguments = deepcopy(baseline_arguments)
        arguments['source']['text'] = 'actual private delivery — 雪 — ' + label
        request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_artifact',
            'arguments': arguments, 'profile_sha256': 'a' * 64, 'catalog_sha256': baseline_catalog}
        request['request_sha256'] = api.digest(request)
        return case, request

    def worker(label, case, request, mode='normal', expected_code=0):
        return execute(label, ['-I', '-c', WORKER, installed, mode,
            '--state-root', case.state_root, '--artifact-root', case.files_root,
            '--request-json-stdin', '--native-helpers-manifest', capsule,
            '--expected-native-helpers-sha256', capsule_sha],
            body=encoded(request), expected_code=expected_code)

    def state(case, request):
        key = api.digest({'tool': request['tool'], 'key': request['arguments']['request_key']})
        with closing(sqlite3.connect(case.state_root / 'state.sqlite3')) as db:
            db.row_factory = sqlite3.Row
            row = db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()
            return {'request': None if row is None else dict(row),
                'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

    # Unconfirmed native delivery has the dedicated Worker diagnostic/exit;
    # a process interruption still supplies its original external exit.
    modes = (('normal', 0), ('ack', 2), ('peer-swallow', 2), ('peer-replace', 2), ('exit', 73))
    # All six databases exist together when their inode identities are checked;
    # later deletion cannot turn inode reuse into a false independence claim.
    prepared = {mode: prepare(mode) for mode, _ in modes}
    prepared['installed-source-drift'] = prepare('installed-source-drift')
    def perform_pair(mode, exit_code):
        case, request = prepared[mode]
        try:
            before = state(case, request)
            first = worker(mode, case, request, mode, exit_code)
            counts = read_counts(first)
            after = state(case, request)
            payload = request['arguments']['source']['text'].encode()
            content = case.state_root / 'artifacts' / sha256(payload).hexdigest()
            assert content.read_bytes() == payload
            assert counts['durable_puts'] == 1
            assert all(counts['request'][name] > 0 for name in ('provider', 'store', 'context', 'journal'))
            assert counts['startup']['store'] > 0
            assert counts['close_attempts'] == (0 if mode == 'exit' else 1)
            assert counts['actual_db_close'] == (1 if mode == 'normal' else 0)
            assert counts['peer_losses'] == counts['swallowed'] == (1 if mode.startswith('peer-') else 0)
            assert counts['lost_ack'] == (1 if mode == 'ack' else 0)
            if mode == 'normal':
                report = json.loads(first.stdout)
                assert report['response']['status'] == 'completed'
                assert report['native_helpers_sha256'] == capsule_sha
                assert after['request']['state'] == 'completed'
                assert after['artifacts'] == before['artifacts'] + 1
                assert after['costs'] == before['costs'] + 1
                assert counts['lost_records'] == counts['Store_unknown_frames'] == 0
            else:
                report = None
                assert first.stdout == b''
                assert after['request']['state'] == 'running' and after['request']['response'] is None
                assert after['artifacts'] == before['artifacts'] and after['costs'] == before['costs']
                if mode == 'exit':
                    assert counts['pending_native_records'] > 0
                else:
                    assert counts['lost_records'] > 0 and counts['Store_unknown_frames'] > 0
                    assert first.stderr.splitlines()[0] == b'HIA_WORKER_DELIVERY_UNKNOWN'
            replay = worker(mode + '-replay', case, request)
            replay_report, replay_counts = json.loads(replay.stdout), read_counts(replay)
            replay_state = state(case, request)
            assert replay_report['native_helpers_sha256'] == capsule_sha
            assert replay_counts['request']['provider'] == replay_counts['request']['store'] == 0
            assert replay_counts['request']['context'] == 0 and replay_counts['request']['journal'] > 0
            assert replay_counts['startup']['store'] > 0
            assert replay_counts['durable_puts'] == replay_counts['lost_records'] == replay_counts['Store_unknown_frames'] == 0
            assert replay_counts['close_attempts'] == replay_counts['actual_db_close'] == 1
            if mode == 'normal':
                assert replay_report['response'] == report['response'] and replay_state == after
            else:
                assert replay_report['response']['status'] == 'rejected'
                assert replay_report['response']['error']['code'] == 'E_HIA_REQUEST_UNKNOWN'
                assert replay_state['request'] == after['request']
                assert replay_state['artifacts'] == after['artifacts']
                assert replay_state['costs'] == after['costs'] + 1
            assert content.read_bytes() == payload
            observation = {'worker_exit_code': first.returncode, 'counts': counts, 'report': report,
                'before': before, 'after': after, 'replay_worker_exit_code': replay.returncode,
                'replay_counts': replay_counts, 'replay_report': replay_report, 'replay_state': replay_state,
                'durable_content_sha256': sha256(payload).hexdigest(),
                'request_provider_calls_on_replay': 0, 'startup_is_not_zero_native_calls': True}
            (root / (mode + '-observations.json')).write_bytes(encoded(observation) + b'\n')
            return observation
        finally:
            case.tearDown()

    schedule_lock = threading.Lock()
    pair_schedule = {'schema': 'hepta.hia.artifact-delivery-pair-schedule.v1',
        'maximum_workers': 2, 'mode_order': [mode for mode, _ in modes],
        'submission_order': [], 'completion_order': [], 'collection_order': [],
        'pairs': {mode: {'status': 'planned', 'expected_first_exit_code': exit_code}
                  for mode, exit_code in modes},
        'active_pairs': 0, 'maximum_observed_active_pairs': 0,
        'all_pairs_joined': False}

    def write_schedule():
        # The caller holds schedule_lock. No worker mutates sources, manifests,
        # capsule, files_root or another pair's independently copied database.
        (root / 'pair-schedule.json').write_bytes(encoded(pair_schedule) + b'\n')

    def run_pair(mode, exit_code):
        with schedule_lock:
            pair = pair_schedule['pairs'][mode]
            pair.update(status='running', started_monotonic_ns=time.monotonic_ns(),
                        thread_id=threading.get_ident())
            pair_schedule['active_pairs'] += 1
            pair_schedule['maximum_observed_active_pairs'] = max(
                pair_schedule['maximum_observed_active_pairs'], pair_schedule['active_pairs'])
            assert pair_schedule['active_pairs'] <= 2
            write_schedule()
        try:
            observation = perform_pair(mode, exit_code)
        except BaseException as error:
            failure_path = root / (mode + '-failure.log')
            failure_path.write_text(''.join(traceback.format_exception(type(error), error, error.__traceback__)))
            with schedule_lock:
                pair.update(status='failed', error_module=type(error).__module__,
                            error_type=type(error).__qualname__, error_message=str(error),
                            failure_log=failure_path.name,
                            failure_log_sha256=sha256(failure_path.read_bytes()).hexdigest())
            raise
        else:
            with schedule_lock:
                pair.update(status='passed', observation_path=mode + '-observations.json',
                    observation_sha256=sha256(encoded(observation) + b'\n').hexdigest())
            return observation
        finally:
            with schedule_lock:
                pair['finished_monotonic_ns'] = time.monotonic_ns()
                pair_schedule['active_pairs'] -= 1
                pair_schedule['completion_order'].append(mode)
                write_schedule()

    observations, failures, futures = {}, [], []
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='hia-artifact-pair') as executor:
        # Submit every independent pair before observing any result. A failed
        # pair never cancels another pair or changes its original assertions.
        for mode, exit_code in modes:
            with schedule_lock:
                future = executor.submit(run_pair, mode, exit_code)
                pair_schedule['pairs'][mode].update(status='submitted',
                    submitted_monotonic_ns=time.monotonic_ns())
                pair_schedule['submission_order'].append(mode)
                write_schedule()
            futures.append((mode, future))
        with schedule_lock:
            pair_schedule['all_pairs_submitted_monotonic_ns'] = time.monotonic_ns()
            write_schedule()
        for mode, future in futures:
            try:
                observations[mode] = future.result()
            except BaseException as error:
                failures.append((mode, error))
            finally:
                with schedule_lock:
                    pair_schedule['collection_order'].append(mode)
                    write_schedule()
                (root / 'worker-observations.partial.json').write_bytes(encoded(observations) + b'\n')
    with schedule_lock:
        pair_schedule['all_pairs_joined'] = True
        pair_schedule['all_pairs_joined_monotonic_ns'] = time.monotonic_ns()
        pair_schedule['failed_modes'] = [mode for mode, _ in failures]
        write_schedule()
    assert pair_schedule['active_pairs'] == 0
    assert pair_schedule['submission_order'] == pair_schedule['collection_order'] == [mode for mode, _ in modes]
    assert len(pair_schedule['completion_order']) == len(modes)
    assert 1 <= pair_schedule['maximum_observed_active_pairs'] <= 2
    if failures:
        raise failures[0][1]
    assert all(pair_schedule['pairs'][mode]['status'] == 'passed' for mode, _ in modes)
    with schedule_lock:
        pair_schedule['mutations_started_monotonic_ns'] = time.monotonic_ns()
        write_schedule()

    case, request = prepared['installed-source-drift']
    source = installed / 'hepta/_data/examples/hia_bootstrap/artifact_publication_policy.hepta'
    original = source.read_bytes()
    try:
        before = state(case, request)
        source.write_bytes(original + b'\n')
        changed = worker('installed-source-drift', case, request, expected_code=None)
        counts = read_counts(changed)
        assert changed.returncode != 0 and changed.stdout == b''
        assert all(value == 0 for phase in ('startup', 'request', 'cleanup') for value in counts[phase].values())
        assert counts['close_attempts'] == 0 and state(case, request) == before
        observations['installed_source_drift'] = {'exit_code': changed.returncode, 'counts': counts,
            'original_sha256': sha256(original).hexdigest(), 'changed_sha256': sha256(source.read_bytes()).hexdigest(),
            'exact_change': 'one appended LF in packaged artifact publication policy',
            'request_database_unchanged': True}
    finally:
        source.write_bytes(original)
        case.tearDown()
    assert source.read_bytes() == original
    observations['installed_source_drift']['restored_sha256'] = sha256(source.read_bytes()).hexdigest()

    # Isolate destructive custody probes from the component's actual build
    # receipts. Each copy carries the exact original bytes and source identity.
    probe = root / 'scope-probe'; probe.mkdir()
    artifact = probe / 'artifact'; artifact.mkdir()
    copied_manifest = artifact / 'build.json'
    shutil.copyfile(manifests['artifact'], copied_manifest)
    shutil.copyfile(Path(manifests['artifact']).parent / 'hia-artifact', artifact / 'hia-artifact')
    probe_capsule = probe / 'capsule.json'
    value = json.loads(capsule.read_bytes())
    value['artifact_manifest'] = str(copied_manifest)
    probe_capsule.write_bytes(encoded(value) + b'\n')
    probe_sha = sha256(probe_capsule.read_bytes()).hexdigest()
    scoped = execute('scope-probe', ['-I', '-c', SCOPE_PROBE, installed, probe_capsule, probe_sha,
                                   bundle, bundle_sha, copied_manifest])
    scope_observations = json.loads(scoped.stdout)
    assert scope_observations['status'] == 'PASS' and scope_observations['artifact_children'] == 0
    assert copied_manifest.read_bytes() == Path(manifests['artifact']).read_bytes()
    assert (artifact / 'hia-artifact').read_bytes() == (Path(manifests['artifact']).parent / 'hia-artifact').read_bytes()
    with zipfile.ZipFile(wheel) as archive:
        for row in wheel_records:
            if not row['name'].endswith('.dist-info/RECORD'):
                assert (installed / row['name']).read_bytes() == archive.read(row['name'])
    (root / 'wheel-records.json').write_bytes(encoded(wheel_records) + b'\n')
    assert len(copies) == 6
    assert {item['label'] for item in copies} == {
        'normal', 'ack', 'peer-swallow', 'peer-replace', 'exit', 'installed-source-drift'}
    result = {'schema': 'hepta.hia.artifact-delivery-installed-observations.v1',
        'worker': observations, 'scope': scope_observations,
        'closed_baseline': baseline_record,
        'pair_schedule': pair_schedule,
        'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
        'wheel_records_sha256': sha256((root / 'wheel-records.json').read_bytes()).hexdigest(),
        'v1_bundle_sha256': bundle_sha, 'v4_capsule_sha256': capsule_sha,
        'source_bound_public_private_manifest_sha256': sha256(Path(manifests['artifact']).read_bytes()).hexdigest(),
        'actual_original_worker': True, 'fresh_wheel_unique_RECORD_verified': True,
        'retained_Store_context_journal_bodies_forbidden_in_child': True,
        'artifact_is_separate_private_ABI_not_six_argument_helper': True,
        'every_public_call_and_normal_terminal_full_inventory_checks': True,
        'source_and_manifest_image_mutations_restored_in_finally': True,
        'whole_native_stack_qualified': False}
    return result
