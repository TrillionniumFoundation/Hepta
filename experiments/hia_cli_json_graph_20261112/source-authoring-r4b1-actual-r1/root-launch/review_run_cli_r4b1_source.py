"""Root readback and one original two-component source request; no native run."""
import hashlib, json, os, pathlib, stat, subprocess, sys, time

ROOT = pathlib.Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/source-authoring-r4b1')
OUT = pathlib.Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4b1-source-actual-r1')
CTX = pathlib.Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4b1-root-context.json')

def wire(v):
    return (json.dumps(v, sort_keys=True, indent=2) + '\n').encode()

def ident(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def read(p):
    p = pathlib.Path(p)
    for parent in reversed(p.parents):
        assert stat.S_ISDIR(parent.lstat().st_mode), str(parent)
    s = p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1, str(p)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert ident(os.fstat(fd)) == ident(s)
        with os.fdopen(fd, 'rb', closefd=False) as f:
            b = f.read()
        assert ident(os.fstat(fd)) == ident(s) and ident(p.lstat()) == ident(s) and len(b) == s.st_size
    finally:
        os.close(fd)
    return {'path':str(p), 'bytes':len(b), 'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),
            'identity':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]}, b

def create(name, value):
    with (OUT/name).open('xb') as f:
        f.write(wire(value)); f.flush(); os.fsync(f.fileno())

context = json.loads(CTX.read_bytes())
prepin, preraw = read(ROOT/'PREEXEC.json'); pre = json.loads(preraw)
reqpin, reqraw = read(ROOT/'guardian/REQUEST.json'); req = json.loads(reqraw)
cfgpin, cfgraw = read(ROOT/'control/CONFIG.json'); cfg = json.loads(cfgraw)
assert prepin['sha256'] == '030e58ce0f6493713fe659f6618f591d7727561839a08716c9e35a6706182a02'
assert reqpin['sha256'] == '78b42eae2a35c0f2f1d579ec71fc044923d2edec99430279c3f528c512067bc7'
raw_proof=json.loads(pathlib.Path('/workspace/scratch/e26ed3e2edcf/root/cli-r4b1-canonical-readback.json').read_bytes())
assert raw_proof['commit'] == context['commit'] == '1cacd301013725b42380da34963ba4d9283fe927'
assert all(x['full_raw_equal'] for x in raw_proof['selected']) and len(raw_proof['selected']) == 7
canonical = []
for row in context['new_files']:
    actual, raw = read(row['local'])
    assert row['mode'] in ('100644','100755') and actual['git_blob'] == row['sha'], row['path']
    canonical.append(actual)
assert len(canonical) == 195
oldcfg=json.loads(pathlib.Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1/source-authoring-r4b/control/CONFIG.json').read_bytes())
assert sorted(cfg['source_pins']) == sorted(oldcfg['source_pins'])
assert [n for n in sorted(cfg['source_pins']) if cfg['source_pins'][n] != oldcfg['source_pins'][n]] == ['tools/generate_hia_cli_json_scalar.py']
for name in ('guardian.py','process_owner_impl.py','source_authoring_worker.py'):
    assert (ROOT/'control'/name).read_bytes() == (ROOT.parent/'source-authoring-r4b/control'/name).read_bytes()
assert len(cfg['source_pins']) == 167 and cfg['source_pins'] == context['source']
assert sum(x['bytes'] for x in cfg['source_pins'].values()) == 2632579
assert sorted(p.relative_to(ROOT/'source').as_posix() for p in (ROOT/'source').rglob('*') if p.is_file()) == sorted(cfg['source_pins'])
for name, pin in cfg['source_pins'].items():
    row, raw = read(ROOT/'source'/name)
    assert all(row[k] == pin[k] for k in ('bytes','sha256','git_blob')), name
assert len(req['source_identities']) == 174
inputs = []
for name, pin in req['source_identities'].items():
    row, raw = read(name); assert row['sha256'] == pin, name
    inputs.append(row)
assert req['controller_seconds'] == 180 and req['expected_qualification'] is None
assert req['cwd'] == str(ROOT/'source') == pre['cwd']
assert req['command'] == [pre['python']['path'],'-I','-S','-B',str(ROOT/'control/source_authoring_worker.py'),str(ROOT/'control/CONFIG.json'),str(ROOT/'actual')]
assert pre['command'] == [pre['python']['path'],'-I','-S','-B',str(ROOT/'control/guardian.py'),'--config',str(ROOT/'guardian/REQUEST.json'),'--config-sha256',reqpin['sha256'],'--implementation',str(ROOT/'control/process_owner_impl.py')]
assert req['source_identities'][str(ROOT/'control/guardian.py')] == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
assert req['source_identities'][str(ROOT/'control/process_owner_impl.py')] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
assert pre['environment'] == {'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'/usr/bin:/bin'}
assert cfg['components'] == pre['components'] == [['scalar','tools.generate_hia_cli_json_scalar'],['py312_chunks','tools.generate_hia_cli_json_py312_chunks']]
assert cfg['limits'] == {'source_bytes':1<<20,'functions':128,'blocks_per_function':256,'blocks_total':1536,'parameters_or_arguments':16,'ssa_names_per_function':2048,'instruction_results':3,'function_results':3,'instructions':8192}
assert len(cfg['original_cli_ids']) == 17 and len(cfg['trace_plan_ids']) == 46
assert not cfg['caller_execution_requested'] and not cfg['trace_execution_requested'] and not cfg['native_executed']
assert not (ROOT/'actual').exists()
assert sorted(p.name for p in (ROOT/'guardian').iterdir()) == ['REQUEST.json']
assert stat.S_IMODE((ROOT/'guardian').stat().st_mode) == 0o700
OUT.mkdir(mode=0o700, exist_ok=False)
create('PRETRIGGER.json', {'schema':'hia.root.cli-r4b1.source-pretrigger.v1','status':'PASS_FOR_TWO_NEW_SOURCE_COMPONENTS_ONLY',
    'canonical_commit':'1cacd301013725b42380da34963ba4d9283fe927','canonical_tree':'5bd0af76404d00148e7356690787aed7ab4c0da0',
    'canonical_leaves_verified':canonical,'request':reqpin,'preexec':prepin,'inputs':inputs,
    'components':cfg['components'],'limits':cfg['limits'],'owner_seconds':180,'cleanup_seconds':3,
    'old_four_regenerated':False,'native_executed':False,'whole_rewrite_closed':False})
create('INVOCATION-INTENT.json', {'time_ns':time.time_ns(),'command':pre['command'],'cwd':pre['cwd'],
    'environment':pre['environment'],'request_sha256':reqpin['sha256'],'unique_invocation':True})
with (OUT/'launcher.stdout.log').open('xb') as stdout, (OUT/'launcher.stderr.log').open('xb') as stderr:
    completed = subprocess.run(pre['command'], cwd=pre['cwd'], env=pre['environment'], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, check=False)
create('INVOCATION-RETURN.json', {'time_ns':time.time_ns(),'returncode':completed.returncode,
    'launcher_stdout':read(OUT/'launcher.stdout.log')[0], 'launcher_stderr':read(OUT/'launcher.stderr.log')[0]})
print(json.dumps({'returncode':completed.returncode,'output':str(OUT),'original_guardian':str(ROOT/'guardian/guardian.json')}))
sys.exit(completed.returncode)
