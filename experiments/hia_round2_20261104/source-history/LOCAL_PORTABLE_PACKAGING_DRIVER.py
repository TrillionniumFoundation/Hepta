"""Preserve existing original Git objects with their real shallow boundary.

This is bounded, offline delivery. It does not fetch or rerun an experiment.
"""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time

B = Path('/data/hepta-hia-round2-20261104/evidence')
S = Path('/data/hepta-hia-round2-20261104/work-integration')
PREFLIGHT = B / 'source-portable-preflight-r2'
OLD = B / 'final-source-history'
OUT = B / 'source-portable-r2'
PUB = OUT / 'public'
H = '5ee6d8fec0e5c72d87a36dbed60789de211abf1b'
T = 'd47a711461dc66d4606bdc9659203889e205d6c7'
F2 = 'f2b76f5741c83822be2e12cf5a50b50a8d27b96a'


def req(v, m):
    if not v:
        raise ValueError(m)


def hashfile(path, alg='sha256'):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, alg).hexdigest()


def record(p):
    return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': hashfile(p)}


def save(p, j):
    b = (json.dumps(j, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()
    p.open('xb').write(b)
    return {'path': str(p), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def copy(src, dst):
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open('rb') as f, dst.open('xb') as g:
        while b := f.read(1024 * 1024):
            g.write(b)
    req(hashfile(src) == hashfile(dst), 'copy hash mismatch')


def export(public, dest):
    dest.mkdir(exist_ok=False)
    rows = []
    for p in sorted(public.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(public).as_posix()
        b = p.read_bytes()
        h = hashlib.sha256(b).hexdigest()
        g = hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest()
        parts = []
        folder = dest / f'{len(rows):04d}'
        folder.mkdir()
        for n, i in enumerate(range(0, len(b), 48000)):
            q = folder / f'{n:05d}.base64'
            q.open('xb').write(base64.b64encode(b[i:i+48000]))
            parts.append(str(q))
        rows.append({'path': rel, 'bytes': len(b), 'sha256': h, 'git_blob_sha1': g,
                     'mode': '100644', 'transport_parts': parts})
    return save(dest / 'INDEX.json', {'schema': 'hepta.hia.base64-public-export.v1',
                'public_root': str(public), 'chunk_decoded_bytes': 48000, 'files': rows,
                'count': len(rows), 'bytes': sum(r['bytes'] for r in rows)})


RESTORE = r'''"""Offline source restoration at its recorded real shallow boundary; no experiment."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,subprocess,tempfile
def req(v,m):
 if not v:raise ValueError(m)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
a=argparse.ArgumentParser();a.add_argument('--package',type=Path,required=True);a.add_argument('--output',type=Path,required=True);x=a.parse_args()
p=x.package.resolve();m=json.loads((p/'MANIFEST.json').read_bytes());x.output.mkdir(parents=True,exist_ok=False);o=x.output.resolve();repo=o/'restored.git'
env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')};env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0')
def run(*args,input=None,check=True):
 c=subprocess.run(['git',*args],env=env,input=input,capture_output=True,timeout=120)
 if check:req(c.returncode==0,c.stderr.decode('utf-8','replace'))
 return c
run('init','--bare','--initial-branch=original',str(repo))
req(run('-C',str(repo),'cat-file','-e',m['source']['commit'],check=False).returncode!=0,'original commit existed before import')
pack=o/'objects.pack';h=hashlib.sha256();n=0
with pack.open('xb') as f:
 for part in m['pack']['parts']:
  b=(p/part['name']).read_bytes();req(len(b)==part['bytes'] and hashlib.sha256(b).hexdigest()==part['sha256'],'part drift');f.write(b);h.update(b);n+=len(b)
req(n==m['pack']['bytes'] and h.hexdigest()==m['pack']['sha256'],'whole pack drift')
with pack.open('rb') as f:
 c=subprocess.run(['git','-C',str(repo),'index-pack','--stdin'],env=env,stdin=f,capture_output=True,timeout=120)
 req(c.returncode==0,c.stderr.decode('utf-8','replace'))
shallow=(p/'RESTORED_SHALLOW_BOUNDARIES.txt').read_bytes();req(hashlib.sha256(shallow).hexdigest()==m['normalized_shallow_sha256'],'shallow drift');(repo/'shallow').open('xb').write(shallow)
run('-C',str(repo),'update-ref','refs/heads/original',m['source']['commit'])
req(run('-C',str(repo),'rev-parse','HEAD','HEAD^{tree}').stdout.decode().splitlines()==[m['source']['commit'],m['source']['tree']],'source identity')
expected=(p/'REACHABLE_OBJECT_IDS.txt').read_bytes();req(hashlib.sha256(expected).hexdigest()==m['object_ids_sha256'],'object inventory drift');wanted=set(expected.decode().split())
got=set(run('-C',str(repo),'cat-file','--batch-all-objects','--batch-check=%(objectname)').stdout.decode().split());req(got==wanted,'object set differs')
for f in (repo/'objects').rglob('*'):
 req(not f.is_symlink(),'object symlink')
 if f.is_file():req(f.stat().st_nlink==1 and not f.name.endswith('.promisor'),'linked or partial object')
req(not (repo/'objects/info/alternates').exists(),'alternate object store')
fsck=run('-C',str(repo),'fsck','--full','--strict');(o/'fsck.stdout').write_bytes(fsck.stdout);(o/'fsck.stderr').write_bytes(fsck.stderr)
raw=gzip.decompress((p/'TRACKED_INVENTORY.json.gz').read_bytes());req(hashlib.sha256(raw).hexdigest()==m['tracked_inventory_sha256'],'tracked manifest drift');rows=json.loads(raw)
tree=run('-C',str(repo),'ls-tree','-rz','HEAD').stdout;req(hashlib.sha256(tree).hexdigest()==m['original_tree_sha256'],'tree records drift')
c=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
total=0
try:
 for r in rows:
  c.stdin.write((r['git_blob']+'\n').encode());c.stdin.flush();hdr=c.stdout.readline().decode().split();req(hdr==[r['git_blob'],'blob',str(r['bytes'])],'blob header')
  left=r['bytes'];s=hashlib.sha256()
  while left:
   b=c.stdout.read(min(left,1024*1024));req(bool(b),'short blob');s.update(b);left-=len(b)
  req(c.stdout.read(1)==b'\n' and s.hexdigest()==r['sha256'],'restored blob bytes');total+=r['bytes']
 c.stdin.close();err=c.stderr.read();req(c.wait(timeout=30)==0,'cat-file exit')
finally:
 if c.poll() is None:c.kill();c.wait()
print(json.dumps({'passed':True,'source':m['source'],'tracked_paths':len(rows),'tracked_bytes':total,'objects':len(got),'full_public_ancestry_present':False,'real_shallow_boundaries':shallow.decode().split(),'preimport_original_commit_absent':True,'all_tree_and_blob_hashes_verified':True,'object_store_independent':True,'pack_sha256':h.hexdigest(),'no_experiments_executed':True},sort_keys=True))
'''


def main():
    start = time.monotonic_ns()
    OUT.mkdir(exist_ok=False)
    PUB.mkdir()
    commands = OUT / 'commands'
    commands.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_NO_REPLACE_OBJECTS='1',
               GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    outcome = {'schema': 'hepta.hia.portable-original-source.v1', 'status': 'failed', 'passed': False,
               'source': {'commit': H, 'tree': T}, 'original_full_qualification_passed': False,
               'full_public_ancestry_present': False, 'network_fetches': 0, 'experiments_executed': 0,
               'error': None, 'commands': [], 'host_exclusive': False, 'actual_affinity': sorted(os.sched_getaffinity(0))}

    def run(name, argv, data=None, output=None, timeout=120):
        now = time.monotonic_ns()
        remaining = 270 - (now - start) / 1e9
        req(remaining > 0, 'bounded source-delivery deadline exhausted')
        prefix = commands / (f'{len(outcome["commands"])+1:03d}-' + name)
        stdout = output or Path(str(prefix) + '.stdout')
        stderr = Path(str(prefix) + '.stderr')
        row = {'name': name, 'argv': argv, 'cwd': str(S), 'returncode': None, 'timed_out': False}
        with stdout.open('xb') as out, stderr.open('xb') as err:
            proc = subprocess.Popen(argv, cwd=S, env=env, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True)
            try:
                proc.communicate(data, timeout=min(timeout, remaining))
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
            row['returncode'] = proc.returncode
        row.update(wall_ns=time.monotonic_ns()-now, stdout=record(stdout), stderr=record(stderr))
        outcome['commands'].append(row)
        save(Path(str(prefix) + '.json'), row)
        req(row['returncode'] == 0 and not row['timed_out'], 'source delivery command failed: ' + name)
        return stdout.read_bytes() if output is None else None

    def state(label):
        ids = run(label+'-identity', ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], timeout=20).decode().splitlines()
        status = run(label+'-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all'], timeout=20).decode()
        return {'commit': ids[0], 'tree': ids[1], 'status': status}

    try:
        before = state('before')
        req(before == {'commit': H, 'tree': T, 'status': ''}, 'frozen source differs')
        outcome['source_before'] = before
        pre = json.loads((PREFLIGHT / 'RESULT.json').read_bytes())
        req(pre['source'] == outcome['source'] and pre['known_reachable_objects'] == 8361, 'preflight differs')
        ids = (PREFLIGHT / 'REACHABLE_OBJECT_IDS.txt').read_bytes()
        req(hashlib.sha256(ids).hexdigest() == pre['object_ids']['sha256'], 'object list drift')
        req(run('actual-object-list', ['git', 'rev-list', '--objects', '--no-object-names', 'HEAD']) == ids, 'actual reachable set drift')
        req(len(ids.splitlines()) == len(set(ids.splitlines())) == 8361, 'duplicate/missing object')
        shallow = (PREFLIGHT / 'ORIGINAL_SHALLOW_BOUNDARIES.txt').read_bytes()
        normalized = ('\n'.join(sorted(set(pre['reachable_shallow_boundaries']))) + '\n').encode()
        req(normalized == b'931c96fcc7fb698226b809862c233a345dcca4ec\n', 'unexpected real shallow boundary')
        copy(PREFLIGHT / 'REACHABLE_OBJECT_IDS.txt', PUB / 'REACHABLE_OBJECT_IDS.txt')
        copy(PREFLIGHT / 'REACHABLE_OBJECT_SIZES.txt', PUB / 'REACHABLE_OBJECT_SIZES.txt')
        (PUB / 'ORIGINAL_SHALLOW_BOUNDARIES.txt').open('xb').write(shallow)
        (PUB / 'RESTORED_SHALLOW_BOUNDARIES.txt').open('xb').write(normalized)
        copy(PREFLIGHT / 'RESULT.json', PUB / 'OBJECT_PREFLIGHT.json')
        inventory = (OLD / 'TRACKED_INVENTORY.json').read_bytes()
        rows = json.loads(inventory)
        req(len(rows) == 8946, 'tracked inventory')
        with (PUB / 'TRACKED_INVENTORY.json.gz').open('xb') as f:
            with gzip.GzipFile(fileobj=f, mode='wb', filename='', mtime=0, compresslevel=1) as g:
                g.write(inventory)
        pack = OUT / 'objects.pack'
        run('pack-existing-objects', ['git', 'pack-objects', '--stdout', '--delta-base-offset', '--compression=1',
                                      '--window=0', '--depth=0'], data=ids, output=pack, timeout=120)
        parts = []
        with pack.open('rb') as stream:
            while b := stream.read(768*1024):
                name = f'objects.pack.part-{len(parts):04d}'
                (PUB / name).open('xb').write(b)
                parts.append({'name': name, 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()})
        manifest = {'schema': 'hepta.hia.portable-original-source-manifest.v1', 'source': outcome['source'],
                    'public_projection': '3102c2bb6cd819c27aef36cc927c23b39b279204',
                    'pack': {'bytes': pack.stat().st_size, 'sha256': hashfile(pack), 'parts': parts,
                             'thin': False, 'contains_exact_existing_reachable_object_set': True},
                    'object_ids_sha256': hashlib.sha256(ids).hexdigest(),
                    'tracked_inventory_sha256': hashlib.sha256(inventory).hexdigest(),
                    'original_tree_sha256': hashfile(OLD / 'commands/006-original-tree.stdout'),
                    'original_shallow_sha256': hashlib.sha256(shallow).hexdigest(),
                    'normalized_shallow_sha256': hashlib.sha256(normalized).hexdigest(),
                    'shallow_normalization': 'The original82-byte file repeats the same real reachable boundary twice. The restore writes its unique sorted boundary once; no new boundary or ancestral object is invented.',
                    'full_public_ancestry_present': False, 'network_dependency_for_this_offline_restore': False,
                    'visible_commits': 53, 'objects': 8361, 'tracked_paths': 8946,
                    'scope': 'Exact original source commit/tree and locally available history truncated at the recorded original shallow boundary. Not complete public GitHub ancestry, not a proof/benchmark/Agent rerun.'}
        save(PUB / 'MANIFEST.json', manifest)
        (PUB / 'RESTORE.py').open('x').write(RESTORE)
        restored = run('independent-offline-restore', [sys.executable, '-B', str(PUB / 'RESTORE.py'),
                       '--package', str(PUB), '--output', str(OUT / 'fresh-restore')], timeout=120)
        verification = json.loads(restored)
        req(verification['passed'] is True and verification['tracked_paths'] == 8946 and
            verification['objects'] == 8361 and verification['source'] == outcome['source'], 'restore receipt mismatch')
        outcome['restore'] = verification
        outcome['pack'] = manifest['pack']
        # Preserve the failed public-ancestry attempt and the separately useful
        # original incremental bundle. Neither is relabeled as a successful fetch.
        for p in sorted((OLD / 'commands').glob('*')):
            copy(p, PUB / 'failed-public-fetch' / 'commands' / p.name)
        copy(OLD / 'RESULT.json', PUB / 'failed-public-fetch/RESULT.json')
        for name in ('final-source-history-driver-r1.py', 'final-source-history-LAUNCH_PLAN-r1.json',
                     'final-source-history-progress-r2.json', 'final-source-history-preflight-r1.json',
                     'final-source-history-prerequisite-closure-check-r1.json'):
            copy(B / name, PUB / 'failed-public-fetch' / name)
        runtime = Path('/home/qian-qi/.local/state/hepta-runtime-mac-worker/jobs/1a1aa539fd7-fc05-4116')
        for name in ('request.json', 'stdout.log', 'stderr.log', 'exit.json'):
            copy(runtime / name, PUB / 'failed-public-fetch/runtime-original' / name)
        incremental = OLD / 'original-source.bundle'
        increment_parts = []
        with incremental.open('rb') as f:
            while b := f.read(768*1024):
                name = f'original-source.bundle.part-{len(increment_parts):04d}'
                (PUB / name).open('xb').write(b)
                increment_parts.append({'name': name, 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()})
        save(PUB / 'INCREMENTAL_BUNDLE.json', {'bundle': record(incremental), 'parts': increment_parts,
             'required_public_prerequisite': F2, 'requires_base_object_closure': True,
             'original_attempt_to_acquire_complete_public_closure': 'failed after900s; not retried',
             'independent_offline_package_is_separate': True})
        omitted = []
        for p in sorted((OLD / 'independent-restore.git').rglob('*')):
            if p.is_file():
                omitted.append({'path': p.relative_to(OLD).as_posix(), 'bytes': p.stat().st_size,
                                'sha256': hashfile(p), 'reason': 'Incomplete failed public-network seed store, not required for the offline restored object set. Original bytes remain remotely preserved.'})
        save(PUB / 'FAILED_FETCH_OMISSIONS.json', {'files': omitted, 'failed_originals_preserved_remotely': True})
        copy(Path(__file__), PUB / 'PACKAGING_DRIVER.py')
        after = state('after')
        req(after == before, 'frozen source changed')
        req(hashfile(OLD/'original-source.bundle') == '0e0b8628a22f23836b2ba0002e475cec83a6e1b53b088896d8e3fd1ff2ca6367', 'incremental source bundle changed')
        for p in sorted(commands.glob('*')):
            copy(p, PUB / 'delivery-commands' / p.name)
        copy(B / 'source-portable-LAUNCH_PLAN-r2.json', PUB / 'LAUNCH_PLAN.json')
        outcome.update(source_after=after, source_unchanged=True, status='completed', passed=True)
        readme = '''# Portable original source with explicit shallow history

This package restores original commit `5ee6d8fec0e5c72d87a36dbed60789de211abf1b`, tree `d47a711461dc66d4606bdc9659203889e205d6c7`, and all8946 tracked paths. It contains8361 actual locally reachable Git objects, including53 commits, in a non-thin pack. Original identity is preserved; the public App commit3102c2bb is only a same-tree projection.

**This is not complete public GitHub history.** The original local repository was shallow at931c96fcc7fb698226b809862c233a345dcca4ec. Its82-byte shallow file repeats that same boundary; the independent restore uses the unique same boundary. No parent history beyond it is claimed. The earlier public f2 fetch reached its900-second delivery timeout, and that failure and its costs remain in failed-public-fetch. It was not retried. The separate3,634,207-byte incremental source bundle still requires the full public f2 prerequisite closure; it does not supply that base by itself.

Offline restore, in a fresh output directory:

```sh
python3 RESTORE.py --package . --output /absolute/new/source-restore
git --git-dir=/absolute/new/source-restore/restored.git worktree add --detach /absolute/new/source-checkout 5ee6d8fec0e5c72d87a36dbed60789de211abf1b
```

RESTORE verifies every pack part and whole pack, requires an initially empty independent store, imports original objects, applies the recorded shallow boundary, compares the entire object inventory, runs strict fsck, and checks all8946 source blob hashes against the original tree inventory. It executes no compiler, proof, native benchmark or model. The actual completed restore receipt is PACKAGE_RESULT.json. Full proof acceptance and performance claims remain those of their separate original records.

This pack contains original Hepta repository objects. Private NDU upstream source/toolchains/model weights and external dependencies are not made available by it. All delivery costs are separate from measured composition costs, and concurrent archive walls must not be added as elapsed time.
'''
        (PUB / 'README.md').open('x').write(readme)
    except BaseException as error:
        outcome['error'] = {'type': type(error).__name__, 'message': str(error)}
    outcome['wall_ns'] = time.monotonic_ns()-start
    outcome['cost_scope'] = 'Offline delivery entry through result preparation; nested pack and restore commands are not additive. The failed900s network attempt is separately retained. No model or experiment was rerun.'
    result = save(PUB / 'PACKAGE_RESULT.json', outcome)
    if outcome['passed']:
        export_start = time.monotonic_ns()
        exports = [export(PUB, OUT / 'base64-export'),
                   export(B / 'composition-v4-public-package-r1/public', B / 'composition-v4-public-package-r1/base64-export')]
        export_result = save(OUT / 'EXPORT_RESULT.json', {'exports': exports, 'wall_ns': time.monotonic_ns()-export_start,
                           'scope': 'Separate delivery-only base64 transport staging; no native/model/proof execution.'})
        outcome['export_result'] = export_result
    print(json.dumps({'result': result, 'passed': outcome['passed'], 'error': outcome['error'],
                      'pack_bytes': outcome.get('pack', {}).get('bytes'), 'wall_ns': outcome['wall_ns'],
                      'export_result': outcome.get('export_result')}, sort_keys=True))
    return 0 if outcome['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
