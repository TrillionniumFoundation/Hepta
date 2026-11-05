"""Finite local typed migration oracle; independent lock expectations, no ABI claims."""
import argparse, collections, hashlib, importlib.util, json, signal, subprocess, sys, tempfile
from pathlib import Path

def sha(b): return hashlib.sha256(b).hexdigest()
def put(p,b):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b if isinstance(b,bytes) else b.encode())
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def expected(app,high):
    selected='candidates/high' if high else 'candidates/low'
    deps={'base64':'stdlib/base64','codec':'stdlib/bytes','order':'stdlib/ordering','utf8':'stdlib/utf8'}
    packages={'.':dict(name='migration_probe',version='0.1.0',kind='bin',entry='src/main.hepta',dependencies={'typed':selected}),selected:dict(name='typed_packet',version='0.2.0' if high else '0.1.0',kind='lib',entry='src/lib.hepta',dependencies=deps)}
    files=['hepta.toml','src/main.hepta',selected+'/hepta.toml',selected+'/src/lib.hepta',selected+'/src/packet.hepta']
    for path in deps.values():
        packages[path]=dict(name='hepta_'+path.split('/')[1],version='0.1.0',kind='lib',entry='src/lib.hepta',dependencies={});files += [path+'/hepta.toml',path+'/src/lib.hepta']
    content=dict(packages=packages,files={p:sha((app/p).read_bytes()) for p in files})
    return dict(schema='hepta.lock.v1',**content,sha256=sha(json.dumps(content,sort_keys=True,separators=(',',':')).encode()))

def manifest(high,reverse=False):
    candidates=['candidates/high','candidates/low'];candidates=candidates[::-1] if reverse else candidates
    return '[package]\nname="migration_probe"\nversion="0.1.0"\nkind="bin"\n[dependencies]\ntyped={package="typed_packet",version="'+('>=0.1.0' if high else '=0.1.0')+'",candidates='+json.dumps(candidates)+'}\n'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);ap.add_argument('--native',action='store_true');args=ap.parse_args()
    if not __debug__: raise RuntimeError('Assertions required')
    root=args.root.resolve();sys.path.insert(0,str(root))
    from hepta.packages import write_lock
    from hepta.pipeline import analyze_project
    from hepta.modules import load_project
    from hepta.lock_diff import compare_locks
    from hepta.ast import HeptaError
    model=module('typed_state_model',Path(__file__).with_name('typed_stdlib_oracle.py'))
    all_cases=model.cases();vectors=[]
    # One case for every error plus empty success, nonempty Unicode and explicit short capacities.
    for stage in range(6):vectors.append(next(c for c in all_cases if model.expected(*c)['stage']==stage))
    vectors += [model.raw_case(b'\0\x08'+ 'éa😀a'.encode(),97,scalars=8),model.raw_case(b'\0\x03abc',98,scalars=2)]
    assert set(model.expected(*c)['stage'] for c in vectors)==set(range(6))
    receipts=[];snapshots=[];identities={}
    with tempfile.TemporaryDirectory(prefix='hepta-independent-migration-') as temp:
        app=Path(temp);put(app/'src/main.hepta',model.source(vectors))
        for part in ('base64','bytes','ordering','utf8'):
            for file in ('hepta.toml','src/lib.hepta'):
                source=root/'stdlib'/part/file;put(app/'stdlib'/part/file,source.read_bytes());identities[str(source.relative_to(root))]=sha(source.read_bytes())
        for name,version in [('low','0.1.0'),('high','0.2.0')]:
            pkg=app/'candidates'/name
            put(pkg/'hepta.toml',f'[package]\nname="typed_packet"\nversion="{version}"\nkind="lib"\n[dependencies]\n'+''.join(f'{alias}={{path="../../stdlib/{part}"}}\n' for alias,part in [('base64','base64'),('codec','bytes'),('order','ordering'),('utf8','utf8')]))
            for file in ('lib.hepta','packet.hepta'):
                src=root/'examples/packages/typed_packet/src'/file;put(pkg/'src'/file,src.read_bytes());identities[str(src.relative_to(root))]=sha(src.read_bytes())
        def execute(label,negative=False):
            a=analyze_project(app,backend='c',locked=True,crate_type='bin');assert a.report['ok'],a.report
            if not args.native:return
            from hepta.c_backend import compile_c
            for opt in (False,True):
                b=compile_c(a.c,output=app/'probe',optimize=opt,sanitize=True);assert b['ok'],b
                assert '-fsanitize=undefined' in b['flags'] and '-fno-sanitize-recover=all' in b['flags']
                p=subprocess.run([str(app/'probe')],capture_output=True,timeout=30)
                assert (p.returncode,p.stdout,p.stderr)==(-signal.SIGABRT if negative else 0,b'',b''),(label,p.returncode,p.stdout,p.stderr)
                receipts.append(dict(label=label,optimized=opt,returncode=p.returncode,flags=b['flags'],artifact_sha256=b['artifact_sha256']))
        previous=None
        for high,reverse in [(False,False),(True,False),(True,True),(False,True)]:
            put(app/'hepta.toml',manifest(high,reverse))
            if previous:
                prior=(app/'Hepta.lock').read_bytes()
                try:load_project(app,locked=True)
                except HeptaError as e:assert e.diagnostic.code=='E_LOCK_STALE'
                else:raise AssertionError('Changed manifest accepted with stale lock')
                assert (app/'Hepta.lock').read_bytes()==prior
            want=expected(app,high);got=write_lock(app)['snapshot'];assert got==want,(got,want)
            lock=app/f'state{len(snapshots)}.json';put(lock,(app/'Hepta.lock').read_bytes())
            if previous:
                d=compare_locks(previous[0],lock);assert d['compatibility']=='not_assessed' and d['changed']
                if previous[1]!=high:
                    before='candidates/high' if previous[1] else 'candidates/low';after='candidates/high' if high else 'candidates/low'
                    assert d['dependencies']['retargeted']==[dict(package='.',alias='typed',before=before,after=after)]
                    assert [x['path'] for x in d['packages']['removed']]==[before]
                    assert [x['path'] for x in d['packages']['added']]==[after]
                    assert not d['packages']['changed']
                else:
                    assert all(not x for x in d['packages'].values()) and all(not x for x in d['dependencies'].values())
                    assert [x['path'] for x in d['files']['changed']]==['hepta.toml']
            snapshots.append(want);previous=(lock,high);execute(f'selection-{len(snapshots)}')
        put(app/'hepta.toml',manifest(True));write_lock(app)
        original=(app/'candidates/high/src/lib.hepta').read_bytes();good_lock=(app/'Hepta.lock').read_bytes();good_snapshot=expected(app,True)
        for label,old,new in [('success-bound',b'lower: result.lower',b'lower: result.lower + 1'),('error-tag',b'PacketError::Decode(done())',b'PacketError::ShortHeader(done())'),('error-payload',b'ScalarCapacity(len(read scalars))',b'ScalarCapacity(len(read scalars) + 1)'),('prefix-canary',b'assert(result.stage == 0);',b'assert(result.stage == 0); scratch[0] = 0;')]:
            assert original.count(old)==1;put(app/'candidates/high/src/lib.hepta',original.replace(old,new));changed=write_lock(app)['snapshot'];assert changed==expected(app,True)
            assert changed['packages']==good_snapshot['packages'] and changed['sha256']!=good_snapshot['sha256']
            a=app/'good.json';b=app/'bad.json';put(a,good_lock);put(b,(app/'Hepta.lock').read_bytes());diff=compare_locks(a,b)
            assert diff['changed'] and diff['compatibility']=='not_assessed'
            assert diff['files']['changed']==[dict(path='candidates/high/src/lib.hepta',before=sha(original),after=sha(original.replace(old,new)))]
            assert all(not v for v in diff['packages'].values()) and all(not v for v in diff['dependencies'].values())
            execute(label,negative=True)
            put(app/'candidates/high/src/lib.hepta',original);put(app/'Hepta.lock',good_lock)
            assert expected(app,True)==good_snapshot;load_project(app,locked=True);execute(label+'-rollback')
    assert identities=={p:sha((root/p).read_bytes()) for p in identities}
    print(json.dumps(dict(result='PASS',native=args.native,states=len(snapshots),vectors=len(vectors),stages=dict(collections.Counter(model.expected(*c)['stage'] for c in vectors)),valid_lock_mutations=4,byte_exact_rollbacks=4,receipts=receipts,source_sha256=identities,oracle_sha256=sha(Path(__file__).read_bytes()),model_sha256=sha(Path(__file__).with_name('typed_stdlib_oracle.py').read_bytes()),scope='Finite synthetic local version migration using real unchanged typed/four-library source; not API compatibility, registry, native Rust or blocker closure'),sort_keys=True))
if __name__=='__main__':main()
