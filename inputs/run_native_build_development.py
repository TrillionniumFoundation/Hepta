"""Exact 4b + Core R3 + Emitter R4 + Byte whole-emit + NativeBuild functional development.

No complete current-source cold or whole/default qualification is asserted.
All original child deadlines and semantic test bodies remain unchanged.
"""
from __future__ import annotations
import argparse,base64,hashlib,importlib.metadata,json,os,platform,signal,stat,subprocess,sys,time,traceback,zlib
from pathlib import Path,PurePosixPath

BASE='4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE='1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
COMPILER='81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
INDEX_SHA256='fa43e7c6b2380492a8266f7cfc9e5dad2bdcb8ae917426d8626b1bc149d7226d'
FINAL_MAP_SHA256='8a04627ecad7f209a422119ac61adac64594fb4d92cfebe5a3cea36825e3c651'

def digest(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def safe(name):
    p=PurePosixPath(name)
    if type(name)is not str or str(p)!=name or p.is_absolute() or any(k in ('','.','..') for k in p.parts) or '.git' in p.parts:raise ValueError('unsafe source path')
    return name

def decode(path,*,legacy=False):
    raw=path.read_bytes();v=json.loads(raw);compressed=base64.b64decode(v['data'],validate=True)
    if len(compressed)!=v['compressed_bytes'] or digest(compressed)!=v['compressed_sha256']:raise ValueError('compressed input differs: '+path.name)
    obj=zlib.decompressobj();data=obj.decompress(compressed)+obj.flush()
    size=v['bytes'] if legacy else v['raw_bytes'];sha=v['sha256'] if legacy else v['raw_sha256']
    if not obj.eof or obj.unused_data or obj.unconsumed_tail or len(data)!=size or digest(data)!=sha:raise ValueError('decoded input differs: '+path.name)
    return data

def git(source,*args):return subprocess.run(['git','-C',str(source),*args],capture_output=True,check=True).stdout

def snapshot(source,expected):
    result={}
    for name,record in sorted(expected.items()):
        path=source/safe(name);st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or path.is_symlink():raise ValueError('source is not an ordinary file: '+name)
        mode='100755' if st.st_mode&0o111 else '100644';raw=path.read_bytes()
        row={'mode':mode,'bytes':len(raw),'sha256':digest(raw),'blob':blob(raw)}
        if row!=record:raise ValueError('source bytes/mode differ: '+name)
        result[name]=row
    paths={p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file() and '.git' not in p.relative_to(source).parts}
    if paths!=set(expected):raise ValueError('source file membership differs: '+repr(sorted(paths^set(expected))))
    return result

def apply(source,expected,rows,*,core=False):
    seen=set()
    for item in rows:
        name=item['path'];name=name[7:] if core and name.startswith('source/') else name;safe(name)
        if name in seen:raise ValueError('duplicate overlay path')
        seen.add(name);raw=item['content'].encode('utf-8')
        if len(raw)!=item['bytes'] or digest(raw)!=item['sha256'] or blob(raw)!=item.get('blob',item.get('git_blob',item.get('git_blob_sha1'))):raise ValueError('overlay bytes differ: '+name)
        mode=item['mode']
        if core:
            if type(mode) is not int or mode not in (0o644,0o755):raise ValueError('Core overlay POSIX mode differs')
            mode='100755' if mode==0o755 else '100644'
        elif type(mode) is not str or mode not in ('100644','100755'):raise ValueError('overlay Git mode differs')
        target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
        if target.is_symlink():raise ValueError('overlay symlink')
        target.write_bytes(raw);target.chmod(0o755 if mode=='100755' else 0o644)
        expected[name]={'mode':mode,'bytes':len(raw),'sha256':digest(raw),'blob':blob(raw)}
    return sorted(seen)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',required=True,type=Path);parser.add_argument('--input',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);a=parser.parse_args()
    source,inputs,output=a.source.resolve(),a.input.resolve(),a.output.resolve();output.mkdir(mode=0o700)
    report={'schema':'hia.native-build.development-ci.v1','status':'HOLD','base':BASE,'base_tree':TREE,'scope':'CPYTHON_314_NATIVE_BUILD_DEVELOPMENT_ONLY','current_source_cold':False,'whole_qualified':False,'default_selected':False,'deletion':False,'backend_hunks_applied':True,'phases':[],'original_child_compile_seconds':20,'component_outer_seconds':1800,'caller_outer_seconds':1800}
    expected=None;failure=None;start=time.monotonic();authority={}
    def command(argv,label,timeout,env):
        t=time.monotonic();p=subprocess.Popen(argv,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);timed_out=False
        try:out,err=p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(p.pid,signal.SIGKILL);out,err=p.communicate(timeout=30)
        (output/(label+'.stdout')).write_bytes(out);(output/(label+'.stderr')).write_bytes(err)
        row={'label':label,'argv':argv,'timeout_seconds':timeout,'timed_out':timed_out,'returncode':p.returncode,'seconds':time.monotonic()-t,'stdout_bytes':len(out),'stdout_sha256':digest(out),'stderr_bytes':len(err),'stderr_sha256':digest(err)};report['phases'].append(row);print(json.dumps(row),flush=True)
        (output/'RESULT.partial.json').write_bytes(encoded(report));return row
    try:
        if sys.version_info[:3]!=(3,14,4) or sys.implementation.name!='cpython':raise ValueError('actual CPython 3.14.4 is required')
        versions={n:importlib.metadata.version(n) for n in ('jsonschema','z3-solver','setuptools','wheel')}
        if versions!={'jsonschema':'4.26.0','z3-solver':'4.15.4.0','setuptools':'78.1.1','wheel':'0.46.3'}:raise ValueError('fixed original 4b package versions differ')
        report['runtime']={'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'dependencies':versions}
        authority={p.name:{'bytes':p.stat().st_size,'sha256':digest(p.read_bytes()),'git_blob':blob(p.read_bytes())} for p in inputs.iterdir() if p.is_file()}
        report['harness_inputs']=authority
        if git(source,'rev-parse','HEAD').decode().strip()!=BASE or git(source,'rev-parse','HEAD^{tree}').decode().strip()!=TREE or git(source,'status','--porcelain'):
            raise ValueError('exact clean original 4b checkout required')
        base=json.loads(decode(inputs/'base-map.zlib.json'))
        if len(base)!=3153:raise ValueError('complete original 3153 file baseline required')
        entries={}
        for row in git(source,'ls-tree','-r','-z','HEAD').split(b'\0'):
            if not row:continue
            header,name=row.split(b'\t',1);mode,typ,sha=header.decode().split();name=name.decode()
            if typ!='blob':raise ValueError('unsupported source tree entry')
            entries[name]=(mode,sha)
        if entries!={n:(r['mode'],r['blob']) for n,r in base.items()}:raise ValueError('base Git tree differs from frozen map')
        report['source_before']=snapshot(source,base)
        index_raw=(inputs/'OVERLAY-INDEX.json').read_bytes()
        if digest(index_raw)!=INDEX_SHA256:raise ValueError('frozen overlay index differs')
        index=json.loads(index_raw)
        if (index['base']!=BASE or index['base_tree']!=TREE or index['base_files']!=3153
                or index['final_files']!=3203 or index['changed_paths']!=66 or index['new_paths']!=50):
            raise ValueError('exact frozen cumulative source boundary differs')
        final_raw=(inputs/'final-map.zlib.json').read_bytes()
        if digest(final_raw)!=FINAL_MAP_SHA256:raise ValueError('frozen final source map differs')
        final=json.loads(decode(inputs/'final-map.zlib.json'))
        expected=dict(base);seen=set();overlays=[]
        for part in index['parts']:
            name=safe(part['path']);part_raw=(inputs/name).read_bytes()
            if len(part_raw)!=part['bytes'] or digest(part_raw)!=part['sha256'] or blob(part_raw)!=part['git_blob']:
                raise ValueError('overlay transport differs: '+name)
            rows=json.loads(decode(inputs/name))
            names=[row['path'] for row in rows]
            if names!=part['source_paths'] or len(set(names))!=len(names) or seen.intersection(names):
                raise ValueError('overlay source membership differs')
            seen.update(names);overlays.extend(apply(source,expected,rows))
        if len(seen)!=66 or len(expected)!=3203 or expected!=final:
            raise ValueError('complete composed source map differs')
        report['cumulative_overlay_paths']=overlays
        report['source_provenance']=index['source_provenance']
        report['source_after_overlay']=snapshot(source,expected)
        report['git_status_after_overlay']=git(source,'status','--porcelain').decode()
        compiler_bytes=decode(inputs/'compiler.zlib.json')
        if len(compiler_bytes)!=669494 or digest(compiler_bytes)!=COMPILER:raise ValueError('retained compiler input differs')
        compiler=output/'retained-development-compiler.bin';compiler.write_bytes(compiler_bytes)
        report['compiler']={'bytes':len(compiler_bytes),'sha256':digest(compiler_bytes),'provenance':'preserved original 81b6 B3, no current-source cold authority'}
        env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_')};env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(source))
        env['HEPTA_HIA_NATIVE_BUILD_DEVELOPMENT_COMPILER']=str(compiler)
        env['HEPTA_HIA_NATIVE_BUILD_EVIDENCE']=str(output/'component')
        env['HEPTA_HIA_TEST_PACKAGING_PYTHON']=sys.executable
        command([sys.executable,'-B','tools/generate_hia_native_build.py','--check'],'generated-HIA',120,env)
        snapshot(source,expected)
        command([sys.executable,'-B','tools/generate_hia_native_build_foreign.py','--check'],'generated-foreign-ports',120,env)
        snapshot(source,expected)
        command([sys.executable,'-B',str(inputs/'run_native_build_components.py'),'--source',str(source),
                 '--output',str(output/'component-SUMMARY.json')],'component-25',1800,env)
        snapshot(source,expected)
        manifest=output/'component/image/development-manifest.json'
        if manifest.exists():
            command([sys.executable,'-B','tools/qualify_hia_native_build.py','--output',str(output/'original-114'),
                     '--development-manifest',str(manifest)],'original-callers-114',1800,env)
        else:report['missing_caller_prerequisite']='component image manifest absent; no substitute compiler or semantic fallback'
        for name in ('component-SUMMARY.json','original-114/report.json'):
            path=output/name
            if path.exists():report[name]=json.loads(path.read_bytes())
        if (len(report['phases'])==4 and all(row['returncode']==0 and not row['timed_out'] for row in report['phases'])
                and report.get('component-SUMMARY.json',{}).get('status')=='PASS'
                and report.get('original-114/report.json',{}).get('status')=='SELECTED_NATIVE_BUILD_CALLERS_PASS'):
            report['status']='PASS'
    except BaseException as error:
        failure=error;report['failure']={'type':type(error).__name__,'text':str(error),'traceback':traceback.format_exc()}
    finally:
        try:
            if expected is not None:report['source_after']=snapshot(source,expected);report['source_stable']=True
            if authority!={p.name:{'bytes':p.stat().st_size,'sha256':digest(p.read_bytes()),'git_blob':blob(p.read_bytes())} for p in inputs.iterdir() if p.is_file()}:raise ValueError('harness input bytes changed')
        except BaseException as error:
            report['custody_failure']={'type':type(error).__name__,'text':str(error),'traceback':traceback.format_exc()};report['status']='HOLD'
        report['seconds']=time.monotonic()-start
        raw=encoded(report);(output/'RESULT.json').write_bytes(raw)
        # The artifact retains every actual file. The lossless log capsule is a
        # bounded text/report subset, explicitly not the complete binary archive.
        small={}
        for path in sorted(output.rglob('*')):
            if path.is_file() and path.suffix in ('.json','.stdout','.stderr') and path.stat().st_size<4<<20:
                data=path.read_bytes()
                try:content=data.decode('utf-8')
                except UnicodeDecodeError:continue
                small[path.relative_to(output).as_posix()]={'bytes':len(data),'sha256':digest(data),'content':content}
        capsule=encoded({'scope':'LOSSLESS_TEXT_REPORT_SUBSET_FULL_RAW_IN_ARTIFACT','files':small});packed=zlib.compress(capsule,6);text=base64.b64encode(packed).decode();parts=[text[i:i+10000] for i in range(0,len(text),10000)]
        (output/'TEXT-CAPSULE.json.zlib').write_bytes(packed)
        for i,part in enumerate(parts):print('HIA_NATIVE_BUILD_DEVELOPMENT_ZLIB_BASE64 '+json.dumps({'index':i,'count':len(parts),'raw_bytes':len(capsule),'raw_sha256':digest(capsule),'compressed_bytes':len(packed),'compressed_sha256':digest(packed),'data':part}),flush=True)
        print(json.dumps({'status':report['status'],'seconds':report['seconds'],'scope':report['scope']}),flush=True)
    return 0 if report['status']=='PASS' and failure is None else 1
if __name__=='__main__':raise SystemExit(main())
