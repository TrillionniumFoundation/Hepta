"""Exact-source selected-release launcher DEVELOPMENT, without cold authority."""
from __future__ import annotations
import argparse,base64,gzip,hashlib,io,json,os,re,shutil,signal,stat,subprocess,sys,tarfile,time,traceback
from pathlib import Path,PurePosixPath
import urllib.error,urllib.parse,urllib.request,zipfile,zlib

HERE=Path(__file__).resolve().parents[1]
def check(ok,message):
    if not ok:raise RuntimeError(message)
def strict(raw):
    def pairs(items):
        result={}
        for k,v in items:
            check(k not in result,'duplicate JSON key '+k);result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def rawjson(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def identity(raw):return {'bytes':len(raw),'sha256':sha(raw),'git_blob':oid('blob',raw)}
def match(raw,pin):
    check(identity(raw)=={k:pin[k] for k in ('bytes','sha256','git_blob')},'content identity mismatch')
def safe(name):
    p=PurePosixPath(name)
    check(type(name) is str and name and '\0' not in name and '\\' not in name and
          not p.is_absolute() and p.as_posix()==name and all(x not in ('','.','..','.git') for x in p.parts),'unsafe path')
    return p
def write(path,raw,mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw)
    path.chmod(mode);check(path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode,'write readback')
def tree(rows):
    root={}
    for row in rows:
        node=root;parts=safe(row['path']).parts
        for part in parts[:-1]:node=node.setdefault(part,{})
        check(parts[-1] not in node,'duplicate tree path')
        node[parts[-1]]=(row['mode'],row['git_blob'])
    def finish(node):
        entries=[]
        for name,value in node.items():
            if isinstance(value,dict):mode,blob,key='40000',finish(value),(name+'/').encode()
            else:mode,blob=value;key=name.encode()
            entries.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(blob)))
        return oid('tree',b''.join(value for key,value in sorted(entries)))
    return finish(root)
def snapshot(source):
    rows=[]
    for p in sorted(source.rglob('*')):
        if p.is_dir():continue
        check(not p.is_symlink() and p.is_file(),'unexpected source kind')
        raw=p.read_bytes();rows.append({'path':p.relative_to(source).as_posix(),
            'mode':format(stat.S_IMODE(p.stat().st_mode)|stat.S_IFREG,'o'),**identity(raw)})
    return sorted(rows,key=lambda row:row['path'])
def git(args,work,evidence,label,token=None,stdin=None):
    env={k:v for k,v in os.environ.items() if not k.startswith(('GITHUB_','GH_','GIT_'))}
    env.update({'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_TERMINAL_PROMPT':'0',
                'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'core.hooksPath','GIT_CONFIG_VALUE_0':os.devnull})
    if token is not None:
        env.update({'GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_1':'http.https://github.com/.extraheader',
          'GIT_CONFIG_VALUE_1':'AUTHORIZATION: basic '+base64.b64encode(('x-access-token:'+token).encode()).decode()})
    p=subprocess.run(['git',*args],input=stdin,cwd=work,env=env,capture_output=True,timeout=600)
    write(evidence/'git'/(label+'.stderr'),p.stderr)
    write(evidence/'git'/(label+'.json'),rawjson({'argv':['git',*args],'returncode':p.returncode,
         'stdout':identity(p.stdout),'stderr':identity(p.stderr),'authentication_supplied':token is not None}))
    check(p.returncode==0,'git operation failed '+label)
    return p.stdout
def known_objects(config,bare,work,evidence):
    known=set()
    for row in config['fixed_originals']:
        commit=git(['--git-dir='+str(bare),'cat-file','commit',row['commit']],work,evidence,'commit-'+row['commit'])
        check(oid('commit',commit)==row['commit'] and commit.splitlines()[0]==('tree '+row['tree']).encode(),'fixed commit')
        write(evidence/'fixed-commits'/(row['commit']+'.txt'),commit)
        raw=git(['--git-dir='+str(bare),'ls-tree','-r','-z','--full-tree',row['commit']],work,evidence,'tree-'+row['commit'])
        entries=[]
        for item in raw.split(b'\0'):
            if not item:continue
            header,path=item.split(b'\t',1);mode,kind,blob=header.decode().split()
            check(kind=='blob' and mode in ('100644','100755','120000'),'unexpected fixed Git member')
            entries.append({'path':path.decode(),'mode':mode,'git_blob':blob});known.add(blob)
        check(len(entries)==row['files'] and tree(entries)==row['tree'],'fixed tree mismatch')
    return known
def blobs(bare,wanted,work,evidence):
    wanted=sorted(set(wanted));raw=git(['--git-dir='+str(bare),'cat-file','--batch'],work,evidence,'blobs',
        stdin=('\n'.join(wanted)+'\n').encode())
    result={};at=0
    for blob in wanted:
        end=raw.index(b'\n',at);fields=raw[at:end].decode().split()
        check(len(fields)==3 and fields[:2]==[blob,'blob'],'missing fixed blob')
        size=int(fields[2]);at=end+1;value=raw[at:at+size];at+=size
        check(raw[at:at+1]==b'\n' and oid('blob',value)==blob,'cat-file bytes');at+=1;result[blob]=value
    check(at==len(raw),'extra cat-file bytes');return result
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def download(config,work,evidence,token):
    pin=config['original_artifact'];url=f"https://api.github.com/repos/{config['repository']}/actions/artifacts/{pin['artifact']}/zip"
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
        'X-GitHub-Api-Version':'2022-11-28','User-Agent':'hia-selected-launch-development'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=90) as response:
            raise RuntimeError('artifact API unexpectedly returned no redirect')
    except urllib.error.HTTPError as error:
        check(error.code in (301,302,303,307,308),'artifact API error '+str(error.code))
        target=error.headers.get('Location');error.close()
    parsed=urllib.parse.urlparse(target)
    check(parsed.scheme=='https' and parsed.username is None and parsed.password is None,'unsafe download redirect')
    path=work/'original-artifact.zip';h=hashlib.sha256();count=0
    # This is a new unauthenticated request. Never forward the API header.
    with urllib.request.urlopen(urllib.request.Request(target,headers={'User-Agent':'hia-selected-launch-development'}),timeout=120) as response,path.open('xb') as output:
        while chunk:=response.read(1024*1024):
            count+=len(chunk);check(count<=pin['bytes'],'artifact larger than pinned length');h.update(chunk);output.write(chunk)
    check(count==pin['bytes'] and h.hexdigest()==pin['sha256'],'artifact ZIP identity')
    write(evidence/'DOWNLOAD.json',rawjson({'bytes':count,'sha256':h.hexdigest(),'redirect_host':parsed.hostname,
        'authorization_forwarded_to_signed_url':False,'original':pin}))
    return path
def prepare(config,work,evidence,local_raw=None,local_git=None):
    token=os.environ.get('GITHUB_TOKEN')
    check(local_raw is not None or bool(token),'read-only Actions token missing')
    if local_raw is None:
        archive=download(config,work,evidence,token);z=zipfile.ZipFile(archive)
        members=z.infolist();names=[m.filename for m in members]
        check(len(members)==config['original_artifact']['zip_members'] and len(set(names))==len(names),'ZIP inventory')
        for m in members:
            safe(m.filename.rstrip('/'));check(not stat.S_ISLNK(m.external_attr>>16),'ZIP symlink')
            if not m.is_dir():
                with z.open(m) as s:
                    while s.read(1024*1024):pass
        write(evidence/'ZIP-CRC.json',rawjson({'members':len(members),'all_members_crc_read':True}))
        member=lambda path:z.read(path)
    else:
        member=lambda path:(local_raw/path).read_bytes()
    raw=member(config['original_terminal_index']['path']);match(raw,config['original_terminal_index'])
    write(evidence/'ORIGINAL-TERMINAL-INDEX.json',raw);index=strict(raw);rows=index['files']
    check(index['fixed_original_dependency_commits']==[x['commit'] for x in config['fixed_originals']],'dependency set')
    check(index['self_contained'] is False and index['changed_or_new_content_bytes_included'] is True,'terminal custody format')
    check(len(rows)==config['original_terminal_files'] and sum(x['bytes'] for x in rows)==config['original_terminal_bytes'],'terminal dimensions')
    check(len({r['path'] for r in rows})==len(rows),'duplicate terminal path')
    dependent=[r for r in rows if r['content_custody'].get('kind')=='exact_fixed_original_git_blob']
    check(len(rows)-len(dependent)==config['original_terminal_captured'],'captured source count')
    if local_git is None:
        bare=work/'fixed.git';git(['init','--bare','--object-format=sha1',str(bare)],work,evidence,'init')
        git(['--git-dir='+str(bare),'fetch','--no-tags','--depth=1','--no-write-fetch-head',
             'https://github.com/'+config['repository']+'.git',*[r['commit'] for r in config['fixed_originals']]],work,evidence,'fetch-fixed',token=token)
    else:bare=local_git
    known=known_objects(config,bare,work,evidence)
    check(all(r['blob'] in known and r['content_custody']['blob']==r['blob'] for r in dependent),'unreachable source dependency')
    raw_objects=blobs(bare,[r['blob'] for r in dependent],work,evidence)
    source=work/'source';source.mkdir();original=[]
    for r in sorted(rows,key=lambda x:x['path']):
        check(r['kind']=='regular' and type(r['mode']) is int and r['mode']==0o644,'unexpected source file kind')
        custody=r['content_custody'];name=safe(r['path'])
        if custody.get('kind')=='exact_fixed_original_git_blob':value=raw_objects[r['blob']]
        else:
            check('kind' not in custody and custody['file']=='terminal-worktree-bytes/'+r['blob']+'.blob','captured member path')
            value=member('raw/'+custody['file'])
            match(value,{'git_blob':custody['blob'],'bytes':custody['bytes'],'sha256':custody['sha256']})
        match(value,{'git_blob':r['blob'],'bytes':r['bytes'],'sha256':r['sha256']})
        write(source/name,value,r['mode']);original.append({'path':r['path'],'mode':'100644',**identity(value)})
    check(tree(original)==config['original_terminal_tree'],'terminal source tree')
    for name,pin in config['frozen_overrides'].items():
        value=(HERE/'frozen-e295-overrides'/safe(name)).read_bytes();match(value,pin)
        check(name in {x['path'] for x in original},'replacement missing preimage')
        (source/name).write_bytes(value)
    base=snapshot(source);check(tree(base)==config['exact_base_tree'],'restored e295 tree')
    packet_raw=(HERE/config['source_packet']['path']).read_bytes();match(packet_raw,config['source_packet'])
    wrapper=strict(packet_raw);payload=zlib.decompress(base64.b64decode(wrapper['payload'],validate=True));match(payload,wrapper)
    packet=strict(payload);check(packet['base_tree']==config['exact_base_tree'],'packet base')
    check(base==sorted(packet['base_files'],key=lambda r:r['path']),'full 2984 base map')
    check(len(packet['files'])==6,'owner delta count')
    for name,row in packet['files'].items():
        check(row['before'] is None and not (source/name).exists(),'new-source preimage')
        value=row['text'].encode();match(value,row);write(source/safe(name),value,int(row['mode'][-3:],8))
    final=snapshot(source)
    check(final==packet['final_files'] and len(final)==config['final_files'] and tree(final)==config['final_tree'],'complete owner source identity')
    write(evidence/'SOURCE-MANIFEST.json',rawjson({'base_tree':config['exact_base_tree'],'tree':tree(final),'files':final,'whole_native':False}))
    for name,pin in config['driver_inputs'].items():
        raw=(HERE/'inputs'/safe(name)).read_bytes();match(raw,pin);write(work/name,raw)
    if local_raw is None:z.close()
    return source,final,packet
def command(argv,cwd,env,evidence,label):
    started=time.monotonic_ns();folder=evidence/'commands'/label;folder.mkdir(parents=True)
    write(folder/'COMMAND.json',rawjson({'argv':argv,'cwd':str(cwd),'wall_seconds':1800,'cleanup_seconds':5}))
    timeout=False
    with (folder/'stdout').open('wb') as out,(folder/'stderr').open('wb') as err:
        p=subprocess.Popen(argv,cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True)
        try:rc=p.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            timeout=True
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            rc=p.wait(timeout=5)
    report={'argv':argv,'returncode':rc,'timed_out':timeout,'wall_ns':time.monotonic_ns()-started,
            'stdout':identity((folder/'stdout').read_bytes()),'stderr':identity((folder/'stderr').read_bytes()),
            'status':'PASS' if rc==0 and not timeout else 'FAIL'}
    write(folder/'REPORT.json',rawjson(report));return report
def retain(work,evidence):
    paths=[]
    for name in ('source','development-build-r1','agent-payload-development-r1','controls','kernel'):
        p=work/name
        if p.exists():paths.extend([p,*p.rglob('*')])
    records=[]
    with tarfile.open(evidence/'COMPLETE-DEVELOPMENT-INPUTS-OUTPUTS.tar.gz','w:gz',compresslevel=1,dereference=False) as tar:
        for p in paths:
            rel=p.relative_to(work).as_posix();mode=stat.S_IMODE(p.lstat().st_mode)
            if p.is_symlink():records.append({'path':rel,'kind':'symlink','mode':mode,'target':os.readlink(p)})
            elif p.is_file():records.append({'path':rel,'kind':'regular','mode':mode,**identity(p.read_bytes())})
            else:records.append({'path':rel,'kind':'directory','mode':mode})
            tar.add(p,arcname=rel,recursive=False)
    write(evidence/'COMPLETE-ARTIFACT-MANIFEST.json',rawjson(records))
    with tarfile.open(evidence/'COMPLETE-DEVELOPMENT-INPUTS-OUTPUTS.tar.gz','r:gz') as tar:
        members=tar.getmembers();check(len(members)==len(records),'archive member count')
        for row,m in zip(records,members):
            check(m.name==row['path'] and m.mode==row['mode'],'archive path/mode')
            if row['kind']=='regular':match(tar.extractfile(m).read(),row)
            elif row['kind']=='symlink':check(m.issym() and m.linkname==row['target'],'archive symlink')
            else:check(m.isdir(),'archive directory')
def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--local-artifact-tree',type=Path);p.add_argument('--local-gitdir',type=Path);p.add_argument('--prepare-only',action='store_true')
    args=p.parse_args();work=args.work.resolve();evidence=args.evidence.resolve();work.mkdir(parents=True);evidence.mkdir(parents=True)
    config=strict((HERE/'inputs/CONFIG.json').read_bytes());report={'status':'FAIL','scope':'DEVELOPMENT_NOT_COLD_OR_WHOLE',
        'python':sys.version,'whole_native':False,'matching_cold':False,'original_source_run_status':'FAILED_SOURCE_TESTS_NOT_INHERITED',
        'stages':[],'prepare_only':args.prepare_only}
    try:
        check(args.prepare_only or sys.version_info[:3]==(3,14,4),'CPython3.14.4 required')
        source,before,packet=prepare(config,work,evidence,args.local_artifact_tree,args.local_gitdir)
        report['source_tree']=tree(before)
        if args.prepare_only:report['status']='PREPARATION_PASS';return 0
        env={k:v for k,v in os.environ.items() if not k.startswith(('GITHUB_','GH_','ACTIONS_','HEPTA_'))}
        env['PYTHONDONTWRITEBYTECODE']='1'
        for label,argv in (
            ('fresh-development-build',[sys.executable,'-B',str(work/'development_build.py'),str(work/'development-build-r1')]),
            ('actual-hia-agent-payload',[sys.executable,'-B',str(work/'build_agent_payload.py'),str(work/'agent-payload-development-r1')])):
            result=command(argv,source,env,evidence,label);report['stages'].append(result)
            check(result['status']=='PASS','build stage failed '+label)
            check(snapshot(source)==before,'source changed during build')
        env['HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_BUILD']=str(work/'development-build-r1/BUILD.json')
        env['HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_AGENT']=str(work/'agent-payload-development-r1/AGENT.json')
        (work/'controls').mkdir()
        for group,count in zip(config['groups'],config['tests']):
            env['HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_EVIDENCE']=str(work/'kernel'/group)
            argv=[sys.executable,'-B',str(work/'run_launch_controls.py'),'--group',group,'--output',str(work/'controls'/group)]
            result=command(argv,source,env,evidence,group);report['stages'].append(result)
            path=work/'controls'/group/'REPORT.json'
            if path.exists():
                child=strict(path.read_bytes());expected=packet['local_control_ids'] if group=='local-observations' else packet['pending_required_ids']
                result['strict_child_pass']=(child['status']=='PASS' and child['tests_run']==count and child['source_unchanged'] is True
                    and child['loaded_ids']==child['executed_ids']==expected and not any(child['anomalies'].values()))
            else:result['strict_child_pass']=False
        after=snapshot(source);report['source_unchanged']=before==after
        report['status']='PASS' if report['source_unchanged'] and all(x['status']=='PASS' and x.get('strict_child_pass',True) for x in report['stages']) else 'FAIL'
        report['complete26_development_controls']=report['status']=='PASS'
        return 0 if report['status']=='PASS' else 1
    except BaseException:
        report['error']=traceback.format_exc();raise
    finally:
        if 'source' in locals() and 'before' in locals():
            final=snapshot(source);report['source_unchanged']=before==final
            write(evidence/'SOURCE-AFTER.json',rawjson(final))
            if before!=final:report['status']='FAIL'
        write(evidence/'REPORT.json',rawjson(report))
        if not args.prepare_only:
            try:retain(work,evidence)
            except BaseException:
                write(evidence/'CUSTODY-ERROR.txt',traceback.format_exc().encode());raise
        print(json.dumps({k:report[k] for k in ('status','scope','whole_native','matching_cold')},sort_keys=True))
        if report.get('source_unchanged') is False:raise RuntimeError('final source guard failed')

if __name__=='__main__':raise SystemExit(main())
