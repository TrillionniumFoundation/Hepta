"""Restore only the frozen 1686 current-v92 input bytes; no project import."""
from pathlib import Path
import hashlib, io, json, os, stat, subprocess, time

ROOT=Path(__file__).resolve().parent
ORIGINAL=ROOT/'reference/original-preserved/experiments/hia_sqlite_varint_20261113/source-authoring-r1'
MAP=ORIGINAL/'reference/V92-PHYSICAL-INPUTS.json'
REPO=Path('/workspace/scratch/e26ed3e2edcf/recovered-Hepta-r1')
WORKSPACE=Path('/workspace/scratch/e26ed3e2edcf')
OUTPUT=ROOT/'source-base'

def digest(raw):
    return hashlib.sha256(raw).hexdigest(),hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def write_new(path,raw,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def body_json(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def main():
    started=time.monotonic()
    rawmap=MAP.read_bytes()
    assert hashlib.sha256(rawmap).hexdigest()=='6d17f9b2d9284a8383def0e8c01950b98ff46aeb1f68b327057dd08aef7f187f'
    manifest=json.loads(rawmap)
    rows=manifest['files']
    assert len(rows)==1686 and sum(r['bytes'] for r in rows)==40890650
    assert manifest['commit']=='0504beb11c0dae875d8590660c42488b7bc634fb'
    assert manifest['tree']=='596ab07e8813e4811a8dca51800cd51eb397aeb2'
    assert len({r['path'] for r in rows})==len(rows)
    assert not OUTPUT.exists()
    OUTPUT.mkdir(mode=0o700)
    journal_path=ROOT/'SOURCE-RESTORE-JOURNAL.jsonl'
    jfd=os.open(journal_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    journal=os.fdopen(jfd,'wb')
    def event(value):
        journal.write((json.dumps(value,sort_keys=True)+'\n').encode());journal.flush();os.fsync(journal.fileno())
    def accept(row,raw,origin):
        sha,git=digest(raw)
        assert len(raw)==row['bytes'] and sha==row['sha256'] and git==row['git_blob'],row['path']
        rel=Path(row['path']);assert not rel.is_absolute() and '..' not in rel.parts
        mode=0o755 if row['mode']=='100755' else 0o644
        assert row['mode'] in ('100644','100755')
        path=OUTPUT/rel
        event({'event':'WRITE_INTENT','path':row['path'],'git_blob':git,'bytes':len(raw),'origin':origin})
        write_new(path,raw,mode)
        current=path.read_bytes();s=path.lstat()
        assert current==raw and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
        event({'event':'WRITE_READBACK','path':row['path'],'sha256':sha,'git_blob':git,'bytes':len(raw),'mode':row['mode'],'origin':origin})
        return {**row,'origin':origin,'fresh_bytes_equal':True,'physical_mode':oct(mode)}
    unique=list(dict.fromkeys(r['git_blob'] for r in rows))
    response=subprocess.run(['git','-C',str(REPO),'cat-file','--batch'],input=('\n'.join(unique)+'\n').encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    event({'event':'READ_LOCAL_GIT_BATCH','returncode':response.returncode,'stdout_bytes':len(response.stdout),'stderr':response.stderr.decode(errors='replace')})
    assert response.returncode==0
    stream=io.BytesIO(response.stdout);available={}
    for sha in unique:
        line=stream.readline().decode().rstrip('\n')
        if line==sha+' missing':
            continue
        got,kind,size=line.split()
        assert got==sha and kind=='blob'
        body=stream.read(int(size));assert len(body)==int(size) and stream.read(1)==b'\n'
        assert digest(body)[1]==sha
        available[sha]=body
    assert stream.read()==b''
    accepted=[];missing=[]
    for row in rows:
        if row['git_blob'] in available:
            accepted.append(accept(row,available[row['git_blob']],{'kind':'local_git_blob','repository':str(REPO),'blob':row['git_blob']}))
        else:
            missing.append(row)
    scan=subprocess.run(['rg','--files','--hidden','-g','!.git/**',str(WORKSPACE)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    event({'event':'WORKSPACE_PATH_SCAN','returncode':scan.returncode,'stderr':scan.stderr.decode(errors='replace')})
    assert scan.returncode in (0,2)
    paths=[Path(s) for s in scan.stdout.decode().splitlines()]
    unresolved=[]
    for row in missing:
        suffix='/'+row['path'];found=None
        for p in paths:
            if not str(p).endswith(suffix):
                continue
            try:
                s=p.lstat()
                if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=row['bytes']:
                    continue
                if bool(s.st_mode&0o111)!=(row['mode']=='100755'):
                    continue
                raw=p.read_bytes()
                if digest(raw)!=(row['sha256'],row['git_blob']):
                    continue
                after=p.lstat()
                identity=lambda t:(t.st_dev,t.st_ino,t.st_mode,t.st_uid,t.st_gid,t.st_nlink,t.st_size,t.st_mtime_ns,t.st_ctime_ns)
                assert identity(s)==identity(after)
                found=accept(row,raw,{'kind':'workspace_exact_physical_file','path':str(p),'identity':identity(s)})
                break
            except (PermissionError,FileNotFoundError):
                continue
        if found:
            accepted.append(found)
        else:
            unresolved.append(row)
    report={'schema':'hia.sqlite-varint.source-base-restore.v1','status':'SOURCE_BASE_COMPLETE' if not unresolved else 'SOURCE_BASE_PARTIAL_MISSING_EXPLICIT',
            'source_commit':manifest['commit'],'source_tree':manifest['tree'],'manifest':str(MAP),'manifest_sha256':hashlib.sha256(rawmap).hexdigest(),
            'output':str(OUTPUT),'expected_files':1686,'expected_bytes':40890650,'restored_files':len(accepted),
            'restored_bytes':sum(r['bytes'] for r in accepted),'files':sorted(accepted,key=lambda x:x['path']),'missing':unresolved,
            'source8_executed':False,'project_code_imported':False,'elapsed_seconds':time.monotonic()-started}
    write_new(ROOT/'SOURCE-RESTORE-INITIAL.json',body_json(report))
    journal.close()
    print(json.dumps({k:v for k,v in report.items() if k not in ('files','missing')}))
    print(json.dumps({'missing':unresolved}))
if __name__=='__main__':
    main()
