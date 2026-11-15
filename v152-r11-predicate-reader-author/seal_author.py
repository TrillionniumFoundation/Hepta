"""Small complete author-byte custody. No product, generator or project import."""
from pathlib import Path
import base64,hashlib,json,stat,zlib

ROOT=Path(__file__).resolve().parent
SOURCES={'boundary':Path('/tmp/hia-r11-predicate-controls-author-r1-dda7'),
         'prefix-reader-author':Path('/tmp/hia-r11-prefix-terminal-reader-r1-dda7')}
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def read(path):
    before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
    raw=path.read_bytes();after=path.lstat()
    assert len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in FIELDS)
    return raw,stat.S_IMODE(before.st_mode),{k:getattr(before,k) for k in FIELDS}
def write(name,raw):
    path=ROOT/name;path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(raw)
    path.chmod(0o644);assert read(path)[:2]==(raw,0o644)
def main():
    paths={}
    for label,root in SOURCES.items():
        for path in sorted(root.rglob('*')):
            if path.is_file():paths[label+'/'+path.relative_to(root).as_posix()]=path
    paths['custody/seal_author.py']=Path(__file__)
    rows={};manifest={}
    for name,path in paths.items():
        raw,mode,stamp=read(path)
        rows[name]={'identity':pin(raw),'mode':mode,'data_base64':base64.b64encode(raw).decode()}
        manifest[name]={'path':str(path),'identity':pin(raw),'mode':mode,'seven_stats':stamp}
    decoded=encode({'schema':'hia.R11.complete-boundary-and-prefix-reader-author-files.v1','files':rows})
    compressed=zlib.compress(decoded,9)
    capsule={'schema':'hia.R11.complete-author-capsule.v1','encoding':'zlib+base64',
             'decoded':pin(decoded),'compressed':pin(compressed),'data':base64.b64encode(compressed).decode()}
    capsule_raw=encode(capsule);write('AUTHOR-CAPSULE.json',capsule_raw)
    parts=[]
    for index,start in enumerate(range(0,len(capsule_raw),180000)):
        data=capsule_raw[start:start+180000];name='parts/AUTHOR-'+str(index).zfill(3)+'.txt'
        write(name,data);parts.append({'mount':name,'path':str(ROOT/name),'identity':pin(data),'start':start})
    collected=b''.join(read(Path(row['path']))[0] for row in parts)
    assert collected==capsule_raw
    wrapper=json.loads(collected);packed=base64.b64decode(wrapper['data'],validate=True)
    decoder=zlib.decompressobj();full=decoder.decompress(packed,len(decoded)+1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and full==decoded
    restored=json.loads(full)['files'];assert set(restored)==set(paths)
    for name,row in restored.items():
        raw=base64.b64decode(row['data_base64'],validate=True);current,mode,stamp=read(paths[name])
        assert raw==current and pin(raw)==row['identity']==manifest[name]['identity']
        assert mode==row['mode']==manifest[name]['mode'] and stamp==manifest[name]['seven_stats']
    for label,root in SOURCES.items():
        assert ({label+'/'+path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}
                =={name for name in paths if name.startswith(label+'/')})
    index={'schema':'hia.R11.complete-author-index.v1','files':manifest,'file_count':len(rows),
           'logical_bytes':sum(row['identity']['bytes'] for row in rows.values()),'capsule':pin(capsule_raw),
           'parts':parts,'complete_local_readback':True,'products':0,'binders':0}
    write('AUTHOR-INDEX.json',encode(index))
    targets=[(label+'/'+name,SOURCES[label]/name) for label,names in (
        ('boundary',('HANDOFF.json','EXECUTION-PLAN.json','LAUNCH.json','CONTRACT.md','STATIC-INVERSE.json',
                     'run_predicate_gate.py','predicate_logic.py','trace_machine.py','boundary_cases.py')),
        ('prefix-reader-author',('HANDOFF.json','READER-LAUNCH.json','EXACT-INVERSE.json'))) for name in names]
    targets += [('AUTHOR-INDEX.json',ROOT/'AUTHOR-INDEX.json'),('seal_author.py',Path(__file__))]
    publish=[{key:value for key,value in row.items() if key!='start'} for row in parts]
    publish += [{'mount':name,'path':str(path),'identity':pin(read(path)[0])} for name,path in targets]
    write('PUBLISH-PLAN.json',encode(publish))
    print(json.dumps({'files':len(rows),'logical_bytes':index['logical_bytes'],'capsule':pin(capsule_raw),
                      'index':pin(encode(index)),'leaves':len(publish),'products':0,'binders':0},sort_keys=True))
if __name__=='__main__':main()
