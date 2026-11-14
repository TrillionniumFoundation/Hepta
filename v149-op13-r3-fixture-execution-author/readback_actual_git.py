"""Restore the returned immutable blob bytes in memory and compare all authors."""
from pathlib import Path
import base64, hashlib, json, stat, zlib

ROOT=Path('/tmp/hia-op13-execution-author-r3-dda7')
OUT=Path('/tmp/hia-op13-execution-custody-r3-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def pin(b):
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def checked(path,identity):
    s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
    b=path.read_bytes();assert pin(b)==identity and seven(s)==seven(path.lstat());return b

def main():
    rows=json.loads((OUT/'PUBLICATION-INPUTS.json').read_bytes())
    index_row=next(r for r in rows if r['logical']=='INDEX.json')
    index=json.loads(checked(OUT/'actual-git/INDEX.json',index_row['pin']))
    parts=[];offset=0
    for i,row in enumerate(index['parts']):
        original=next(r for r in rows if r['logical']==Path(row['path']).name)
        wrapper=json.loads(checked(OUT/'actual-git'/original['logical'],original['pin']))
        assert row['index']==wrapper['index']==i and row['offset']==wrapper['offset']==offset
        b=base64.b64decode(wrapper['data_base64'],validate=True)
        assert pin(b)==row['compressed_pin']==wrapper['compressed_pin']and len(b)==wrapper['bytes']
        parts.append(b);offset+=len(b)
    packed=b''.join(parts);assert pin(packed)==index['zlib']
    decoder=zlib.decompressobj();payload=decoder.decompress(packed)+decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(payload)==index['payload']
    restored=json.loads(payload);assert restored['root']==str(ROOT)
    files=restored['files'];dirs=restored['directories'];logical=0
    assert len(files)==index['files']==36 and len(dirs)==index['directories']==3
    for name,row in files.items():
        assert not Path(name).is_absolute() and all(p not in ('','.','..')for p in name.split('/'))
        b=row['content'].encode()if row['encoding']=='utf-8'else base64.b64decode(row['content'],validate=True)
        assert pin(b)==row['pin'];path=ROOT/name;s=path.lstat()
        assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and seven(s)==row['stat']
        assert stat.S_IMODE(s.st_mode)==row['mode']and path.read_bytes()==b and seven(path.lstat())==row['stat']
        logical+=len(b)
    actual_files=set();actual_dirs={}
    def visit(path,rel):
        s=path.lstat();assert stat.S_ISDIR(s.st_mode)
        actual_dirs[rel]={'mode':stat.S_IMODE(s.st_mode),'stat':seven(s)}
        for p in path.iterdir():
            r=p.relative_to(ROOT).as_posix();s=p.lstat();assert not stat.S_ISLNK(s.st_mode)
            if stat.S_ISDIR(s.st_mode):visit(p,r)
            else:assert stat.S_ISREG(s.st_mode);actual_files.add(r)
    visit(ROOT,'.')
    assert actual_files==set(files)and actual_dirs==dirs and logical==index['logical_bytes']
    for name,row in files.items():assert seven((ROOT/name).lstat())==row['stat']
    result={'schema':'hepta.hia.op13.fixture-successor.actual-git-readback.v1',
        'status':'PASS_FULL_ACTUAL_GET_REASSEMBLY_AND_AUTHOR_BYTES_MODES_SEVEN_STATS',
        'files':len(files),'directories':len(dirs),'logical_bytes':logical,'parts':len(parts),
        'payload':index['payload'],'zlib':index['zlib'],'source_materialization':0,'binder_execution':0,
        'product_executions':0,'all_source_author_files_unchanged':True,'whole':False}
    with(OUT/'ACTUAL-GIT-READBACK.json').open('xb')as f:f.write(enc(result))
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
