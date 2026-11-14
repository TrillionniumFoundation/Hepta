"""Seal small author metadata only. No source materialization or products."""
from pathlib import Path
import base64, hashlib, json, os, stat, zlib

ROOT=Path('/tmp/hia-op13-execution-author-r3-dda7')
OUT=Path('/tmp/hia-op13-execution-custody-r3-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def enc(value): return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def seven(s): return {k:getattr(s,k) for k in FIELDS}
def put(path,raw):
    with path.open('xb') as f: f.write(raw)
    assert path.read_bytes()==raw
    return {'path':str(path),'pin':pin(raw)}

def capture():
    files={};dirs={}
    def visit(path,rel):
        s=path.lstat();assert stat.S_ISDIR(s.st_mode)
        dirs[rel]={'mode':stat.S_IMODE(s.st_mode),'stat':seven(s)}
        for p in sorted(path.iterdir(),key=lambda p:p.name):
            r=p.relative_to(ROOT).as_posix();a=p.lstat()
            assert not stat.S_ISLNK(a.st_mode)
            if stat.S_ISDIR(a.st_mode): visit(p,r)
            else:
                assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
                raw=p.read_bytes();assert seven(p.lstat())==seven(a)
                row={'path':str(p),'mode':stat.S_IMODE(a.st_mode),'stat':seven(a),'pin':pin(raw)}
                try: row.update(encoding='utf-8',content=raw.decode('utf-8'))
                except UnicodeDecodeError: row.update(encoding='base64',content=base64.b64encode(raw).decode())
                files[r]=row
    visit(ROOT,'.')
    return files,dirs

def decode_file(row):
    return row['content'].encode('utf-8') if row['encoding']=='utf-8' else base64.b64decode(row['content'],validate=True)

def main():
    assert not Path('/tmp/hia-op13-execution-r3-dda7').exists()
    files,dirs=capture();logical=sum(r['pin']['bytes']for r in files.values())
    payload=enc({'schema':'hepta.hia.op13.fixture-successor.author-capsule.v1','root':str(ROOT),
        'files':files,'directories':dirs,'product_executions':0,'binder_execution':0,'source_materialization':0})
    packed=zlib.compress(payload,9);parts=[]
    for i,start in enumerate(range(0,len(packed),240*1024)):
        chunk=packed[start:start+240*1024]
        wrapper=enc({'schema':'hepta.hia.op13.fixture-successor.transport-part.v1','index':i,
            'offset':start,'bytes':len(chunk),'compressed_pin':pin(chunk),'data_base64':base64.b64encode(chunk).decode()})
        row=put(OUT/('part-%03d.json'%i),wrapper);row.update(index=i,offset=start,compressed_pin=pin(chunk));parts.append(row)
    index={'schema':'hepta.hia.op13.fixture-successor.transport-index.v1','root':str(ROOT),
        'files':len(files),'directories':len(dirs),'logical_bytes':logical,'payload':pin(payload),'zlib':pin(packed),
        'parts':parts,'source_materialization':0,'binder_execution':0,'product_executions':0}
    idx=put(OUT/'INDEX.json',enc(index))
    rejoined=b''.join(base64.b64decode(json.loads(Path(r['path']).read_bytes())['data_base64'],validate=True)for r in parts)
    assert rejoined==packed
    d=zlib.decompressobj();decoded=d.decompress(rejoined)+d.flush()
    assert d.eof and not d.unused_data and not d.unconsumed_tail and decoded==payload
    restored=json.loads(decoded)
    assert set(restored['files'])==set(files) and restored['directories']==dirs
    for name,row in restored['files'].items():
        raw=decode_file(row);path=ROOT/name;s=path.lstat()
        assert pin(raw)==row['pin'] and raw==path.read_bytes() and stat.S_IMODE(s.st_mode)==row['mode']
        assert seven(s)==seven(path.lstat())==row['stat']
    final_files,final_dirs=capture();assert final_files==files and final_dirs==dirs
    readback=put(OUT/'LOCAL-READBACK.json',enc({'schema':'hepta.hia.op13.fixture-successor.local-readback.v1',
        'status':'PASS_COMPLETE_AUTHOR_BYTES_MODES_SEVEN_STATS_AND_PATHSETS', 'files':len(files),'directories':len(dirs),
        'logical_bytes':logical,'complete_payload_pin':pin(payload),'complete_zlib_pin':pin(packed),'index':idx,
        'full_zlib_eof':True,'all_originals_unchanged':True,'source_materialization':0,'binder_execution':0,'product_executions':0}))
    leaves=[{'logical':'INDEX.json',**idx},{'logical':'LOCAL-READBACK.json',**readback}]
    leaves += [{'logical':Path(r['path']).name,'path':r['path'],'pin':r['pin']}for r in parts]
    for path in [OUT/'seal_author.py',ROOT/'HANDOFF.json',ROOT/'PREPARATION-PLAN.json',ROOT/'PREPARATION-LAUNCH.json',
        ROOT/'OUTER-INVOCATION.json',ROOT/'STATIC-REVIEW.json',ROOT/'SOURCE-PROJECTION.json',ROOT/'CONTRACT.md']:
        leaves.append({'logical':path.name,'path':str(path),'pin':pin(path.read_bytes())})
    put(OUT/'PUBLICATION-INPUTS.json',enc(leaves))
    print(json.dumps({'status':'PASS_LOCAL_COMPLETE_AUTHOR_READBACK','files':len(files),'directories':len(dirs),
        'logical_bytes':logical,'payload_bytes':len(payload),'zlib_bytes':len(packed),'parts':len(parts),'leaves':len(leaves)}))

if __name__=='__main__': main()
