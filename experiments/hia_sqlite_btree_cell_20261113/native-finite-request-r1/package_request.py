"""Lossless publication of a frozen B-tree native request; no qualification execution."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
ROOT=P/'sqlite-btree-cell-native-r1'
OUT=P/'sqlite-btree-cell-native-r1-publication'
REQ_SHA='52a027b7a31642b10f7860e2cafc430244157e258464f84ec28a17eb19c46993'
PARENT='69a6e96e40499a86db48f76e6d2bc54dd9788d06'
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
    p=Path(p);s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('regular single link')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        if ident(os.fstat(f.fileno()))!=ident(s):raise ValueError('opened identity')
        b=f.read()
        if ident(os.fstat(f.fileno()))!=ident(s):raise ValueError('read identity')
    if ident(p.lstat())!=ident(s) or len(b)!=s.st_size:raise ValueError('named identity')
    return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'git_blob':blob(b),'identity':ident(s)}
def put(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    got,pin=read(p)
    if got!=b:raise ValueError('created bytes')
    return pin
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def main():
    qraw,qpin=read(ROOT/'REQUEST.json')
    if qpin['sha256']!=REQ_SHA:raise ValueError('frozen request changed')
    q=json.loads(qraw)
    if os.path.lexists(q['output']):raise ValueError('request publication must precede actual')
    if OUT.exists():raise ValueError('new publication only')
    OUT.mkdir(mode=0o700)
    originals={}
    for base,dirs,names in os.walk(ROOT,followlinks=False):
        for d in dirs:
            if not stat.S_ISDIR((Path(base)/d).lstat().st_mode):raise ValueError('special directory')
        for name in sorted(names):
            p=Path(base)/name;rel=str(p.relative_to(ROOT));b,pin=read(p)
            originals[rel]=(b,pin)
    for name,expected in q['inputs'].items():
        if originals[name][1]!=expected:raise ValueError('frozen exact input changed '+name)
    archive=OUT/'native-request-originals.tar'
    with tarfile.open(archive,'x',format=tarfile.PAX_FORMAT) as tar:
        for name,(b,pin) in sorted(originals.items()):
            info=tarfile.TarInfo(name);info.size=len(b);info.mode=stat.S_IMODE(pin['identity'][2])
            info.uid=pin['identity'][3];info.gid=pin['identity'][4];info.mtime=0
            tar.addfile(info,io.BytesIO(b))
    compressed=OUT/'native-request-originals.tar.gz'
    with archive.open('rb') as src,compressed.open('xb') as dst:
        with gzip.GzipFile(filename='',mode='wb',fileobj=dst,mtime=0,compresslevel=6) as gz:
            while True:
                b=src.read(1<<20)
                if not b:break
                gz.write(b)
        dst.flush();os.fsync(dst.fileno())
    packed,packed_pin=read(compressed);tar_raw,tar_pin=read(archive)
    if gzip.decompress(packed)!=tar_raw:raise ValueError('full gzip decoding')
    seen=[]
    with tarfile.open(fileobj=io.BytesIO(tar_raw),mode='r:') as tar:
        for item in tar:
            if not item.isfile() or item.name not in originals:raise ValueError('archive member kind/name')
            b,pin=originals[item.name]
            if tar.extractfile(item).read()!=b or item.size!=len(b) or item.mode!=stat.S_IMODE(pin['identity'][2]):
                raise ValueError('archive complete original mismatch')
            seen.append(item.name)
    if seen!=sorted(originals):raise ValueError('archive exact full member set')
    files=[]
    def add(name,b):
        p=put(OUT/name,b);files.append({'path':name,'bytes':p['bytes'],'sha256':p['sha256'],'git_blob_sha1':p['git_blob']})
        return p
    carriers=[]
    for number,offset in enumerate(range(0,len(packed),196608)):
        body=packed[offset:offset+196608]
        name='carriers/part-%03d.b64'%number
        pin=add(name,base64.b64encode(body)+b'\n')
        carriers.append({'path':name,'offset':offset,'decoded_bytes':len(body),'decoded_sha256':sha(body),
            'bytes':pin['bytes'],'sha256':pin['sha256'],'git_blob_sha1':pin['git_blob']})
    mirrored=[]
    for name,(body,pin) in sorted(originals.items()):
        if len(body)>192<<10:continue
        try:body.decode('utf-8')
        except UnicodeDecodeError:continue
        add('text/'+name,body);mirrored.append(name)
    rows=[{'name':n,'bytes':p['bytes'],'sha256':p['sha256'],'git_blob_sha1':p['git_blob'],
        'mode':stat.S_IMODE(p['identity'][2]),'original':p} for n,(_,p) in sorted(originals.items())]
    for name,(b,p) in originals.items():
        after,ap=read(ROOT/name)
        if after!=b or ap!=p:raise ValueError('publication changed original '+name)
    manifest={'schema':'hia.sqlite.btree.cell.native-request-originals.v1','status':'COMPLETE_FROZEN_INPUTS_ONLY',
        'root':str(ROOT),'request':qpin,'original_count':len(rows),'original_bytes':sum(r['bytes'] for r in rows),
        'originals':rows,'tar':tar_pin,'gzip':packed_pin,'carriers':carriers,'mirrored_originals':mirrored,
        'gzip_and_tar_all_originals_roundtrip':True,'all_originals_after_equal':True,
        'shared_source':{'count':1686,'bytes':40890650,'complete_bytes_already_in_parent':PARENT,
            'parent_source_archive_prefix':'experiments/hia_sqlite_btree_cell_20261113/source12-r1-r2-r3-actual-r1'},
        'external_system_files':'4806 complete fixed identities and hashes in included SYSTEM-INPUTS; static freeze physically read them, no runtime qualification implied.',
        'qualifications_executed':0}
    add('ARCHIVE-MANIFEST.json',wire(manifest))
    restore="from pathlib import Path\nimport base64,gzip,hashlib,io,json,tarfile,sys\nroot=Path(sys.argv[1]);out=Path(sys.argv[2])\nm=json.loads((root/'ARCHIVE-MANIFEST.json').read_text())\ndef sha(b):return hashlib.sha256(b).hexdigest()\npacked=bytearray()\nfor row in m['carriers']:\n b=(root/row['path']).read_bytes()\n if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('full carrier')\n raw=base64.b64decode(b,validate=False)\n if len(raw)!=row['decoded_bytes'] or sha(raw)!=row['decoded_sha256'] or len(packed)!=row['offset']:raise ValueError('complete decoded carrier')\n packed.extend(raw)\nif len(packed)!=m['gzip']['bytes'] or sha(packed)!=m['gzip']['sha256']:raise ValueError('whole gzip')\nraw=gzip.decompress(packed)\nif len(raw)!=m['tar']['bytes'] or sha(raw)!=m['tar']['sha256']:raise ValueError('whole tar')\nexpected={r['name']:r for r in m['originals']};seen=set();out.mkdir(mode=0o700,parents=False,exist_ok=False)\nwith tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:\n for item in tar:\n  if not item.isfile() or item.name not in expected or item.name in seen or item.name.startswith('/') or '..' in Path(item.name).parts:raise ValueError('archive namespace')\n  row=expected[item.name];b=tar.extractfile(item).read()\n  if len(b)!=row['bytes'] or sha(b)!=row['sha256'] or item.mode!=row['mode']:raise ValueError('complete member')\n  p=out/item.name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)\n  with p.open('xb') as f:f.write(b)\n  p.chmod(row['mode']);seen.add(item.name)\nif seen!=set(expected):raise ValueError('missing member')\nprint(json.dumps({'originals':len(seen),'bytes':m['original_bytes'],'qualification_executed':False}))\n"
    add('restore_originals.py',restore.encode())
    add('package_request.py',Path(__file__).read_bytes())
    handoff={'schema':'hia.sqlite.btree.cell.native-request-publication.v1','status':'FROZEN_UNEXECUTED_ROOT_REVIEW_REQUIRED',
        'sole_parent':PARENT,'prefix':'experiments/hia_sqlite_btree_cell_20261113/native-finite-request-r1',
        'request':qpin,'execute':originals['EXECUTE.json'][1],'owned_inputs':len(q['inputs']),
        'source_count':1686,'system_count':4806,'originals':len(rows),'original_bytes':manifest['original_bytes'],
        'archive_gzip':packed_pin,'expected_methods':12,'native_returns':339,'oracle_calls_each':253,
        'refused_cases_not_called_each':86,'owner_seconds':180,'cleanup_seconds':3,
        'compiler_wall_seconds':20,'compiler_cpu_seconds':10,'compiler_output_bytes':1<<20,
        'all_original_tests_and_limits_unchanged':True,'actual_still_absent':True,'qualification_executed':False}
    add('HANDOFF.json',wire(handoff))
    put(OUT/'PUBLISH.json',wire({'schema':'hia.sqlite.btree.cell.native-publication-files.v1','files':files,
        'whole_archive_readback':True,'frozen_request':qpin,'qualification_executed':False}))
    print(json.dumps({'output':str(OUT),'status':handoff['status'],'originals':len(rows),'original_bytes':manifest['original_bytes'],
        'gzip':packed_pin,'files':len(files),'carriers':len(carriers),'PUBLISH':read(OUT/'PUBLISH.json')[1]}))
if __name__=='__main__':main()
