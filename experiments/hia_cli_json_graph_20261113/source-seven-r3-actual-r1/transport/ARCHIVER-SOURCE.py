"""Seal existing closed R3 actual originals; no product or source generation."""
import base64,gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3-actual-publication-r1')
BASE=Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3')
AUDIT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3-actual-audit-r1')
PARENT=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
FIELDS=('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')
def ident(st):return [getattr(st,'st_'+k) for k in FIELDS]
def hashes(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
def read(path):
    path=Path(path);st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_uid!=os.geteuid():raise ValueError('owned regular single-link '+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if ident(os.fstat(fd))!=ident(st):raise ValueError('opened identity')
        out=bytearray()
        while len(out)<st.st_size:
            x=os.read(fd,min(65536,st.st_size-len(out)))
            if not x:raise ValueError('short read')
            out.extend(x)
        if os.read(fd,1) or ident(os.fstat(fd))!=ident(st) or ident(path.lstat())!=ident(st):raise ValueError('changed read')
    finally:os.close(fd)
    raw=bytes(out)
    return raw,dict(path=str(path),mode=stat.S_IMODE(st.st_mode),identity=ident(st),**hashes(raw))
def wire(o):return(json.dumps(o,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode()
def create(path,raw):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        v=memoryview(raw)
        while v:
            n=os.write(fd,v)
            if n<=0:raise OSError('short archive write')
            v=v[n:]
        os.fsync(fd)
    finally:os.close(fd)
    got,rec=read(path)
    if got!=raw:raise ValueError('new evidence readback')
    return rec
def walk(root):
    names=[]
    for parent,dirs,files in os.walk(root,followlinks=False):
        for n in dirs:
            if not stat.S_ISDIR((Path(parent)/n).lstat().st_mode):raise ValueError('non-directory link')
        for n in files:names.append(Path(parent)/n)
    return sorted(names)
def main():
    # The exact fixed parent receipt is the first original opened.
    raw,g=read(BASE/'guardian/guardian.json')
    if g['sha256']!='0f8323882df8f9d48cfccdf7b2ce622b2fef4585c81c0095f2dd803f81e8a141':raise ValueError('guardian pin')
    v=json.loads(raw);l=v['lifecycle'];c=l['cleanup']
    if (v['status']!='EXTERNAL_OWNED_PROCESS_COMPLETED' or l['schema']!='hepta.hia.external-qualification-guardian.v1.lifecycle'
        or l['qualification_seconds']!=180 or l['cleanup_seconds']!=3 or l['returncode']!=0
        or l['subreaper_enabled'] is not True or c['complete'] is not True or c['observed_echild'] is not True
        or c['leader_reaped'] is not True or c['errors']!=[] or c['remaining_direct_children']!=[]
        or c['deadline_exceeded'] is not False):raise ValueError('unclosed owner')
    rootread,rootpin=read(PARENT/'root-cli-source7-r3-OWNER-READBACK.json')
    if rootpin['sha256']!='bde3d2c9508a2ed79ec918d37ba85d78e3c4c2a8513225376f1abb388b618381':raise ValueError('root final readback')
    auditraw,auditpin=read(AUDIT/'AUDIT.json')
    if auditpin['sha256']!='8a8f628cbb50998a76e384356ab48a053b52b67b2c2e9a31eecb54c1c7fba006':raise ValueError('independent audit')
    selected=[]
    for category,directory in [('actual',BASE/'actual'),('independent-audit',AUDIT),('audit-transport',ROOT/'transport')]:
        for p in walk(directory):selected.append((category+'/'+p.relative_to(directory).as_posix(),p))
    for n in ('root-cli-source7-r3-execution-INTENT.json','root-cli-source7-r3-OWNER-READBACK.json','root-cli-source7-r3-HJOB-ACK.json','root-cli-source7-r3-HJOB-STATUS.json','root-cli-source7-r3-HJOB-OUTPUT.json','root-cli-source7-r3-static.py','root-cli-source7-r3-static-r1/READBACK.json'):
        selected.append(('root-execution/'+n,PARENT/n))
    for n in ('REQUEST.json','guardian.json','child.stdout.log','child.stderr.log'):selected.append(('guardian/'+n,BASE/'guardian'/n))
    selected.append(('control/CONFIG.json',BASE/'control/CONFIG.json'))
    selected.append(('control/PREEXEC.json',BASE/'PREEXEC.json'))
    selected.sort()
    originals=[];bodies={};seen=set()
    for name,p in selected:
        if name in seen or name.startswith('/') or '..' in Path(name).parts:raise ValueError('archive name')
        seen.add(name);raw,rec=read(p);originals.append({'member':name,**rec});bodies[name]=raw
    if len([x for x in originals if x['member'].startswith('actual/')])!=38:raise ValueError('complete38 actual')
    manifest={'schema':'hia.cli-json.source-seven.r3.closed-archive-manifest.v1','original_status':'SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN',
              'scope':'All 38 actual files, guardian request/receipt/logs, configuration/preexec, the seven stopped Root execution/static proof files and independent audit plus actual audit transport. Fixed source198/system14 are identified by existing request, not falsely counted as all archived runtime binaries.',
              'source_request_commit':'a66b7478ad1596384c5aa137aa0b652a79a16cae',
              'members':originals,'files':len(originals),'raw_bytes':sum(r['bytes'] for r in originals)}
    create(ROOT/'ARCHIVE-MANIFEST.json',wire(manifest))
    tar_buffer=io.BytesIO()
    with tarfile.open(fileobj=tar_buffer,mode='w',format=tarfile.PAX_FORMAT) as tf:
        for row in originals:
            info=tarfile.TarInfo(row['member']);info.size=row['bytes'];info.mode=row['mode'];info.uid=0;info.gid=0;info.mtime=0
            tf.addfile(info,io.BytesIO(bodies[row['member']]))
    tarraw=tar_buffer.getvalue();gz=gzip.compress(tarraw,compresslevel=6,mtime=0)
    archive=create(ROOT/'ORIGINALS.tar.gz',gz)
    decoded=gzip.decompress(read(ROOT/'ORIGINALS.tar.gz')[0])
    if decoded!=tarraw:raise ValueError('complete gzip decode differs')
    with tarfile.open(fileobj=io.BytesIO(decoded),mode='r:') as tf:
        members=tf.getmembers()
        if [m.name for m in members]!=[r['member'] for r in originals] or any(not m.isfile() for m in members):raise ValueError('complete archive membership')
        for m,row in zip(members,originals):
            data=tf.extractfile(m).read()
            if hashes(data)!={k:row[k] for k in ('bytes','sha256','git_blob')} or data!=bodies[m.name] or m.mode!=row['mode']:raise ValueError('member full bytes')
    for row in originals:
        raw,now=read(row['path'])
        if {k:row[k] for k in now}!=now or raw!=bodies[row['member']]:raise ValueError('original changed after archive')
    parts=[]
    for i,at in enumerate(range(0,len(gz),147456)):
        raw=base64.b64encode(gz[at:at+147456])+b'\n'
        part=create(ROOT/'parts'/('part-%03d.base64.txt'%i),raw);parts.append(part)
    rebuilt=b''.join(base64.b64decode(read(x['path'])[0],validate=False) for x in parts)
    if rebuilt!=gz:raise ValueError('full base64 restoration')
    keys=[]
    for row in originals:
        name=row['member']
        if (name.startswith('actual/') and not name.endswith(('.document.json','.verified.json'))) or name.startswith('guardian/') or name in ('root-execution/root-cli-source7-r3-OWNER-READBACK.json','independent-audit/AUDIT.json'):
            keys.append(create(ROOT/'key-originals'/name,bodies[name]))
    receipt={'schema':'hia.cli-json.source-seven.r3.closed-archive-readback.v1','status':'LOSSLESS_ARCHIVE_READBACK_PASS_SEVEN_SOURCE_COMPONENTS_ONLY',
             'original_status':'SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN','passed_components':7,'expected_components':7,
             'all38_actual_preserved':True,'all_seven_stopped_root_proof_files_preserved':True,
             'files':len(originals),'raw_bytes':sum(r['bytes'] for r in originals),
             'archive':archive,'uncompressed_tar':hashes(tarraw),'parts':parts,
             'complete_tar_decode_and_all_member_bytes_verified':True,'complete_base64_decode_verified':True,
             'all_original_physical_identities_and_bytes_unchanged_after_archive':True,
             'key_originals':keys,'native_or_product_or_source_execution_performed_by_archiver':False}
    create(ROOT/'ARCHIVE-READBACK.json',wire(receipt))
    inventory=[dict(relative=p.relative_to(ROOT).as_posix(),**read(p)[1]) for p in walk(ROOT)]
    create(ROOT/'PUBLICATION-FILES.json',wire({'schema':'hia.cli-json.r3.archive-publication-files.v1','files':inventory}))
    print(json.dumps({'files':len(originals),'raw_bytes':receipt['raw_bytes'],'archive':archive,
                      'parts':len(parts),'keys':len(keys),'root':str(ROOT),'status':receipt['status']},sort_keys=True))
if __name__=='__main__':main()
