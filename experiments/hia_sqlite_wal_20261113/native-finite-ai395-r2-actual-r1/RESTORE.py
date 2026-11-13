"""Restore exact frozen files from complete lossless parts; restored inode identities are new, so this does not authorize execution."""
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile
from decimal import Decimal
from pathlib import Path,PurePosixPath
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def main():
    src=Path(__file__).resolve().parent;dest=Path(sys.argv[1])
    if len(sys.argv)!=2 or dest.exists():raise RuntimeError('new explicit destination required')
    doc=json.loads((src/'ARCHIVE.json').read_bytes());chunks=[]
    for n,p in enumerate(doc['parts']):
        if p['path']!='archive/part-%04d.b64'%n:raise RuntimeError('part order')
        text=(src/p['path']).read_bytes()
        if len(text)!=p['text_bytes'] or sha(text)!=p['text_sha256']:raise RuntimeError('part text')
        raw=base64.b64decode(text,validate=True)
        if len(raw)!=p['bytes'] or sha(raw)!=p['sha256']:raise RuntimeError('part raw')
        chunks.append(raw)
    raw=b''.join(chunks)
    if len(raw)!=doc['compressed_bytes'] or sha(raw)!=doc['compressed_sha256']:raise RuntimeError('whole compressed seal')
    dest.mkdir(mode=0o700);names=set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tf:
        members=tf.getmembers()
        if len(members)!=len(doc['members']):raise RuntimeError('member denominator')
        for m,r in zip(members,doc['members']):
            p=PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or not p.parts or m.name in names:raise RuntimeError('unsafe namespace')
            names.add(m.name)
            kind='file' if m.isfile() else 'directory' if m.isdir() else 'refused'
            ns=int(Decimal(m.pax_headers.get('mtime',str(m.mtime)))*1000000000)
            if (m.name,kind,m.mode,m.uid,m.gid,ns,m.size)!=(r['name'],r['type'],r['mode'],r['uid'],r['gid'],r['mtime_ns'],r['bytes']):raise RuntimeError('typed metadata')
            path=dest/p
            if kind=='directory':path.mkdir(mode=0o700,exist_ok=False)
            elif kind=='file':
                data=tf.extractfile(m).read()
                if len(data)!=r['bytes'] or sha(data)!=r['sha256'] or blob(data)!=r['git_blob']:raise RuntimeError('whole member bytes')
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
            else:raise RuntimeError('unsupported member')
        for m,r in reversed(list(zip(members,doc['members']))):
            path=dest/m.name;st=path.lstat()
            if (st.st_uid,st.st_gid)!=(r['uid'],r['gid']):
                if os.geteuid()!=0:raise RuntimeError('ownership differs; no invented restoration')
                os.chown(path,r['uid'],r['gid'],follow_symlinks=False)
            os.chmod(path,r['mode'],follow_symlinks=False);os.utime(path,ns=(r['mtime_ns'],r['mtime_ns']),follow_symlinks=False)
            s=path.lstat()
            if (stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid,s.st_mtime_ns)!=(r['mode'],r['uid'],r['gid'],r['mtime_ns']):raise RuntimeError('restored metadata')
            if r['type']=='file' and (len(path.read_bytes())!=r['bytes'] or sha(path.read_bytes())!=r['sha256']):raise RuntimeError('restored full body')
    print(json.dumps({'status':'EXACT_FROZEN_BYTES_RESTORED_NOT_EXECUTION_AUTHORIZATION','typed_members':len(names),'source_tree_unchanged':True,'physical_request_identity_requires_new_review':True}))
if __name__=='__main__':main()
