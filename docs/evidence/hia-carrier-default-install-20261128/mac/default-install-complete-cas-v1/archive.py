from pathlib import Path
from hashlib import sha256
import io,json,os,stat,sys,tarfile,time
root=Path(sys.argv[1]).resolve(strict=True)
out=Path(sys.argv[2]).resolve()
out.mkdir(mode=0o700)
entries={};blobs={};start=time.monotonic()
selected=('default-install-v1','default-install-v2','default-install-v3','default-install-v4','default-slot-installed-controls-v1')
for p in sorted(p for name in selected for base in (root/name,) for p in (base,*base.rglob('*'))):
    relative=p.relative_to(root)
    if '.git' in relative.parts or '__pycache__' in relative.parts or out==p or out in p.parents:
        continue
    mode=stat.S_IMODE(p.lstat().st_mode)
    if p.is_symlink():
        entries[relative.as_posix()]={'kind':'symlink','mode':mode,'target':os.readlink(p)}
    elif p.is_file():
        raw=p.read_bytes();digest=sha256(raw).hexdigest()
        entries[relative.as_posix()]={'kind':'file','mode':mode,'bytes':len(raw),'sha256':digest}
        if digest not in blobs:blobs[digest]=p
    elif p.is_dir():
        entries[relative.as_posix()]={'kind':'directory','mode':mode}
    else: raise ValueError('unsupported original entry '+str(p))
manifest={'schema':'hepta.complete-physical-cas.v1','root':str(root),'entries':entries,
          'scope':'COMPLETE_EXPLICIT_DEFAULT_INSTALL_ATTEMPTS_EXCLUDING_GIT_AND_PYCACHE','selected_roots':list(selected),
          'excluded_output':str(out),'original_bytes':sum(v.get('bytes',0) for v in entries.values())}
manifest_raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
(out/'members.json').write_bytes(manifest_raw)
archive=out/'complete-physical.tar.gz'
with tarfile.open(archive,'w:gz',compresslevel=6) as tf:
    item=tarfile.TarInfo('members.json');item.size=len(manifest_raw);item.mode=0o400;item.mtime=0
    tf.addfile(item,io.BytesIO(manifest_raw))
    for digest,p in sorted(blobs.items()):
        raw=p.read_bytes();assert sha256(raw).hexdigest()==digest
        item=tarfile.TarInfo('blobs/'+digest);item.size=len(raw);item.mode=0o400;item.mtime=0
        tf.addfile(item,io.BytesIO(raw))
with tarfile.open(archive,'r:gz') as tf:
    seen=set()
    for member in tf:
        assert member.isfile() and member.name not in seen;seen.add(member.name)
        raw=tf.extractfile(member).read()
        if member.name=='members.json':assert raw==manifest_raw
        else:assert member.name=='blobs/'+sha256(raw).hexdigest() and member.name[6:] in blobs
    assert seen=={'members.json'}|{'blobs/'+x for x in blobs}
for name,want in entries.items():
    p=root/name;assert stat.S_IMODE(p.lstat().st_mode)==want['mode']
    if want['kind']=='file':
        assert p.is_file() and not p.is_symlink()
        raw=p.read_bytes();assert len(raw)==want['bytes'] and sha256(raw).hexdigest()==want['sha256']
    elif want['kind']=='symlink':assert p.is_symlink() and os.readlink(p)==want['target']
    else:assert p.is_dir() and not p.is_symlink()
raw=archive.read_bytes()
receipt={'archive':{'bytes':len(raw),'sha256':sha256(raw).hexdigest()},
         'manifest':{'bytes':len(manifest_raw),'sha256':sha256(manifest_raw).hexdigest()},
         'entries':len(entries),'unique_blobs':len(blobs),'original_bytes':manifest['original_bytes'],
         'source_reread_and_archive_each_member_verified':True,'seconds':time.monotonic()-start}
(out/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt),flush=True)
