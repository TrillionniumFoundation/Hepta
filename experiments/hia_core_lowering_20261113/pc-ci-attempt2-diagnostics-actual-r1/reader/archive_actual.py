"""Archive only public current reception originals; never private SDK/proxy values."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile
ROOT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-ci-a2-small-14022456964-r1")
BASE=ROOT.parent
META=BASE/'pc-ci-a2-diagnostics-only-r1'
sys.path.insert(0,str(ROOT/'control'));import source_common as c
os.umask(0o077)
archive_root=ROOT/'custody';archive_root.mkdir(mode=0o700)
items=[]
for name in ('control','authoring','actual','audit'):
    for p in sorted((ROOT/name).rglob('*')):
        s=p.lstat();c.require(not stat.S_ISLNK(s.st_mode),'no archive aliases')
        if stat.S_ISREG(s.st_mode):items.append(('reception/'+p.relative_to(ROOT).as_posix(),p))
        else:c.require(stat.S_ISDIR(s.st_mode),'no archive specials')
for name in ('REQUEST.json','LAUNCH.json','PREEXEC.json'):items.append(('reception/'+name,ROOT/name))
for p in sorted((META/'publication').iterdir()):
    if p.is_file() and (p.name.startswith('SMALL-') or p.name.startswith('RECOVERY-TERMINAL-') or p.name=='RECOVERY-NATIVE-JOB-131783442461.original.log.json'):
        items.append(('journals/'+p.name,p))
for name in ('root-ci-a2-diagnostics-only-trigger-INTENT.json','root-ci-a2-diagnostics-only-trigger-READBACK.json'):
    items.append(('root/'+name,BASE/name))
c.require(len({x[0] for x in items})==len(items),'archive names unique')
items.sort();rows=[]
for name,path in items:
    raw,pin=c.read_regular(path)
    rows.append({'archive_path':name,**pin})
manifest={'schema':'hia.pc-attempt2-small.actual-full-public-custody.v1','status':'COMPLETE_ORIGINALS_OF_ACTUAL_PRODUCT_TIMEOUT','repository':'TrillionniumFoundation/Hepta','recovery_A':'1fbeb3f2706e7521f4b234c7ccabbbcad7009767','recovery_B':'744512bdb82a5f700e8fe50e2c01637c161bb99d','recovery_run':43394928015,'recovery_attempt':1,'provider_artifact':14022456964,'official_zip_bytes':20296527,'official_zip_sha256':'bd30d0548b826a2863267ae98455ad2e08ee2f3e1d63fb53f0a42ac710f85af0','files':rows,'regular_count':len(rows),'regular_bytes':sum(x['bytes'] for x in rows),'private_SDK_and_proxy_files_excluded':True,'private_opaque_pins_remain_in_actual_original_receipts':True,'product_timeout_preserved':True,'old_UNKNOWN_not_reclassified':True,'archive_contents_include_complete_official_ZIP':True}
manifest_raw=c.wire(manifest);c.save(archive_root/'ORIGINALS.json',manifest_raw)
target=archive_root/'ACTUAL.tar.gz'
fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:
    with gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0,compresslevel=6) as gz:
        with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as t:
            for row in rows:
                raw,_=c.read_regular(row['path'],{k:v for k,v in row.items() if k!='archive_path'})
                info=tarfile.TarInfo(row['archive_path']);info.size=len(raw);info.mode=row['identity']['mode'];info.uid=0;info.gid=0;info.mtime=0
                t.addfile(info,io.BytesIO(raw))
            info=tarfile.TarInfo('ORIGINALS.json');info.size=len(manifest_raw);info.mode=0o600;info.uid=0;info.gid=0;info.mtime=0;t.addfile(info,io.BytesIO(manifest_raw))
    f.flush();os.fsync(f.fileno())
archive_raw,archive_pin=c.read_regular(target)
wanted={x['archive_path']:x for x in rows};seen=[];restored=0
with gzip.open(target,'rb') as gz:
    with tarfile.open(fileobj=gz,mode='r|') as t:
        for info in t:
            c.require(info.isfile() and info.name not in seen,'restored unique regular')
            raw=t.extractfile(info).read();seen.append(info.name)
            if info.name=='ORIGINALS.json':
                c.require(raw==manifest_raw and info.mode==0o600,'complete manifest restored')
            else:
                row=wanted[info.name];c.require(info.size==row['bytes'] and info.mode==row['identity']['mode'] and len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'restored whole original');restored+=len(raw)
    tail=gz.read();c.require(not tail.strip(b'\0'),'nonzero trailing TAR data')
c.require(set(seen)==set(wanted)|{'ORIGINALS.json'} and restored==manifest['regular_bytes'],'full archive population')
for row in rows:c.read_regular(row['path'],{k:v for k,v in row.items() if k!='archive_path'})
c.read_regular(target,archive_pin)
parts=[];partdir=archive_root/'parts';partdir.mkdir(mode=0o700)
for i,start in enumerate(range(0,len(archive_raw),262144)):
    piece=archive_raw[start:start+262144];encoded=base64.b64encode(piece)+b'\n';p=partdir/('part-%03d.b64'%i);pin=c.save(p,encoded)
    parts.append({'index':i,'offset':start,'raw_bytes':len(piece),'raw_sha256':hashlib.sha256(piece).hexdigest(),**pin})
joined=b''.join(base64.b64decode(c.read_regular(x['path'],{k:x[k] for k in ('path','bytes','sha256','identity')})[0],validate=False) for x in parts)
c.require(joined==archive_raw,'full published partition restore')
receipt={'schema':'hia.pc-attempt2.small-actual-archive-readback.v1','status':'FULL_ARCHIVE_AND_ALL_ORIGINALS_READBACK_PASS_OF_PRODUCT_TIMEOUT','archive':archive_pin,'manifest':c.read_regular(archive_root/'ORIGINALS.json')[1],'regular_originals':len(rows),'regular_bytes':manifest['regular_bytes'],'archive_members':len(seen),'parts':parts,'whole_binary_restored':True,'every_member_mode_size_SHA_verified':True,'all_source_original_nine_field_identity_preserved':True,'public_private_values_excluded':True,'product_executions':0,'new_network_GETs':0,'original_product_pass_claimed':False}
pin=c.save_json(archive_root/'ARCHIVE.json',receipt)
print(json.dumps({'status':receipt['status'],'archive':archive_pin,'manifest':receipt['manifest'],'receipt':pin,'parts':len(parts),'originals':len(rows),'original_bytes':manifest['regular_bytes']},sort_keys=True))
