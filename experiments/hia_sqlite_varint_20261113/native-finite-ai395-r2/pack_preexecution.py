"""Lossless request publication package, not a native/source execution."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,sys,tarfile
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'control'))
import common,support
def main():
    pub=ROOT/'publication'
    if pub.exists():raise RuntimeError('new publication directory required')
    pub.mkdir(mode=0o700);payload=pub/'payload';payload.mkdir(mode=0o700);(payload/'archive').mkdir(mode=0o700)
    qpin,q=support.read_json(ROOT/'REQUEST.json')
    frozen=support.input_records(q);common.require(len(frozen)==94,'frozen count')
    names=set(q['inputs'])
    names.update(['REQUEST.json','LAUNCH.json','FROZEN-READBACK.json','STATIC-CALCULATIONS.json',
       'freeze_request.py','calculate_static_plan.py','restore_development_compiler.py',
       'capture_system.py','capture_system_r2.py','capture_system_r3.py','capture_system_r4.py',
       'SYSTEM-INPUTS.json','revise_controls_r2.py','PREPARATION-JOURNAL.json','pack_preexecution.py','restore_preexecution.py'])
    for base in ('history','peer-reviews'):
        names.update(str(p.relative_to(ROOT)) for p in (ROOT/base).rglob('*') if p.is_file())
    rows=[];archive=pub/'preexecution-originals.tar.gz'
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',filename='',compresslevel=1,mtime=0) as gz:
            with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as t:
                for name in sorted(names):
                    pin,raw=common.read(ROOT/name);s=(ROOT/name).stat()
                    row={'relative_path':name,**pin};rows.append(row)
                    ti=tarfile.TarInfo(name);ti.size=len(raw);ti.mode=stat.S_IMODE(s.st_mode)
                    ti.uid=s.st_uid;ti.gid=s.st_gid;ti.mtime=s.st_mtime_ns//1000000000
                    ti.pax_headers={'mtime':str(s.st_mtime_ns//1000000000)+'.'+str(s.st_mtime_ns%1000000000).zfill(9)}
                    t.addfile(ti,io.BytesIO(raw))
        stream.flush();os.fsync(stream.fileno())
    apin,compressed=common.read(archive,32<<20)
    readback=[]
    with tarfile.open(fileobj=io.BytesIO(compressed),mode='r:gz') as t:
        members=t.getmembers()
        common.require(len(members)==len(rows) and [m.name for m in members]==[r['relative_path'] for r in rows],'archive exact whole population')
        for m,row in zip(members,rows):
            data=t.extractfile(m).read();current,raw=common.read(ROOT/row['relative_path'])
            common.require(m.isfile() and data==raw and current=={k:v for k,v in row.items() if k!='relative_path'}
                and m.size==row['bytes'] and m.mode==row['identity'][2]&0o777
                and m.uid==row['identity'][3] and m.gid==row['identity'][4],'full original archive bytes/metadata differs')
            readback.append({'relative_path':m.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    parts=[]
    for i,start in enumerate(range(0,len(compressed),524288)):
        raw=compressed[start:start+524288];name='archive/part-%04d.b64'%i
        wire=base64.b64encode(raw)+b'\n';pin=common.create(payload/name,wire,raw=True)
        parts.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                      'text_bytes':len(wire),'text_sha256':pin['sha256'],'git_blob':pin['git_blob']})
    manifest={'schema':'hia.sqlite.varint.preexecution-lossless-archive.v2','status':'FROZEN_UNEXECUTED',
        'archive':apin,'parts':parts,'originals':rows,'full_member_readback':readback,
        'file_count':len(rows),'bytes':sum(r['bytes'] for r in rows),'source_base_reference':{
            'commit':q['source_commit'],'tree':q['source_tree'],'files':1686,'bytes':40890650,
            'manifest':'SOURCE-BASE.json','not_duplicated_in_archive':True},
        'system_source_reference':{'manifest':q['system_map'],'files':q['system_count'],
            'bytes':q['system_bytes'],'new_host_identity_required':True}}
    common.create(payload/'ARCHIVE.json',manifest)
    readable=['REQUEST.json','LAUNCH.json','FROZEN-READBACK.json','PREEXECUTION-PLAN.md',
        'EXPECTED-MATRIX.json','EXPECTED-TRACE.json','COMPILER-READBACK.json','STATIC-CALCULATIONS.json',
        'restore_preexecution.py','pack_preexecution.py','freeze_request.py','PREPARATION-JOURNAL.json']
    readable += [str(p.relative_to(ROOT)) for p in (ROOT/'control').iterdir() if p.is_file()]
    readable += [str(p.relative_to(ROOT)) for p in (ROOT/'peer-reviews').iterdir() if p.is_file()]
    for name in sorted(readable):
        target=payload/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        common.create(target,common.read(ROOT/name)[1],raw=True)
    common.require(support.input_records(q)==frozen,'package changed frozen input')
    prefix='experiments/hia_sqlite_varint_20261113/native-finite-ai395-r2'
    files=[]
    for p in sorted(payload.rglob('*')):
        if p.is_file():
            pin,raw=common.read(p)
            common.require(len(raw)<1<<20,'every published text blob under 1 MiB')
            raw.decode('utf-8')
            files.append({'path':prefix+'/'+str(p.relative_to(payload)),'relative_path':str(p.relative_to(payload)),
                'local_path':str(p),'mode':'100644','type':'blob','sha':pin['git_blob'],'size':pin['bytes'],'sha256':pin['sha256']})
    plan={'schema':'hia.sqlite.varint.canonical-plan.v2','status':'UNEXECUTED_ALL_INPUTS_FROZEN',
        'repository':'TrillionniumFoundation/Hepta','parent_commit':'bfe97dc70f0c3470621605946f55aaa2ec67419d',
        'parent_tree':'f9b91765ffb63b1b1c9aaf11ce466c1288cd5ad4','prefix':prefix,'files':files,
        'archive_file_count':len(rows),'archive_original_bytes':sum(r['bytes'] for r in rows),
        'compressed':apin,'request':qpin,'no_source8_native_C_or_qualification_execution':True}
    common.create(pub/'PLAN.json',plan)
    print(json.dumps({'status':plan['status'],'files':len(files),'unique_blobs':len({r['sha'] for r in files}),
        'published_bytes':sum(r['size'] for r in files),'archive':apin,'full_originals':len(rows),'original_bytes':plan['archive_original_bytes']}))
if __name__=='__main__':main()
