"""Complete CAS transport of immutable actual originals; every reference reread."""
from pathlib import Path
import argparse,base64,gzip,hashlib,importlib.util,json,stat,time,zlib
HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('C',HERE/'seal_actual.py');C=importlib.util.module_from_spec(sp);sp.loader.exec_module(C)
def main():
    p=argparse.ArgumentParser();p.add_argument('label',choices=['prefix','bound','helper-admission']);a=p.parse_args();started=time.monotonic_ns()
    old=Path('/workspace/hia-r10-'+a.label+'-actual-custody-r1-dda7');dest=old/'transport-r1';assert not dest.exists();dest.mkdir(mode=0o700)
    index=json.loads(C.read(old/'INDEX.json')[0]);old_result=json.loads(C.read(old/'RESULT.json')[0]);assert old_result['status']=='PASS_ALL_ORIGINAL_BYTES_MODES_SEVEN_STATS_AND_PATHSETS'
    originals=list(index['originals']);objects={}
    # The first full readback already checked the original gzip. This second
    # representation contains each original byte plus complete per-file metadata.
    for name in ('INPUT-PLAN.json','INTENT.json','INDEX.json','ORIGINALS.json','LOCAL-ROUNDTRIP.json','RESULT.json'):
        b,s=C.read(old/name);originals.append({'logical':'custody-seal/'+name,'path':str(old/name),'identity':C.pin(b),'mode':stat.S_IMODE(s['st_mode']),'seven_stat':s})
    for name,path in [('make_transport.py',Path(__file__)),(a.label.upper()+'-SEAL.stdout.raw',HERE/(a.label.upper()+'-SEAL.stdout.raw')),(a.label.upper()+'-SEAL.stderr.raw',HERE/(a.label.upper()+'-SEAL.stderr.raw')),(a.label.upper()+'-SEAL.PROCESS.json',HERE/(a.label.upper()+'-SEAL.PROCESS.json'))]:
        b,s=C.read(path);originals.append({'logical':'custody-seal/'+name,'path':str(path),'identity':C.pin(b),'mode':stat.S_IMODE(s['st_mode']),'seven_stat':s})
    for row in originals:
        b,s=C.read(row['path']);assert C.pin(b)==row['identity'] and s==row['seven_stat'] and stat.S_IMODE(s['st_mode'])==row['mode'];key=row['identity']['git_blob'];value={'identity':row['identity'],'base64':base64.b64encode(b).decode()}
        if key in objects:assert objects[key]==value
        else:objects[key]=value
    capsule={'schema':'hia.R10.actual.complete-cas.v1','header':index['header'],'files':originals,'objects':objects,'historical_jsonl_archive_identity':index['archive'],'historical_jsonl_archive_local_retained':True,'products':0}
    raw=C.encode(capsule);packed=gzip.compress(raw,compresslevel=6,mtime=0);packed_path=dest/'COMPLETE-ORIGINALS.json.gz';C.put(dest,packed_path.name,packed)
    d=zlib.decompressobj(31);restored=d.decompress(packed)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail and restored==raw
    decoded=json.loads(restored);assert decoded==capsule
    for row in decoded['files']:
        # Never skip a reference because the same object identity was seen before.
        obj=decoded['objects'][row['identity']['git_blob']];b=base64.b64decode(obj['base64'],validate=True);actual,s=C.read(row['path'])
        assert obj['identity']==row['identity']==C.pin(b) and actual==b and s==row['seven_stat'] and stat.S_IMODE(s['st_mode'])==row['mode']
    for name,path in decoded['header']['scopes'].items():assert C.state(Path(path))==decoded['header']['scope_states'][name]
    parts=[]
    for offset in range(0,len(packed),196608):
        b=packed[offset:offset+196608];name='parts/%03d.json'%len(parts);item={'schema':'hia.R10.actual.cas-gzip-part.v1','index':len(parts),'offset':offset,'piece':C.pin(b),'base64':base64.b64encode(b).decode()};ident=C.put(dest,name,C.encode(item));parts.append({'path':name,**ident})
    manifest={'schema':'hia.R10.actual.complete-transport-index.v1','scope':a.label,'archive':C.pin(packed),'capsule':C.pin(raw),'logical_files':len(originals),'logical_bytes':sum(x['identity']['bytes'] for x in originals),'original_stage_files':index['logical_files'],'original_stage_bytes':index['logical_bytes'],'objects':len(objects),'parts':parts,'directory_states_in_capsule':True,'all_original_modes_and_seven_stats_in_capsule':True,'products':0,'qualification_boundary':index['header']['qualification_boundary']}
    C.put(dest,'TRANSPORT-INDEX.json',C.encode(manifest))
    proof={'status':'PASS_FULL_LOCAL_CAS_RECONSTRUCTION_AND_ALL_CURRENT_ORIGINAL_REFERENCES','index':C.pin(C.encode(manifest)),'files':len(originals),'objects':len(objects),'logical_bytes':manifest['logical_bytes'],'archive':C.pin(packed),'capsule':C.pin(raw),'all_current_bytes_modes_seven_stats_pathsets':True,'full_single_gzip_CRC':True,'elapsed_ns':time.monotonic_ns()-started,'products':0}
    C.put(dest,'LOCAL-CAS-READBACK.json',C.encode(proof))
    leaves=[{'mount':'parts/'+Path(r['path']).name,'path':str(dest/r['path']),'identity':{k:r[k] for k in ('bytes','sha256','git_blob')}} for r in parts]
    for name in ('TRANSPORT-INDEX.json','LOCAL-CAS-READBACK.json'):
        b,_=C.read(dest/name);leaves.append({'mount':name,'path':str(dest/name),'identity':C.pin(b)})
    C.put(dest,'PUBLISH-PLAN.json',C.encode({'repository_full_name':'TrillionniumFoundation/Hepta','leaves':leaves}))
    print(json.dumps(proof|{'parts':len(parts),'transport':str(dest)},sort_keys=True))
if __name__=='__main__':main()
