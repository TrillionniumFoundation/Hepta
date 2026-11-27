"""Independent stdlib-only readback of recovered source and complete source-origin coverage."""
from pathlib import Path
import hashlib,json,os,stat,time
ROOT=Path(__file__).resolve().parent
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(name):return json.loads((ROOT/name).read_bytes())
def tree(rows):
    nested={}
    for name,row in rows.items():
        node=nested;parts=name.split('/')
        for part in parts[:-1]:node=node.setdefault(part,{})
        assert parts[-1] not in node;node[parts[-1]]=(row['mode'],row['git_blob'])
    def digest(node):
        items=[]
        for name,value in node.items():
            if isinstance(value,dict):mode='40000';sha=digest(value);key=name.encode()+b'/'
            else:mode=format(stat.S_IFREG|value[0],'o');sha=value[1];key=name.encode()
            items.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
        raw=b''.join(value for _,value in sorted(items))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return digest(nested)
def main():
    started=time.monotonic();raw=(ROOT/'FROZEN-3180-MANIFEST.json').read_bytes()
    assert pin(raw)=={'bytes':843469,'git_blob':'1c4770702659539f148b0dc64610d4c34d6f04dc','sha256':'e0951f9fee6e2b0663c8344ce5d7759bb65c106b255d3abe63f85718205486af'}
    target=json.loads(raw);base=read('ACTUAL-R19-MANIFEST.json');five=read('FIVE-U32.json')
    assert len(base)==3175 and len(five)==5 and not set(base)&set(five) and dict(base,**five)==target
    assert tree(base)=='d15d7a476fc3f711b2729236e84b7a9573da7a3d' and sum(q['bytes'] for q in base.values())==97961656
    origins={};transports={};receipt_pins={}
    def origin(row):
        name=row['path'];assert name not in origins and row['identity']==target[name]
        origins[name]=row;kind=row['origin']['type'];t=transports.setdefault(kind,{'files':0,'bytes':0})
        t['files']+=1;t['bytes']+=row['identity']['bytes']
    embedded=read('EMBEDDED-RESTORATION.json');assert embedded['new_source_files']==len(embedded['records'])==525
    for row in embedded['records']:origin(row)
    requests=read('GIT-BASE-REQUESTS.json');indices=[]
    for path in sorted((ROOT/'receipts').glob('*.json')):
        receipt_raw=path.read_bytes();receipt=json.loads(receipt_raw);assert receipt['status']=='PASS'
        assert len(receipt['indices'])==receipt['blob_count'] and len(receipt['files'])==receipt['file_count']
        indices+=receipt['indices'];receipt_pins[path.relative_to(ROOT).as_posix()]=pin(receipt_raw)
        expected_paths=[]
        for i in receipt['indices']:expected_paths+=requests[i]['paths']
        assert [q['path'] for q in receipt['files']]==expected_paths
        for row in receipt['files']:origin(row)
    deferred={1143,1154,1156,1164}
    assert len(indices)==len(set(indices))==2539 and set(indices)==set(range(2543))-deferred
    four=read('binary-span0/RESTORATION.json');assert four['status']=='PASS_FOUR_EXACT_SOURCE_MEMBERS' and len(four['records'])==4
    for row in four['records']:origin(row)
    assert set(origins)==set(target) and sum(v['files'] for v in transports.values())==3180
    assert transports['exact-published-Git-object']['files']==2651
    assert transports['actual-R19-original-ZIP']['files']==520
    assert transports['hosted-R4-full-after-material']['files']==5
    assert transports['exact-u32-original-ZIP-member-from-authorized-span0']['files']==4
    source=ROOT/'source';seen={};inodes=set();current=read('CURRENT-SOURCE-MAP.json');directories=read('CURRENT-DIRECTORY-MAP.json');seen_dirs=set()
    for parent,dirs,files in os.walk(source,followlinks=False):
        p=Path(parent);rel=p.relative_to(source).as_posix();s=p.lstat();assert stat.S_ISDIR(s.st_mode)
        assert seven(s)==directories[rel]['seven_stats'];seen_dirs.add(rel)
        for d in dirs:assert not (p/d).is_symlink()
        for name in files:
            path=p/name;rel=path.relative_to(source).as_posix();assert rel in target
            before=path.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==target[rel]['mode']
            assert (before.st_dev,before.st_ino) not in inodes;inodes.add((before.st_dev,before.st_ino))
            assert seven(before)==current[rel]['seven_stats']==origins[rel]['seven_stats']
            data=path.read_bytes();assert seven(before)==seven(path.lstat())
            actual=pin(data);assert actual=={k:target[rel][k] for k in ('bytes','sha256','git_blob')}
            seen[rel]=dict(actual,mode=stat.S_IMODE(before.st_mode))
    assert set(seen)==set(target) and seen_dirs==set(directories)
    actual_tree=tree(seen);assert actual_tree=='4c62be4ed66ff107fa6f88c6131313a354868bd9'
    assert sum(q['bytes'] for q in seen.values())==98471253
    assert (ROOT/'FROZEN-3180-MANIFEST.json').read_bytes()==raw
    report={'schema':'hepta.r8.source-static-independent-readback.v1','status':'PASS','source_root':str(source),'files':3180,'bytes':98471253,'tree':actual_tree,'all_full_bytes_SHA_Git_modes_new_seven_stats_and_distinct_single_link_inodes_verified':True,'directories':len(directories),'directory_stat_scope':'new recovery namespace only; no original directory mode or old inode/ctime claim','origin_coverage':'all 3180 exactly once','transport_breakdown':transports,'exact_direct_Git_unique_blobs':2539,'four_Git_dependency_files_recovered_via_original_u32_span_not_Git_binary_endpoint':True,'actual_R19':{'files':3175,'bytes':97961656,'tree':'d15d7a476fc3f711b2729236e84b7a9573da7a3d','artifact_self_contained':False},'receipt_pins':receipt_pins,'identities':{n:pin((ROOT/n).read_bytes()) for n in ['FROZEN-3180-MANIFEST.json','ACTUAL-R19-MANIFEST.json','FIVE-U32.json','CURRENT-SOURCE-MAP.json','CURRENT-DIRECTORY-MAP.json','RESTORATION.json','binary-span0/RESTORATION.json']},'fresh_stat_identity_not_inherited':True,'products':0,'recovered_binary_execution':0,'generator_execution':0,'binder':0,'CI':0,'ref_changes':0,'runtime_and_948_input_recovery':'separate peer scopes, not validated by this report','elapsed_seconds':time.monotonic()-started}
    out=ROOT/'INDEPENDENT-READBACK.json'
    with out.open('xb') as f:f.write((json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({k:report[k] for k in ['status','files','bytes','tree','directories','transport_breakdown','products','elapsed_seconds']},sort_keys=True))
if __name__=='__main__':main()
