"""Reconstruct exclusively from full Git GETs and compare every original byte."""
from pathlib import Path
import base64,gzip,hashlib,json,os,stat,tarfile,time,traceback
R=Path(__file__).absolute().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def require(v,m):
    if not v:raise AssertionError(m)
def seven(s):return [getattr(s,k)for k in FIELDS]
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def read(p):
    p=Path(p);before=seven(p.lstat())
    require(stat.S_ISREG(before[2])and before[3]==1,'ordinary independent file required')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(seven(os.fstat(fd))==before,'opened inode differs')
        with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(before[4]+1)
        require(len(b)==before[4]and seven(os.fstat(fd))==before==seven(p.lstat()),'file changed during full read')
    finally:os.close(fd)
    return b,stat.S_IMODE(before[2]),before
def dump(name,v):
    with (R/name).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def main():
    started=time.monotonic_ns();plan=json.loads(read(R/'PUBLICATION-PLAN.json')[0]);rows=plan['files'];got={}
    for i,row in enumerate(rows):
        require(row['index']==i and row['relative']not in got,'ordered publication differs')
        number=str(i).zfill(3)
        ack=json.loads(read(R/'ACK'/(number+'.json'))[0]);response=json.loads(read(R/'GET'/(number+'.json'))[0])
        receipt=json.loads(read(R/'VERIFIED'/(number+'.json'))[0])
        require(ack.get('isError')is not True and ack['structuredContent']['sha']==row['git_blob'],'POST ACK differs')
        require(response.get('isError')is not True and isinstance(response['structuredContent']['content'],str),'full GET unavailable')
        b=response['structuredContent']['content'].encode();expected={k:row[k]for k in ('bytes','sha256','git_blob')}
        require(pin(b)==expected and b==read(row['path'])[0]and receipt['full_get_exact']is True
            and receipt['git_blob']==row['git_blob'],'full GET differs')
        got[row['relative']]=b
    index=json.loads(got['TRANSPORT-INDEX.json']);manifest_raw=got['MANIFEST.json'];manifest=json.loads(manifest_raw)
    require(pin(manifest_raw)==index['manifest'],'manifest differs')
    target=R/'GIT-RECONSTRUCTED.tar.gz';offset=0
    with target.open('xb')as f:
        for i,row in enumerate(index['parts']):
            wrapper=json.loads(got[row['path']]);data=base64.b64decode(wrapper['data'],validate=True)
            require(wrapper['index']==i==row['index']and wrapper['offset']==offset==row['offset']
                and wrapper['archive']==index['archive']and pin(data)==wrapper['decoded']==row['decoded'],'part identity/order differs')
            f.write(data);offset+=len(data)
    archive=read(target)[0]
    require(pin(archive)==index['archive']and archive==read(R/'COMPLETE-ORIGINALS.tar.gz')[0],'full archive differs')
    del archive
    aliases={}
    for name,row in manifest['files'].items():
        key=row['identity']['sha256'];require(row['storage_path']=='objects/'+key
            and row['identity']==manifest['objects'][key]['identity'],'logical mapping differs')
        aliases.setdefault(key,[]).append(name)
    seen=set();count=total=0
    with gzip.open(target,'rb')as gz:
        with tarfile.open(fileobj=gz,mode='r|')as tar:
            for m in tar:
                require(m.isfile()and not m.issym()and not m.islnk()and m.mode==0o444 and m.name not in seen,'transport member differs')
                seen.add(m.name);b=tar.extractfile(m).read(m.size+1);require(len(b)==m.size,'short tar member')
                if m.name=='MANIFEST.json':require(b==manifest_raw,'embedded manifest differs');continue
                require(m.name.startswith('objects/'),'unknown transport path');key=m.name[8:]
                require(key in aliases and pin(b)==manifest['objects'][key]['identity'],'CAS object differs')
                for name in aliases[key]:
                    row=manifest['files'][name];actual,mode,s=read(row['source_path'])
                    require(actual==b and mode==row['mode']and s==row['seven_stats'],'complete original/mode/stat differs')
                    count+=1;total+=len(b)
        while gz.read(1048576):pass
    require(seen=={'MANIFEST.json'}|{'objects/'+k for k in aliases},'complete archive pathset differs')
    require(count==manifest['file_count']==index['file_count']==140
        and total==manifest['logical_bytes']==index['logical_bytes']==34477797,'complete original denominator differs')
    for row in manifest['files'].values():require(seven(Path(row['source_path']).lstat())==row['seven_stats'],'terminal stat drift')
    result={'schema':'hepta.op8-generation.complete-originals.Git-readback.v1',
        'status':'PASS_ALL_FULL_GET_AND_COMPLETE_ORIGINAL_BYTE_MODE_READBACK','archive':index['archive'],
        'manifest':index['manifest'],'full_GET_leaves':len(rows),'parts':len(index['parts']),
        'logical_files':count,'logical_bytes':total,'CAS_objects':len(aliases),'gzip_footer_CRC':True,
        'all_original_bytes_modes_seven_stats_exact':True,'generation_raw_files':103,
        'all_six_owner_and_copy_records_included':True,'all_actual_terminal_reader_outputs_included':True,
        'source_payload_repeated':False,'product_executions':0,'refs':0,'signed_access_credentials_included':False,
        'qualification':'GENERATION_ONLY_NOT_NEW_OP8_TEST_QUALIFICATION','elapsed_ns':time.monotonic_ns()-started}
    dump('GIT-FULL-READBACK.json',result);print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
    try:main()
    except BaseException:
        dump('GIT-READBACK-FAILURE.json',{'status':'FAIL','products':0,'partial_retained':True,'traceback':traceback.format_exc()});raise
