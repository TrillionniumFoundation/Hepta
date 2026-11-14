"""Verify only full-GET payloads and stream every retained original; no products."""
import base64,gzip,hashlib,io,json,os,stat,tarfile,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-generation-transport-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(p):return {k:getattr(Path(p).lstat(),k)for k in FIELDS}
def read(p,expected=None):
    p=Path(p);before=seven(p);assert stat.S_ISREG(before['st_mode'])and before['st_nlink']==1
    if expected is not None:assert before==expected
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        assert {k:getattr(os.fstat(fd),k)for k in FIELDS}==before
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(before['st_size']+1)
        assert len(raw)==before['st_size']and {k:getattr(os.fstat(fd),k)for k in FIELDS}==before==seven(p)
    finally:os.close(fd)
    return raw
def main():
    rows=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes());actual={};reads=0
    for i,row in enumerate(rows):
        tag='%03d'%i;raw=read(ROOT/'actual-get'/(tag+'-GET.txt'))
        ack=json.loads(read(ROOT/'actual-get'/(tag+'-ACK.json')))
        receipt=json.loads(read(ROOT/'actual-get'/(tag+'-VERIFIED.json')))
        assert ack['sha']==receipt['sha']==row['pin']['git_blob']and receipt['full_get_exact']is True
        assert pin(raw)==row['pin']and raw==read(row['path'])
        assert row['logical']not in actual;actual[row['logical']]=raw;reads+=1
    index=json.loads(actual['INDEX.json'])
    def join(parts,kind,identity):
        all_parts=[];offset=0
        for i,row in enumerate(parts):
            raw=actual[row['logical']];assert pin(raw)==row['pin'];value=json.loads(raw)
            assert value['schema']=='hepta.hia.patch.complete.transport-part.v1'
            assert value['kind']==kind and value['index']==row['index']==i and value['offset']==row['offset']==offset
            chunk=base64.b64decode(value['data_base64'],validate=True)
            assert pin(chunk)==value['chunk']==row['chunk']and len(chunk)<=index['maximum_part_payload']
            all_parts.append(chunk);offset+=len(chunk)
        raw=b''.join(all_parts);assert pin(raw)==identity;return raw
    archive=join(index['archive_parts'],'archive',index['archive']['pin'])
    compressed=join(index['metadata_parts'],'metadata',index['metadata_zlib'])
    z=zlib.decompressobj();payload=z.decompress(compressed)
    assert z.eof and not z.unused_data and not z.unconsumed_tail and pin(payload)==index['metadata_payload']
    metadata=json.loads(payload)['files'];assert len(metadata)==len(index['metadata_files'])==11
    for name,row in metadata.items():
        descriptor=row['descriptor'];raw=row['text'].encode()
        assert row['encoding']=='utf-8'and descriptor==index['metadata_files'][name]
        assert pin(raw)==descriptor['pin']and raw==read(descriptor['path'],descriptor['stat'])
        assert stat.S_IMODE(Path(descriptor['path']).lstat().st_mode)==descriptor['mode']
    manifest_raw=metadata['MANIFEST.json']['text'].encode();manifest=json.loads(manifest_raw)
    aliases={}
    for logical,row in manifest['files'].items():aliases.setdefault(row['identity']['sha256'],[]).append((logical,row))
    seen=set();compared=0
    with gzip.GzipFile(fileobj=io.BytesIO(archive),mode='rb')as gz:
        with tarfile.open(fileobj=gz,mode='r|')as tar:
            for item in tar:
                assert item.isfile()and item.mode==0o444 and item.name not in seen;seen.add(item.name)
                raw=tar.extractfile(item).read(item.size+1);assert len(raw)==item.size
                if item.name=='MANIFEST.json':assert raw==manifest_raw;continue
                assert item.name.startswith('objects/');key=item.name[8:]
                assert key in manifest['objects']and pin(raw)==manifest['objects'][key]['identity']
                for logical,row in aliases[key]:
                    assert read(row['source_path'],row['seven_stats'])==raw
                    assert stat.S_IMODE(Path(row['source_path']).lstat().st_mode)==row['mode'];compared+=1
        while gz.read(1048576):pass
    assert compared==manifest['file_count']==index['logical_files']==127
    assert len(seen)==manifest['unique_objects']+1==105
    plan=json.loads(metadata['INPUT-PLAN.json']['text']);files={};directories={}
    for root in plan['roots']:
        base=Path(root['path']);excluded=root.get('exclude',[])
        def walk(path,relative):
            directories[root['label']+'/'+relative]={'source_path':str(path),'stat':seven(path)}
            for e in sorted(os.scandir(path),key=lambda x:x.name):
                name=e.name if relative=='.'else relative+'/'+e.name
                if any(name==n or name.startswith(n+'/')for n in excluded):continue
                p=Path(e.path);s=e.stat(follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):walk(p,name)
                else:assert stat.S_ISREG(s.st_mode)and s.st_nlink==1;files[root['label']+'/'+name]={'path':str(p),'stat':seven(p)}
        walk(base,'.')
    for name,path in plan['extras'].items():files[name]={'path':path,'stat':seven(path)}
    assert files==plan['files']and directories==plan['directories']==manifest['directories']
    assert set(files)==set(manifest['files'])
    for name,row in manifest['files'].items():assert seven(row['source_path'])==row['seven_stats']==files[name]['stat']
    report={'status':'PASS_ACTUAL_GIT_FULL_GET_COMPLETE_GZIP_CAS_AND_ORIGINAL_READBACK',
        'full_GET_leaves':reads,'full_GET_bytes':sum(len(b)for b in actual.values()),
        'metadata_files':len(metadata),'original_files':compared,'original_directories':len(directories),
        'original_logical_bytes':manifest['logical_bytes'],'CAS_objects':manifest['unique_objects'],
        'CAS_bytes':manifest['unique_bytes'],'archive':pin(archive),'metadata_payload':pin(payload),
        'full_CRC':True,'every_original_full_bytes_mode_seven_stat_equal':True,'complete_pathsets_equal':True,
        'product_execution':0,'generator_execution':0,'independent_terminal_reader_execution':0,
        'whole_native':False,'original_generation_status':plan['original_product_status'],
        'no_second_uncompressed_original_tree':True}
    with (ROOT/'ACTUAL-GIT-READBACK.json').open('xb')as stream:stream.write((json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
