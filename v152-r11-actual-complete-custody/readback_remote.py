"""Full actual Git payload decode and all original byte/mode/stat comparison."""
from pathlib import Path
import ast, base64, gzip, hashlib, io, json, os, stat, tarfile, time, traceback, zlib
ROOT=Path(__file__).resolve().parent
SOURCE=Path('/workspace/hia-r11-controls-complete-custody-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(value,message):
    if not value:raise ValueError(message)
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def stamp(p):return [getattr(p.lstat(),key) for key in FIELDS]
def read(p):
    p=Path(p);before=stamp(p);s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'non-regular input')
    for parent in p.parents:need(stat.S_ISDIR(parent.lstat().st_mode),'input ancestor is not directory')
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        need([getattr(os.fstat(fd),key) for key in FIELDS]==before,'opened input differs')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(s.st_size+1)
        need(len(raw)==s.st_size and [getattr(os.fstat(fd),key) for key in FIELDS]==before==stamp(p),'input changed')
    finally:os.close(fd)
    return raw,stat.S_IMODE(s.st_mode),before
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def dump(name,value):
    with (ROOT/name).open('xb') as f:f.write(enc(value))
def main():
    started=time.monotonic_ns();plan=json.loads(read(ROOT/'PUBLISH-PLAN.json')[0]);actual={};get_rows=[]
    for i,row in enumerate(plan['leaves']):
        prefix=ROOT/'GIT-ACK'/(str(i).zfill(3)+'-'+row['mount'].replace('/','_'))
        post=json.loads(read(str(prefix)+'.POST.json')[0]);get=json.loads(read(str(prefix)+'.GET.json')[0])
        need(post['structuredContent']['sha']==row['identity']['git_blob'],'POST ACK differs')
        raw=get['structuredContent']['content'].encode('utf-8');local,mode,st=read(row['path'])
        need(raw==local and dict(pin(raw),mode=mode)==row['identity'],'full GET byte/mode differs')
        actual[row['mount']]=raw;get_rows.append({'mount':row['mount'],'identity':row['identity'],'full_GET_equal':True})
    index=json.loads(actual['TRANSPORT-INDEX.json']);parts=[];offset=0
    for i,row in enumerate(index['parts']):
        data=json.loads(actual[row['mount']]);raw=base64.b64decode(data['data'],validate=True)
        need(data['schema']=='hia.R11.complete-raw.part.v1' and data['index']==i and data['offset']==offset
            and data['archive']==index['archive'] and pin(raw)==data['decoded']==row['decoded'],'ordered complete part differs')
        offset+=len(raw);parts.append(raw)
    archive=b''.join(parts);del parts
    need(pin(archive)==index['archive'],'complete archive hash differs')
    local,mode,st=read(index['archive_original_path'])
    need(archive==local and mode==index['archive_original_mode'] and st==index['archive_original_seven_stats'],'local archive changed');del local
    wrappers={}
    for name in ('MANIFEST','INTENT'):
        data=json.loads(actual[name+'.zlib.json']);packed=base64.b64decode(data['data'],validate=True)
        need(pin(packed)==data['compressed'],'compressed metadata differs')
        inflater=zlib.decompressobj();raw=inflater.decompress(packed)+inflater.flush()
        need(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail and pin(raw)==data['original'],'complete text decode differs')
        original,mode,st=read(data['original_path'])
        need(raw==original and mode==data['original_mode'] and st==data['original_seven_stats'],'original metadata changed')
        wrappers[name]=raw
    manifest=json.loads(wrappers['MANIFEST']);intent=json.loads(wrappers['INTENT'])
    need(pin(wrappers['MANIFEST'])==index['manifest'],'manifest identity differs')
    aliases={}
    for logical,row in manifest['files'].items():aliases.setdefault(row['storage_path'],[]).append(logical)
    seen=set();compared=0;byte_count=0
    with gzip.GzipFile(fileobj=io.BytesIO(archive),mode='rb') as gz:
        with tarfile.open(fileobj=gz,mode='r|') as tar:
            for member in tar:
                need(member.isfile() and not member.issym() and not member.islnk() and member.mode==0o444
                    and member.name not in seen,'invalid/duplicate archive member')
                seen.add(member.name);stream=tar.extractfile(member);raw=stream.read(member.size+1)
                need(len(raw)==member.size,'truncated archive member')
                if member.name=='MANIFEST.json':need(raw==wrappers['MANIFEST'],'embedded manifest differs');continue
                need(member.name in aliases,'unregistered archive object')
                identity=pin(raw)
                for logical in aliases[member.name]:
                    row=manifest['files'][logical];original,mode,st=read(row['source_path'])
                    need(raw==original and identity==row['identity'] and mode==row['mode'] and st==row['seven_stats'],
                        'whole logical byte/mode/seven-stat differs: '+logical)
                    compared+=1;byte_count+=len(raw)
        while gz.read(1048576):pass
    need(seen==set(aliases)|{'MANIFEST.json'} and compared==2221 and byte_count==1122135347,'complete archive denominator differs')
    # Read exact original inventory function; no sealer or product main is run.
    sealer=read(SOURCE/'build_custody.py')[0];nodes=ast.parse(sealer).body;lines=sealer.splitlines(keepends=True)
    environment={'Path':Path,'os':os,'stat':stat,'stamp':lambda p:stamp(Path(p)),'need':need}
    for node in nodes:
        names=[t.id for t in node.targets if isinstance(t,ast.Name)] if isinstance(node,ast.Assign) else []
        if set(names)&{'ROOTS','EXTRAS'} or isinstance(node,ast.FunctionDef) and node.name=='inventory':
            exec(compile(b''.join(lines[node.lineno-1:node.end_lineno]),'<original-data-inventory>','exec'),environment)
    files,dirs=environment['inventory']()
    need(files==intent['all_original_files'] and dirs==intent['directories']==manifest['directories'],'original pathsets/directory stats differ')
    need({n:stamp(Path(p)) for n,p in files.items()}==intent['before_seven_stats'],'original final stats differ')
    for row in index['metadata']:
        if 'original' not in row:continue
        old=row['original'];raw,mode,st=read(old['path'])
        need(actual[row['mount']]==raw and dict(pin(raw),mode=mode)==old['identity'] and st==old['seven_stats'],'extra original metadata changed')
    report={'schema':'hia.R11.complete-raw.actual-Git-readback.v1','status':'PASS_ALL_ACTUAL_GIT_BYTES_AND_ORIGINALS',
        'actual_POST_and_full_GET_leaves':len(get_rows),'archive':index['archive'],'manifest':index['manifest'],
        'logical_files':compared,'logical_bytes':byte_count,'archive_members':len(seen),
        'gzip_footer_CRC_complete':True,'all_original_bytes_modes_seven_stats_pathsets_exact':True,
        'original_qualification':'FAIL','products':0,'refs':0,'deletions':0,'additional_uncompressed_copy_created':False,
        'full_reader_other_outputs_not_in_this_transport':True,'elapsed_ns':time.monotonic_ns()-started}
    dump('ACTUAL-GIT-READBACK.json',report);dump('ALL-ACTUAL-GETS.json',get_rows)
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':
    try:main()
    except BaseException:
        dump('READBACK-FAILURE.json',{'status':'FAIL_DATA_READBACK','products':0,'traceback':traceback.format_exc()});raise
