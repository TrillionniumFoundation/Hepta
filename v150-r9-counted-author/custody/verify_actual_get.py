"""Verify only author transport; never import a project or run a product."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
ROOT=Path('/tmp/hia-r9-cross-counted-author-custody-r1-dda7')
AUTHOR=Path('/tmp/hia-r9-cross-counted-author-r1-dda7')
KEYS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(b):
    return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def read(p):
    before=p.lstat();assert stat.S_ISREG(before.st_mode)
    b=p.read_bytes();assert all(getattr(p.lstat(),k)==getattr(before,k) for k in KEYS)
    return b,stat.S_IMODE(before.st_mode),{k:getattr(before,k) for k in KEYS}
def write(name,value):
    b=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with (ROOT/name).open('xb') as f:f.write(b)
    (ROOT/name).chmod(0o644)
    return pin(b)
plan=json.loads(read(ROOT/'PUBLISH-PLAN-R2.json')[0]);content={};rows=[];envelopes=[]
for i,row in enumerate(plan['leaves']):
    prefix=ROOT/'GIT-ACK'/('%03d'%i)
    pb,pm,ps=read(Path(str(prefix)+'.POST.json'))
    gb,gm,gs=read(Path(str(prefix)+'.GET.json'))
    post=json.loads(pb);get=json.loads(gb);text=get['structuredContent']['content'];raw=text.encode()
    assert not post.get('isError') and post['structuredContent']['sha']==row['identity']['git_blob']
    assert not get.get('isError') and pin(raw)==row['identity']
    local,lm,ls=read(Path(row['path']));assert raw==local and lm==0o644
    content[row['mount']]=raw
    marker='"structuredContent":{"content":'
    old=gb.decode();assert old.count(marker)==1
    at=old.index(marker)+len(marker)
    quoted=json.dumps(text,ensure_ascii=False,separators=(',',':'))
    assert old[at:at+len(quoted)]==quoted
    left,right=old[:at],old[at+len(quoted):]
    assert (left+json.dumps(raw.decode(),ensure_ascii=False,separators=(',',':'))+right).encode()==gb
    envelopes.append({'mount':row['mount'],'content_identity':row['identity'],'post_raw_utf8':pb.decode(),
        'post_identity':pin(pb),'post_mode':pm,'post_original_stat':ps,'get_prefix_utf8':left,
        'get_suffix_utf8':right,'get_identity':pin(gb),'get_mode':gm,'get_original_stat':gs})
    rows.append({'mount':row['mount'],'identity':row['identity'],'POST_ACK':True,'full_GET_equal':True,
        'POST_envelope':pin(pb),'GET_envelope':pin(gb)})
parts=json.loads(content['custody/PARTS-INDEX.json'])
capsule=b''.join(content[x['mount']] for x in parts['parts']);assert pin(capsule)==parts['payload']
package=json.loads(capsule);payload=zlib.decompress(base64.b64decode(package['data'],validate=True))
assert pin(payload)==package['payload_identity']
members=json.loads(payload)['members'];index=json.loads(content['custody/AUTHOR-INDEX.json'])
assert len(members)==package['files']==index['files']==36
assert [{k:v for k,v in x.items() if k!='base64'} for x in members]==index['members']
names=set()
for row in members:
    q=row['path'];assert q not in names and not Path(q).is_absolute() and '..' not in Path(q).parts
    names.add(q);b=base64.b64decode(row['base64'],validate=True)
    assert pin(b)==row['identity']
    actual,mode,stamp=read(AUTHOR/q)
    assert actual==b and mode==row['mode'] and stamp==row['original_stat']
assert names=={p.relative_to(AUTHOR).as_posix() for p in AUTHOR.rglob('*') if p.is_file()}
write('API-ENVELOPES-LOSSLESS.json',{'schema':'hepta.exact-api-envelope-payload-dedup.v1',
    'encoding':'GET raw = prefix + json.dumps(exact mounted UTF8 blob, ensure_ascii=False, separators=comma-colon) + suffix',
    'all_40_original_envelopes_full_bytes_reconstruct_equal':True,'rows':envelopes})
write('ACTUAL-GIT-READBACK.json',{'schema':'hepta.r9.cross-counted-author-actual-git-readback.v1',
    'status':'PASS_AUTHOR_TRANSPORT_ONLY','product_executions':0,'repository':plan['repository'],
    'leaves':rows,'complete_GET_leaves':len(rows),'capsule_files':len(members),
    'logical_bytes':sum(x['identity']['bytes'] for x in members),'all_original_bytes_modes_seven_stats_equal':True,
    'all_paths_equal':True,'capsule':parts['payload'],'API_envelope_lossless':True,
    'runtime_guard_scope':'only executable and libpython; two files, no2496-file claim',
    'not_execution_or_qualification':True})
print(json.dumps({'status':'PASS_AUTHOR_TRANSPORT_ONLY','leaves':len(rows),'files':len(members),
    'logical_bytes':sum(x['identity']['bytes'] for x in members),'product_executions':0},sort_keys=True))
