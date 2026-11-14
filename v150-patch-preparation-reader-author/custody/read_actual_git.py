"""Decode only actual full-GET author payloads, without invoking any reader."""
import base64,hashlib,json,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/hia-patch-terminal-quarantine-preparation-reader-publication-r1-dda7')
BASE=Path('/workspace/hia-patch-terminal-quarantine-preparation-reader-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def seven(s):return {k:getattr(s,k)for k in FIELDS}
def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def write(name,value):
    raw=encode(value)
    with (ROOT/name).open('xb')as stream:stream.write(raw)
    return raw
rows=json.loads((ROOT/'PUBLICATION-INPUTS.json').read_bytes());actual={}
for i,row in enumerate(rows):
    tag='%03d'%i
    ack=json.loads((ROOT/'actual-git'/f'{tag}-ACK.json').read_bytes())
    receipt=json.loads((ROOT/'actual-git'/f'{tag}-VERIFIED.json').read_bytes())
    raw=(ROOT/'actual-git'/f'{tag}-GET.txt').read_bytes()
    assert ack['sha']==receipt['sha']==row['git_blob']and receipt['full_get_exact']is True
    assert raw==row['text'].encode()and pin(raw)=={k:row[k]for k in ('bytes','sha256','git_blob')}
    actual[row['name']]=raw
capsule=json.loads(actual['custody/AUTHORING-CAPSULE.json'])
compressed=base64.b64decode(capsule['data'],validate=True);assert pin(compressed)==capsule['compressed']
decoder=zlib.decompressobj();payload=decoder.decompress(compressed)
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(payload)==capsule['payload']
restored=json.loads(payload)['files'];assert len(restored)==11
for row in restored:
    path=BASE/row['name'];raw=row['text'].encode()
    assert pin(raw)==row['pin']and path.read_bytes()==raw
    assert seven(path.lstat())==row['stat']and stat.S_IMODE(path.lstat().st_mode)==row['mode']
assert sorted(p.name for p in BASE.iterdir())==sorted(r['name']for r in restored)
report={'status':'PASS_ACTUAL_GIT_FULL_GET_AND_COMPLETE_AUTHOR_DECODE',
    'full_get_leaves':len(rows),'full_get_bytes':sum(r['bytes']for r in rows),
    'author_files':len(restored),'author_logical_bytes':sum(r['pin']['bytes']for r in restored),
    'all_author_bytes_modes_seven_stats_equal':True,'gzip_or_zlib_complete':True,
    'capsule':pin(actual['custody/AUTHORING-CAPSULE.json']),
    'reader_execution_by_this_verifier':0,'product_execution':0,'source_copy':False,
    'historical_author_false_execution_markers_not_current_product_status':True}
write('ACTUAL-GIT-READBACK.json',report)
print(json.dumps(report,sort_keys=True))
