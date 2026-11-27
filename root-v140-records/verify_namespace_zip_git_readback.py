import base64,hashlib,io,json,stat,zipfile,zlib
from pathlib import Path
ROOT=Path('/workspace/scratch/dda74a4fae35')
BASE=ROOT/'v95-audit-mount-r1/v140-progress'
PARTS=BASE/'namespace-Git-readback'
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
recipe_raw=(BASE/'NAMESPACE-COMPLETE-RECIPE.json').read_bytes()
assert pin(recipe_raw)['git_blob']=='66698d0b1b1f3e4597cbb5751bc725970797e707'
recipe=json.loads(recipe_raw); spans=recipe['zip_transport'];assert len(spans)==7
chunks=[];offset=0
for index,entry in enumerate(spans):
 raw=(PARTS/('part-%02d.json'%index)).read_bytes();actual=pin(raw)
 assert all(actual[k]==entry[k] for k in actual)
 d=json.loads(raw);assert d['index']==index and d['offset']==entry['offset']==offset
 piece=base64.b64decode(d['payload_base64'],validate=True)
 assert base64.b64encode(piece).decode()==d['payload_base64'] and pin(piece)==entry['decoded']==d['decoded']
 chunks.append(piece);offset+=len(piece)
archive=b''.join(chunks);expected=recipe['original_zip'];identity=pin(archive)
assert all(identity[k]==expected[k] for k in identity)
assert archive==Path(expected['path']).read_bytes()
members=json.loads((PARTS/'ZIP-MEMBERS.json').read_bytes())
central=json.loads((PARTS/'ZIP-CENTRAL.json').read_bytes())
assert len(members)==len(central)==46
total=0;modes=set()
with zipfile.ZipFile(io.BytesIO(archive)) as z:
 infos=z.infolist();assert len(infos)==46 and len({i.filename for i in infos})==46
 for info,row,old in zip(infos,members,central):
  assert not info.is_dir() and not info.filename.startswith('/') and '..' not in Path(info.filename).parts
  assert stat.S_ISREG(info.external_attr>>16)
  raw=z.read(info);p=pin(raw)
  assert all(p[k]==row[k] for k in p)
  assert row['path']==old['path']==info.filename
  assert row['compressed_bytes']==old['compressed_bytes']==info.compress_size
  assert row['crc32']==old['crc32']=='%08x'%(zlib.crc32(raw)&0xffffffff)=='%08x'%info.CRC
  assert row['external_attr']==old['external_attr']==info.external_attr
  assert row['create_system']==old['create_system']==info.create_system
  assert row['mode']==stat.S_IMODE(info.external_attr>>16)
  assert row['zip_datetime']==list(info.date_time) and row['header_offset']==info.header_offset
  assert old['is_dir'] is False
  total+=len(raw);modes.add(row['mode'])
assert total==8003833
report={'schema':'hepta.root-namespace-original-zip-Git-readback.v1','status':'PASS',
 'source':'seven full GET-verified Git JSON blobs; strict canonical Base64 decode; ordered exact original ZIP reconstruction',
 'recipe':pin(recipe_raw),'parts':7,'original_zip':identity,'original_local_zip_full_bytes_equal':True,
 'member_count':46,'member_bytes':total,'all_members_CRC_SHA_Git_full_bytes_verified':True,
 'all_recorded_member_metadata_and_POSIX_modes_verified':True,'member_posix_modes':sorted(modes),
 'original_directory_entries':0,'no_directory_mode_invented':True,'no_archive_extraction':True,
 'original_method_status':'FAIL','workflow_harness_status':'SUCCESS','qualification':False,
 'new_product_execution':False,'whole_native':False,'production_legacy_retired':False,
 'reader':pin(Path(__file__).read_bytes())}
out=BASE/'ROOT-NAMESPACE-COMPLETE-GIT-READBACK.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'report':str(out),'pin':pin(out.read_bytes()),'status':'PASS','members':46,'raw_bytes':total}))
