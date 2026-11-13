"""Independent complete original ZIP/selected-body audit; no network or product."""
from __future__ import annotations
import gzip,hashlib,io,json,os,stat,sys,tarfile,zipfile
from pathlib import Path
ROOT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-wire89-failure-artifact-r1")
sys.path.insert(0,str(ROOT/'control'));import source_common as c
os.umask(0o077)
OUT=ROOT/'actual';DEST=ROOT/'custody';DEST.mkdir(mode=0o700)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return c.read_regular(p)
def dump(p,v):return c.save_json(p,v)
qraw,qp=read(ROOT/'REQUEST.json');q=json.loads(qraw)
q['worker_command']=[qp['sha256'] if x=='<REQUEST-SHA256>' else x for x in q['worker_command_template']]
wraw,wp=read(OUT/'owner-wrapper.json');owner,oreq,natural=c.bind_closed(q,json.loads(wraw),OUT/'process-owner.json')
assert natural
fraw,fp=read(OUT/'FINAL.json');f=json.loads(fraw)
assert f['closed'] is True and f['natural_zero'] is True and f['status']=='OFFICIAL_ARTIFACT_READBACK_PASS_NOT_PRODUCT_PASS' and f['errors']==[]
rraw,rp=read(OUT/'REPORT.json');r=json.loads(rraw)
assert r['status']=='WHOLE_OFFICIAL_ARTIFACT_READBACK_COMPLETE_NOT_PRODUCT_PASS' and r['exception'] is None and r['download_attempts']==1
zraw,zp=read(OUT/'ARTIFACT.original.zip')
assert len(zraw)==q['artifact']['bytes']==184277812 and sha(zraw)==q['artifact']['sha256']=='7fbf94897cc2ad1866ff9be22fe203ce91ec90519f69827afc456755c4135b16'
names=[x['name'] for x in r['members']]
assert len(names)==len(set(names))==9436 and [x['index'] for x in r['members']]==list(range(9436))
selected={x['name']:x for x in r['selected']};assert len(selected)==len(r['selected'])==39
assert set(selected)=={x['name'] for x in r['members'] if not x['is_directory'] and any(x['name'].startswith(p) for p in q['selected_prefixes'])}
extra=DEST/'current-cold-B3';extra.mkdir(mode=0o700)
checks=0;expanded=0;b3={}
with zipfile.ZipFile(io.BytesIO(zraw)) as z:
    infos=z.infolist();assert len(infos)==len(r['members'])
    for info,row in zip(infos,r['members']):
        body=z.read(info)
        assert info.filename==row['name'] and len(body)==info.file_size==row['bytes'] and sha(body)==row['sha256'] and info.CRC==row['crc32'] and info.compress_type==row['compress_type'] and info.compress_size==row['compressed_bytes'] and info.is_dir()==row['is_directory'] and row['full_body_read_and_crc_verified'] is True
        expanded+=len(body);checks+=1
        if info.filename in selected:
            saved,pin=read(selected[info.filename]['file'])
            assert saved==body and pin==selected[info.filename]['pin'];checks+=1
        prefix='hia-cold.cold/qualification.evidence/B3.'
        if info.filename.startswith(prefix):
            key=info.filename[len(prefix):];b3[key]=body;c.save(extra/('B3.'+key),body)
assert expanded==r['expanded_bytes']==f['expanded_bytes']==871369381
assert set(b3)=={'image.bin','input.bin','output.bin','request.json','receipt.json','stdout.log','stderr.log'}
qual_raw,qual_pin=read(selected['hia-json-wire-callers.json']['file']);qual=json.loads(qual_raw)
assert qual_pin['sha256']=='741cd08c460515fbb4b4d79ec34b2dd2795cc2dd5ba49b40a43f010bc2181a59'
assert qual['tests_chosen']==qual['tests_loaded']==qual['tests_run']==89
assert qual['chosen_test_ids']==qual['loaded_test_ids']==qual['executed_test_ids'] and len(set(qual['chosen_test_ids']))==89
assert not any(qual[k] for k in ('errors','skipped','expected_failures','unexpected_successes','retained_owner_entries','host_encoder_entries'))
assert qual['status']=='FAIL_OR_INCOMPLETE' and len(qual['failures'])==1
target='tests.test_hia_agent_native_tools.NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'
assert qual['failures'][0]['test']==target and '6.0103386270002375 not less than 5' in qual['failures'][0]['trace']
assert qual['source_sha256']=={"examples/hia_bootstrap/json_wire.hiaasm":"f4e353af23b251d645dee41596dd590820322af4bce5b2545375b74f8eed36a5","hepta/hia_agent_store.py":"822a493b7c6096934af384099eaadd5c4467c6d89193dc3f695887aca256e579","hepta/hia_json_wire_native.py":"0160150f250108452dcbdab5fa09fe3daf3b659822bb2780828dfedaba4a9148","hepta/hia_program_tools.py":"f25118745cd5eb4a9b9023f531812597b776196498591232f49d5bc93966c501","tools/generate_hia_json_wire.py":"89566c2b2a3cfff176a00fd6b92a4c49eb01c56ae91afc11f01c09155fc8baaf","tools/qualify_hia_json_wire_native_callers.py":"10be90961c09fdf6166e2860707191ffc905ba8fd0a3be8d5dd2a1a93e2672d6"}
def selected_body(name):
    return read(selected['hia-json-wire-callers-evidence/wire/'+name]['file'])[0]
image=selected_body('json-wire.image.bin');output=selected_body('json-wire.output.bin');source=selected_body('json-wire.input.bin')
receipt=json.loads(selected_body('json-wire.receipt.json'));request=json.loads(selected_body('json-wire.request.json'));stdout=json.loads(selected_body('json-wire.stdout.log'));manifest=json.loads(selected_body('manifest.json'))
assert len(image)==receipt['produced_bytes']==412976 and len(output)==1048576 and output[:len(image)]==image
assert len(source)==receipt['input_bytes']==361637 and sha(source)==receipt['input_sha256']==request['source_sha256']==manifest['source_sha256']==qual['source_sha256']['examples/hia_bootstrap/json_wire.hiaasm']
assert sha(image)==receipt['produced_sha256']==manifest['image_sha256']==qual['image_sha256']=='6926176cd5907f7b601a0123134d5e145ecb95f0b49d68957adf17cb6d9fd8aa'
assert sha(output)==receipt['output_sha256']==stdout['output_sha256']
assert sha(b3['image.bin'])==receipt['artifact_sha256']==request['image_sha256']==manifest['compiler_sha256']=='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892'
assert b3['output.bin'][:len(b3['image.bin'])]==b3['image.bin'] and len(b3['output.bin'])==1048576
assert receipt['status']==stdout['status']=='returned' and receipt['abi_status']==stdout['abi_status']==0 and receipt['limits']['cpu_seconds']==10 and receipt['limits']['output_capacity']==receipt['limits']['workspace_bytes']==1048576 and request['capacity']==request['workspace_size']==1048576
assert all(receipt[k]==v for k,v in stdout.items()) and selected_body('json-wire.stderr.log')==b''
for item in q['inputs']:read(item['path'])[1]==item
audit={'status':'COMPLETE_OFFICIAL_ZIP_AND_SELECTED_RAW_READBACK_OF_PRODUCT_FAILURE','artifact':q['artifact'],'zip_pin':zp,'members':9436,'expanded_bytes':expanded,'all_member_checks':checks,'selected_originals':39,'selected_bytes':r['selected_bytes'],'report_pin':rp,'final_pin':fp,'owner_original':owner,'qualifier_report':qual_pin,'qualifier_tests':89,'chosen_loaded_executed_equal':True,'failures':qual['failures'],'method_wide_counts':qual['per_test_entries'][target],'method_wide_not_evaluate_only':True,'no_evaluate_phase_timing_in_retained_report':True,'wire_source_sha256':sha(source),'wire_image_sha256':sha(image),'current_cold_B3_sha256':sha(b3['image.bin']),'compile_wall_ns':receipt['wall_elapsed_ns'],'compile_outside_failed_test_timer':True,'source_six_full_Git_blobs_joined':qual['source_sha256'],'old_product_failure_retained':True,'new_attempt1_runner_shutdown_separate':True,'GETs':1,'product_reexecutions':0,'root_request_budgets':{'owner':180,'cleanup':3},'whole_ZIP_disposition':'Retained unchanged on durable ai395 host; small custody archive contains all39 selected originals and complete9436-member hashes, not a replacement for whole ZIP.'}
dump(DEST/'READBACK.json',audit)
paths=[p for p in OUT.rglob('*') if p.is_file() and p.name!='ARTIFACT.original.zip']+[ROOT/n for n in ('REQUEST.json','LAUNCH.json','PREEXEC.json','INTENT.json','SPAWN.json','OWNER-FIRST-READBACK.json','QUALIFIER-REPORT-EXACT.json')]+list((ROOT/'control').glob('*.py'))+list(extra.iterdir())+[DEST/'READBACK.json']
records=[]
for p in sorted(paths):
    b,pin=read(p);records.append({'name':p.relative_to(ROOT).as_posix(),'pin':pin,'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\x00'+b).hexdigest()})
manifest={'schema':'hia.wire89.original-custody-archive.v1','whole_zip_retained':zp,'whole_zip_in_small_archive':False,'files':records}
dump(DEST/'ARCHIVE.json',manifest)
archive=DEST/'WIRE89-ORIGINAL-REPORTS-AND-RECEPTION.tar.gz'
fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as target:
  with gzip.GzipFile(fileobj=target,mode='wb',compresslevel=1,mtime=0) as gz:
    with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
      for row in records:
        p=ROOT/row['name'];b,pin=read(p);assert pin==row['pin']
        item=tarfile.TarInfo(row['name']);item.size=len(b);item.mode=0o600;item.mtime=0;tar.addfile(item,io.BytesIO(b))
      b=(DEST/'ARCHIVE.json').read_bytes();item=tarfile.TarInfo('custody/ARCHIVE.json');item.size=len(b);item.mode=0o600;item.mtime=0;tar.addfile(item,io.BytesIO(b))
  target.flush();os.fsync(target.fileno())
archraw,archpin=read(archive);observed=[]
with tarfile.open(fileobj=io.BytesIO(archraw),mode='r:gz') as tar:
  for item in tar:
    b=tar.extractfile(item).read();observed.append(item.name)
    expected=(ROOT/item.name).read_bytes();assert b==expected
assert observed==[x['name'] for x in records]+['custody/ARCHIVE.json']
with gzip.GzipFile(fileobj=io.BytesIO(archraw)) as gz:
  while gz.read(1048576):pass
dump(DEST/'ARCHIVE-READBACK.json',{'archive':archpin,'members':len(observed),'raw_bytes':sum(x['pin']['bytes'] for x in records)+(DEST/'ARCHIVE.json').stat().st_size,'complete_gzip_crc_read':True,'all_tar_bodies_equal':True,'whole_ZIP_external_retained_pin':zp})
print(json.dumps({'audit':read(DEST/'READBACK.json')[1],'archive':archpin,'members':len(observed),'whole_ZIP_bytes':zp['bytes'],'selected39':True,'product_reexecutions':0},sort_keys=True))
