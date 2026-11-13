from pathlib import Path
import hashlib,json
ROOT=Path('/workspace/scratch/dda74a4fae35/v90-linux-process-cold-r1/raw-custody')
SOURCE=ROOT.parent
def identity(b):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(name,value):
 b=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
 with (ROOT/name).open('xb') as f:f.write(b)
 return identity(b)
def checked(base,row,destination):
 record=json.loads((base/'GIT-CUSTODY'/(row['file']+'.receipt.json')).read_bytes())
 actual=(base/'GIT-CUSTODY/readback'/row['file']).read_bytes()
 assert identity(actual)=={k:row[k] for k in ('bytes','sha256','git_blob')}
 assert record['full_get_verified'] is True and record['full_get_blob']==row['git_blob']
 return {'entry':{'path':destination,'mode':'100644','type':'blob','sha':row['git_blob']},
         'identity':identity(actual),'original_receipt':record}
rows=json.loads((ROOT/'FINAL-PUBLISH-LIST.json').read_bytes())
rows+=json.loads((ROOT/'TRANSPORT.json').read_bytes())['chunks']
checked_rows=[checked(ROOT,r,r['file']) for r in rows]
for receipt in sorted((SOURCE/'GIT-CUSTODY').rglob('*.receipt.json')):
 r=json.loads(receipt.read_bytes())
 checked_rows.append(checked(SOURCE,r,'source/'+Path(r['file']).name))
assert len(checked_rows)==79
assert len({r['entry']['path'] for r in checked_rows})==79
result={'schema':'hepta.custody.complete-leaf-readback.v1','status':'ALL79_FIXED_BLOBS_FULL_GET_BYTES_RECHECKED',
        'members':checked_rows,'restoration_report':'ab0f8c4a878180c1e3280abe7edb8812196a9b06',
        'raw_wrappers':56,'source_packets_and_records':5,'metadata_and_restore_records':18,
        'audit_refs_changed':False,'product_execution':False,'whole_native':False}
meta=write('FINAL-READBACK.json',result)
entries=[r['entry'] for r in checked_rows]
entries.append({'path':'FINAL-READBACK.json','mode':'100644','type':'blob','sha':meta['git_blob']})
entries.sort(key=lambda r:r['path'])
write('MOUNT-RECIPE.json',{'schema':'hepta.audit.immutable-entries.v1','scope':'linux-process-cold-local-source-portable-originals',
                        'status':'COMPLETE_PENDING_AUDIT_MOUNT','entry_count':len(entries),'entries':entries,
                        'all_entries_full_get_verified':True,'source_tree':'3a1c42c02bee93486b1cb440b2f44a8b32dccf65',
                        'matching_current_source_cold':False,'whole_native':False})
print(json.dumps({'final_readback':meta,'recipe':identity((ROOT/'MOUNT-RECIPE.json').read_bytes()),'entries':len(entries)}))
