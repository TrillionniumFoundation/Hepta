"""Omit complete credential-bearing response files from public custody."""
from pathlib import Path
import base64
import hashlib
import json
import re
import urllib.parse
import zlib

ROOT=Path(__file__).resolve().parents[1]
OUT=Path(__file__).resolve().parent
BLOCKED=('actual/artifact-download-001.RESPONSE.json','actual/TRANSFER.json')
PRIVATE_HEADERS={'authorization','proxy-authorization','set-cookie','cookie','www-authenticate'}

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def js(x):return (json.dumps(x,indent=2,sort_keys=True)+'\n').encode()
def write(name,raw):
    p=OUT/name;p.open('xb').write(raw);p.chmod(0o644);assert p.read_bytes()==raw
    return {'path':'custody-public-r2/'+name,'local_path':str(p),'mode':420,'git_mode':'100644',**pin(raw)}

def signed_urls(raw):
    count=0
    for m in re.finditer(r'https?://[^\s\"<>]+',raw.decode()):
        q=urllib.parse.parse_qs(urllib.parse.urlsplit(m.group(0).replace('\\u0026','&')).query)
        if set(q)&{'sig','signature','token','access_token','X-Amz-Signature'}:count+=1
    return count

def main():
    oldwrapper=json.loads((ROOT/'custody-r1/SMALL-ORIGINALS.zlib.json').read_bytes())
    original=zlib.decompress(base64.b64decode(oldwrapper['payload'],validate=True))
    assert pin(original)==oldwrapper['decoded']
    old=json.loads(original);assert len(old['files'])==132
    files=dict(old['files']);excluded={name:files.pop(name) for name in BLOCKED}
    for row in excluded.values():
        raw=base64.b64decode(row['base64'],validate=True)
        assert Path(row['origin']).read_bytes()==raw
    assert len(files)==130
    for name,row in files.items():
        raw=base64.b64decode(row['base64'],validate=True)
        assert pin(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
        assert signed_urls(raw)==0,(name,'unexpected signed URL')
    download_raw=base64.b64decode(excluded[BLOCKED[0]]['base64'],validate=True)
    assert signed_urls(download_raw)==3
    provider=json.loads(download_raw)['structuredContent']
    transfer=json.loads(base64.b64decode(excluded[BLOCKED[1]]['base64'],validate=True))
    excluded_headers=[name for name,value in transfer['response_headers'] if name.lower() in PRIVATE_HEADERS]
    assert excluded_headers==['set-cookie','set-cookie']
    local_only={name:{'bytes':row['bytes'],'sha256':row['sha256'],'mode':row['mode'],
                      'retained_location':row['origin'],'complete_original_retained_locally':True}
                for name,row in excluded.items()}
    provider_public={'schema':'hepta.namespace-provider-result-public.v2','artifact_id':provider['artifact_id'],
        'file_name':provider['file_name'],'mime_type':provider['mime_type'],
        'complete_source_response_local_only':local_only[BLOCKED[0]],'download_urls_included':False}
    transfer_public={key:value for key,value in transfer.items() if key!='response_headers'}
    transfer_public.update(schema='hepta.namespace-transfer-public-projection.v2',
        response_headers=[(name,value) for name,value in transfer['response_headers'] if name.lower() not in PRIVATE_HEADERS],
        excluded_header_names=excluded_headers,complete_source_response_local_only=local_only[BLOCKED[1]])
    provider_leaf=write('PROVIDER-RESULT-PUBLIC.json',js(provider_public))
    transfer_leaf=write('TRANSFER-PUBLIC.json',js(transfer_public))
    classification={'schema':'hepta.namespace-public-custody-classification.v2','original_file_count':132,
        'public_lossless_original_file_count':130,'excluded_local_only_file_count':2,
        'excluded_files':local_only,'excluded_reasons':{
           BLOCKED[0]:'Provider signed download URL repeated in three result fields.',
           BLOCKED[1]:'Two actual provider Set-Cookie response headers.'},
        'signed_url_expiry_utc':'2026-11-14T12:44:05Z','expiry_checked_at_utc':'2026-11-14T12:54:16Z',
        'signed_url_expired_at_check':True,'masked_authorization_log_files':['actual/FULL-JOB.log','actual/job-log-001.RESPONSE.json'],
        'masked_log_value_is_only_asterisks':True,'credential_values_included':False,
        'no_claim_to_publish_all_132_original_bytes':True}
    classification_leaf=write('PUBLIC-CLASSIFICATION.json',js(classification))
    payload=js({'schema':'hepta.namespace-fresh-nonsensitive-originals.v2','files':files,
        'original_nonsensitive_files':130,'excluded_local_only':local_only,
        'provider_result_public_projection':provider_public,'transfer_public_projection':transfer_public,
        'classification':classification,'scope':'Lossless 130 non-sensitive original files; two complete credential-bearing responses retained locally only. This capsule does not contain all 132 original files.'})
    wrapped=js({'schema':'hepta.lossless-zlib-capsule.v1','decoded':pin(payload),'members':130,
        'credential_bearing_originals_included':False,'payload':base64.b64encode(zlib.compress(payload,1)).decode()})
    capsule=write('PUBLIC-ORIGINALS.zlib.json',wrapped)
    assert zlib.decompress(base64.b64decode(json.loads(wrapped)['payload'],validate=True))==payload
    report={'schema':'hepta.namespace-fresh-public-custody-correction.v2','status':'PUBLIC_SUCCESSOR_LOCAL_READBACK_PASS',
        'cause':'The initial public capsule erroneously included credential-bearing provider responses; use only this separately classified public successor.',
        'public_lossless_original_files':130,'excluded_local_only_original_files':2,
        'excluded_names':list(BLOCKED),'complete_originals_retained_locally':True,
        'public_capsule_contains_signed_url':False,'public_capsule_contains_provider_cookie_values':False,
        'decoded_payload':pin(payload),'capsule':capsule,'original_zip_six_parts_unchanged':True,
        'product_executions':0,'downloads':0,'original_run_source_reports_unchanged':True}
    report_leaf=write('PUBLIC-READBACK.json',js(report))
    prior=json.loads((ROOT/'custody-r1/LEAVES.json').read_bytes())['files']
    leaves=[row for row in prior if row['path'] not in ('custody-r1/SMALL-ORIGINALS.zlib.json','custody-r1/LOCAL-READBACK.json')]
    leaves += [capsule,provider_leaf,transfer_leaf,classification_leaf,report_leaf]
    p=OUT/'seal_public.py';leaves.append({'path':'custody-public-r2/seal_public.py','local_path':str(p),'mode':420,'git_mode':'100644',**pin(p.read_bytes())})
    # Private reconciliation records are not members of this publication list.
    assert all('LOCAL-ONLY' not in r['path'] and r['path']!='custody-public-r2/CLASSIFICATION.json' for r in leaves)
    private=json.loads((OUT/'LOCAL-ONLY-CREDENTIAL-RECONCILIATION.json').read_bytes())
    legacy_ids=(private['unsafe_blob_git'],private['unsafe_recipe_git'])
    for row in leaves:
        raw=Path(row['local_path']).read_bytes()
        assert all(value.encode() not in raw for value in legacy_ids)
    assert all(value.encode() not in payload for value in legacy_ids)
    result=write('LEAVES.json',js({'schema':'hepta.namespace-fresh-public-custody-leaves.v2','leaf_count':len(leaves),
        'files':leaves,'public_original_files':130,'excluded_local_only_files':2}))
    print(json.dumps({'leaves':len(leaves),'result':result,'capsule':capsule,'excluded_files':list(BLOCKED),'no_product_calls':True},sort_keys=True))

if __name__=='__main__':main()
