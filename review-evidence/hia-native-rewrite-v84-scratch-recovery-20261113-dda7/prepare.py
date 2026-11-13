"""Plan exact base-only removal from three inactive, recoverable source exports."""
from __future__ import annotations
import base64
from hashlib import sha1,sha256
import json
from pathlib import Path
import sys
import zlib

HERE=Path(__file__).resolve().parent
WORK=HERE.parent
BASE=WORK/'v76-product-publication-r1/source'
TARGETS=('v80-joint-global-source-generation-r2/source','v80-public-front-development-r2/source','v81-service-requests-development-r1/source')
sys.path.insert(0,str(WORK/'v81-service-requests-development-r1'))
from package_source import manifest,tree_hash


def main():
    before=manifest(BASE)
    assert len(before)==3153 and tree_hash(before)=='1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
    targets=[]
    for name in TARGETS:
        root=WORK/name
        assert not (root.parent/'PARTIAL-SOURCE-NOT-RUNNABLE.json').exists()
        current=manifest(root)
        same={n:r for n,r in current.items() if before.get(n)==r}
        changed={n:r for n,r in current.items() if n not in same}
        for n in same:assert (root/n).read_bytes()==(BASE/n).read_bytes()
        targets.append({'source':str(root),'original_file_count':len(current),'original_tree':tree_hash(current),
            'recoverable':same,'retained':changed,
            'single_link_reclaimable_bytes':sum(r['bytes'] for n,r in same.items() if (root/n).stat().st_nlink==1)})
    assert manifest(BASE)==before
    plan={'schema':'hia.exact-inactive-base-reclamation.plan.v84.r1',
        'base_source':str(BASE),'base_git_commit':'4b19af89a766593f7d5f1cc2db256e81aba7afcb',
        'base_git_tree':tree_hash(before),'targets':targets,
        'only_inactive_exact_base_duplicates':True,'all_unique_changed_sources_retained':True,
        'all_original_archives_and_logs_retained':True,'production_cleanup':False,'whole_native':False}
    raw=(json.dumps(plan,sort_keys=True,indent=2)+'\n').encode();(HERE/'PLAN.json').write_bytes(raw)
    envelope=(json.dumps({'encoding':'zlib-base64','uncompressed_bytes':len(raw),'uncompressed_sha256':sha256(raw).hexdigest(),
        'data':base64.b64encode(zlib.compress(raw,9)).decode()},sort_keys=True)+'\n').encode()
    (HERE/'PLAN.zlib.json').write_bytes(envelope)
    parts=[]
    for i,at in enumerate(range(0,len(envelope),350000)):
        data=envelope[at:at+350000]; name=f'plan-{i:03d}.utf8';(HERE/name).write_bytes(data)
        parts.append({'number':i,'path':name,'bytes':len(data),'sha256':sha256(data).hexdigest(),
            'blob':sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
    index={'schema':'hia.exact-inactive-base-reclamation.transport.v84.r1','parts':parts,
        'envelope_bytes':len(envelope),'envelope_sha256':sha256(envelope).hexdigest(),
        'plan_bytes':len(raw),'plan_sha256':sha256(raw).hexdigest(),
        'reclaimable_bytes':sum(x['single_link_reclaimable_bytes'] for x in targets),
        'base_commit':plan['base_git_commit'],'base_tree':plan['base_git_tree'],
        'unique_changed_files_retained':sum(len(x['retained']) for x in targets),'whole_native':False}
    (HERE/'INDEX-PREPARED.json').write_text(json.dumps(index,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in index.items() if k!='parts'},sort_keys=True))


if __name__=='__main__':main()
