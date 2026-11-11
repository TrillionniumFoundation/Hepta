"""Independent complete member and logical CAS readback of sealed peer originals."""
from hashlib import sha256
import gzip
import json
from pathlib import Path
import re
import tarfile
import time
import traceback
import zlib

OUT=Path(__file__).resolve().parent; BASE=OUT.parent
NAMESPACE=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/commit-r2-complete-02')
jobs=[
 dict(name='worker-request-r1',archive=BASE/'hia-native-agent-worker-request-r1-development.tar.xz',
      sha='e971d4672e8a0630d014e65a57bf26a1b2fef77fcbd05c87ecaffbe849eea14b',bytes=2263696,
      index=BASE/'hia-native-agent-worker-request-r1-development.tar.members.json',
      index_sha='e3ce5a6bed8a4b17200b07f080d8585a334ebe48d53ae5642b73769172114e33',field=None,members=5503,cas=3747),
 dict(name='cli-argv-formatter-r1',archive=BASE/'hia-native-cli-argv-formatter-r1-development.tar.xz',
      sha='37ed85a727a2c18f08e0a5b3c473556db14a51e376cb62ce4c62169c7f311d9e',bytes=13539564,
      index=BASE/'hia-native-cli-argv-formatter-r1-development.custody.json',
      index_sha='7988b5d2b91759cbaa854ba6c89e8946b8efe9708ea69115c7ad16ff22083641',field='rows',members=27046,cas=26842),
 dict(name='namespace-commit-r2-complete',archive=NAMESPACE/'namespace-commit-r2-development.tar.xz',
      sha='5434f4ca606ba0437fd9ec91928d8ad3209e90b3b22d68dd0b9c902c0c22557f',bytes=2162412,
      index=NAMESPACE/'custody.json',index_sha='87e9e9ebab1ef970dedca4c1fb1cef37736d03de3de91d028b8398a0ecf6e66a',
      field='members',members=103,cas=None,extra='CUSTODY.json')]
rows=[]; start=time.monotonic_ns(); summary=dict(status='INCOMPLETE',scope='INDEPENDENT_COMPLETE_ARCHIVE_READBACK_NOT_NEW_SEMANTIC_EXECUTION')
try:
    for job in jobs:
        raw=job['archive'].read_bytes();assert (len(raw),sha256(raw).hexdigest())==(job['bytes'],job['sha'])
        index_raw=job['index'].read_bytes();assert sha256(index_raw).hexdigest()==job['index_sha']
        data=json.loads(index_raw); members=data[job['field']] if job['field'] else data
        expected={x['name']:x for x in members};assert len(expected)==len(members)
        seen=set(); total=0; cas=0; logical=0
        with tarfile.open(job['archive'],'r|xz') as archive:
            for member in archive:
                assert member.isfile() and member.name not in seen;seen.add(member.name)
                payload=archive.extractfile(member).read()
                if member.name==job.get('extra'):
                    assert payload==index_raw and member.mode==0o644
                    continue
                row=expected[member.name]
                assert (len(payload),sha256(payload).hexdigest(),member.mode)==(row['bytes'],row['sha256'],row['mode'])
                total+=len(payload)
                stem=Path(member.name).name.split('.')[0]
                if re.fullmatch('[0-9a-f]{64}',stem) and member.name.endswith(('.gz','.zlib')):
                    expanded=gzip.decompress(payload) if member.name.endswith('.gz') else zlib.decompress(payload)
                    assert sha256(expanded).hexdigest()==stem
                    cas+=1;logical+=len(expanded)
        assert len(seen)==job['members'] and seen==set(expected)|({job['extra']} if job.get('extra') else set())
        if job['cas'] is not None:assert cas==job['cas']
        assert job['archive'].read_bytes()==raw and job['index'].read_bytes()==index_raw
        result=dict(name=job['name'],status='PASS',archive=str(job['archive']),archive_bytes=len(raw),archive_sha256=job['sha'],
                    index=str(job['index']),index_bytes=len(index_raw),index_sha256=job['index_sha'],
                    members=len(seen),original_bytes=total,logical_cas_objects=cas,logical_cas_bytes=logical,
                    all_member_names_bytes_modes_sha_verified=True,all_logical_cas_reassembled_and_sha_verified=True)
        rows.append(result);print(json.dumps(result,sort_keys=True),flush=True)
    summary.update(status='PASS',results=rows)
except BaseException as exc:
    summary.update(status='FAIL',completed=rows,error_class=type(exc).__name__,error=str(exc));traceback.print_exc();raise
finally:
    summary['elapsed_ns']=time.monotonic_ns()-start
    (OUT/'peer-root-readback-r1.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('results','completed')},sort_keys=True),flush=True)
