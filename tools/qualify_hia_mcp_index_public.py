"""Observe actual native metadata against two pinned unchanged-Rust runs.

Both originals use their real public usage_stats_at entry, not a model of the
index policy. The twelve cases distinguish immutable changes, valid completion,
stamp-only writes, deletion/recreation, and recovery after restoring an original.
Full request/response bytes are retained by UsageAudit. Error text parity beyond
the established native unavailable response is deliberately not claimed here.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import time

from tests.hia_request_audit_native_support import good, write_json
from tools.qualify_hia_mcp_request_archive import seed_archive, UNAVAILABLE
from tools.qualify_hia_mcp_usage import UsageAudit, projected

ORIGINAL_PINS = (
    'fdbfb11edccd9f66342eb3ec68d7dcdc5094724dece4f91b435c1334362d4d14',
    'c01c4e4c49e4d3139bbcc0c64163a6842d3ed8b9c4a5b4998670125e2b630c2e',
)


def relative_times(value, baseline):
    value=dict(value)
    for field in ('first_accepted_unix_ms','last_accepted_unix_ms'):
        # Only the baseline request's real system-clock value differs between
        # hosts. Synthetic retained time 7 and every other field remain exact.
        if value[field] == baseline['last_accepted_unix_ms']:
            value[field]='original-baseline-system-clock'
    return value


def qualify(image, original_paths, output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    expected=[]
    for path,pin in zip(original_paths,ORIGINAL_PINS,strict=True):
        raw=path.read_bytes();assert sha256(raw).hexdigest()==pin
        expected.extend(json.loads(line) for line in raw.splitlines())
    assert len(expected)==12 and len({r['case'] for r in expected})==12
    report={'schema':'hia.native.retained-index-public-original-controls.v1','passed':False,
            'native_image_sha256':sha256(image.read_bytes()).hexdigest(),
            'observer_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
            'original_source_ref':'ae1c7ea593da45f7299c692a2acd44605c35be09',
            'original_observation_sha256':list(ORIGINAL_PINS),'query_budget_seconds':3,
            'original_error_text_parity_claimed':False,'whole_runtime_qualified':False,
            'whole_cold_qualified':False,'checks':[]}
    try:
        for original in expected:
            kind=original['case'];directory=output/kind;directory.mkdir(mode=0o700)
            with UsageAudit(directory/'root',image,directory/'wire') as a:
                good(a.prepare());a.lease(0);start=good(a.begin(tool='host_list'));good(a.finish(start,1))
                row={'request_id':f'{777:064x}','owner':'a'*64,'tool_name':'file_info',
                     'accepted_unix_ms':7,'state':'unknown' if kind=='unknown-completes' else 'completed',
                     'elapsed_ms':None if kind=='unknown-completes' else 3}
                seed_archive(a.root,[row]);before=projected(a.usage())
                assert relative_times(before,before)==relative_times(original['before'],original['before'])
                path=a.root/'request-archive-v11'/(row['request_id']+'.json')
                if kind in ('owner','mutation-restored'):row['owner']='b'*64
                elif kind=='tool':row['tool_name']='host_list'
                elif kind=='accepted':row['accepted_unix_ms']+=1
                elif kind=='terminal':row['state']='failed'
                elif kind=='elapsed':row['elapsed_ms']=4
                elif kind=='terminal-regresses':row.update(state='unknown',elapsed_ms=None)
                elif kind=='unknown-completes':row.update(state='completed',elapsed_ms=9)
                if kind=='new-record':
                    row['request_id']=f'{778:064x}';write_json(path.with_name(row['request_id']+'.json'),row)
                elif kind in ('deleted-record','deleted-recreated'):path.unlink()
                else:path.write_text(json.dumps(row,separators=(',',':')))
                started=time.monotonic_ns();after=a.usage();elapsed=time.monotonic_ns()-started
                if kind=='mutation-restored':
                    row['owner']='a'*64;path.write_text(json.dumps(row,separators=(',',':')))
                if kind=='deleted-recreated':row['owner']='b'*64;write_json(path,row)
                repeated=a.usage()
                checks=[(after['status']==0)==original['after_ok'],
                        (repeated['status']==0)==original['repeated_ok']]
                if original['after_ok']:
                    checks.append(after['status']==0 and relative_times(after['value'],before)==relative_times(original['after'],original['before']))
                for observed in (after,repeated):
                    if observed['status']!=0:
                        checks.append(observed['reason']==38 and observed['text']==UNAVAILABLE)
                if kind=='mutation-restored':checks.append(repeated['value']==before)
                if kind=='deleted-recreated':checks.append(repeated['value']==after['value'])
                item={'case':kind,'passed':all(checks),'before':before,'after':after,
                      'repeated':repeated,'original':original,'query_elapsed_ns':elapsed}
                report['checks'].append(item)
                (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
                print('NATIVE_INDEX_PUBLIC',kind,item['passed'],flush=True)
        report['passed']=all(r['passed'] for r in report['checks'])
        assert report['passed'],'unchanged original public behavior differs'
        return report
    finally:
        (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--original-v1',type=Path,required=True);parser.add_argument('--original-v2',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    report=qualify(args.audit.resolve(),[args.original_v1.resolve(),args.original_v2.resolve()],args.output.resolve())
    print(json.dumps({'passed':report['passed'],'checks':len(report['checks'])}))
