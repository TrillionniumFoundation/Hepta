"""Owned exact-head wrapper around the unchanged active release checker."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import traceback
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import probe_c_typedef_alignment as owner
OUT=ROOT/'artifacts/c-typedef-port-release'


def validate_report(report, names):
    gates=report.get('gates',[])
    owner.require(report.get('status')=='passed' and report.get('snapshot_unchanged') is True,'Full release did not pass unchanged')
    owner.require([g.get('name') for g in gates]==names and len(names)==36,'Active gate denominator/order changed')
    owner.require(all(g.get('status')=='passed' and type(g.get('exit_code')) is int and g['exit_code']==0 for g in gates),'An active gate failed')
    unit=gates[0]
    owner.require(type(unit.get('test_count')) is int and unit['test_count']>0 and type(unit.get('skipped')) is int and unit['skipped']==0,'Missing tests or nonzero skips')


def worker():
    pins=json.loads((ROOT/'tools/c_typedef_port_controls.json').read_text())
    result={'schema':'hepta.typedef-port-full-release.v1','ok':False,'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA')}
    try:
        for path,expected in pins['files_sha256'].items():
            owner.require(owner.sha(ROOT/path)==expected,'Source/control identity mismatch: '+path)
        head=owner.run(['git','-c','safe.directory='+str(ROOT),'rev-parse','HEAD'],OUT/'identity','head').strip()
        owner.require(head==result['expected_head'],'Wrong published head')
        result['head']=head
        result['tree']=owner.run(['git','-c','safe.directory='+str(ROOT),'rev-parse','HEAD^{tree}'],OUT/'identity','tree').strip()
        status=owner.run(['git','-c','safe.directory='+str(ROOT),'diff','--name-only','HEAD','--','.',':(exclude)artifacts',':(exclude)evidence',':(exclude)build'],OUT/'identity','status')
        owner.require(not status.strip(),'Tracked source not clean at admission')
        files=owner.run(['git','-c','safe.directory='+str(ROOT),'ls-files'],OUT/'identity','files').splitlines()
        excluded={'.git','__pycache__','artifacts','evidence','build','.venv'}
        files=[p for p in files if not excluded.intersection(Path(p).parts) and Path(p).suffix not in {'.pyc','.bundle'} and not p.endswith('.hepta-lock')]
        before={p:owner.sha(ROOT/p) for p in files};result['source_before']=before
        owner.run([sys.executable,str(ROOT/'tools/release_check.py')],OUT,'release-check',timeout=3300)
        report=json.loads((ROOT/'artifacts/release-validation.json').read_text())
        validate_report(report,pins['active_gate_names'])
        after={p:owner.sha(ROOT/p) for p in files};result['source_after']=after
        owner.require(before==after,'Tracked source/control files changed')
        result.update(ok=True,unit_tests=report['gates'][0]['test_count'],skips=report['gates'][0]['skipped'],gates=36,
                      release_report_sha256=owner.sha(ROOT/'artifacts/release-validation.json'))
    except Exception as exc:
        result['error']=str(exc);(OUT/'exception.txt').write_text(traceback.format_exc())
    finally:owner.write(OUT/'report.json',result)
    return 0 if result['ok'] else 1


def main():
    if '--worker' in sys.argv:return worker()
    owner.require(not OUT.exists(),'Stale release wrapper output')
    OUT.mkdir(parents=True)
    result=owner.supervise([sys.executable,str(Path(__file__).resolve()),'--worker'],timeout=3420,max_output=1_000_000)
    (OUT/'worker.stdout').write_bytes(result.pop('stdout'));(OUT/'worker.stderr').write_bytes(result.pop('stderr'))
    owner.write(OUT/'owned-process-receipt.json',result)
    if not result['cleanup']['confirmed']:
        owner.write(OUT/'UNSEALED.json',{'reason':'Owned cleanup unknown; preserve evidence without qualification seal','supervisor':result});return 1
    files={str(p.relative_to(OUT)):{'bytes':p.stat().st_size,'sha256':owner.sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file()}
    owner.write(OUT/'manifest.json',{'schema':'hepta.typedef-port-release-artifacts.v1','exit_code':result['exit_code'],'files':files,
                'owned_cleanup_confirmed':True,'expected_head':os.environ.get('HEPTA_QUALIFICATION_HEAD_SHA'),
                'scope':'This hosted execution context only; no other host/model/hardware qualification'})
    return result['exit_code']


if __name__=='__main__':raise SystemExit(main())
