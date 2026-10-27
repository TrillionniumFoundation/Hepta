"""Replay the independently discovered operand-order cases against a checkout.

Pass the checkout explicitly; the script records its real compiler/file hashes
and reports counterexamples instead of treating native rejections as successes.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cases',type=Path,default=Path(__file__).with_name('cases.json'))
    args=parser.parse_args()
    checkout=args.checkout.resolve()
    if args.output.exists():parser.error('Refusing to overwrite audit evidence')
    sys.path.insert(0,str(checkout))
    from hepta.pipeline import analyze,compiler_hash,concurrent_ir_analysis
    cases=json.loads(args.cases.read_text())
    report={'schema':'hepta.concurrent-ir-audit.v1','generated_at_utc':datetime.now(timezone.utc).isoformat(),
            'checkout':str(checkout),'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,text=True).strip(),
            'compiler_sha256':compiler_hash(),'cases_sha256':hashlib.sha256(args.cases.read_bytes()).hexdigest(),
            'reviewed_files':{name:hashlib.sha256((checkout/name).read_bytes()).hexdigest() for name in
                              ('hepta/concurrent_ir.py','hepta/concurrent_lowering.py','hepta/pipeline.py','hepta/backend.py')},
            'source_to_ir_refinement_proved':False,'native_unsafe_artifact_produced':False,'cases':[]}
    graphs=args.output.with_suffix('.graphs');graphs.mkdir(parents=True,exist_ok=False)
    for expectation,sources in cases.items():
        for label,source in sources.items():
            analysis=analyze(source,native=False)
            export=concurrent_ir_analysis(analysis)
            native=analyze(source)
            row={'case':label,'expectation':expectation,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
                 'frontend_ok':analysis.report['ok'],'concurrent_ir_ok':export['ok'],
                 'verifier':export.get('verifier'),'lowering_diagnostics':export.get('diagnostics'),
                 'native_ok':native.report['ok'],'native_checks':native.report['checks'],
                 'native_diagnostics':[{'code':item['code'],'phase':item['phase'],'message':item['message']}
                                       for item in native.report['diagnostics']],
                 'native_toolchain':native.report.get('backend',{}).get('toolchain')}
            if export.get('concurrent_ir') is not None:
                raw=(json.dumps(export['concurrent_ir'],sort_keys=True,indent=2)+'\n').encode()
                path=graphs/(label+'.json');path.write_bytes(raw)
                row['graph']={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
            report['cases'].append(row)
    report['unexpectedly_accepted_invalid_ir']=sum(row['concurrent_ir_ok'] for row in report['cases'] if row['expectation']=='invalid')
    report['native_rejected_invalid']=sum(not row['native_ok'] for row in report['cases'] if row['expectation']=='invalid')
    report['valid_ir_and_native_accepted']=sum(row['concurrent_ir_ok'] and row['native_ok'] for row in report['cases'] if row['expectation']=='valid')
    report['compiler_unchanged_during_audit']=compiler_hash()==report['compiler_sha256']
    with args.output.open('x') as out:json.dump(report,out,sort_keys=True,indent=2);out.write('\n')
    print(json.dumps({key:report[key] for key in ('unexpectedly_accepted_invalid_ir','native_rejected_invalid','valid_ir_and_native_accepted','compiler_unchanged_during_audit')}))


if __name__=='__main__':main()
