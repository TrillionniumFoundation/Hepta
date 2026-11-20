"""Own the unchanged complete bootstrap caller command and retain its raw report."""
from __future__ import annotations
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
from tests.hia_slot_operations_qualification_support import run_owned
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope",choices=("ordinary","journal","context"),required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cold-report",type=Path)
    group.add_argument("--development-manifest",type=Path)
    parser.add_argument("--development-compiler",type=Path)
    parser.add_argument("--journal-development-manifest",type=Path)
    parser.add_argument("--evidence",type=Path,required=True)
    args=parser.parse_args();args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    source=support.source_snapshot()
    command=[sys.executable,"-I","-B",str(ROOT/"tools/qualify_hia_service_bootstrap_callers.py"),
             "--scope",args.scope,"--evidence",str(args.evidence/"callers")]
    for name in ("cold_report","development_manifest","development_compiler","journal_development_manifest"):
        value=getattr(args,name)
        if value is not None:command+=["--"+name.replace("_","-"),str(value)]
    report={"schema":"hepta.hia.service-bootstrap-owned-callers.v1","status":"HOLD",
            **support.child_identity(),"scope":args.scope,"source_before":source,
            "command":command,"original_budget_seconds":1800,"whole_native_stack_qualified":False}
    try:
        result=run_owned(command,cwd=ROOT,directory=args.evidence/"owned",timeout_seconds=1800,
                         environment=dict(os.environ))
        report["owned_result"]=support.file_pin(args.evidence/"owned/result.json")
        report["owned_command"]=support.file_pin(args.evidence/"owned/command.json")
        cleanup=result["owned_cleanup"]
        if (type(result["exit_code"]) is not int or result["exit_code"]!=0 or result["timed_out"]
                or result["interruption"] is not None or not cleanup["reaped"]
                or cleanup["after"] or cleanup["signals"]):
            raise AssertionError("unchanged complete caller command failed")
        raw,inner,pin=support.capture_json(args.evidence/"callers/report.json")
        report["original_inner_report"]=pin
        if inner["status"]!="PASS" or inner["scope"]!=args.scope:
            raise AssertionError("actual complete original caller report failed")
        report["source_after"]=support.source_snapshot()
        if not support.same(source,report["source_after"]):
            raise AssertionError("owned caller source changed")
        support.exact_reread(args.evidence/"callers/report.json",raw)
        report["status"]="PASS_COMPLETE_CALLERS"
        return 0
    finally:support.write_json(args.evidence/"report.json",report)
if __name__=="__main__":raise SystemExit(main())
