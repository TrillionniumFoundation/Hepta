"""One complete Budget B suite in a fresh owned 1800-second process."""
from __future__ import annotations
import argparse,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",choices=("native",),required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    before=support.source_snapshot()
    command=[sys.executable,"-I","-B",str(ROOT/"tests/hia_budget_resource_retirement_suite.py"),
             "--suite",args.suite,"--output",str(args.output/"suite")]
    environment=dict(os.environ)
    variable="HEPTA_HIA_BUDGET_RESOURCE_EVIDENCE"
    environment[variable]=str(args.output/"component")
    result,report,raw=support.run_child(args.output,"suite",command,seconds=1800,env=environment)
    if report["status"]!="PASS_COMPLETE_SUITE":raise AssertionError("complete Budget B suite failed")
    after=support.source_snapshot()
    if not support.same(before,after):raise AssertionError("suite source changed")
    support.write_json(args.output/"report.json",{
        "schema":"hepta.hia.budget-resource-owned-suite.v1","suite":args.suite,
        "status":"PASS_COMPLETE_SUITE","source_before":before,"source_after":after,
        "command":command,"outer_result":support.file_pin(args.output/"suite.result.json"),
        "outer_start":support.file_pin(args.output/"suite.start.json"),
        "suite_report":support.bytes_pin(raw),"component_evidence":report["component_evidence"],
        "whole_native_stack_qualified":False})
    return 0
if __name__=="__main__":raise SystemExit(main())
