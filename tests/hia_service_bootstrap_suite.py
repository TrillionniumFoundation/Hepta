"""Complete declared bootstrap unittest suites with raw method events."""
from __future__ import annotations
import argparse,ast,os,sys,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
SELECTIONS={
 "source":("tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests",
           "tests.test_hia_service_bootstrap_qualification.ServiceBootstrapQualificationSourceTests"),
 "native":("tests.test_hia_service_bootstrap_qualification.ServiceBootstrapNativeTests",
           "tests.test_hia_service_bootstrap_qualification.ServiceBootstrapResourceTests")}
COUNTS={"source":6,"native":12}
def static_ids(selectors):
    result=[]
    for selector in selectors:
        module,classname=selector.rsplit(".",1)
        tree=ast.parse((ROOT/(module.replace(".","/")+".py")).read_bytes())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==classname)
        result.extend(module+"."+classname+"."+name for name in sorted(
            n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")))
    return result
def flatten(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite):yield from flatten(test)
        else:yield test.id()
def run(args):
    output=args.output;output.mkdir(mode=0o700,parents=True,exist_ok=False)
    source_before=support.source_snapshot()
    expected=static_ids(SELECTIONS[args.suite])
    if len(expected)!=COUNTS[args.suite]:raise ValueError("full declared method count changed")
    planned=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name)
                               for name in SELECTIONS[args.suite])
    if list(flatten(planned))!=expected:
        raise ValueError("actual complete TestLoader IDs differ from declared original inventory")
    events=[];statuses={}
    stream=(output/"events.jsonl").open("xb",buffering=0)
    def emit(value):
        events.append(value);stream.write(support.canonical(value)+b"\n")
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            statuses[test.id()]="running"
            emit({"event":"start","id":test.id()});super().startTest(test)
        def addSuccess(self,test):
            statuses[test.id()]="success";super().addSuccess(test)
        def addFailure(self,test,error):
            statuses[test.id()]="failure";super().addFailure(test,error)
        def addError(self,test,error):
            statuses[test.id()]="error";super().addError(test,error)
        def addSkip(self,test,reason):
            statuses[test.id()]="skip";super().addSkip(test,reason)
        def addExpectedFailure(self,test,error):
            statuses[test.id()]="expected-failure";super().addExpectedFailure(test,error)
        def addUnexpectedSuccess(self,test):
            statuses[test.id()]="unexpected-success";super().addUnexpectedSuccess(test)
        def addSubTest(self,test,subtest,error):
            if error is not None:statuses[test.id()]="subtest-failure"
            super().addSubTest(test,subtest,error)
        def stopTest(self,test):
            emit({"event":"stop","id":test.id(),"status":statuses[test.id()]});super().stopTest(test)
    report={"schema":"hepta.hia.service-bootstrap-suite.v1",**support.child_identity(),
            "suite":args.suite,"status":"HOLD","planned":expected,"source_before":source_before,
            "new_outer_budget_seconds":1800,"whole_native_stack_qualified":False}
    try:
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(planned)
        report.update({"run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
            "skips":len(result.skipped),"expected_failures":len(result.expectedFailures),
            "unexpected_successes":len(result.unexpectedSuccesses)})
        report["source_after"]=support.source_snapshot()
        starts=[row["id"] for row in events if row["event"]=="start"]
        stops=[row["id"] for row in events if row["event"]=="stop"]
        report["starts"],report["stops"]=starts,stops;report["method_statuses"]=statuses
        from tests import test_hia_service_bootstrap_qualification as tests
        if args.suite=="source":
            root=getattr(tests.ServiceBootstrapQualificationSourceTests,"root",None)
        else:
            root=None if tests._NATIVE_AUTHORITY is None else tests._NATIVE_AUTHORITY[0]
        report["component_evidence"]=None if root is None else str(root)
        if root is None:
            report["component_authority"]=None
        elif args.suite=="source":
            report["component_authority"]={
                "path":str(tests.ServiceBootstrapQualificationSourceTests.authority),
                "pin":tests.ServiceBootstrapQualificationSourceTests.authority_pin}
        else:
            report["component_authority"]={"path":str(root/"authority.json"),
                                          "pin":tests._NATIVE_AUTHORITY_PIN}
        if (result.wasSuccessful() and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses and result.testsRun==len(expected)
                and starts==stops==expected and all(statuses[name]=="success" for name in expected)
                and support.same(source_before,report["source_after"])):
            report["status"]="PASS_COMPLETE_SUITE"
        return 0 if report["status"]=="PASS_COMPLETE_SUITE" else 1
    finally:
        stream.close();report["events"]=support.file_pin(output/"events.jsonl")
        support.write_json(output/"report.json",report)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",choices=tuple(SELECTIONS),required=True)
    parser.add_argument("--output",type=Path,required=True)
    return run(parser.parse_args())
if __name__=="__main__":raise SystemExit(main())
