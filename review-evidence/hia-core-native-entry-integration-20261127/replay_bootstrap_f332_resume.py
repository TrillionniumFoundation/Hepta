from pathlib import Path
from hashlib import sha256
import ast,json,os,subprocess,sys,tempfile,time,unittest
BASE="f332fff0f5a11e16d7dc58c9ddeb8d18158c14e1"
OWNER=Path("/home/qian-qi/hia-core-wiring-20261127-2807")
ROOT=Path("/home/qian-qi/hia-core-wiring-bootstrap-source-f332-2807")
OUT=Path("/home/qian-qi/hia-core-wiring-bootstrap-source-controls-f332-2807")
assert OUT.is_dir()
assert not (OUT/'summary.json').exists()
assert not (OUT/'strict-source-controls.log').exists()
def git(root,*args,data=None):
    result=subprocess.run(["git",*args],cwd=root,input=data,capture_output=True)
    label=str(len(list(OUT.glob("git-*.json")))).zfill(3)
    (OUT/("git-"+label+".json")).write_text(json.dumps({
        "cwd":str(root),"argv":["git",*args],"returncode":result.returncode,
        "stdout":result.stdout.decode(errors="replace"),
        "stderr":result.stderr.decode(errors="replace")},sort_keys=True,indent=2)+"\n")
    if result.returncode:
        raise RuntimeError((args,result.returncode,result.stderr.decode(errors="replace")))
    return result.stdout
assert ROOT.is_dir()
assert git(ROOT,"rev-parse","HEAD").decode().strip()==BASE
from hashlib import sha1
present=0
for row in git(ROOT,"ls-files","-s","-z").split(b"\0"):
    if not row:continue
    info,name=row.split(b"\t",1)
    mode,expected,stage=info.decode().split()
    assert stage=="0"
    path=ROOT/os.fsdecode(name)
    if path.is_symlink():
        assert mode=="120000"
        raw=os.fsencode(os.readlink(path))
    elif path.is_file():
        assert mode in ("100644","100755")
        raw=path.read_bytes()
    else:
        continue
    actual=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    assert actual==expected,("refuse overwriting changed snapshot input",str(path))
    present+=1
(OUT/"resume-existing-bytes.json").write_text(json.dumps(
    {"unchanged_present_files":present,"source_commit":BASE,
     "prior_job":"1a21dd34bd0-ffbe-54ac","prior_checkout_failed_before_tests":True},
    sort_keys=True,indent=2)+"\n")
git(ROOT,"checkout","--detach","--force",BASE)
assert git(ROOT,"rev-parse","HEAD").decode().strip()==BASE
assert not git(ROOT,"status","--porcelain=v1").strip()
before_tree=git(ROOT,"rev-parse","HEAD^{tree}").decode().strip()
temporary=OUT/"tmp";temporary.mkdir()
os.environ["TMPDIR"]=str(temporary);tempfile.tempdir=str(temporary)
os.environ["HEPTA_HIA_SERVICE_BOOTSTRAP_SOURCE_EVIDENCE"]=str(OUT/"source-evidence")
os.chdir(ROOT);sys.path.insert(0,str(ROOT))
selector="tests.test_hia_service_bootstrap_qualification.ServiceBootstrapQualificationSourceTests"
suite=unittest.defaultTestLoader.loadTestsFromName(selector)
def flatten(s):
    for item in s:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item.id()
ids=list(flatten(suite))
assert len(ids)==3 and len(set(ids))==3
started=time.monotonic()
with (OUT/"strict-source-controls.log").open("w") as stream:
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
summary={"source_commit":BASE,"source_tree":before_tree,"python":sys.version,
    "selector":selector,"ids":ids,"planned":len(ids),"run":result.testsRun,
    "failures":len(result.failures),"errors":len(result.errors),"skipped":len(result.skipped),
    "elapsed_seconds":time.monotonic()-started,
    "original_child_budget_seconds":600,"original_cleanup_budget_seconds":3,
    "budget_or_source_code_changed":False,"native_cold_campaign_executed":False,
    "tmpdir":str(temporary),
    "log_sha256":sha256((OUT/"strict-source-controls.log").read_bytes()).hexdigest(),
    "failure_details":[[str(test),error] for test,error in result.failures+result.errors],
    "tracked_after":git(ROOT,"status","--porcelain=v1","--untracked-files=no").decode(),
    "head_after":git(ROOT,"rev-parse","HEAD").decode().strip()}
(OUT/"summary.json").write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
print(json.dumps(summary,sort_keys=True),flush=True)
if (not result.wasSuccessful() or result.skipped or result.testsRun!=len(ids)
        or summary["tracked_after"] or summary["head_after"]!=BASE):
    raise SystemExit(1)

