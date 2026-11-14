#!/usr/bin/env python3
"""One bounded restored-interpreter metadata preparation; no project entry."""
from pathlib import Path
import ctypes,hashlib,json,os,signal,stat,subprocess,sys,time,traceback
BASE=Path("/tmp/hia-u32-r8-post-reset-r3-dda7")
LAUNCH=BASE/"PREPARATION-LAUNCH.json"
AUTH=Path("/tmp/hia-progress-v148-20261114-dda7/R8-PREPARATION-AUTHORIZATION.json")
OUT=Path("/tmp/hia-r8-input-view-preparation-r3-outer-dda7")
def pin(b):
    return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
def seven(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,str(p)
    b=p.read_bytes();assert seven(p.lstat())==seven(s),str(p)
    return b,seven(s)
def dump(name,v):
    with (OUT/name).open("x",encoding="utf-8") as f:f.write(json.dumps(v,sort_keys=True,indent=2)+"\n")
def group_exists(pid):
    try:os.killpg(pid,0);return True
    except ProcessLookupError:return False
def main():
    auth_raw,_=read(AUTH);auth=json.loads(auth_raw)
    assert auth["authorized"] is True and auth["maximum_attempts"]==1
    assert auth["scope"]=="R8_808_INPUT_VIEW_ONLY_NO_ORACLE_OR_PRODUCTS"
    assert auth["outer_seconds"]==180 and auth["cleanup_seconds"]==3
    review_raw,_=read(Path(auth["root_review"]["path"]))
    assert pin(review_raw)==auth["root_review"]["identity"]
    review=json.loads(review_raw);assert review["status"]=="PASS_R3_AUTHORING_AND_MAPPING_ONLY"
    launch_raw,launch_stats=read(LAUNCH)
    assert pin(launch_raw)==auth["launch_identity"]
    launch=json.loads(launch_raw)
    assert launch["outer_root"]==str(OUT) and launch["maximum_attempts"]==1
    assert launch["products"]==0 and launch["input_copies"]==808
    assert launch["cwd"]==str(BASE)
    assert launch["argv"][0:2]==["/usr/bin/env","-i"]
    for key in ("runner","plan"):
        desc=launch[key];b,s=read(Path(desc["path"]))
        assert pin(b)=={k:desc["identity"][k] for k in ("bytes","sha256","git_blob")}
        assert stat.S_IMODE(s[2])==desc["identity"]["mode"] and s==desc["new_seven_stats"]
    plan=json.loads(read(Path(launch["plan"]["path"]))[0])
    assert launch["argv"][-4:]==["--plan",launch["plan"]["path"],"--plan-sha256",launch["plan"]["identity"]["sha256"]]
    assert all(not Path(p).exists() for p in plan["must_be_absent"])
    assert not OUT.exists()
    OUT.mkdir(mode=0o700)
    dump("INTENT.json",{"schema":"hia.root.r8.input-preparation.outer-intent.v1","authorization":pin(auth_raw),"launch":pin(launch_raw),"launch_seven_stats":launch_stats,"argv":launch["argv"],"cwd":launch["cwd"],"owner_seconds":180,"cleanup_seconds":3,"maximum_attempts":1,"project_products":0,"metadata_launcher_python":sys.version,"metadata_launcher_executable":sys.executable})
    libc=ctypes.CDLL(None,use_errno=True)
    assert libc.prctl(36,1,0,0,0)==0,ctypes.get_errno()
    value=ctypes.c_int()
    assert libc.prctl(37,ctypes.byref(value),0,0,0)==0 and value.value==1
    result={"schema":"hia.root.r8.input-preparation.outer-result.v1","status":"FAIL","restored_interpreter_invocations":0,"project_products":0,"original_oracle_owner_executions":0,"maximum_attempts":1,"timeout":False,"subreaper":True}
    child=None;start=time.monotonic_ns();adopted=[];echild=False
    try:
        with (OUT/"stdout.bin").open("xb") as stdout,(OUT/"stderr.bin").open("xb") as stderr:
            child=subprocess.Popen(launch["argv"],cwd=launch["cwd"],env={},stdout=stdout,stderr=stderr,start_new_session=True,close_fds=True)
            result["restored_interpreter_invocations"]=1;result["pid"]=child.pid
            dump("SPAWNED.json",{"pid":child.pid,"pgid":child.pid,"started_monotonic_ns":start})
            try:result["returncode"]=child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                result["timeout"]=True
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                result["returncode"]=child.wait(timeout=3)
        deadline=time.monotonic()+3
        if group_exists(child.pid):
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        while True:
            try:
                pid,status=os.waitpid(-1,os.WNOHANG)
                if pid:adopted.append({"pid":pid,"status":status});continue
            except ChildProcessError:echild=True;break
            if time.monotonic()>=deadline:break
            time.sleep(0.01)
        result.update(ECHILD=echild,adopted=adopted,process_group_absent=not group_exists(child.pid))
        result["stdout"]=pin((OUT/"stdout.bin").read_bytes());result["stderr"]=pin((OUT/"stderr.bin").read_bytes())
        if result["returncode"]==0 and not result["timeout"] and echild and result["process_group_absent"]:
            result["status"]="PASS_ONE_METADATA_PREPARATION_PROCESS"
    except BaseException:
        result["error"]=traceback.format_exc()
        raise
    finally:
        if child is not None and child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:result["cleanup_incomplete"]=True
        result["elapsed_ns"]=time.monotonic_ns()-start
        dump("RESULT.json",result)
        print(json.dumps(result,sort_keys=True))
    return 0 if result["status"]=="PASS_ONE_METADATA_PREPARATION_PROCESS" else 1
if __name__=="__main__":raise SystemExit(main())
