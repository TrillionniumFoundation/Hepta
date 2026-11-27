"""Read only complete Git-GET transport and restore every logical original."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent
def write(path,value):
    with path.open("x",encoding="utf-8") as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write("\n")
def identity(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
            "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def main():
    output=ROOT/"git-readback-restore-r1"
    output.mkdir()
    target=output/"restored"
    argv=[sys.executable,"-B",str(ROOT/"restore.py"),str(ROOT/"TRANSPORT.json"),
          str(ROOT/"GIT-CUSTODY/readback"),str(target)]
    request={"argv":argv,"cwd":str(ROOT),"product_execution":False,"extra_git_posts":0}
    write(output/"REQUEST.json",request)
    started=time.monotonic_ns()
    result=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    elapsed=time.monotonic_ns()-started
    for name,raw in (("stdout",result.stdout),("stderr",result.stderr)):
        with (output/name).open("xb") as stream:stream.write(raw)
    report={"schema":"hepta.custody.actual-full-get-restore.v1","returncode":result.returncode,
            "elapsed_ns":elapsed,"stdout":identity(result.stdout),"stderr":identity(result.stderr),
            "matching_current_source_cold":False,"new_product_execution":False,"whole_native":False,
            "transport":identity((ROOT/"TRANSPORT.json").read_bytes()),
            "source_tree":"3a1c42c02bee93486b1cb440b2f44a8b32dccf65"}
    if result.returncode==0:
        report["observations"]=json.loads(result.stdout)
        assert report["observations"]["logical_count"]==1339
        assert report["observations"]["logical_bytes"]==101776815
        assert report["observations"]["all_bytes_sha_git_modes_verified"] is True
        assert report["observations"]["complete_gzip_crc_isize"] is True
        assert report["observations"]["tar_members"]==854
        report["status"]="ALL_GIT_GET_LOGICAL_ORIGINALS_RESTORED"
    else:report["status"]="RESTORE_FAILED"
    write(output/"REPORT.json",report)
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"]=="ALL_GIT_GET_LOGICAL_ORIGINALS_RESTORED" else 1
if __name__=="__main__":raise SystemExit(main())
