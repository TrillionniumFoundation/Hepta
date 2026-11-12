"""Fetch one immutable original seven-inline FOLLOW51 ZIP for a read-only evidence reader."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY="TrillionniumFoundation/Hepta"
RUN=43225855642
ARTIFACT=13948294840
HEAD="969bebebdd71f5bf185dd5e22ef990cfc0a6bc0b"
SIZE=99436852
SHA="1b1509d6f1aba5ff1f10e907f4ae8c31cad3431ffc01131d16bcd89f77d6d920"
NAME="hia-ordinary-impact-json-inline-r1-recovery-43225855642-1"
API="https://api.github.com/repos/"+REPOSITORY
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None
def timeout(*_):
    raise TimeoutError("original artifact transport180wall")
def digest(path):
    value=sha256()
    with path.open("rb") as stream:
        for part in iter(lambda:stream.read(1<<20),b""):value.update(part)
    return value.hexdigest()
def main():
    assert sys.version_info[:3]==(3,12,14)
    assert os.environ["GITHUB_REPOSITORY"]==REPOSITORY
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    started=time.monotonic_ns();cpu=time.process_time()
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();output=args.output.absolute();output.parent.mkdir(parents=True,exist_ok=True)
    partial=output.with_name(output.name+".partial")
    assert not output.exists() and not partial.exists()
    own=Path(__file__).resolve();before=own.read_bytes()
    headers={"Authorization":"Bearer "+os.environ["HIA_ARTIFACT_TOKEN"],
             "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    phase="metadata";status="FAIL";error=None;count=0
    try:
        opener=urllib.request.build_opener(NoRedirect())
        request=urllib.request.Request(API+"/actions/runs/"+str(RUN)+"/artifacts?per_page=100",headers=headers)
        with opener.open(request,timeout=30) as response:
            metadata=response.read(1<<20)
            assert len(metadata)<1<<20
        output.with_name(output.name+".metadata.json").write_bytes(metadata)
        rows=[row for row in json.loads(metadata)["artifacts"] if row["id"]==ARTIFACT]
        assert len(rows)==1
        row=rows[0]
        assert row["name"]==NAME
        assert row["size_in_bytes"]==SIZE and row["digest"]=="sha256:"+SHA and row["expired"] is False
        assert row["workflow_run"]["id"]==RUN and row["workflow_run"]["head_sha"]==HEAD
        endpoint=API+"/actions/artifacts/"+str(ARTIFACT)+"/zip"
        assert row["archive_download_url"]==endpoint
        phase="archive-response"
        response=None
        try:
            response=opener.open(urllib.request.Request(endpoint,headers=headers),timeout=30)
        except urllib.error.HTTPError as redirect:
            if redirect.code not in (301,302,303,307,308):raise
            location=redirect.headers.get("Location")
            assert location and urllib.parse.urlparse(location).scheme=="https"
            redirect.close()
            # Fresh request: the repository token is never forwarded to storage.
            response=urllib.request.urlopen(urllib.request.Request(location),timeout=30)
        assert response is not None
        phase="complete-archive-stream";value=sha256()
        with response,partial.open("xb") as target:
            for part in iter(lambda:response.read(1<<20),b""):
                count+=len(part);assert count<=SIZE
                target.write(part);value.update(part)
        assert count==SIZE and value.hexdigest()==SHA
        partial.chmod(0o600);partial.rename(output)
        assert output.stat().st_size==SIZE and digest(output)==SHA
        status="PASS"
    except BaseException as exc:
        # Do not echo tokens, API error bodies or signed storage URLs.
        error={"phase":phase,"error_class":type(exc).__name__,
               "http_status":getattr(exc,"code",None)}
    finally:
        after_errors=[];unchanged=False
        try:
            unchanged=own.read_bytes()==before
            if not unchanged:after_errors.append({"scope":"SELF_AFTER","error_class":"SourceChanged"})
        except BaseException as exc:
            after_errors.append({"scope":"SELF_AFTER","error_class":type(exc).__name__})
        if status=="PASS":
            try:
                assert output.stat().st_size==SIZE and digest(output)==SHA
            except BaseException as exc:
                after_errors.append({"scope":"ZIP_AFTER","error_class":type(exc).__name__})
        elapsed=time.monotonic_ns()-started;used=time.process_time()-cpu
        if after_errors or not unchanged or elapsed>=180000000000 or used>=90:status="FAIL"
        receipt={"schema":"hia-impact51-original-zip-transport-v1","status":status,
                 "run":RUN,"artifact":ARTIFACT,"head":HEAD,
                 "bytes":count,"expected_bytes":SIZE,"expected_sha256":SHA,
                 "self_sha256":sha256(before).hexdigest(),"self_unchanged":unchanged,
                 "elapsed_ns":str(elapsed),"CPU_seconds":used,"error":error,
                 "after_errors":after_errors,
                 "post_stdout_budget_file":output.name+".post-stdout-budget.json",
                 "repository_token_forwarded_to_storage":False,
                 "project_imports":0,"native_entries":0}
        receipt_path=output.with_name(output.name+".receipt.json")
        try:
            receipt_path.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
            print("HIA_IMPACT51_ZIP_TRANSPORT "+json.dumps(receipt,sort_keys=True),flush=True)
        except BaseException as exc:
            status="FAIL"
            after_errors.append({"scope":"RECEIPT_OR_STDOUT","error_class":type(exc).__name__})
        post_cpu=time.process_time()-cpu;post_elapsed=time.monotonic_ns()-started
        post={"schema":"hia-impact51-transport-post-stdout-budget-v1",
              "status":"PASS" if status=="PASS" and post_cpu<90 and post_elapsed<180000000000 else "FAIL",
              "CPU_seconds":post_cpu,"elapsed_ns":str(post_elapsed),
              "includes_receipt_write_and_stdout_flush":True,
              "limits":{"CPU_seconds":90,"wall_ns":180000000000},
              "original_primary_error_preserved":True,"target_executions":0}
        post_path=output.with_name(output.name+".post-stdout-budget.json")
        try:
            post_raw=(json.dumps(post,sort_keys=True,indent=2)+"\n").encode("utf-8")
            with post_path.open("xb") as stream:stream.write(post_raw)
            assert post_path.read_bytes()==post_raw
        except BaseException as exc:
            status="FAIL"
            after_errors.append({"scope":"POST_STDOUT_BUDGET_WRITE_READBACK","error_class":type(exc).__name__})
        final_cpu=time.process_time()-cpu;final_elapsed=time.monotonic_ns()-started
        if post["status"]!="PASS" or final_cpu>=90 or final_elapsed>=180000000000:status="FAIL"
        if status!="PASS":
            # Preserve the original primary error; finalization failures are separate.
            receipt["status"]="FAIL";receipt["after_errors"]=after_errors
            receipt["final_CPU_seconds"]=final_cpu;receipt["final_elapsed_ns"]=str(final_elapsed)
            receipt["final_measurement_includes_post_budget_readback"]=True
            try:
                receipt_path.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
            except BaseException as exc:
                after_errors.append({"scope":"FAIL_RECEIPT_WRITE","error_class":type(exc).__name__})
            try:
                print("HIA_IMPACT51_ZIP_TRANSPORT_FINAL_FAIL "+json.dumps(receipt,sort_keys=True),flush=True)
            except BaseException:
                pass
        # The original alarm stays active through receipt/flush/post-file readback
        # and the strict final gate. Failed finalization never returns success.
        signal.setitimer(signal.ITIMER_REAL,0)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
