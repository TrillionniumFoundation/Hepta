"""Fetch one immutable original Group6 FOLLOW53 ZIP for a read-only evidence reader."""
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
RUN=43237029243
ARTIFACT=13952974167
HEAD="8f27671ad748dc7c081a1eaad897b057d8d9f42e"
SIZE=100633717
SHA="36f8063dd97c8fffeed958797a22d38e091d9185ef1c90604c75ff509b70093d"
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
    finalization_errors=[]
    def final_failure(where,exc):
        nonlocal status,error
        status="FAIL"
        # Preserve the first sanitized failure; never print tokens or signed URLs.
        value=dict(phase=where,error_class=type(exc).__name__,http_status=getattr(exc,"code",None))
        finalization_errors.append(value)
        if error is None:error=value
    def attempt(where,operation):
        try:return operation()
        except BaseException as exc:
            final_failure(where,exc)
            return None
    def strict_budget(where):
        value=attempt(where,lambda:(time.monotonic_ns()-started,time.process_time()-cpu))
        if value is not None and not (0<=value[0]<180000000000 and 0<=value[1]<90):
            final_failure(where,TimeoutError("original transport strict90CPU180wall"))
        return value
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
        status="FAIL"
        error={"phase":phase,"error_class":type(exc).__name__,
               "http_status":getattr(exc,"code",None)}
    finally:
        observed=attempt("self_after",lambda:own.read_bytes()==before)
        unchanged=observed is True
        if observed is False:final_failure("self_after",AssertionError("transport source changed"))
        if status=="PASS":
            def verify_output():
                assert output.stat().st_size==SIZE and digest(output)==SHA
            attempt("complete_output_after",verify_output)
        measurement=strict_budget("original_budget")
        elapsed,used=(None,None) if measurement is None else measurement
        receipt={"schema":"hia-group6-follow53-original-zip-transport-r1","status":status,
                 "run":RUN,"artifact":ARTIFACT,"head":HEAD,
                 "bytes":count,"expected_bytes":SIZE,"expected_sha256":SHA,
                 "self_sha256":sha256(before).hexdigest(),"self_unchanged":unchanged,
                 "elapsed_ns":None if elapsed is None else str(elapsed),"CPU_seconds":used,"error":error,
                 "repository_token_forwarded_to_storage":False,
                 "project_imports":0,"native_entries":0}
        receipt_path=output.with_name(output.name+".receipt.json")
        def synchronize():
            receipt["status"]=status;receipt["error"]=error
            receipt["finalization_errors"]=list(finalization_errors)
        def save_receipt():
            synchronize()
            receipt_path.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
        def print_receipt(marker):
            synchronize()
            print(marker+" "+json.dumps(receipt,sort_keys=True),flush=True)
        attempt("receipt_write",save_receipt)
        attempt("receipt_stdout",lambda:print_receipt("HIA_GROUP6_53_ZIP_TRANSPORT"))
        final=strict_budget("post_output_budget")
        if final is not None:
            receipt["post_output_budget"]={"elapsed_ns":str(final[0]),"CPU_seconds":final[1]}
        if status!="PASS":
            attempt("rewrite_failure_receipt",save_receipt)
            attempt("failure_stdout",lambda:print_receipt("HIA_GROUP6_53_ZIP_TRANSPORT_FINAL_FAILURE"))
            attempt("save_final_failure_receipt",save_receipt)
        attempt("disable_alarm",lambda:signal.setitimer(signal.ITIMER_REAL,0))
        last=strict_budget("return_budget")
        if last is not None:
            receipt["return_budget"]={"elapsed_ns":str(last[0]),"CPU_seconds":last[1]}
        if status!="PASS":attempt("save_return_failure_receipt",save_receipt)
    if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
