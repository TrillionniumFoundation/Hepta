"""Download one immutable completed E development artifact and its old input."""
from pathlib import Path
import argparse,json,subprocess
REPO="TrillionniumFoundation/Hepta"
RUN=43129195254
HEAD="bfc30ce5c77fc5541cd0900015cf2e64f5568457"
JOB=130888828985
NAME="hia-edit-public-service-43129195254-1"
def get(path):
    return subprocess.check_output(["gh","api","repos/"+REPO+"/"+path])
def main():
    p=argparse.ArgumentParser();p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    run_raw=get("actions/runs/"+str(RUN));run=json.loads(run_raw)
    assert run["id"]==RUN and run["head_sha"]==HEAD and run["run_attempt"]==1
    job_raw=get("actions/jobs/"+str(JOB));job=json.loads(job_raw)
    assert job["id"]==JOB and job["run_id"]==RUN and job["head_sha"]==HEAD
    assert job["status"]=="completed" and job["conclusion"]=="success"
    listing=json.loads(get("actions/runs/"+str(RUN)+"/artifacts?per_page=100"))
    assert listing["total_count"]==len(listing["artifacts"])
    choices=[x for x in listing["artifacts"] if x["name"]==NAME]
    assert len(choices)==1,(NAME,len(choices))
    artifact_raw=get("actions/artifacts/"+str(choices[0]["id"]))
    artifact=json.loads(artifact_raw)
    assert artifact["id"]==choices[0]["id"] and artifact["name"]==NAME and artifact["expired"] is False
    assert artifact["workflow_run"]["id"]==RUN and artifact["workflow_run"]["head_sha"]==HEAD
    for name,raw in (("run.json",run_raw),("job.json",job_raw),("artifact.json",artifact_raw)):
        (a.out/name).write_bytes(raw)
    for artifact_id,name in ((artifact["id"],"new-E.zip"),(13901534373,"original-E.zip")):
        with (a.out/name).open("xb") as stream:
            subprocess.run(["gh","api","repos/"+REPO+"/actions/artifacts/"+str(artifact_id)+"/zip"],
                stdout=stream,check=True)
    print(json.dumps(dict(run=RUN,head=HEAD,job=JOB,artifact_id=artifact["id"],
        name=NAME,bytes=artifact["size_in_bytes"],digest=artifact["digest"],
        scope="DOWNLOAD_ONLY_FULL_READBACK_REQUIRED"),sort_keys=True),flush=True)
if __name__=="__main__":main()
