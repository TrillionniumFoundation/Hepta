"""Regenerate the support contract with its unmodified authoritative generator.

This is a source-only recovery job. It executes no compiler or qualification,
does not alter a resource limit, and never turns the old pre-admission failure
into a cold result. The entire generated file and commands are retained.
"""
from __future__ import annotations
import argparse,base64,copy,importlib.util,json,os,stat,subprocess,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
def digest(raw):return sha256(raw).hexdigest()
def blobsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def metadata(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=digest(raw),gitsha=blobsha(raw),mode=stat.S_IMODE(path.stat().st_mode))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    repo=args.repo.resolve();output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    expected={
      "tools/generate_hia_selfhost_contract.py":"8697f63b20f2817b3cc6071c60946e5f9bb2fbc3",
      "tools/hia_selfhost_contract.py":"9301f6130754304255a8c1def20668ff07ec9bdf",
      "tools/hia_selfhost_chain_allocator_child.py":"188c22a42ecd2da42ab6d536e861849cc741c035"}
    summary=dict(schema="hia-original-support-contract-regeneration-v1",
        status="INCOMPLETE",native_entries=0,qualification_runs=0,
        historical_cold_status_changed=False,resource_limits_changed=False,
        generator_modified=False,commands=[])
    before={};generated=repo/"docs/HIA_SELFHOST_CORE_SUPPORT.json"
    try:
        summary["head"]=subprocess.check_output(["git","rev-parse","HEAD"],cwd=repo,text=True).strip()
        summary["initial_diff"]=subprocess.check_output(["git","diff","--name-only"],cwd=repo,text=True).splitlines()
        assert not summary["initial_diff"],summary["initial_diff"]
        for name,want in expected.items():
            raw=(repo/name).read_bytes();assert blobsha(raw)==want,(name,blobsha(raw),want)
        before_raw=generated.read_bytes()
        (output/"HIA_SELFHOST_CORE_SUPPORT.before.json").write_bytes(before_raw)
        before_value=json.loads(before_raw)
        sys.path.insert(0,str(repo))
        from tools.hia_selfhost_contract import file_digests
        before_files=file_digests(repo)
        for name,expected_hash in before_files.items():
            path=repo/name;raw=path.read_bytes()
            assert digest(raw)==expected_hash,name
            before[name]=dict(bytes=len(raw),sha256=expected_hash,mode=stat.S_IMODE(path.stat().st_mode))
        save(output/"source-before.json",before)
        for label,arguments in (
            ("authoritative-write",[sys.executable,"-B","tools/generate_hia_selfhost_contract.py"]),
            ("authoritative-check",[sys.executable,"-B","tools/generate_hia_selfhost_contract.py","--check"])):
            start=time.monotonic_ns()
            completed=subprocess.run(arguments,cwd=repo,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
            (output/(label+".stdout.bin")).write_bytes(completed.stdout)
            (output/(label+".stderr.bin")).write_bytes(completed.stderr)
            record=dict(argv=arguments,returncode=completed.returncode,
                elapsed_ns=time.monotonic_ns()-start,stdout_bytes=len(completed.stdout),
                stdout_sha256=digest(completed.stdout),stderr_bytes=len(completed.stderr),
                stderr_sha256=digest(completed.stderr))
            save(output/(label+".process.json"),record);summary["commands"].append(record)
            print(json.dumps(dict(event="SUPPORT_CONTRACT_COMMAND",record=record),sort_keys=True),flush=True)
            if completed.stdout:print(completed.stdout.decode("utf-8"),end="",flush=True)
            if completed.stderr:print(completed.stderr.decode("utf-8"),end="",flush=True)
            assert completed.returncode==0,record
        actual=generated.read_bytes();value=json.loads(actual)
        assert value["source_identity"]["files"]==before_files
        old_static=copy.deepcopy(before_value);new_static=copy.deepcopy(value)
        old_files=old_static["source_identity"].pop("files")
        new_files=new_static["source_identity"].pop("files")
        assert old_static==new_static,"support policy changed, not an identity-only regeneration"
        delta=[dict(path=path,old_sha256=old_files.get(path),new_sha256=new_files.get(path))
               for path in sorted(set(old_files)|set(new_files)) if old_files.get(path)!=new_files.get(path)]
        save(output/"identity-delta.json",delta)
        (output/"HIA_SELFHOST_CORE_SUPPORT.json").write_bytes(actual)
        changed=subprocess.check_output(["git","diff","--name-only"],cwd=repo,text=True).splitlines()
        assert set(changed)<= {"docs/HIA_SELFHOST_CORE_SUPPORT.json"},changed
        after={}
        for name,row in before.items():
            path=repo/name;raw=path.read_bytes()
            after[name]=dict(bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
        assert after==before,"source changed during generator invocation"
        save(output/"source-after.json",after)
        summary.update(status="PASS",source_unchanged=True,source_count=len(before),
            support_policy_unchanged=True,identity_delta=delta,
            generated=metadata(generated),only_generated_contract_modified=True)
        raw=(output/"HIA_SELFHOST_CORE_SUPPORT.json").read_bytes()
        for offset in range(0,len(raw),18000):
            print(json.dumps(dict(event="HIA_REGENERATED_CONTRACT_BASE64",
                path="docs/HIA_SELFHOST_CORE_SUPPORT.json",offset=offset,total_bytes=len(raw),
                sha256=digest(raw),gitsha=blobsha(raw),
                data=base64.b64encode(raw[offset:offset+18000]).decode("ascii")),sort_keys=True),flush=True)
    except BaseException as exc:
        summary.update(status="FAIL",error_class=type(exc).__name__,error=str(exc))
        (output/"failure.log").write_text(traceback.format_exc());traceback.print_exc()
    finally:
        save(output/"summary.json",summary)
        print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
