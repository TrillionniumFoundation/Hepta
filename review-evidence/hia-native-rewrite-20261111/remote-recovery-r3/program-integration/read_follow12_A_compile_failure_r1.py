"""Read all exact follow12 A bytes and explain the first parent compile failure.
No project code, compiler, reference oracle or native entry is executed.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,ast,base64,json,os,resource,stat,struct,tarfile,traceback,zlib
PIN=dict(bytes=178949096,sha256="726f5e283210a76c9c7adb73ada116dd217ebcf0c224d16a99bb1196680bd4f1",
 members=858,original_bytes=522199566,member_index_bytes=416483,
 member_index_sha256="1152615da628cc4070d2f022b20ee4817fdbef485453f1a538515fad6147fe74",
 scope="real-A-service-fixed-carrier-integration",status="FAIL")
PREFIX="program-integration/workspace/native-cli-program-service-integration-r1/development/actual-r1/"
FAILED="hepta-hia-composite-v1-action-6-parent"
def h(raw):return sha256(raw).hexdigest()
def fh(path):
    result=sha256()
    with path.open("rb") as f:
        for part in iter(lambda:f.read(1<<20),b""):result.update(part)
    return result.hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def emit(name,raw):
    for at in range(0,len(raw),18000):
        print(json.dumps(dict(event="EXACT_A_FOLLOW12_ORIGINAL_BASE64",name=name,offset=at,
            bytes=len(raw),sha256=h(raw),data=base64.b64encode(raw[at:at+18000]).decode()),sort_keys=True),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument("--download",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    source=Path(__file__).read_bytes();archives=list(a.download.rglob("evidence.tar.xz"));assert len(archives)==1
    archive=archives[0];index=archive.with_name("evidence-members.json");custody=archive.with_name("custody.json")
    before={p:(p.stat().st_size,fh(p),stat.S_IMODE(p.stat().st_mode)) for p in (archive,index,custody)}
    assert before[archive][:2]==(PIN["bytes"],PIN["sha256"])
    assert before[index][:2]==(PIN["member_index_bytes"],PIN["member_index_sha256"])
    seal=json.loads(custody.read_bytes());assert all(seal[k]==v for k,v in PIN.items())
    ledger=json.loads(index.read_bytes());wanted={r["name"]:r for r in ledger};assert len(wanted)==len(ledger)==PIN["members"]
    checked=set();raw_total=0;root=out/"original"
    with tarfile.open(archive,"r:xz") as tf:
        for item in tf:
            name=PurePosixPath(item.name)
            assert item.isfile() and not item.issym() and not item.islnk()
            assert not name.is_absolute() and ".." not in name.parts and "\\" not in item.name and item.name not in checked
            row=wanted[item.name];assert (item.size,stat.S_IMODE(item.mode))==(row["bytes"],row["mode"])
            keep=item.name.startswith(PREFIX)
            target=root/item.name[len(PREFIX):] if keep else None
            if target:target.parent.mkdir(parents=True,exist_ok=True)
            output=target.open("xb") if target else None
            size=0;digest=sha256()
            try:
                with tf.extractfile(item) as stream:
                    for part in iter(lambda:stream.read(1<<20),b""):
                        size+=len(part);digest.update(part)
                        if output:output.write(part)
            finally:
                if output:output.close()
            assert (size,digest.hexdigest())==(row["bytes"],row["sha256"]),item.name
            if target:
                target.chmod(row["mode"])
                assert (target.stat().st_size,fh(target),stat.S_IMODE(target.stat().st_mode))==(size,row["sha256"],row["mode"])
            checked.add(item.name);raw_total+=size
    assert checked==set(wanted) and raw_total==PIN["original_bytes"]
    save(out/"verified-original-members.json",ledger)
    def raw(name):return (root/name).read_bytes()
    def cas(row):
        value=zlib.decompress(raw(row["path"]));assert (len(value),h(value))==(row["bytes"],row["sha256"]);return value
    summary_raw=raw("summary.json");summary=json.loads(summary_raw);emit("summary.json",summary_raw)
    assert summary["status"]=="FAIL" and summary["error_class"]=="AssertionError" and FAILED in summary["error"]
    assert (summary["completed_cases"],summary["native_processes"],summary["actual_packer_entries"])==(24,24,24)
    rows=json.loads(raw("cases-so-far.json"));assert len(rows)==24
    expected={f"core-v{version}-action-{action}" for version in range(1,9) for action in (6,7,8)}
    assert {r["label"] for r in rows}==expected
    observed=[]
    for row in rows:
        assert row["status"]=="PASS" and row["accepted"] and row["real_program_admission"]
        process=json.loads(raw("cases/"+row["label"]+"/process.json"));stdout=cas(process["stdout"]);stderr=cas(process["stderr"])
        assert process["exit"]==0 and process["timed_out"] is False and stderr==b""
        assert stdout==raw("cases/"+row["label"]+"/stdout.bin") and stderr==raw("cases/"+row["label"]+"/stderr.bin")
        assert list(struct.unpack_from("<16Q",stdout))==row["event"]
        assert stdout[128:]==cas(row["expected"])
        observed.append(dict(label=row["label"],full_bytes_equal=True,exit=0,stdout_sha256=h(stdout)))
    failed=root/"compiles"/FAILED
    author=(failed/"authoring-expanded.py").read_bytes();hia=(failed/"source.hiaasm").read_bytes()
    profile_raw=(failed/"profile.json").read_bytes();profile=json.loads(profile_raw)
    receipts=list(failed.glob("*.receipt.json"));assert len(receipts)==1
    receipt_raw=receipts[0].read_bytes();receipt=json.loads(receipt_raw)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["core_u32"]==4294967295
    assert receipt["source_unchanged"] and receipt["output_unchanged"]
    assert receipt["input_bytes"]==len(hia) and receipt["source_sha256"]==h(hia)
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    functions=[dict(name=n.name,top_statements=len(n.body),calls=sum(isinstance(x,ast.Call) for x in ast.walk(n)))
        for n in ast.parse(author).body if isinstance(n,ast.FunctionDef)]
    cursor=receipt["workspace_header"]["0"];assert 0<=cursor<len(hia)
    excerpt=hia[max(0,cursor-512):min(len(hia),cursor+512)].decode()
    emit("failed-profile.json",profile_raw);emit("failed-receipt.json",receipt_raw)
    print("A_COMPILE_FAILURE_SOURCE_CONTEXT "+json.dumps(dict(cursor=cursor,excerpt=excerpt,
        source_bytes=len(hia),source_sha256=h(hia),authoring_functions=functions),sort_keys=True),flush=True)
    after={p:(p.stat().st_size,fh(p),stat.S_IMODE(p.stat().st_mode)) for p in before}
    assert before==after and Path(__file__).read_bytes()==source
    result=dict(status="PASS_READBACK_ONLY",original_qualification_status="FAIL",
        original_job=130855636142,artifact_id=13900586328,all_original_members_verified=len(checked),
        all_original_bytes_verified=raw_total,original_seals_unchanged=True,exact_successful_native_cases=24,
        exact_successful_packer_entries=24,case_scope="Core v1..v8 times verify inspect normalize",
        first_unexecuted_native_case="hepta-hia-composite-v1-action-6",
        failure_stage="private HIA issuer compilation",compiler_profile=profile,
        failed_compile_receipt_sha256=h(receipt_raw),complete_original_case_outputs_verified=observed,
        new_native_entries=0,new_compiler_entries=0,new_reference_calls=0,whole_stack_closed=False)
    save(out/"readback-summary.json",result);print("A_FOLLOW12_EXACT_READBACK "+json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
