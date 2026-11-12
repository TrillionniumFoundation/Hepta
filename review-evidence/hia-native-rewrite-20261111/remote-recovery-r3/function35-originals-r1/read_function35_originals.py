"""Read the exact successful Function35 artifact; never execute target code.
The only network request is the exact repository artifact ZIP download.
Every ZIP member and every inner tar ledger row is read completely.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,base64,collections,io,json,os,resource,signal,stat,sys,tarfile,time,traceback,urllib.error,urllib.request,zipfile,zlib
RUN=43165373215
JOB=131005901343
ARTIFACT=13920236505
HEAD="2544ec88203992d5d8590b4ab09fb0231066be72"
ZIP_BYTES=253988864
ZIP_SHA="78b472ab95217a7ad3ff9ef1d63d98d222b8b41f4984f8658f3ffc397a2025d9"
ROOT="function-lowering/"
SCHEDULE=[["smoke",0,25,0]]+[["scalars",i,24,0] for i in range(10)]+[["casts",i,20,0] for i in range(10)]+[
 ["booleans",0,32,0],["resources",0,30,0],["edges",0,21,0],["calls",0,12,0],["selection",0,16,0]]+[
 ["inventory",i,1,0] for i in range(5)]+[["budget",i,1,0] for i in range(6)]+[
 ["tape-protocol",0,59,58],["issuer-protocol",0,72,71]]
KINDS=("frame","tape","issuer","encoder","finalizer")
CASE_KINDS={"ACTUAL_NATIVE_FUNCTION_CHAIN","FRAME_SEMANTIC_REFUSAL","COMPLETE_TAPE_ONLY",
 "PRIVATE_ABI_REJECTION","PURE_SAME_INPUT","ISSUER_PRIVATE_INITIAL_BAD","ISSUER_PRIVATE_ACK_BAD",
 "ISSUER_PRIVATE_SHORT_WORK","PRIVATE_FORMAT_PRESSURE_ONLY"}
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
AUTHOR={
 "frame":"27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd",
 "tape":"e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb",
 "issuer":"f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219",
 "encoder":"92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a",
 "finalizer":"92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"}
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
START=None
def check_time():
    if time.monotonic()-START>=180:raise TimeoutError("original Function35 reader exceeded 180 wall seconds")
def alarm(_signal,_frame):raise TimeoutError("original Function35 reader exceeded 180 wall seconds")
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def file_pin(path):
    h=sha256();n=0
    with path.open("rb") as f:
        while True:
            check_time();part=f.read(1<<20)
            if not part:break
            n+=len(part);h.update(part)
    return dict(bytes=n,sha256=h.hexdigest())
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and "\\" not in name and all(x not in("","..",".") for x in p.parts),name
    assert str(p)==name,name
    return p
def download(path):
    token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    assert token,"exact artifact download requires the job's actions:read token"
    url="https://api.github.com/repos/TrillionniumFoundation/Hepta/actions/artifacts/"+str(ARTIFACT)+"/zip"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):return None
    opener=urllib.request.build_opener(NoRedirect())
    request=urllib.request.Request(url,headers={
        "Accept":"application/vnd.github+json","Authorization":"Bearer "+token,
        "X-GitHub-Api-Version":"2022-11-28","User-Agent":"HIA-Function35-read-only-custody"})
    try:
        response=opener.open(request,timeout=30)
    except urllib.error.HTTPError as error:
        assert error.code in(301,302,303,307,308)
        target=error.headers.get("Location");error.close()
        assert target and target.startswith("https://")
        # Do not forward the repository token to artifact storage.
        response=urllib.request.urlopen(urllib.request.Request(target,
            headers={"User-Agent":"HIA-Function35-read-only-custody"}),timeout=30)
    with response,path.open("xb") as out:
        while True:
            check_time();chunk=response.read(1<<20)
            if not chunk:break
            out.write(chunk)
    assert file_pin(path)==dict(bytes=ZIP_BYTES,sha256=ZIP_SHA)

def zip_read(path,out):
    assert file_pin(path)==dict(bytes=ZIP_BYTES,sha256=ZIP_SHA)
    directory=out/"outer";directory.mkdir()
    inventory=[]
    with zipfile.ZipFile(path) as archive:
        members=archive.infolist();assert len({i.filename for i in members})==len(members)
        required={}
        for info in members:
            check_time()
            if info.is_dir():
                assert info.file_size==0;continue
            safe(info.filename)
            mode=info.external_attr>>16
            assert not stat.S_ISLNK(mode) and not (info.flag_bits&1)
            assert stat.S_IFMT(mode) in(0,stat.S_IFREG), (info.filename,mode)
            target=directory/info.filename;target.parent.mkdir(parents=True,exist_ok=True)
            h=sha256();n=0
            with archive.open(info) as source,target.open("xb") as dest:
                while True:
                    check_time();chunk=source.read(1<<20)
                    if not chunk:break
                    h.update(chunk);n+=len(chunk);dest.write(chunk)
            assert n==info.file_size
            row=dict(name=info.filename,bytes=n,sha256=h.hexdigest(),crc32=info.CRC,
                     compression=info.compress_type,external_attr=info.external_attr)
            inventory.append(row)
            basename=PurePosixPath(info.filename).name
            if basename in("evidence.tar.xz","evidence-members.json","custody.json"):
                assert basename not in required,(basename,"ambiguous original outer file")
                required[basename]=target
        assert set(required)=={"evidence.tar.xz","evidence-members.json","custody.json"}
    save(out/"outer-members-readback.json",inventory)
    return required,inventory

def stream_item(source,declared,sink=None,lines=None,collect=False):
    h=sha256();size=0;buffer=b"";parts=[]
    while True:
        check_time();chunk=source.read(1<<20)
        if not chunk:break
        h.update(chunk);size+=len(chunk)
        assert size<=declared
        if sink is not None:sink.write(chunk)
        if collect:parts.append(chunk)
        if lines is not None:
            buffer+=chunk
            while True:
                at=buffer.find(b"\n")
                if at<0:break
                line,buffer=buffer[:at],buffer[at+1:]
                assert line
                lines(json.loads(line))
    if lines is not None:assert not buffer
    assert size==declared
    return dict(bytes=size,sha256=h.hexdigest()),b"".join(parts) if collect else None

def read_inner(required,out):
    custody_raw=required["custody.json"].read_bytes();custody=json.loads(custody_raw)
    index_raw=required["evidence-members.json"].read_bytes();rows=json.loads(index_raw)
    assert custody["schema"]=="hia-independent-ci-artifact-custody-v1"
    assert custody["scope"]=="function-lowering-r1" and custody["status"]=="PASS"
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    assert custody["member_index_bytes"]==len(index_raw) and custody["member_index_sha256"]==digest(index_raw)
    assert file_pin(required["evidence.tar.xz"])==dict(bytes=custody["bytes"],sha256=custody["sha256"])
    assert len(rows)==custody["members"] and sum(x["bytes"] for x in rows)==custody["original_bytes"]
    expected={r["name"]:r for r in rows};assert len(expected)==len(rows)
    paths={}
    for r in rows:
        safe(r["name"]);assert r["bytes"]>=0 and 0<=r["mode"]<=0o7777 and len(r["sha256"])==64
        paths.setdefault(r["path"],[]).append(r)
    jsons={};originals=out/"original";originals.mkdir()
    entries={};cases={};pages={};snapshot_counts=collections.Counter()
    checked=[];seen=set()
    def entry_line(group,row):
        state=entries.setdefault(group,dict(next=0,pending=None,count=0,components=collections.Counter()))
        number=row["number"]
        if row["status"]=="ENTERING":
            assert state["pending"] is None and number==state["next"]
            assert row["component"] in KINDS and len(row["before"])==3
            state["pending"]=row
        else:
            assert row["status"]=="RETURNED" and state["pending"] is not None
            first=state["pending"]
            for key in("number","component","label","before","capacities","readonly"):
                assert row[key]==first[key],(group,key,number)
            assert len(row["after"])==3 and row["canaries_intact"] is True
            for i,is_ro in enumerate(row["readonly"]):
                if is_ro:assert row["before"][i]["sha256"]==row["after"][i]["sha256"]
            state["count"]+=1;state["components"][row["component"]]+=1
            state["next"]+=1;state["pending"]=None
    def case_line(group,row):
        value=cases.setdefault(group,dict(count=0,labels=set(),categories=collections.Counter(),success=0,error=0))
        assert row["status"]=="PASS" and row["kind"] in CASE_KINDS and row["label"] not in value["labels"]
        value["labels"].add(row["label"]);value["count"]+=1;value["categories"][row["kind"]]+=1
        if row["kind"]=="ACTUAL_NATIVE_FUNCTION_CHAIN":
            assert row["complete_command_prefix_equal"] and row["complete_machine_bytes_equal"]
            assert row["complete_labels_fixups_relocations_equal"]
            assert row["code_state"]["all_code_bytes_equal"] and row["code_state"]["all_registry_values_equal"]
            assert (row["error"] is None)==row["finalizer_equal"]==row["original_Function_symbol_and_frame_equal"]
            assert row["native_commands"]>0 and row["full_trace"]["bytes"]>0
            if row["error"] is None:value["success"]+=1
            else:value["error"]+=1
        elif row["kind"]=="COMPLETE_TAPE_ONLY":
            assert row["original_full_Function_trace_equal"] and row["actual_Code_ack_chain_not_run_for_this_case"]
        elif row["kind"]=="FRAME_SEMANTIC_REFUSAL":assert row["code_unchanged"]
        elif row["kind"] in("ISSUER_PRIVATE_INITIAL_BAD","ISSUER_PRIVATE_ACK_BAD"):
            assert row["permanent_poison"]
    def snapshot_line(group,row):
        assert row["id"]==snapshot_counts[group]
        snapshot_counts[group]+=1
        assert row["bytes"]>=0 and row["page_size"]==4096
        assert row["page_count"]==(row["bytes"]+4095)//4096
        assert len(row["sha256"])==64
        assert row["base"] is None or 0<=row["base"]<row["id"]
        changed=row["changed"];assert len({i for i,h in changed})==len(changed)
        assert all(0<=i<row["page_count"] and len(h)==64 for i,h in changed)
    with tarfile.open(required["evidence.tar.xz"],mode="r|xz") as archive:
        for member in archive:
            check_time();assert member.isfile() and member.name not in seen
            row=expected[member.name];assert member.size==row["bytes"] and member.mode==row["mode"]
            assert member.uid==member.gid==0
            seen.add(member.name)
            name=member.name;group=None;lines=None
            if name.startswith(ROOT+"development/native-"):
                relative=name[len(ROOT+"development/"):]
                group=relative.split("/",1)[0][len("native-"):-len("-r1")]
                if name.endswith("/entries.jsonl"):lines=lambda r,g=group:entry_line(g,r)
                elif name.endswith("/cases.jsonl"):lines=lambda r,g=group:case_line(g,r)
                elif name.endswith("/snapshots.jsonl"):lines=lambda r,g=group:snapshot_line(g,r)
            keep=(name=="run/summary.json" or name.endswith("/summary.json") or
                  name.startswith(ROOT+"development/build-r1/") and
                  not "/source/" in name or name.startswith(ROOT+"docs/") or
                  name.startswith(ROOT+"tools/") or name.startswith(ROOT+"tests/") or
                  name.startswith(ROOT+"reference/"))
            target=originals/name;sink=None
            collect=(name=="run/summary.json" or name.endswith("/summary.json") or
                     name.endswith("/source-before.json") or name.endswith("/source-after.json") or
                     name.endswith("/function-lowering.manifest.json") or name.endswith("/bundle.json") or
                     "/cas/" in name and name.endswith(".zlib"))
            try:
                if keep:target.parent.mkdir(parents=True,exist_ok=True);sink=target.open("xb")
                result,raw=stream_item(archive.extractfile(member),member.size,sink=sink,lines=lines,collect=collect)
            finally:
                if sink is not None:sink.close()
            assert result==dict(bytes=row["bytes"],sha256=row["sha256"]),(name,result,row)
            if keep:target.chmod(member.mode)
            if collect:
                if "/cas/" in name and name.endswith(".zlib"):
                    unpacked=zlib.decompress(raw);h=PurePosixPath(name).name[:-5]
                    assert digest(unpacked)==h and 0<len(unpacked)<=4096
                    counter=pages.setdefault(group,dict(count=0,raw_bytes=0))
                    counter["count"]+=1;counter["raw_bytes"]+=len(unpacked)
                else:jsons[name]=json.loads(raw)
            checked.append(dict(name=name,bytes=result["bytes"],sha256=result["sha256"],mode=member.mode))
    assert seen==set(expected)
    save(out/"inner-members-readback.json",checked)
    for group,entry in entries.items():assert entry["pending"] is None
    return custody,rows,paths,jsons,entries,cases,pages,snapshot_counts

def validate(custody,rows,paths,jsons,entries,cases,pages,snapshots):
    run=jsons["run/summary.json"]
    assert run["schema"]=="hia-independent-ci-qualification-v1" and run["scope"]=="function-lowering-r1"
    assert run["status"]=="PASS" and run["prepared"]
    assert run["frozen_source_and_reference_before_after_equal"] and run["submitted_script_pins_before_after_equal"]
    assert not run["whole_stack_closed"] and not run["production_activated"] and not run["inherited_test_counts"]
    detail=run["details"];assert detail["status"]=="PASS"
    assert (detail["actual_new_compilations"],detail["actual_cases"],detail["actual_private_controls"])==(5,718,129)
    assert not any(detail[k] for k in("whole_emitter","whole_backend","installed","cold","runtime_host_instruction_selection",
                                     "old_test_results_inherited","old_frame_suite_rerun","old_x64_suite_rerun"))
    build=jsons[ROOT+"development/build-r1/summary.json"]
    assert build["status"]=="PASS_BUILD_ONLY" and build["compilations"]==5 and build["native_semantic_entries"]==0
    assert build["source_pins_unchanged"] and build["actual_limits"]==LIMITS
    assert set(build["components"])==set(KINDS)
    ledger={r["name"]:r for r in rows}
    before=jsons[ROOT+"development/build-r1/source-before.json"]
    after=jsons[ROOT+"development/build-r1/source-after.json"]
    after_by_path={r["path"]:r for r in after}
    assert len(after_by_path)==len(after)==len(before)
    assert set(after_by_path)=={r["path"] for r in before}
    for row in before:
        current=after_by_path[row["path"]]
        assert current["same"] and (current["bytes"],current["sha256"])==(row["bytes"],row["sha256"])
        frozen=ledger[ROOT+"development/build-r1/"+row["snapshot"]]
        assert (frozen["bytes"],frozen["sha256"],frozen["mode"])==(row["bytes"],row["sha256"],row["mode"])
    components={}
    for kind,m in build["components"].items():
        assert m["author_sha256"]==AUTHOR[kind] and m["compiler_sha256"]==COMPILER
        assert m["component"]==kind and m["status"]=="BUILT_ONLY"
        p=m["profile"];assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
        assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
        assert p["max_ssa_index"]==p["max_function_values"]-1
        for what in("source","image"):
            found=paths[m[what+"_path"]];assert len(found)==1
            assert (found[0]["bytes"],found[0]["sha256"])==(m[what+"_bytes"],m[what+"_sha256"])
        receipt=m["compile_receipt"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_sha256"]==receipt["input_sha256"]==m["source_sha256"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER
        assert receipt["produced_sha256"]==m["image_sha256"] and receipt["produced_bytes"]==m["image_bytes"]
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        components[kind]=dict(author_sha256=m["author_sha256"],source_bytes=m["source_bytes"],
            source_sha256=m["source_sha256"],image_bytes=m["image_bytes"],image_sha256=m["image_sha256"],profile=p)
    groups={};total=collections.Counter();categories=collections.Counter();all_ops=set();all_types=set()
    chain_success=chain_error=0
    assert len(SCHEDULE)==39
    for group,variant,expected_cases,controls in SCHEDULE:
        label=group+"-"+str(variant)
        g=jsons[ROOT+"development/native-"+label+"-r1/summary.json"]
        e=entries[label];c=cases[label];page=pages[label]
        assert g["status"]=="PASS" and (g["group"],g["variant"])==(group,variant)
        assert (g["cases"],g["private_controls"])==(expected_cases,controls)
        assert g["limits"]==LIMITS and g["native_entries"]==e["count"]==sum(e["components"].values())
        assert {k:e["components"][k] for k in KINDS}==g["by_component"]
        assert g["cases"]==c["count"] and snapshots[label]==g["native_entries"]*6
        kept=g["custody"]
        assert kept["status"]=="PASS" and kept["source_pins_unchanged"] and not kept["changed"]
        assert jsons[ROOT+"development/native-"+label+"-r1/source-after.json"]==kept
        for number,pin in enumerate(kept["pins"],1):
            frozen=ledger[ROOT+"development/native-"+label+"-r1/sources/"+str(number)+"/"+PurePosixPath(pin["path"]).name]
            assert (frozen["bytes"],frozen["sha256"])==(pin["bytes"],pin["sha256"])
        assert page["count"]==kept["cas_pages"] and page["raw_bytes"]==kept["cas_raw_bytes"]
        for flag in("all_new_pages_decompressed_equal","all_final_pages_rehashed","full_memory_read_before_after_each_entry",
                    "delta_pages_reconstruct_identically"):
            assert kept[flag]
        assert kept["complete_snapshot_descriptors"]==snapshots[label]
        assert not any(g[k] for k in("whole_emitter","whole_backend","installed","cold","runtime_host_instruction_selection"))
        groups[label]=dict(cases=g["cases"],private_controls=g["private_controls"],native_entries=e["count"],
            by_component={k:e["components"][k] for k in KINDS},case_categories=dict(c["categories"]),
            actual_chain_successes=c["success"],actual_chain_errors=c["error"],
            source_before_after_equal=kept["source_pins_unchanged"],cas_pages=page["count"],
            cas_raw_bytes=page["raw_bytes"],logical_buffer_bytes=kept["logical_buffer_bytes"],
            snapshots=snapshots[label],elapsed_ns=g["elapsed_ns"],
            issuer_GROW=g["issuer_GROW"],code_GROW=g["code_GROW"],tape_GROW=g["tape_GROW"])
        total.update(e["components"]);categories.update(c["categories"])
        all_ops.update(g["source_opcodes"]);all_types.update(g["source_types"])
        chain_success+=c["success"];chain_error+=c["error"]
    assert set(entries)==set(groups)==set(cases)==set(pages)==set(snapshots)
    assert sum(x["cases"] for x in groups.values())==718 and sum(x["private_controls"] for x in groups.values())==129
    assert sum(total.values())==detail["actual_native_entries"] and dict(total)==detail["actual_by_component"]
    assert categories["ACTUAL_NATIVE_FUNCTION_CHAIN"]==584 and chain_success==580 and chain_error==4
    assert categories["COMPLETE_TAPE_ONLY"]==2 and categories["FRAME_SEMANTIC_REFUSAL"]==1
    assert {name:categories[name] for name in sorted(CASE_KINDS)}==detail["category_counts"] and len(all_ops)==50 and len(all_types)==16
    assert sorted(all_ops)==detail["source_opcodes"] and sorted(all_types)==detail["source_types"]
    return dict(actual_original_scope="FRESH_FIVE_KERNEL_FUNCTION_LOWERING",compilations=5,
        original_groups=39,original_cases=718,original_private_controls=129,
        original_native_entries=sum(total.values()),original_by_component=dict(total),case_categories=dict(categories),
        actual_chain_successes=chain_success,actual_chain_errors=chain_error,
        components=components,groups=groups,source_opcodes=sorted(all_ops),source_types=sorted(all_types),
        exact_source_before_after_equal=True,original_limits_unchanged=True,
        old_suite_counts_inherited=False,whole_emitter=False,whole_backend=False,installed=False,cold=False)

def main():
    global START
    START=time.monotonic()
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,180)
    parser=argparse.ArgumentParser();parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--zip",type=Path)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    report=dict(status="INCOMPLETE",scope="READ_ONLY_COMPLETE_ORIGINAL_FUNCTION35_ARTIFACT",
        run=RUN,job=JOB,head=HEAD,artifact=ARTIFACT,zip_expected_bytes=ZIP_BYTES,zip_expected_sha256=ZIP_SHA,
        target_executions=0,target_generations=0,target_compilations=0,whole_backend=False)
    failed=None;failure_tb=None
    try:
        assert sys.version_info[:3]==(3,12,14)
        path=out/"original-function35.zip"
        if args.zip is None:download(path)
        else:
            assert args.zip.resolve()!=path
            with args.zip.open("rb") as source,path.open("xb") as target:
                while True:
                    check_time();chunk=source.read(1<<20)
                    if not chunk:break
                    target.write(chunk)
            assert file_pin(path)==dict(bytes=ZIP_BYTES,sha256=ZIP_SHA)
        required,outer=zip_read(path,out)
        custody,rows,paths,jsons,entries,cases,pages,snapshots=read_inner(required,out)
        observed=validate(custody,rows,paths,jsons,entries,cases,pages,snapshots)
        report.update(status="PASS",outer_members=len(outer),inner_members=len(rows),
            inner_original_bytes=sum(r["bytes"] for r in rows),
            original_custody=custody,observed_original=observed,
            all_outer_member_bytes_and_CRC_read=True,all_inner_bytes_SHA256_modes_read=True,
            all_CAS_pages_losslessly_decompressed_and_rehashed=True,
            all_entry_pairs_and_snapshot_descriptor_counts_checked=True,
            independent_full_logical_buffer_reconstruction=False,
            original_all_buffer_readback_claim_kept_distinct=True,
            original_GitHub_job_log_not_available_via_transport=True,
            original_run_summary_and_all_group_JSON_retained_exact=True)
    except BaseException as error:
        failed=error;failure_tb=error.__traceback__
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        report["elapsed_seconds"]=time.monotonic()-START
        report["reader_actual_limits"]=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)))
        save(out/"reader-summary.json",report)
        print("HIA_FUNCTION35_READONLY_ORIGINAL_COUNTS "+json.dumps(report,sort_keys=True),flush=True)
    if failed is not None:raise failed.with_traceback(failure_tb)
if __name__=="__main__":main()
