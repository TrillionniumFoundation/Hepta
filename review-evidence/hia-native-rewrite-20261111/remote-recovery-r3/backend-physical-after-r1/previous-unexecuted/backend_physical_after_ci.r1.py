"""Fresh physical-after composition: 23 actual HIA images, two fixed carriers.
No retained semantic suite is rerun or inherited. Readbacks execute no targets.
"""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,importlib.util,json,os,stat,sys,traceback,types
sys.dont_write_bytecode=True
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
INDEX_GIT="e114d9ee2305b91484412337712422719d054b27"
INDEX_SHA="45766d34e17220bdb0cdbeeb70c0b91d63c1c2b320a130a4a5db175793a11b31"
INDEX_BYTES=23716
SEAL_GIT="469fbcde38e6a909da911d91c733ab7840c31726"
SOURCE_PREFIX="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/backend-physical-after-r1/"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
SCHEDULE=[
 ["cross",0,1,0],["cross",1,1,0],["plan",0,4,0],["borrowed",0,3,0],
 ["paths",0,4,0],["stale",0,2,0],["stale",1,1,0],["files",0,3,0],["files",1,2,0],
 ["precedence",0,4,0],["initial",0,13,13],
 ["switch",0,1,1],["switch",1,1,1],["switch",2,1,1],["switch",3,1,1],
 ["peer",0,1,1],["peer",1,1,1],["peer",2,1,1],["fs",0,1,1],["fs",1,1,1]]
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
def digest(raw):return sha256(raw).hexdigest()
def git(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def identity(path):
    path=Path(path);info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    h=sha256();n=0
    with path.open("rb") as stream:
        while True:
            raw=stream.read(1<<18)
            if not raw:break
            h.update(raw);n+=len(raw)
    after=path.lstat()
    assert (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(
        after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    assert n==info.st_size
    return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def loaded(name,path,expected):
    path=Path(path);raw=path.read_bytes()
    assert git(raw)==expected,(str(path),git(raw),expected)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module,raw
def original(path,label):
    path=Path(path)
    if not path.exists():return None
    raw=path.read_bytes()
    print("HIA_PHYSICAL_ORIGINAL "+json.dumps(dict(label=label,path=str(path),
        bytes=len(raw),sha256=digest(raw),gitsha=git(raw),
        base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
    return raw
def process_gate(value):
    assert value["status"]=="PASS" and value["returncode"]==0 and not value["timed_out"]
    assert value["timeout_seconds"]==180
    assert value["child_cpu_seconds"]<90 and value["elapsed_ns"]<180_000_000_000
def final_subject_gate(value,status):
    assert value["status"]==status and value["source_pins_unchanged"] and not value["failures"]
    assert value["actual_limits"]==LIMITS
    for name in ("pre_output_budget","post_output_budget","post_persist_budget"):
        row=value[name]
        assert row["cpu_success_exclusive"]==90 and row["wall_success_exclusive"]==180
        assert row["includes_parent_and_reaped_children"] and row["cpu_seconds"]<90 and row["wall_seconds"]<180
def closure(project,rows):
    result=[]
    for row in rows:
        path=project/row["path"];actual=identity(path)
        assert actual==dict(bytes=row["bytes"],sha256=row["sha256"],mode=int(row["mode"],8)&0o777)
        raw=path.read_bytes();assert git(raw)==row["gitsha"]
        result.append(dict(path=row["path"],**actual,gitsha=row["gitsha"]))
    return result
def run_gate(common,label,command,out,env,project,report,kind,summary_required=True):
    primary=None;notes=[];value=None;process=None
    try:common.run(label,command,cwd=project,timeout=180,env=env)
    except BaseException as error:primary=error
    finally:
        step=common.OUTPUT/"steps"/label
        # Preserve every raw source of a failure before parsing its contents.
        for name in ("stdout.log","stderr.log","process.json"):
            try:original(step/name,label+":"+name)
            except BaseException as error:notes.append(("original-"+name,error))
        try:
            raw=original(out/"summary.json",label+":summary.json")
            if raw is not None:value=json.loads(raw);report[kind][label]=value
            elif summary_required:raise AssertionError("missing complete subject summary: "+label)
        except BaseException as error:notes.append(("summary",error))
        try:
            if step.exists():process=json.loads((step/"process.json").read_bytes())
        except BaseException as error:notes.append(("process",error))
        if out.exists():
            for name in ("profile-before-gates.json","profile-functions-before-gates.json"):
                try:
                    for path in sorted(out.rglob(name)):original(path,label+":"+name)
                except BaseException as error:notes.append((name,error))
            try:
                paths=sorted(set(out.rglob("*.stderr"))|set(out.rglob("*.stderr.log")))
                for path in paths:original(path,label+":nested-stderr")
            except BaseException as error:notes.append(("nested-stderr",error))
        if primary is None and notes:primary=notes.pop(0)[1]
        if primary is not None:
            for title,error in notes:primary.add_note(title+": "+repr(error))
            raise primary
    process_gate(process)
    report.setdefault("actual_process_receipts",{})[label]=process
    return value
def compiler_gate(manifest):
    receipt=manifest["compile_receipt"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1<<20
    assert receipt["source_sha256"]==receipt["input_sha256"]==manifest["source_sha256"]
    assert receipt["input_bytes"]==manifest["source_bytes"]
    assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
    assert receipt["produced_sha256"]==manifest["image_sha256"] and receipt["produced_bytes"]==manifest["image_bytes"]
    assert receipt["wall_elapsed_ns"]<20_000_000_000
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    common,common_raw=loaded("physical_after_common",common_path,COMMON_GIT)
    common.PINS[common_path]=common_raw
    driver_path=Path(__file__).resolve();driver_raw=driver_path.read_bytes();common.PINS[driver_path]=driver_raw
    root=driver_path.parents[1]
    index_path=root/"source-index.json";index_raw=index_path.read_bytes()
    assert (len(index_raw),digest(index_raw),git(index_raw))==(INDEX_BYTES,INDEX_SHA,INDEX_GIT)
    index=json.loads(index_raw)
    assert index["source_prefix"]==SOURCE_PREFIX and index["counts"]["files"]==len(index["rows"])==75
    assert index["counts"]["bytes"]==sum(r["bytes"] for r in index["rows"])
    assert len({r["path"] for r in index["rows"]})==75
    assert [r["path"] for r in index["rows"]]==sorted(r["path"] for r in index["rows"])
    common.PINS[index_path]=index_raw
    seal,seal_raw=loaded("physical_after_independent_seal",root/"ci/physical_after_streamed_finish.py",SEAL_GIT)
    common.PINS[root/"ci/physical_after_streamed_finish.py"]=seal_raw
    report=dict(scope="NEW_NATIVE_BACKEND_PHYSICAL_IMPLEMENTATION_AFTER",status="INCOMPLETE",
        planned_fresh_B3=23,planned_groups=20,planned_cases=47,planned_private_controls=22,
        actual_compilations=0,builds={},c_builds={},groups={},readbacks={},
        actual_completed_cases=0,actual_completed_private_controls=0,
        actual_completed_backend_entries=0,actual_completed_before_entries=0,
        actual_target_count_status="not assumed before complete raw receipts",
        old_semantic_suites_rerun=False,old_semantic_results_inherited=False,
        public_native_Core_admission=False,full_public_error_presentation=False,
        independent_second_compile_emission=False,publication=False,
        whole_public_build=False,installed=False,cold=False,
        new_seal_has_its_own_strict_90CPU_180wall_gate=True,
        old_unbounded_seal_observations_not_rewritten=True)
    project=None;roles={};pairs={};status="FAIL";primary=None;context=None
    try:
        context=common.prepare()
        assert sys.version_info[:3]==(3,12,14)
        assert identity(context["compiler"])["sha256"]==COMPILER_SHA and identity(context["compiler"])["bytes"]==669556
        mine=Path(context["base"])/"backend-physical-after-recovery-r1";mine.mkdir()
        project=mine/"native-backend-physical-after-next";project.mkdir()
        for row in index["rows"]:
            common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
            (project/row["path"]).chmod(int(row["mode"],8)&0o777)
        (project/"source-index-original.json").write_bytes(index_raw)
        (project/"ci-driver-original.py").write_bytes(driver_raw)
        report["submitted_source_before"]=closure(project,index["rows"])
        rowmap={r["path"]:r for r in index["rows"]}
        def pin(path):return rowmap[path]["sha256"]
        prior,unused=loaded("physical_exact_prior_backend_CI",project/"reference/backend_join_ci_reference.py",
            rowmap["reference/backend_join_ci_reference.py"]["gitsha"])
        assert prior.COMPILER_SHA==COMPILER_SHA and prior.COMMON_GIT==COMMON_GIT
        # Existing dependency source files are byte-identical, including the old
        # tests. Only their builders/profile readers are used in this new job.
        prior.file_closure(project)
        predecessor=json.loads((project/"reference/predecessor-build-identities.json").read_bytes())
        assert predecessor["status"]=="EXACT_PRIOR_BUILD_LOG_IDENTITIES_NOT_A_NEW_QUALIFICATION"
        old={row["physical_role"]:row for row in predecessor["rows"]}
        assert set(old)==set(range(1,22))
        syntax=ast.parse((project/"tests/test_hia_backend_physical_after.py").read_bytes())
        schedules=[n for n in syntax.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SCHEDULE" for t in n.targets)]
        assert len(schedules)==1 and ast.literal_eval(schedules[0].value)==SCHEDULE
        assert len(SCHEDULE)==20 and sum(r[2] for r in SCHEDULE)==47 and sum(r[3] for r in SCHEDULE)==22
        env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
        tasks=[]
        for role,component in enumerate(prior.EMITTER,1):
            tasks.append((role,"emitter",component,"build_hia_complete_emitter.py",prior.EMITTER_OWNERS[role-1]))
        for role,component in enumerate(prior.PLAN,12):
            owner="hia_checked_plan_controller.py" if component=="controller" else "hia_checked_machine_plan.py"
            tasks.append((role,"plan",component,"build_hia_checked_plan.py",owner))
        tasks.append((17,"inventory","inventory","build_hia_elf_object_inventory.py","hia_elf_object_inventory.py"))
        for role,component in enumerate(prior.POST,18):
            if role!=20:tasks.append((role,"backend",component,"build_hia_backend_join.py",prior.POST_OWNERS[role-18]))
        assert [t[0] for t in tasks]==list(range(1,20))+[21]
        for role,family,component,builder,owner in tasks:
            label="physical-retained-"+str(role)+"-"+component
            out=project/"development"/("build-"+label)
            command=[context["python"],"-B",project/"tools"/builder,"--reference",context["reference"],
                "--compiler",context["compiler"],"--out",out,"--component",component]
            if family=="plan" and component in prior.WIRE:
                wire=Path(context["workspace"])/prior.WIRE[component]["path"]
                actual=identity(wire)
                assert {k:actual[k] for k in ("bytes","sha256")}=={k:prior.WIRE[component][k] for k in ("bytes","sha256")}
                command.extend(["--wire-source",wire])
            value=run_gate(common,label,command,out,env,project,report,"builds")
            assert value["status"]=="PASS_BUILD_ONLY" and value["compilations"]==1 and value["native_semantic_entries"]==0
            assert value.get("actual_limits",value.get("limits"))==LIMITS and value["source_pins_unchanged"]
            report["actual_compilations"]+=1
            if family=="emitter":
                assert set(value["components"])=={component};m=value["components"][component];docdir=out/component
                assert m["schema"]=="hepta.hia.complete-emitter-development.v1" and m["role"]==role
            else:
                m=value["manifest"];docdir=out
                if family=="plan":
                    assert m["schema"]=="hia-checked-machine-plan-development-component-v1" and m["role"]==role-11
                    assert m["abi_second_readonly"]==(role!=16)
                elif family=="inventory":assert m["schema"]=="hepta.hia.elf-object-inventory-development.v1"
                else:
                    assert m["schema"]=="hia-backend-join-development-component-v1" and m["role"]==role
                    assert m["abi_second_readonly"]==(role in (18,21))
            expected=prior.WIRE[component]["sha256"] if family=="plan" and component in prior.WIRE else pin("tools/"+owner)
            assert m["component"]==component and m["author_sha256"]==expected==old[role]["author_sha256"]
            compiler_gate(m)
            value["independent_gate_readback"]=prior.gates(out,m,docdir)
            if family=="plan" and component in prior.WIRE:value["full_inverse"]=prior.alpha_readback(out,m)
            for kind in ("source","image"):
                assert dict(bytes=m[kind+"_bytes"],sha256=m[kind+"_sha256"])==old[role][kind]
            roles[str(role)]=dict(name=family+"-"+component,manifest=m,actual_role=role,second_readonly=role in prior.RRW)
        for role,component in ((20,"parent"),(22,"files"),(23,"bridge")):
            label="physical-new-"+str(role)+"-"+component;out=project/"development"/("build-"+label)
            value=run_gate(common,label,[context["python"],"-B",project/"tools/build_hia_backend_physical_after.py",
                "--reference",context["reference"],"--compiler",context["compiler"],"--out",out,"--component",component],
                out,env,project,report,"builds")
            final_subject_gate(value,"PASS_BUILD_ONLY")
            assert value["compilations"]==1
            m=value["manifest"]
            assert m["schema"]=="hia-physical-after-development-component-v1" and m["role"]==role and m["component"]==component
            assert m["author_sha256"]==pin("tools/hia_implementation_files.py" if role==22 else "tools/hia_backend_physical_after.py")
            assert not m["abi_second_readonly"] and not m["full_public_transaction"]
            compiler_gate(m);value["independent_gate_readback"]=prior.gates(out,m,out)
            if role==20:
                assert value["reference_source_reproductions"]==1
                got=identity(out/"original-parent.hiaasm")
                assert {k:got[k] for k in ("bytes","sha256")}==old[20]["source"]
            if role==22:
                assert value["reference_source_reproductions"]==1
                assert (m["source_bytes"],m["source_sha256"])==(196675,"c77b262cac0e34c2b1db0db0ef5c28471a6546a3c7ad85764d6589b74eea4069")
                assert (m["image_bytes"],m["image_sha256"])==(203390,"b8268f47b1f3295a968ec44b54626373cbc4c35dd6b19ea8dc3348820ae47b13")
            roles[str(role)]=dict(name="physical-"+component,manifest=m,actual_role=role,second_readonly=False)
            report["actual_compilations"]+=1
        assert report["actual_compilations"]==23 and set(roles)=={str(i) for i in range(1,24)}
        for role,row in roles.items():
            m=row["manifest"];pairs[role]={kind:dict(path=m[kind+"_path"],**identity(m[kind+"_path"])) for kind in ("source","image")}
        assets=project/"development/runtime-assets.json"
        save(assets,dict(schema="hia-backend-physical-after-assets-v1",roles=roles,
            root_role=20,fixed_context_switch_edges=[[20,23],[23,20]],fresh_B3=23,
            unchanged_backend_peers=20,actual_file_after_child=True,after_digest_is_not_input=True,
            first_digest_and_admitted_Core_require_private_actual_issuers=True,header_is_authentication=False,
            installed=False,whole_public_build=False))
        before_assets=project/"development/before-runtime-assets.json"
        save(before_assets,dict(schema="hia-implementation-files-runtime-assets-v1",
            roles={"1":dict(roles["22"]),"2":dict(roles["19"])},
            explicit_development_logical_aliases={"1":22,"2":19},
            same_HIA_image_bytes_not_host_digest=True,new_physical_first_digest_tests=True,
            installed=False,whole_public_build=False))
        save(project/"development/source-image-pairs.json",pairs)
        carriers={}
        definitions=[
            ("before","tools/build_implementation_files_native_mechanics.py","tools/implementation_files_native_mechanics.c","implementation-files-native-mechanics"),
            ("after","tools/build_backend_physical_after_native_mechanics.py","tools/backend_physical_after_native_mechanics.c","backend-physical-after-native-mechanics")]
        for name,builder,source,filename in definitions:
            label="physical-C-"+name;out=project/"development"/("build-"+label)
            run_gate(common,label,[context["python"],"-B",project/builder,"--stage","build",
                "--source",project/source,"--out",out],out,env,project,report,"c_builds",summary_required=False)
            value=run_gate(common,label+"-seal",[context["python"],"-B",project/builder,"--stage","seal",
                "--source",project/source,"--out",out,"--receipt",common.OUTPUT/"steps"/label/"process.json"],
                out,env,project,report,"c_builds")
            assert value["status"]=="PASS_BUILD_ONLY" and value["source_sha256"]==pin(source)
            assert value["source_before_after_exact"] and value["native_semantic_entries"]==0 and not value["installed"]
            process_gate(value["actual_build_receipt"])
            carrier=out/filename;observed=identity(carrier)
            assert {k:observed[k] for k in ("bytes","sha256")}==value["executable"]
            carriers[name]=(carrier,observed)
        for group,variant,count,private in SCHEDULE:
            label="physical-native-"+group+"-"+str(variant);out=project/"development"/label
            value=run_gate(common,label,[context["python"],"-B",project/"tests/test_hia_backend_physical_after.py",
                "--assets",assets,"--carrier",carriers["after"][0],
                "--before-assets",before_assets,"--before-carrier",carriers["before"][0],
                "--reference",context["reference"],"--out",out,"--group",group,"--variant",str(variant)],
                out,env,project,report,"groups")
            final_subject_gate(value,"PASS")
            assert (value["group"],value["variant"],value["cases"],value["private_controls"])==(group,variant,count,private)
            assert value["native_entries"]==value["completed_case_entries"]==sum(value["by_role"].values())
            assert value["before_native_entries"]==sum(value["before_by_role"].values())
            assert value["all_target_semantics_HIA"] and value["encoding_in_subject_budget"]
            assert not any(value[k] for k in ("header_is_authentication","native_public_Core_admission",
                "full_public_error_presentation","second_compile_emission","publication","whole_public_build","installed","cold","old_results_inherited"))
            report["actual_completed_cases"]+=count;report["actual_completed_private_controls"]+=private
            report["actual_completed_backend_entries"]+=value["native_entries"]
            report["actual_completed_before_entries"]+=value["before_native_entries"]
            reading=project/"development"/("readback-"+group+"-"+str(variant))
            read_label="physical-readback-"+group+"-"+str(variant)
            observed=run_gate(common,read_label,[context["python"],"-B",project/"tests/read_backend_physical_after_originals.py",
                "--group-root",out,"--assets",assets,"--before-assets",before_assets,"--out",reading],
                reading,env,project,report,"readbacks")
            final_subject_gate(observed,"PASS")
            assert observed["native_entries_executed"]==observed["VM_entries_executed"]==observed["product_imports"]==0
            assert observed["cases"]==count and observed["private_controls"]==private
            assert observed["native_entries"]==value["native_entries"] and observed["by_role"]==value["by_role"]
            assert observed["before_native_entries"]==value["before_native_entries"] and observed["before_by_role"]==value["before_by_role"]
            assert observed["all_full_recorded_bytes_read"] and observed["complete_raw_target_trace_and_ACK_comparison"]
            closure(project,index["rows"])
            for carrier,expected in carriers.values():assert identity(carrier)==expected
        assert len(report["groups"])==len(report["readbacks"])==20
        assert (report["actual_completed_cases"],report["actual_completed_private_controls"])==(47,22)
        readbacks=list(report["readbacks"].values());groups=list(report["groups"].values())
        assert sum(v["full_CAS_cases"] for v in readbacks)==25
        assert sum(v["fixed_C_crosschecks"] for v in readbacks)==3
        assert sum(v["encoded_original_files"] for v in readbacks)==120
        assert sum(v["actual_before_processes_started"] for v in groups)==35
        assert sum(v["actual_backend_processes_started"] for v in groups)==25
        report.update(status="PASS",actual_target_count_status="complete exact new group and all-original readback receipts",
            complete_retained20_source_image_pairs_equal=True,actual_fresh_new23_HIA_compilations=True,
            actual_backend_by_role={str(i):sum(v["by_role"][str(i)] for v in readbacks) for i in range(1,24)},
            actual_before_by_logical_role={str(i):sum(v["before_by_role"][str(i)] for v in readbacks) for i in (1,2)},
            actual_full_CAS_cases=25,actual_small_CAS_C_crosschecks=3,
            actual_encoded_complete_original_files=120,actual_before_native_processes=35,actual_backend_native_processes=25,
            actual_file_hash_after_successful_independent_ELF_inventory=True,
            no_after_digest_input=True,all_original_HIA_sources_documents_images_receipts_retained=True)
        status="PASS"
    except BaseException as error:
        primary=error;report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        try:traceback.print_exc()
        except BaseException as later:error.add_note("traceback output: "+repr(later))
    finally:
        errors=[]
        if project is not None:
            try:report["submitted_source_after"]=closure(project,index["rows"])
            except BaseException as error:errors.append(("source-after",error))
        for role,pair in pairs.items():
            for kind,row in pair.items():
                try:assert identity(row["path"])=={k:row[k] for k in ("bytes","sha256","mode")}
                except BaseException as error:errors.append((role+":"+kind,error))
        report["source_image_after_errors"]=[dict(label=label,error=repr(error)) for label,error in errors]
        report["actual_source_image_pairs"]=pairs
        if errors:
            status="FAIL";report["status"]="FAIL"
            if primary is None:primary=errors[0][1]
            for label,error in errors:primary.add_note(label+": "+repr(error))
        roots={} if project is None else {"backend-physical-after":project}
        try:seal.finish(common,"backend-physical-after-r1",status,report,roots=roots)
        except BaseException as error:
            if primary is None:primary=error
            else:primary.add_note("independent evidence seal: "+repr(error))
    if primary is not None:raise primary
    assert status==report["status"]=="PASS"
if __name__=="__main__":main()
