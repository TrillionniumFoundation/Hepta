"""New completed-FSTAT adoption gate with exact SQLite3461 C oracle.

This first gate uses controlled filesystem receipts and full VM/native buffer
equality. It does not issue database locking syscalls or qualify ordinary Store.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-db-reuse-r3-generator.py\",\"blob\":\"ba5452a46daa5532cb6a83f0a0ecf2e780f35959\",\"bytes\":34186,\"sha256\":\"f5e4d87baf5046db3b1ec77300b057010b94529a3ea11408bb99abd15fc3f0b3\",\"target\":null},{\"name\":\"namespace-db-reuse-r3-protocol.py\",\"blob\":\"43e85d83883d89cdd6c274925f82043c849c3bc9\",\"bytes\":36296,\"sha256\":\"3ae329f51a511867ad1aa8511c1bdf65d604878f1fe7df987561ec066953b62e\",\"target\":\"tests/namespace_db_reuse_original.py\"},{\"name\":\"namespace-db-reuse-r3-oracle.c\",\"blob\":\"6a33d663f59f33bbcd87090f44fe77d7068140d2\",\"bytes\":36095,\"sha256\":\"989c2db0e13f2a19f9af3f79066a733a0e03e14c732ae745dc44c64dc4ff578f\",\"target\":null},{\"name\":\"namespace-db-reuse-r3-extract.json\",\"blob\":\"073805d450fb39c988f43426ef3ef5a941664124\",\"bytes\":4334,\"sha256\":\"2644d5447902ecd6c06c54ebef2a30329e55e2edc3b133de353a30ddaa31e4cb\",\"target\":null},{\"name\":\"namespace-db-reuse-r3-abi.json\",\"blob\":\"b61695983baaca0a6e91ee00eee93523be3a8da5\",\"bytes\":12831,\"sha256\":\"312b6d28c1144ec09101d5013d06b543483a039a160df889cc1f9ac5a24cb207\",\"target\":null},{\"name\":\"os_unix_3461_original.c\",\"blob\":\"9e7ba05d6882b1f3c310b99102e8ecbf7f830af2\",\"bytes\":283843,\"sha256\":\"83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9\",\"target\":null},{\"name\":\"old-db2-protocol.py\",\"blob\":\"88db473aeeb2038dbe54257bf0e0fc31c65ca393\",\"bytes\":27725,\"sha256\":\"06a4d944a54668042a6bfeab9f8759e2530577a7fdc5cb5aa2c3dbb888e399e0\",\"target\":null},{\"name\":\"source-reconstruction-proof.json\",\"blob\":\"06d0540016ea1487e814100288b6687317bd8bc4\",\"bytes\":9672,\"sha256\":\"9436f66fc64d3a7e040e01b5208b18be74b4a6592ba012c787e19a04083b559e\",\"target\":null},{\"name\":\"namespace-db-adopt-r4-generator.py\",\"blob\":\"ce44c2cdcb0fcb94cda064128dada7dfe089a21d\",\"bytes\":39322,\"sha256\":\"e1ee5b8fdcdc3fcc9e84858a565921e07f25f36dfe7ade0eb78f9848cbed10e6\",\"target\":\"tools/generate_hia_agent_namespace_db_node_adopt_r4.py\"},{\"name\":\"namespace-db-adopt-r4-protocol.py\",\"blob\":\"a9b9f415ee62a0870516f9e1dc96083d83264ae3\",\"bytes\":12052,\"sha256\":\"52004dfc018ee9d92ecbc922e4825b8af088980d96b9df357c9bd627439ef880\",\"target\":\"tests/test_hia_agent_namespace_db_node.py\"},{\"name\":\"namespace-db-adopt-r4-abi.json\",\"blob\":\"bde8e089479b45474722bbc5edfcbabcace42b59\",\"bytes\":6884,\"sha256\":\"50ee4334b12f7ba32ef47067477f14deaa1b04cf310957c9afb6fbc41dc72123\",\"target\":\"docs/HIA_AGENT_NAMESPACE_MAIN_DB_FSTAT_ADOPTION_ABI.json\"},{\"name\":\"namespace-db-adopt-r4-generate.py\",\"blob\":\"8c74024a835333d4a20d97df575c2b18a770cf14\",\"bytes\":3703,\"sha256\":\"86f8b50f9ce5b2fc3faed98950d1d48d970343c2110ff3f90a05c4e2d3b7edc3\",\"target\":null},{\"name\":\"namespace-db-adopt-r4-validate.py\",\"blob\":\"1ae0b0070de96076c52abafdf2fe8c1ac8a8c3ba\",\"bytes\":16575,\"sha256\":\"da3d84d31c61354ffa700efc2252e155b9343b103f3c7f38705b06d10f1b444b\",\"target\":null}]")
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def module(name,path):
    path=Path(path);raw=path.read_bytes()
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value
def test_ok(value):
    assert value["passed"] and 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==60
    assert len(set(value["test_ids"]))==60
    assert not any(value[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
ORACLE_LIMITER=r'''
import ctypes,json,os,resource,sys
parent=os.getppid();libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(1,9,0,0,0)!=0 or os.getppid()!=parent:raise OSError("oracle compiler parent custody")
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
limits={name:list(resource.getrlimit(kind)) for name,kind in (("cpu_seconds",resource.RLIMIT_CPU),("address_bytes",resource.RLIMIT_AS),("core_bytes",resource.RLIMIT_CORE))}
assert limits=={"cpu_seconds":[10,10],"address_bytes":[256<<20,256<<20],"core_bytes":[0,0]}
print(json.dumps(dict(kind="NEW_C_REFERENCE_COMPILER_LIMITS",limits=limits,pid=os.getpid()),sort_keys=True),flush=True)
os.execv(sys.argv[1],sys.argv[1:])
'''
def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    raw=common_path.read_bytes();assert git(raw)==COMMON
    common=module("namespace_db_node_ci_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==raw
    location=Path(__file__).resolve().parent;inputs={};working=[];context=None;evidence=None;status="FAIL"
    details=dict(status="INCOMPLETE",scope="NEW_COMPLETED_FSTAT_ADOPTION_EXACT_SQLITE3461_POLICY_COMPONENT",
        prior_execution_counts_inherited=False,actual_physical_syscalls=0,complete_31_SQL_operations_closed=False,
        ordinary_AgentStore_closed=False,migration_closed=False,whole_SQLite_oracle=False,
        older_WAL_inode_18_tests_are_not_DB_lock_qualification=True,
        inaccessible26_file_draft_counts_or_identity_inherited=False,
        original32_test_bodies_retained=True,original_reuse40_test_bodies_retained=True,new_adoption_test_groups=20,
        global_path_stat_lookup_is_foreign_to_this_selected_inode_component=True,
        original_ROG_full="FAIL/HOLD unchanged; NDU deletion actor UNKNOWN",
        limits=dict(generation_cpu_seconds=90,generation_wall_seconds=180,
            C_reference_compile_cpu_seconds=10,C_reference_compile_wall_seconds=20,C_reference_compile_address_bytes=256<<20,
            HIA_B3_compile_cpu_seconds=10,HIA_B3_compile_wall_seconds=20,HIA_B3_compile_address_bytes=256<<20,
            HIA_B3_output_bytes=1<<20,HIA_B3_workspace_bytes=1<<20,
            VM_per_entry_steps=4000000,VM_arena_bytes=32<<20,component_aggregate_wall_seconds=900),
        execution_counts="UNKNOWN_UNTIL_ACTUAL_RUN")
    try:
        inputs[str(Path(__file__).resolve())]=pin(__file__);paths={}
        for item in FILES:
            path=location/item["name"]
            raw=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(raw),sha(raw))==(item["bytes"],item["sha256"])
            if path.suffix==".py":ast.parse(raw,filename=str(path))
            inputs[str(path)]=pin(path);paths[item["name"]]=path
        context=common.prepare()
        cc=shutil.which("cc");assert cc is not None,"required C reference compiler absent"
        cc=str(Path(cc).resolve())
        ns=Path(context["base"])/"namespace-ci-db-adopt-r4";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-db-adopt-r4";evidence.mkdir()
        (evidence/"source").mkdir()
        for path in [Path(__file__),*paths.values()]:
            target=evidence/"source"/path.name
            with target.open("xb") as stream:stream.write(path.read_bytes())
            target.chmod(stat.S_IMODE(path.stat().st_mode));assert target.read_bytes()==path.read_bytes()
        for item in FILES:
            if item["target"] is not None:
                target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as stream:stream.write(paths[item["name"]].read_bytes())
                target.chmod(0o644)
        (evidence/"compiler").mkdir()
        compiler=Path(context["compiler"]);compiler_raw=compiler.read_bytes()
        assert len(compiler_raw)==669556 and sha(compiler_raw)==B3
        (evidence/"compiler/B3.image.bin").write_bytes(compiler_raw)
        oracle=evidence/"oracle";oracle.mkdir()
        for name,target in (("namespace-db-reuse-r3-oracle.c","sqlite3461-policy.c"),("namespace-db-reuse-r3-extract.json","exact-function-extract.json")):
            (oracle/target).write_bytes(paths[name].read_bytes())
        extract=json.loads((oracle/"exact-function-extract.json").read_bytes());c_raw=(oracle/"sqlite3461-policy.c").read_bytes()
        assert extract["actual_source_bytes"]==len(c_raw) and extract["actual_source_sha256"]==sha(c_raw)
        assert len(extract["functions"])==15 and extract["original_function_bytes_unchanged"]
        full_raw=paths["os_unix_3461_original.c"].read_bytes()
        assert len(full_raw)==extract["full_reference"]["bytes"] and sha(full_raw)==extract["full_reference"]["sha256"]
        assert git(full_raw)==extract["full_reference"]["git_blob"]
        for item in extract["functions"]:
            raw=full_raw[item["start"]:item["end"]]
            assert len(raw)==item["bytes"] and sha(raw)==item["sha256"] and c_raw.count(raw)==1
        def test_methods(raw):
            text=raw.decode("utf-8");tree=ast.parse(text)
            cls=[node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=="NamespaceDBNodeTests"]
            assert len(cls)==1
            return {node.name:ast.get_source_segment(text,node) for node in cls[0].body
                if isinstance(node,ast.FunctionDef) and node.name.startswith("test_")}
        old_methods=test_methods(paths["old-db2-protocol.py"].read_bytes())
        new_methods=test_methods(paths["namespace-db-reuse-r3-protocol.py"].read_bytes())
        assert len(old_methods)==32 and len(new_methods)==40
        assert all(new_methods[name]==body for name,body in old_methods.items())
        details["original32_test_method_bodies_unchanged"]=True
        adoption_text=paths["namespace-db-adopt-r4-protocol.py"].read_text()
        adoption_tree=ast.parse(adoption_text)
        adoption_classes=[node for node in adoption_tree.body if isinstance(node,ast.ClassDef) and node.name=="NamespaceDBAdoptionTests"]
        assert len(adoption_classes)==1
        adoption_class=adoption_classes[0]
        assert len(adoption_class.bases)==1 and isinstance(adoption_class.bases[0],ast.Name) and adoption_class.bases[0].id=="Original"
        added={node.name for node in adoption_class.body if isinstance(node,ast.FunctionDef) and node.name.startswith("test_")}
        assert len(added)==20 and not (added & set(new_methods))
        assert {int(name.split("_",2)[1]) for name in added}==set(range(41,61))
        assert "NamespaceDBNodeTests=NamespaceDBAdoptionTests" in adoption_text
        details["original40_test_method_bodies_retained_without_override"]=True
        details["new20_adoption_methods_present"]=True
        selected=c_raw.split(b"/* BEGIN exact original policy functions, in their original dependency order. */\n\n",1)[1]
        selected=selected.split(b"/* END exact original policy functions.",1)[0]
        cursor=0
        for item in extract["functions"]:
            while selected[cursor:cursor+1]==b"\n":cursor+=1
            part=selected[cursor:cursor+item["bytes"]]
            assert len(part)==item["bytes"] and sha(part)==item["sha256"],item
            cursor+=item["bytes"]
        assert not selected[cursor:].strip()
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence))
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"],"HIA_NAMESPACE_CI_CONTEXT":str(context_path)}
        generated=common.run("db-node-new-generation",
            [context["python"],"-B",paths["namespace-db-adopt-r4-generate.py"]],
            cwd=context["reference"],timeout=180,env=env)
        details["generation_process"]=generated
        assert generated["returncode"]==0,"new DB-node generation failed"
        generation=json.loads((evidence/"generation-r1/result.json").read_bytes())
        assert generation["status"]=="GENERATED" and generation["source_unchanged"]
        compile_argv=[cc,"-std=c11","-O2","-fPIC","-shared","-Wall","-Wextra",
            "-Werror=implicit-function-declaration","-Werror=return-type","-Werror=incompatible-pointer-types",
            "-o",str(oracle/"sqlite3461-policy.so"),str(oracle/"sqlite3461-policy.c")]
        compiled=common.run("db-node-exact-original-C-reference",
            [context["python"],"-I","-S","-c",ORACLE_LIMITER,*compile_argv],
            cwd=context["reference"],timeout=20,env=env)
        details["C_reference_process"]=compiled
        assert compiled["returncode"]==0,"exact selected SQLite C oracle compilation failed"
        so=oracle/"sqlite3461-policy.so";assert so.is_file() and so.stat().st_size>0
        build=dict(status="COMPILED",source=pin(oracle/"sqlite3461-policy.c"),output=pin(so),
            compiler=pin(cc),argv=compile_argv,process=compiled,
            limits=dict(cpu_seconds=10,wall_seconds=20,address_bytes=256<<20,core_bytes=0),
            exact_original_functions=15,real_database_syscalls=0,new_HIA_native_entries=0)
        save(oracle/"build.json",build)
        validated=common.run("db-node-exact-C-VM-B3-native-complete-buffers",
            [context["python"],"-B",paths["namespace-db-adopt-r4-validate.py"]],
            cwd=context["reference"],timeout=900,env=env)
        details["validation_process"]=validated
        result_path=evidence/"validation-r1/result.json"
        if result_path.exists():
            result=json.loads(result_path.read_bytes());details["validation_result"]=result
            details["result_pin"]=pin(result_path)
        else:result=None
        assert validated["returncode"]==0 and result is not None,"new DB-node component failed"
        assert result["status"]=="PASS" and result["source_unchanged"]
        assert result["produced_images_unchanged"]=={"db_node":True}
        assert result["real_OS_policy_syscalls"]==0 and result["actual_physical_syscalls"]==0
        assert result["vm_entries"]==2*result["native_entries"] and result["native_entries"]>0
        assert result["C_policy_operations"]>0 and result["controlled_FS_receipts"]>0
        assert result["controlled_reuse_stat_calls"]>0
        assert result["adoption_packets_observed"]>0 and result["adoption_successes"]>0
        assert set(result["tests"])=={"vm","paired"}
        for group in result["tests"].values():test_ok(group)
        details["execution_counts"]=dict(vm_entries=result["vm_entries"],native_entries=result["native_entries"],
            C_policy_operations=result["C_policy_operations"],controlled_FS_receipts=result["controlled_FS_receipts"],
            controlled_reuse_stat_calls=result["controlled_reuse_stat_calls"],
            adoption_packets_observed=result["adoption_packets_observed"],adoption_successes=result["adoption_successes"],
            physical_database_syscalls=0,VM_test_groups=60,paired_test_groups=60,HIA_B3_compiles=1,C_reference_compiles=1)
        details["status"]="PASS";status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        unchanged={}
        for path,row in inputs.items():
            try:unchanged[path]=pin(path)==row
            except BaseException:unchanged[path]=False
        for row in working:
            try:unchanged[row["path"]]=pin(row["path"])==row
            except BaseException:unchanged[row["path"]]=False
        details["source_checks"]=unchanged
        if not unchanged or not all(unchanged.values()):status="FAIL";details["status"]="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        common.finish(scope="NAMESPACE_DB_COMPLETED_FSTAT_ADOPTION_EXACT_SQLITE_C_VM_NATIVE_COMPONENT",
            status=status,details=details,roots={"db-working-source":context["namespace_working"]} if context and "namespace_working" in context else {})
        print(json.dumps(dict(status=status,scope=details["scope"],execution_counts=details["execution_counts"],
            actual_physical_syscalls=0,ordinary_AgentStore_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
