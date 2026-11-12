"""Independent DB main-inode HIA policy gate with exact SQLite3461 C oracle.

This first gate uses controlled filesystem receipts and full VM/native buffer
equality. It does not issue database locking syscalls or qualify ordinary Store.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-db-node-r1-generator.py\",\"blob\":\"fcfaf458202a389118b0943b0a94cb3ada693d79\",\"bytes\":31388,\"sha256\":\"3cd91e29d966c22d038abeec5ad3a8b4834e5c766e77b24d4a266e4a988fb4b4\",\"target\":\"tools/generate_hia_agent_namespace_db_node_r1.py\"},{\"name\":\"namespace-db-node-r1-protocol.py\",\"blob\":\"88db473aeeb2038dbe54257bf0e0fc31c65ca393\",\"bytes\":27725,\"sha256\":\"06a4d944a54668042a6bfeab9f8759e2530577a7fdc5cb5aa2c3dbb888e399e0\",\"target\":\"tests/test_hia_agent_namespace_db_node.py\"},{\"name\":\"namespace-db-node-r1-oracle.c\",\"blob\":\"3d7e9c8232c98fe9600dc28c5a8e73dfcd63291f\",\"bytes\":32768,\"sha256\":\"54cf24549003b20cf6623c59068c6f13fc1a985c5b0f557c0b389ddc5b44858b\",\"target\":null},{\"name\":\"namespace-db-node-r1-extract.json\",\"blob\":\"c3d920a3e26c12e073800a0dbdcacb2f4821b3ea\",\"bytes\":3839,\"sha256\":\"028c7cd2daf88d10b1932539227c00870f7d37268c62a80315a1e0918338e05e\",\"target\":null},{\"name\":\"namespace-db-node-r1-abi.json\",\"blob\":\"d5867f5879eba2904826201b5fcaf01767dba4f1\",\"bytes\":8219,\"sha256\":\"87a54af201c7dec610ebee2a84b13dfe2ebb07d5fbb43c1196e5a2ffd3df8617\",\"target\":\"docs/HIA_AGENT_NAMESPACE_MAIN_DB_NODE_ABI.json\"},{\"name\":\"namespace-db-node-r2-generate.py\",\"blob\":\"758762b82613b881a52a4d494b8e90e4064c5fc1\",\"bytes\":2961,\"sha256\":\"f021e4b53bd464009be3833fedef2b1013e47711c7f3210853d68a58bf124787\",\"target\":null},{\"name\":\"namespace-db-node-r2-validate.py\",\"blob\":\"6a3f41048cdc1b43ea342a554e07da0e3f5a38c1\",\"bytes\":15821,\"sha256\":\"584f1902bb983647a7b21abeb70595cc0a3721014f5cf26b9322936faf8babb6\",\"target\":null}]")
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
    assert value["passed"] and 0<value["tests_loaded"]==value["tests_run"]==len(value["test_ids"])==32
    assert len(set(value["test_ids"]))==32
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
    details=dict(status="INCOMPLETE",scope="NEW_DB_MAIN_INODE_EXACT_SQLITE3461_POLICY_COMPONENT",
        prior_execution_counts_inherited=False,actual_physical_syscalls=0,complete_31_SQL_operations_closed=False,
        ordinary_AgentStore_closed=False,migration_closed=False,whole_SQLite_oracle=False,
        older_WAL_inode_18_tests_are_not_DB_lock_qualification=True,
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
        ns=Path(context["base"])/"namespace-ci-db-node-r1";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-db-node-r1";evidence.mkdir()
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
        for name,target in (("namespace-db-node-r1-oracle.c","sqlite3461-policy.c"),("namespace-db-node-r1-extract.json","exact-function-extract.json")):
            (oracle/target).write_bytes(paths[name].read_bytes())
        extract=json.loads((oracle/"exact-function-extract.json").read_bytes());c_raw=(oracle/"sqlite3461-policy.c").read_bytes()
        assert extract["actual_source_bytes"]==len(c_raw) and extract["actual_source_sha256"]==sha(c_raw)
        assert len(extract["functions"])==14 and extract["original_function_bytes_unchanged"]
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
            [context["python"],"-B",paths["namespace-db-node-r2-generate.py"]],
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
            exact_original_functions=14,real_database_syscalls=0,new_HIA_native_entries=0)
        save(oracle/"build.json",build)
        validated=common.run("db-node-exact-C-VM-B3-native-complete-buffers",
            [context["python"],"-B",paths["namespace-db-node-r2-validate.py"]],
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
        assert set(result["tests"])=={"vm","paired"}
        for group in result["tests"].values():test_ok(group)
        details["execution_counts"]=dict(vm_entries=result["vm_entries"],native_entries=result["native_entries"],
            C_policy_operations=result["C_policy_operations"],controlled_FS_receipts=result["controlled_FS_receipts"],
            physical_database_syscalls=0,VM_test_groups=32,paired_test_groups=32,HIA_B3_compiles=1,C_reference_compiles=1)
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
        common.finish(scope="NAMESPACE_MAIN_DB_NODE_NEW_EXACT_SQLITE_C_POLICY_VM_NATIVE_COMPONENT",
            status=status,details=details,roots={"namespace_db_node":str(evidence)} if evidence is not None else {})
        print(json.dumps(dict(status=status,scope=details["scope"],execution_counts=details["execution_counts"],
            actual_physical_syscalls=0,ordinary_AgentStore_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
