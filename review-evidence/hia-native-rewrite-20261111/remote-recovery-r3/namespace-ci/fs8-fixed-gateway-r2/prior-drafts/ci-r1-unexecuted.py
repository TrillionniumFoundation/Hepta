"""Fresh six-image physical DB inode / shared-FS / DMS / map / memory gate.

Every source is pinned and every role and packer is generated and B3-compiled
anew. The fixed ELF owns all service calls. Python only authors test fixtures,
observes independent POSIX/SQLite behavior and replays the complete raw trace.
No earlier target test count, native image, full qualification or cold is reused.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast,hashlib,importlib.util,json,os,shutil,stat,traceback
from pathlib import Path
COMMON="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
FILES=json.loads("[{\"name\":\"namespace-values-reference.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\",\"target\":\"tools/generate_hia_agent_namespace_store.py\"},{\"name\":\"namespace-objects-reference.py\",\"blob\":\"a188e9553b61ffc4293950908a71a93a3a9a27bb\",\"bytes\":27802,\"sha256\":\"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de\",\"target\":\"tools/generate_hia_agent_namespace_objects.py\"},{\"name\":\"namespace-filesystem-r8-generator.py\",\"blob\":\"87d7cba2d02b1c694722c7285666f066b89b2ec8\",\"bytes\":23645,\"sha256\":\"0dab33207147efd8f8ff7f62b4223a08c330aeb18ef0d2642ea97f2bd8e3acc7\",\"target\":\"tools/generate_hia_agent_namespace_filesystem_r8.py\"},{\"name\":\"namespace-shm-map-r3-generator.py\",\"blob\":\"58f0b8db47774ac75d073336b9fc1160d34d3fd2\",\"bytes\":23289,\"sha256\":\"1ac940af6b31b8e7cc02ada063a46fc5a28ee04f524bb60d5bfeb5fde109fcde\",\"target\":\"tools/generate_hia_agent_namespace_shm_map_r3.py\"},{\"name\":\"namespace-memory-r2-generator.py\",\"blob\":\"7711bad8273121820a1fa169250acf9f6d43a726\",\"bytes\":22372,\"sha256\":\"e9f5e580bbd69149f51f577f9246fb3f553b1574726e945bd0af0a31f7996560\",\"target\":\"tools/generate_hia_agent_namespace_memory_leases.py\"},{\"name\":\"namespace-dms-fixed-header-builder-r1.py\",\"blob\":\"837e09e975db0215d0572cf23d5d129aaf43dfad\",\"bytes\":5082,\"sha256\":\"c4b4835cc21258ee0fa1a678dfe8e4e8911927568da6b39e9aa2a9e0fa10e619\",\"target\":\"tools/hia_namespace_dms_fixed_header_builder.py\"},{\"name\":\"namespace-dms-map-join-r9-generator.py\",\"blob\":\"47beb3764f3774acab90883ee202cf5c03b8643d\",\"bytes\":72876,\"sha256\":\"963445ac091c3a6ba08df05d8436e5936c616f7dd77cf9626c0ec5f0197c3117\",\"target\":\"tools/generate_hia_agent_namespace_dms_map_join_r9.py\"},{\"name\":\"namespace-db-reuse-r3-generator.py\",\"blob\":\"ba5452a46daa5532cb6a83f0a0ecf2e780f35959\",\"bytes\":34186,\"sha256\":\"f5e4d87baf5046db3b1ec77300b057010b94529a3ea11408bb99abd15fc3f0b3\",\"target\":\"tools/generate_hia_agent_namespace_db_reuse_r3.py\"},{\"name\":\"namespace-db-global-reuse-r2-generator.py\",\"blob\":\"9dba2741beba0a1b567358fc9f5a385bfad66408\",\"bytes\":46342,\"sha256\":\"ca5dccb84ad25953986accdd9bbc991376ae6735bbd49bbf2985aaf66ffc1e5b\",\"target\":\"tools/generate_hia_agent_namespace_db_fixed_join_r3.py\"},{\"name\":\"four-role-base.S\",\"blob\":\"fd7ed1070fa4e9bd93805f4ad0babe0ab762010b\",\"bytes\":53632,\"sha256\":\"23d7be3dcda3c46a61fa43f8dc9aed83fe4be26088bda86c6c07556ebfbd0582\",\"target\":null},{\"name\":\"compose-namespace-db-join-r2.py\",\"blob\":\"f17929728426ee5c566d860ddf9016b37bb348d9\",\"bytes\":14008,\"sha256\":\"5d35ff33c37cabfcc31d0b3d04b5efe591f9832feb246a4263872af8cc3f3c96\",\"target\":null},{\"name\":\"namespace-fs8-db-fixed-executor.S\",\"blob\":\"f90bbc7cbdff24135df2e4e0b7e1f0592c9723ba\",\"bytes\":64899,\"sha256\":\"fc47cfc647affed2db900351834845b819c4c07f838dcb701a3a03f418813b9b\",\"target\":null},{\"name\":\"namespace-db-join-r3-packer.py\",\"blob\":\"599a68532e177e68562ca708a3173bd691300456\",\"bytes\":5254,\"sha256\":\"7f01bf037ef627017306cfc1ec836d7309e884d05cbb50949102a52cf7cda9b4\",\"target\":null},{\"name\":\"namespace-fs8-db-build-r1.py\",\"blob\":\"565a92795e75db2a873c0ae69838b753b654ca14\",\"bytes\":24144,\"sha256\":\"7c6e7b20f0b1ebceb77896a1e7c421c34ba203ecb3eedf18231df9cdd1405027\",\"target\":null},{\"name\":\"namespace-db-join-r1-client.py\",\"blob\":\"c489da3fc832d9caecaa271069bfc3608746ffec\",\"bytes\":22281,\"sha256\":\"e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270\",\"target\":null},{\"name\":\"namespace-fs8-full-inner-replay.py\",\"blob\":\"b6f1eee12f5c3a0b7f25262365d29cfd924c2570\",\"bytes\":20813,\"sha256\":\"ec3b3ce5f7d03b05c8fd4bf4ac17170cb75a3c47b6373ace8bf04b8d6ec8c30f\",\"target\":null},{\"name\":\"namespace-fs8-outer-replay.py\",\"blob\":\"9ed7fbee842c3513de6ded1a48cbb39adc01594a\",\"bytes\":17687,\"sha256\":\"060fa3ae8da88e699b881ae5e59f1f49fb030e2f6b02b4082cf16ea3e0d91a6e\",\"target\":null},{\"name\":\"namespace-fs8-db-physical-r1.py\",\"blob\":\"a292aab4cc749b93caac04f6485fdb78d3db7af2\",\"bytes\":68461,\"sha256\":\"03eb21eda25a45df6267b8e7c12366dff44850fc8f62c67de4b38ce58ab6920d\",\"target\":null},{\"name\":\"namespace-db-join-r3-abi.json\",\"blob\":\"11d61218756b56ebaa15428b8aa991057610ee10\",\"bytes\":11567,\"sha256\":\"22e1d2c47af9cd7c82dcbeb60a8be1b6217ee4b8cdd8db8f89dae35b47bff00d\",\"target\":\"docs/HIA_AGENT_NAMESPACE_DB_PHYSICAL_JOIN_ABI.json\"},{\"name\":\"namespace-db-join-r2-packer.reference.py\",\"blob\":\"f8cc9ac750dd926f5bdee2164504620161801a52\",\"bytes\":5631,\"sha256\":\"c202f7a769132850d0b58b6525dc0104f3be6e18f8aa430d7b635fb40f1aabf5\",\"target\":null},{\"name\":\"namespace-packer-three-way-r1.py\",\"blob\":\"5fd6f484cd65f9e2177efb6476f8327bbcf6ea55\",\"bytes\":12414,\"sha256\":\"18abd61c4a696ec576c5c45ca6e5d5022b457a8973d76b7e29687358b76db947\",\"target\":null},{\"name\":\"physical-r6-original.py\",\"blob\":\"ea1bc3da7d58fe6ad5bc68cb324601cacbd4e175\",\"bytes\":48707,\"sha256\":\"bc56d2c488f5b83127762a4ff43b1837954b92e6a50e733cdeeb0235e31412d7\",\"target\":null},{\"name\":\"outer-r1-original.py\",\"blob\":\"92f06c473bd42fe5f3f16666c4e9aa9b3cebadcf\",\"bytes\":40272,\"sha256\":\"c2d2d5f522febe4956db2ccd5d7b8003014fedb16b915c751c0e3a810008ba7b\",\"target\":null},{\"name\":\"namespace-fs8-fixed-gateway-abi.json\",\"blob\":\"2ccad4383e28cc9181edc5fe30cf8707c0e5c7de\",\"bytes\":3577,\"sha256\":\"8f524f1c5190799dc5a9654c3be279a66c355b7ab921ac2fec2c7156ced5bbde\",\"target\":\"docs/HIA_AGENT_NAMESPACE_FS8_FIXED_GATEWAY_ABI.json\"},{\"name\":\"source-delta-proof.json\",\"blob\":\"e5e7a49dac33fc5d58d28d536d8c6bbecfd1b6cc\",\"bytes\":4963,\"sha256\":\"7f908ff66295a1574f02aa79306291e2af62c23b86d2a16a84a8a6773ce2b1c2\",\"target\":null},{\"name\":\"added-physical-methods.txt\",\"blob\":\"37eb6ff4558fe1c9133ffbfdc5a0a52378617c16\",\"bytes\":19754,\"sha256\":\"93e83c10c24fb9e7aa1aacab0d8d44ffbb3b9562108457720d2cccce6cbee3f1\",\"target\":null},{\"name\":\"single-fstat-scope-correction.json\",\"blob\":\"2e51acb19a70d8b13ed6ad6b3f0272b0fcfe35ba\",\"bytes\":3520,\"sha256\":\"96969a3e6420c685f53eaf2851a8f77dfcefa25f1a8ab76c228f532acfca8398\",\"target\":null},{\"name\":\"compose-fs8-db-gateway-r1.py\",\"blob\":\"6a823f5e7e43161f0d5761f10d33989d80a81d8c\",\"bytes\":3187,\"sha256\":\"729c3e1cd4250f3eb531f41cc7b7faeca8aa0289cc684cb22fa5faaaed9bc0b0\",\"target\":null},{\"name\":\"filesystem-r7-original.py\",\"blob\":\"ccddae25e9187a30c30b4af7631f054f37a1ba3b\",\"bytes\":23500,\"sha256\":\"e457bad764e6bf33eca22e7ca947c7d7457f57cb0ac944b033bf199bea32c0b8\",\"target\":null},{\"name\":\"dms-r8-original.py\",\"blob\":\"9ba36ef7fe77ce697a78720e4d7d0039116c386c\",\"bytes\":72876,\"sha256\":\"4063dfbcd35c7b3c3b3b4a8baaf6037e1f32e9c133afdd12ca35cd6638ace1d8\",\"target\":null},{\"name\":\"executor-r6-original.S\",\"blob\":\"a1d68041c8c25e92855844b5174837e582856c49\",\"bytes\":64323,\"sha256\":\"8876c8172b3f2166e1482e53f0698517dad1fde164c4b59bd481186d437b2224\",\"target\":null},{\"name\":\"inner-replay-original.py\",\"blob\":\"96762602378d98db79755759b4ad3f4e6a8662bf\",\"bytes\":20780,\"sha256\":\"0b9bab8e16b0174c54062d56c5042afdaea35a1e936932bbd31ade04f06436a6\",\"target\":null},{\"name\":\"outer-replay-original.py\",\"blob\":\"38b7813e00ddf13f047cff6fdd9b407d1d2acce1\",\"bytes\":17457,\"sha256\":\"3886e4af2d36ec42c7db076e954dd4ab7459f065c64e5847e83bb470b83db570\",\"target\":null},{\"name\":\"global-r1-physical.reference.py\",\"blob\":\"b1bfc7e982f97f6f588b08ede915e05790ae65bc\",\"bytes\":61915,\"sha256\":\"91379bce048814995394245cd354bf8de41ad0b1a1f7961b6cf66caa84ff9f17\",\"target\":null}]")
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
EXPECTED_TESTS=34
EXPECTED_PACKER_CONTROLS=33
ROLES={"1","2","3","4","5","6"}

def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path).absolute();info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def equal(row):
    try:return pin(row["path"])==row
    except BaseException:return False
def module(name,path):
    path=Path(path);raw=path.read_bytes()
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    exec(compile(raw,str(path),"exec"),value.__dict__);return value

def main():
    common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
    common_raw=common_path.read_bytes();assert git(common_raw)==COMMON
    common=module("namespace_six_role_physical_common",common_path)
    assert common.pinned(common_path.relative_to(common.REPO).as_posix(),COMMON)==common_raw
    inputs={};working=[];context=None;evidence=None;status="FAIL"
    details=dict(status="INCOMPLETE",
        scope="NEW_FIXED_SIX_ROLE_FS8_GATEWAY_GLOBAL_REUSE_PRIVATE_PREDECESSOR",
        source_revisions={"FS":8,"Map":3,"memory":2,"DMS_join":9,"DB_node":3,"outer":3},
        prior_execution_counts_inherited=False,prior_images_reused=False,Python_business_router=False,
        complete_31_SQL_operations_closed=False,ordinary_AgentStore_closed=False,
        full_unixOpen_and_findReusableFd_closed=False,migration_closed=False,
        original_ROG_full="FAIL/HOLD unchanged; NDU deletion actor UNKNOWN",
        process_limits=dict(
            HIA_B3_cpu_seconds=10,HIA_B3_wall_seconds=20,HIA_B3_address_bytes=256<<20,
            HIA_B3_output_bytes=1<<20,HIA_B3_workspace_bytes=1<<20,
            builder_cpu_seconds=90,builder_wall_seconds=180,builder_address_bytes=1<<30,
            each_actual_ELF_cpu_seconds=90,each_actual_ELF_wall_seconds=180,
            each_actual_ELF_address_bytes=1<<30,each_actual_ELF_core_bytes=0,
            native_mandatory_exact_wait4=True,physical_aggregate_wall_seconds=900,
            VM_per_original_entry_steps=4000000,VM_arena_bytes=32<<20),
        execution_counts="UNKNOWN_UNTIL_ACTUAL_REPORTS")
    try:
        location=Path(__file__).resolve().parent;paths={}
        inputs[str(Path(__file__).resolve())]=pin(__file__)
        for item in FILES:
            path=location/item["name"]
            raw=common.pinned(path.relative_to(common.REPO).as_posix(),item["blob"])
            assert (len(raw),sha(raw))==(item["bytes"],item["sha256"])
            if path.suffix==".py":ast.parse(raw,filename=str(path))
            inputs[str(path)]=pin(path);paths[item["name"]]=path

        original=paths["physical-r6-original.py"].read_bytes()
        current=paths["namespace-fs8-db-physical-r1.py"].read_bytes()
        fragment=paths["added-physical-methods.txt"].read_bytes()
        assert current.count(fragment)==1 and fragment
        restored=current.replace(fragment,b"").replace(b"EXPECTED_TESTS=34"+bytes([10]),b"EXPECTED_TESTS=18"+bytes([10]))
        replayer_identity_changes=(
            (b"060fa3ae8da88e699b881ae5e59f1f49fb030e2f6b02b4082cf16ea3e0d91a6e",
             b"3886e4af2d36ec42c7db076e954dd4ab7459f065c64e5847e83bb470b83db570"),
            (b"ec3b3ce5f7d03b05c8fd4bf4ac17170cb75a3c47b6373ace8bf04b8d6ec8c30f",
             b"0b9bab8e16b0174c54062d56c5042afdaea35a1e936932bbd31ade04f06436a6"))
        for actual,previous in replayer_identity_changes:
            assert restored.count(actual)==1
            restored=restored.replace(actual,previous,1)
        assert restored==original,"all original18 methods and every old harness assertion must remain byte-identical"
        original_ast=ast.parse(original)
        current_ast=ast.parse(current)
        def test_names(tree):
            classes=[n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.name=="ActualJoin"]
            assert len(classes)==1
            return [n.name for n in classes[0].body if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")]
        previous_ids=test_names(original_ast);current_ids=test_names(current_ast)
        assert len(previous_ids)==18 and len(current_ids)==34
        assert current_ids[:18]==previous_ids and len(set(current_ids))==34
        assert [name.split("_",2)[1] for name in current_ids[18:]]==[str(n) for n in range(19,35)]
        def hia_functions(path,variable="JOIN"):
            program=ast.parse(path.read_bytes())
            values=[n for n in program.body if isinstance(n,ast.Assign) and
                any(isinstance(target,ast.Name) and target.id==variable for target in n.targets)]
            assert len(values)==1
            raw=ast.literal_eval(values[0].value)
            parsed=ast.parse(raw)
            functions={n.name:ast.get_source_segment(raw,n) for n in parsed.body if isinstance(n,ast.FunctionDef)}
            assert len(functions)==len(parsed.body)
            return functions
        before=hia_functions(paths["outer-r1-original.py"])
        after=hia_functions(paths["namespace-db-global-reuse-r2-generator.py"])
        changed=[name for name in before if after.get(name)!=before[name]]
        added=[name for name in after if name not in before]
        assert changed==["j_user_shape","j_user","j_child"]
        assert added==["j_reuse_start","j_reuse_stat_frame","j_reuse_stat","j_reuse_completed"]
        assert len(before)==39 and len(after)==43
        details["retained_source_controls"]=dict(
            entire_original18_harness_restored_byte_identically=True,
            original_test_ids=previous_ids,new_test_ids=current_ids[18:],
            unchanged_original_HIA_functions=36,changed_original_HIA_functions=changed,
            added_HIA_functions=added,
            carrier_only_four_exact_mechanical_changes=True,
            client_and_all_original_limits_unchanged=True,
            inner_replayer_only_five_syscall_numbers_added=True,
            outer_replayer_executable_source_unchanged=True)

        prior_global=paths["global-r1-physical.reference.py"].read_bytes()
        prior_global_ast=ast.parse(prior_global)
        assert test_names(prior_global_ast)==current_ids[:28]
        def test_bodies(raw,tree):
            nodes=[n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.name=="ActualJoin"]
            assert len(nodes)==1
            return {n.name:ast.get_source_segment(raw.decode("utf-8"),n)
                for n in nodes[0].body if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")}
        prior_bodies=test_bodies(prior_global,prior_global_ast)
        current_bodies=test_bodies(current,current_ast)
        assert all(current_bodies[name]==value for name,value in prior_bodies.items())
        fs_before=hia_functions(paths["filesystem-r7-original.py"],"FS")
        fs_after=hia_functions(paths["namespace-filesystem-r8-generator.py"],"FS")
        assert set(fs_before)==set(fs_after)
        fs_changed=[name for name in fs_before if fs_before[name]!=fs_after[name]]
        assert fs_changed==["steady","call_shape","prepare","emit_system","acknowledge"]
        dms_before=hia_functions(paths["dms-r8-original.py"],"DMS")
        dms_after=hia_functions(paths["namespace-dms-map-join-r9-generator.py"],"DMS")
        assert set(dms_before)==set(dms_after)
        dms_changed=[name for name in dms_before if dms_before[name]!=dms_after[name]]
        assert dms_changed==["dms_request_shape"]
        assert dms_after["dms_request_shape"].count("dms_read(s, 64) > 29")==1
        assert dms_after["dms_request_shape"].replace("dms_read(s, 64) > 29","dms_read(s, 64) > 24")==dms_before["dms_request_shape"]
        composer_tree=ast.parse(paths["compose-fs8-db-gateway-r1.py"].read_bytes())
        declarations=[n for n in composer_tree.body if isinstance(n,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=="EDITS" for target in n.targets)]
        assert len(declarations)==1
        edit_call=declarations[0].value
        assert isinstance(edit_call,ast.Call) and len(edit_call.args)==1 and not edit_call.keywords
        mechanical_edits=json.loads(ast.literal_eval(edit_call.args[0]))
        assert len(mechanical_edits)==4
        restored_assembly=paths["namespace-fs8-db-fixed-executor.S"].read_text()
        for previous,replacement in reversed(mechanical_edits):
            assert restored_assembly.count(replacement)==1
            restored_assembly=restored_assembly.replace(replacement,previous,1)
        assert restored_assembly.encode()==paths["executor-r6-original.S"].read_bytes()
        previous_inner=paths["inner-replay-original.py"].read_bytes()
        actual_inner=paths["namespace-fs8-full-inner-replay.py"].read_bytes()
        def syscall_declaration(raw):
            decoded=raw.decode("utf-8");parsed=ast.parse(raw)
            values=[n for n in parsed.body if isinstance(n,ast.Assign) and
                any(isinstance(target,ast.Name) and target.id=="SYSCALLS" for target in n.targets)]
            assert len(values)==1
            return ast.literal_eval(values[0].value),ast.get_source_segment(decoded,values[0])
        previous_numbers,previous_declaration=syscall_declaration(previous_inner)
        actual_numbers,actual_declaration=syscall_declaration(actual_inner)
        assert actual_numbers==previous_numbers|{25:257,26:39,27:21,28:257,29:262}
        assert actual_inner.count(actual_declaration.encode())==1
        assert actual_inner.replace(actual_declaration.encode(),previous_declaration.encode(),1)==previous_inner
        previous_outer=paths["outer-replay-original.py"].read_bytes()
        actual_outer=paths["namespace-fs8-outer-replay.py"].read_bytes()
        marker=b"from __future__ import annotations"
        assert previous_outer.count(marker)==actual_outer.count(marker)==1
        assert previous_outer.split(marker,1)[1]==actual_outer.split(marker,1)[1]
        details["retained_source_controls"].update(
            original_global10_test_bodies_byte_identical=True,
            FS7_to_FS8_changed_functions=fs_changed,DMS8_to_DMS9_changed_functions=dms_changed,
            actual_new_primitive_numbers=[25,26,27,28,29],
            old_original18_restoration_identity_changes_only=2)
        context=common.prepare()
        assert sys.version_info[:3]==(3,12,14)
        assert os.sysconf("SC_PAGE_SIZE")==4096,"this fixed x86-64 ABI requires the recorded actual 4096-byte page"
        required={}
        for name in ("as","readelf","nm","objcopy","strace"):
            path=shutil.which(name)
            assert path is not None,("required physical tool is absent",name)
            path=Path(path).resolve();required[name]=pin(path)
        details["actual_required_tools"]=required
        # strace is mandatory. A ptrace failure remains a real test failure.
        common.run("six-role-strace-version",[required["strace"]["path"],"--version"],
            cwd=context["reference"],timeout=10)
        base=Path(context["base"]);ns=base/"namespace-ci-fs8-fixed-gateway-r1";ns.mkdir()
        tree=ns/"working-source";tree.mkdir()
        evidence=Path(context["output"])/"namespace-db-physical-join-r1";evidence.mkdir()
        (evidence/"source").mkdir();(evidence/"compiler").mkdir()
        for path in [Path(__file__).resolve(),*paths.values()]:
            raw=path.read_bytes();target=evidence/"source"/path.name
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(stat.S_IMODE(path.stat().st_mode))
            assert target.read_bytes()==raw
        for item in FILES:
            if item["target"] is None:continue
            target=tree/item["target"];target.parent.mkdir(parents=True,exist_ok=True)
            raw=paths[item["name"]].read_bytes()
            with target.open("xb") as stream:stream.write(raw)
            target.chmod(0o644)
            assert (len(raw),sha(raw))==(item["bytes"],item["sha256"])
            assert target.read_bytes()==raw
        compiler=Path(context["compiler"]);raw=compiler.read_bytes()
        assert len(raw)==669556 and sha(raw)==B3
        copied=evidence/"compiler/B3.image.bin";copied.write_bytes(raw)
        copied.chmod(stat.S_IMODE(compiler.stat().st_mode));assert copied.read_bytes()==raw
        context.update(namespace_working=str(tree),namespace_evidence=str(evidence),
            namespace_fixtures=str(ns/"live-physical-fixtures"))
        assert context.get("namespace_predecessor") is None
        context_path=evidence/"context.json";save(context_path,context)
        working=[pin(p) for p in sorted(tree.rglob("*")) if p.is_file()]
        environment={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":context["reference"]}
        composed=evidence/"namespace-db-join-actual-composed.S"
        composition=common.run("six-role-source-composition",
            [context["python"],"-B",paths["compose-fs8-db-gateway-r1.py"],
             paths["four-role-base.S"],composed,"--old-composer",paths["compose-namespace-db-join-r2.py"]],
            cwd=context["reference"],timeout=30,env=environment)
        assert composed.read_bytes()==paths["namespace-fs8-db-fixed-executor.S"].read_bytes()
        assert all(equal(row) for row in inputs.values())
        details["mechanical_composition"]=dict(process=composition,
            exact_composed_source=pin(composed),declared_edits=10,
            original_outer_edits=4,same_address_local_call_edits=2,new_FS8_mechanical_edits=4,
            original_four_role_base_reversed_exactly=True,assembler_or_native_execution=False)
        builder=common.run("six-role-fresh-B3-and-actual-HIA-packer",
            [context["python"],"-B",paths["namespace-fs8-db-build-r1.py"],
             "--context",context_path,"--executor",composed,
             "--packer",paths["namespace-db-join-r3-packer.py"]],
            cwd=context["reference"],timeout=180,env=environment)
        details["builder_process"]=builder
        build_path=evidence/"db-join-build-r1/summary.json";build=json.loads(build_path.read_bytes())
        details["build"]=build;details["build_pin"]=pin(build_path)
        assert build["status"]=="PASS_BUILD_ONLY" and build["source_pins_unchanged"]
        assert build["fresh_role_compiles"]==6
        assert build["packer_entries"]==len(build["packer_controls"])==EXPECTED_PACKER_CONTROLS
        assert all(row["exact_output_equal"] and row["source_unchanged"] and
            row["workspace_unchanged"] and row["guards"] and
            row["actual_return"]==row["expected_return"] for row in build["packer_controls"])
        assert set(build["exact_roles"])==set(build["generated_roles"])==set(build["compiled_roles"])==ROLES
        assert build["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert build["process_limits"]["wall_seconds"]==180
        assert builder["timeout_seconds"]==180 and not builder["timed_out"]
        for role,row in build["exact_roles"].items():
            receipt=row["compile_receipt"]
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==row["source"]["sha256"]
            assert receipt["produced_sha256"]==row["image"]["sha256"]
            assert receipt["produced_bytes"]==row["image"]["bytes"]
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        receipt=build["compile_receipt"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["produced_sha256"]==build["packer_image_sha256"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        comparison_process=common.run("six-role-packer-old-VM-new-VM-new-native-complete-differential",
            [context["python"],"-B",paths["namespace-packer-three-way-r1.py"],
             "--context",context_path,"--old-packer",paths["namespace-db-join-r2-packer.reference.py"],
             "--new-packer",paths["namespace-db-join-r3-packer.py"],"--executor",composed],
            cwd=context["reference"],timeout=180,env=environment)
        details["packer_differential_process"]=comparison_process
        comparison_path=evidence/"packer-differential-r1/summary.json"
        comparison=json.loads(comparison_path.read_bytes())
        details["packer_differential"]=comparison;details["packer_differential_pin"]=pin(comparison_path)
        assert comparison["status"]=="PASS" and comparison["cases"]==84
        assert comparison["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
        assert comparison["source_before_after_equal"] and comparison["no_masks"] and comparison["complete_buffers_equal"]
        assert comparison["old_profile_not_relaxed"] and comparison["old_native_compiles"]==0
        assert comparison["new_B3_compiles_in_this_process"]==comparison["actual_physical_syscalls"]==0
        assert comparison["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        assert comparison["limits"]==dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20)
        assert len(comparison["results"])==len({r["name"] for r in comparison["results"]})==84
        assert all(r["three_way_equal"] and r["workspace_unchanged"] for r in comparison["results"])
        physical_process=common.run("six-role-actual-physical-and-complete-original-trace-replay",
            [context["python"],"-B",paths["namespace-fs8-db-physical-r1.py"],
             "--context",context_path,"--client",paths["namespace-db-join-r1-client.py"],
             "--replay",paths["namespace-fs8-outer-replay.py"],
             "--inner-replay",paths["namespace-fs8-full-inner-replay.py"]],
            cwd=context["reference"],timeout=900,env=environment)
        details["physical_process"]=physical_process
        physical_path=evidence/"db-join-native-r1/summary.json"
        physical=json.loads(physical_path.read_bytes())
        details["physical"]=physical;details["physical_pin"]=pin(physical_path)
        assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
        tests=physical["tests"]
        assert tests["tests_loaded"]==tests["tests_run"]==len(tests["test_ids"])==EXPECTED_TESTS>0
        assert len(set(tests["test_ids"]))==EXPECTED_TESTS
        assert not any(tests[k] for k in
            ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert physical["native_entries"]==physical["vm_entries"]>0
        assert physical["actual_primitive_acks"]>0
        assert set(physical["entries_by_role"])==ROLES
        assert all(v>0 for v in physical["entries_by_role"].values())
        assert sum(physical["entries_by_role"].values())==physical["native_entries"]
        assert physical["all_actual_trace_processes_fully_replayed"]
        assert physical["process_traces"]==len(physical["replay"])==len(physical["process_limit_readbacks"])>0
        assert physical["actual_DB_retirements"]>0 and physical["actual_inner_retirements"]>0
        assert physical["abort_cleanup_pure_control_count"]==3
        assert len(physical["abort_cleanup_pure_controls"])==3
        for entry in physical["process_limit_readbacks"]:
            assert entry["actual"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
            assert entry["limits"]["wall_seconds"]==180 and entry["returncode"]==0
            assert os.WIFEXITED(entry["wait_status"]) and os.WEXITSTATUS(entry["wait_status"])==0
        for entry in physical["replay"]:
            assert entry["status"]=="PASS" and entry["no_masks"] and entry["no_inherited_counts"]
            assert entry["all_original_records_partitioned_exactly_once"]
            assert entry["all_input_output_workspace_return_bytes_equal"]
            assert entry["native_entries"]==entry["vm_entries"]>0
            assert entry["original_trace_before"]==entry["original_trace_after"]
            assert entry["no_OS_primitive_executed_by_replayer"]
        assert not any(physical[k] for k in
            ("ordinary_store_closed","full_sql31_closed","root_policy_closed",
             "unixOpen_and_findReusableFd_closed","migration_closed","python_router_used","counts_inherited"))
        details["execution_counts"]=dict(
            fresh_HIA_role_compiles=6,fresh_HIA_packer_compiles=1,
            direct_HIA_packer_controls=EXPECTED_PACKER_CONTROLS,
            packer_three_way_cases=84,packer_old_VM=84,packer_new_VM=84,packer_extra_native=84,
            physical_tests=tests["tests_run"],retained_physical_tests=18,new_global_reuse_tests=10,
            new_FS8_raw_primitive_tests=6,
            actual_fixed_processes=physical["process_traces"],
            target_native_entries=physical["native_entries"],full_trace_VM_entries=physical["vm_entries"],
            primitive_acks_including_memory=physical["actual_primitive_acks"],
            entries_by_role=physical["entries_by_role"],
            DB_context_retirements=physical["actual_DB_retirements"],
            inner_context_retirements=physical["actual_inner_retirements"],
            pure_abort_cleanup_controls=3,prior_counts_inherited=False)
        details["status"]="PASS";status="PASS"
    except BaseException as error:
        details.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        # Read and expose any genuine partial results before sealing. Never
        # invent zeros or PASS for a stage that did not complete.
        if evidence is not None:
            for name,relative in (
                ("build","db-join-build-r1/summary.json"),
                ("physical","db-join-native-r1/summary.json"),
                ("packer_differential","packer-differential-r1/summary.json")):
                path=evidence/relative
                if path.exists():
                    try:
                        raw=path.read_bytes()
                        details[name+"_original_report"]=json.loads(raw)
                        details[name+"_original_report_pin"]=pin(path)
                        observed=details[name+"_original_report"]
                        selected={key:observed[key] for key in (
                            "status","scope","error_class","error","traceback","tests",
                            "fresh_role_compiles","packer_entries","actual_carrier_processes","profile_frontiers",
                            "native_entries","vm_entries","entries_by_role","actual_primitive_acks",
                            "process_traces","actual_DB_retirements","actual_inner_retirements",
                            "source_pins_unchanged","all_actual_trace_processes_fully_replayed",
                            "counts","cases","cases_completed","source_before_after_equal")
                            if key in observed}
                        print("HIA_NAMESPACE_SIX_ROLE_ORIGINAL_"+name.upper()+" "+
                            json.dumps(dict(original_pin=details[name+"_original_report_pin"],
                                selected_original_fields=selected,
                                complete_original_bytes_preserved_in_artifact=True),sort_keys=True),flush=True)
                    except BaseException as read_error:
                        details[name+"_report_read_error"]=repr(read_error)
        details["input_pins"]=list(inputs.values())
        details["inputs_unchanged"]=bool(inputs) and all(equal(row) for row in inputs.values())
        details["working_source_before"]=working
        details["working_source_unchanged"]=bool(working) and all(equal(row) for row in working)
        if not details["inputs_unchanged"] or not details["working_source_unchanged"]:
            status="FAIL";details["status"]="FAIL"
        if evidence is not None:save(evidence/"summary.json",details)
        # OUTPUT already contains every raw output. The extra root contains
        # only immutable working source under BASE, never live fixture links.
        common.finish("NAMESPACE_SIX_ROLE_FS8_GATEWAY_GLOBAL_REUSE",status,details,
            roots={"six-role-working-source":context["namespace_working"]}
            if context and "namespace_working" in context else {})
        print(json.dumps(dict(status=status,scope=details["scope"],
            execution_counts=details["execution_counts"],whole_store_closed=False),sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
