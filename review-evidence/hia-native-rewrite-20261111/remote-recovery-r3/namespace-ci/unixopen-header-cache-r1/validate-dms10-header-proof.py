"""Exact DMS10 proof transfer; pure source controls, zero HIA execution."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ast,hashlib,json,resource,signal,stat,traceback
from pathlib import Path
PINS=json.loads("[{\"name\":\"generate_hia_agent_namespace_store.py\",\"blob\":\"3d45466a68eca7a88d2352879ea1979848318f63\",\"bytes\":11623,\"sha256\":\"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50\"},{\"name\":\"original-dms8-header-proof.py\",\"blob\":\"837e09e975db0215d0572cf23d5d129aaf43dfad\",\"bytes\":5082,\"sha256\":\"c4b4835cc21258ee0fa1a678dfe8e4e8911927568da6b39e9aa2a9e0fa10e619\"},{\"name\":\"namespace-dms-map-r10.py\",\"blob\":\"d44bc02375b6b8be297569638219013236e4b426\",\"bytes\":76176,\"sha256\":\"7198fd77427b45fc5de80b06290de5cbd524bb9752ef9509241fd3095a4a1c33\"},{\"name\":\"original-dms8.py\",\"blob\":\"9ba36ef7fe77ce697a78720e4d7d0039116c386c\",\"bytes\":72876,\"sha256\":\"4063dfbcd35c7b3c3b3b4a8baaf6037e1f32e9c133afdd12ca35cd6638ace1d8\"},{\"name\":\"namespace-dms10-header-proof.py\",\"blob\":\"6bbf64463f93e1e010f2e975a2de047fd883a4d6\",\"bytes\":5811,\"sha256\":\"686d3e61ebb09a164bbe2af2ed2c9298700c124d706dffe8fcff64869a45c82a\"}]")
ORIGINAL="7fe09da5b8d59c14d1b5cd6fbc65b4c937677e410356d843a74affc62770d310"
CURRENT="be06bdfccb352998a53eb09f572f0f77fc00c6bc76d98060537d85442cd9491e"
OLD_TERM="dms_read(s, 64) > 24"
NEW_TERM="dms_read(s, 64) > 31"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    raw=path.read_bytes()
    return raw,dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(st.st_mode),
        git_blob_sha1=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def assignment(raw,name):
    found=[node for node in ast.parse(raw).body if isinstance(node,ast.Assign) and
        any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
    assert len(found)==1,name
    return ast.literal_eval(found[0].value)
def expand(raw,values):
    source=assignment(raw,"DMS")
    for name,word in (("DMS_MAGIC",b"HIANDM03"),("DMS_BAD",b"HIANDMB3"),("DMS_CHANNEL",b"HIANDX03"),
        ("FS_MAGIC",b"HIANFR03"),("DEV_NULL_WORD",b"/dev/nul"),("JOIN_MAP_MAGIC",b"HIASMP01"),
        ("JOIN_MAP_CHANNEL",b"HIASMX01"),("JOIN_MEM_MAGIC",b"HIANML01"),("JOIN_MEM_CHANNEL",b"HIANMX01")):
        source=source.replace(name,str(int.from_bytes(word,"little")))
    source+=values[values.index("\ndef read64("):]
    return source
def guard(raw,label):
    tree=ast.parse(raw,filename=label)
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="fixed_header_origins"]
    assert len(functions)==1
    namespace=dict(ast=ast,hashlib=hashlib,SOURCE_SHA256=assignment(raw,"SOURCE_SHA256"))
    if b"ORIGINAL_SOURCE_SHA256=" in raw:
        namespace["ORIGINAL_SOURCE_SHA256"]=assignment(raw,"ORIGINAL_SOURCE_SHA256")
    # Execute the exact guard function AST, with its actual constants and stdlib
    # globals. No Builder class, HIA generator, VM or image is called here.
    exec(compile(ast.Module(body=functions,type_ignores=[]),label,"exec"),namespace)
    return namespace
def normalized(value):
    origins,bindings=value
    return dict(origins={name:{key:sorted(scope) for key,scope in buffers.items()}
        for name,buffers in origins.items()},bindings=[list(row) for row in bindings])
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(10,10))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("source proof wall30")))
    signal.alarm(30)
    p=argparse.ArgumentParser();p.add_argument("--directory",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    before={};texts={};controls=[];status="FAIL";report={}
    try:
        for row in PINS:
            path=args.directory/row["name"];raw,actual=pin(path)
            assert actual["bytes"]==row["bytes"] and actual["sha256"]==row["sha256"]
            assert actual["git_blob_sha1"]==row["blob"]
            before[str(path.absolute())]=actual;texts[row["name"]]=raw
        values=assignment(texts["generate_hia_agent_namespace_store.py"],"VALUES")
        old=expand(texts["original-dms8.py"],values)
        new=expand(texts["namespace-dms-map-r10.py"],values)
        assert len(old.encode())==len(new.encode())==70707
        assert sha(old.encode())==ORIGINAL and sha(new.encode())==CURRENT
        assert new.count(NEW_TERM)==1 and new.count(OLD_TERM)==0
        assert new.replace(NEW_TERM,OLD_TERM,1)==old
        original_helper=texts["original-dms8-header-proof.py"]
        current_helper=texts["namespace-dms10-header-proof.py"]
        marker=b"class FixedHeaderBuilder"
        assert original_helper.count(marker)==current_helper.count(marker)==1
        assert original_helper.split(marker,1)[1]==current_helper.split(marker,1)[1]
        bodymark=b"    if not nodes or nodes[0].name!='dms_entry':"
        assert original_helper.split(bodymark,1)[1]==current_helper.split(bodymark,1)[1]
        left=guard(original_helper,"original-proof.py")
        right=guard(current_helper,"current-proof.py")
        before_origins=normalized(left["fixed_header_origins"](old,ast.parse(old).body))
        after_origins=normalized(right["fixed_header_origins"](new,ast.parse(new).body))
        assert before_origins==after_origins
        controls.append(dict(name="original_DMS8_accept",accepted=True))
        controls.append(dict(name="current_DMS10_accept_identical_origins_bindings",accepted=True))
        def reject(name,namespace,source,expected):
            try:namespace["fixed_header_origins"](source,ast.parse(source).body)
            except ValueError as error:
                assert str(error)==expected,(name,str(error),expected)
                controls.append(dict(name=name,accepted=False,error_class="ValueError",error=str(error),
                    source_sha256=sha(source.encode())))
            else:raise AssertionError((name,"unexpected accepted source"))
        digest_error="DMS fixed-header proof requires the exact reviewed source"
        reject("original_guard_reproduces_DMS10_failure",left,new,digest_error)
        reject("current_guard_rejects_DMS8",right,old,digest_error)
        mutations=[
            ("workspace_guard",new.replace("length(w) < 8192","length(w) < 8191",1)),
            ("input_guard",new.replace("length(s) < 320","length(s) < 319",1)),
            ("extra_source_byte",new+"\n"),
            ("gateway_bound32",new.replace(NEW_TERM,"dms_read(s, 64) > 32",1))]
        for name,changed in mutations:
            assert changed!=new
            reject(name,right,changed,digest_error)
        forged=dict(right)
        # Recompile the same exact function in independent globals: this
        # explicit test fault changes only the expected current source hash.
        # Production constants and original files are not modified.
        changed=mutations[0][1]
        forged=guard(current_helper,"fault-control-proof.py")
        forged["SOURCE_SHA256"]=sha(changed.encode())
        reject("matching_forged_current_digest_still_rejects_changed_old_guard",forged,changed,
            "DMS10 proof requires byte-identical original guard and reader bodies")
        changed=mutations[3][1]
        forged=guard(current_helper,"fault-control-bound.py")
        forged["SOURCE_SHA256"]=sha(changed.encode())
        reject("matching_forged_current_digest_still_rejects_changed_delta",forged,changed,
            "DMS10 proof requires the single gateway-bound delta")
        assert len(controls)==10
        save(args.output/"exact-origin-bindings.json",after_origins)
        (args.output/"original-DMS8.dsl.py").write_text(old)
        (args.output/"current-DMS10.dsl.py").write_text(new)
        report.update(status="PASS_SOURCE_PROOF_ONLY",controls=controls,
            source_bytes=70707,original_source_sha256=ORIGINAL,current_source_sha256=CURRENT,
            original_builder_class_byte_identical=True,original_origin_propagation_byte_identical=True,
            one_literal_delta_reversed_byte_identically=True,
            origin_bindings_equal=True)
        status="PASS_SOURCE_PROOF_ONLY"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc(),controls=controls)
        traceback.print_exc()
    finally:
        after={}
        for name in before:
            try:after[name]=pin(Path(name))[1]
            except BaseException as error:after[name]=dict(error_class=type(error).__name__,error=str(error))
        report.update(source_before=before,source_after=after,source_unchanged=before==after,
            actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
                address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))),
            new_HIA_generation=0,new_B3_compiles=0,new_VM_entries=0,new_native_entries=0)
        if before!=after or not before:status="FAIL";report["status"]="FAIL"
        save(args.output/"summary.json",report);signal.alarm(0)
        print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if status=="PASS_SOURCE_PROOF_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
