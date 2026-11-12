"""Exact author-source proof for the complete original42 candidate.
No HIA document is generated, compiled or executed by this source check.
The original ten DMS9 controls must already have passed unchanged.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ast,hashlib,importlib.util,json,resource,signal,stat,time,traceback
from pathlib import Path
MANIFEST_SHA="42728496bc7117ea464433c85a64ddc0562663e75522949fa13e3f0d0b4105ab"
MANIFEST_GIT="a85ed388c8028c5f275dd365e86f584abe8447b3"
REFERENCE="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(10,10))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    started=time.monotonic_ns()
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("exact three-helper source proof wall30")))
    signal.alarm(30)
    ap=argparse.ArgumentParser();ap.add_argument("--directory",type=Path,required=True)
    ap.add_argument("--reference",type=Path,required=True);ap.add_argument("--dms-proof",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True);args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    pins={};rows=[];controls=[];report=dict(status="INCOMPLETE",HIA_document_calls=0,B3=0,VM=0,native=0)
    def pin(path,expected=None):
        path=Path(path).absolute();st=path.lstat()
        assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
        raw=path.read_bytes()
        row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),blob=git(raw),mode=stat.S_IMODE(st.st_mode))
        if expected:
            assert (row["bytes"],row["sha256"],row["blob"])==(expected["bytes"],expected["sha256"],expected["blob"])
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def module(name,path,expected):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value
        exec(compile(raw,str(path),"exec"),value.__dict__);return value
    def normalized(value):
        origins,bindings=value
        return dict(origins={name:{param:sorted(scopes) for param,scopes in ps.items()}
            for name,ps in origins.items()},bindings=[list(row) for row in bindings])
    try:
        pin(__file__)
        mraw=pin(args.directory/"exact-byte-source-proof.json")
        assert sha(mraw)==MANIFEST_SHA and git(mraw)==MANIFEST_GIT
        spec=json.loads(mraw);assert len(spec["roles"])==6
        original_proof=json.loads(pin(args.dms_proof))
        assert original_proof["status"]=="PASS_SOURCE_PROOF_ONLY" and original_proof["source_unchanged"]
        assert len(original_proof["controls"])==10
        assert original_proof["current_source_sha256"]=="95e13ccf13d9780c06e089773133479a44fd83e6d9fc9fe5f0a40820c7946e3e"
        assert original_proof["original_builder_class_byte_identical"] and original_proof["original_origin_propagation_byte_identical"]
        assert original_proof["one_literal_delta_reversed_byte_identically"] and original_proof["origin_bindings_equal"]
        assert all(original_proof[k]==0 for k in ("new_HIA_generation","new_B3_compiles","new_VM_entries","new_native_entries"))
        assert original_proof["actual_limits"]==dict(cpu=[10,10],address=[256<<20,256<<20],core=[0,0])
        report["original_ten_DMS9_proof_complete_before_transform"]=True
        sys.path.insert(0,str(args.reference.resolve()))
        dep={row["name"]:row for row in spec["original_dependencies"]}
        module("tools.generate_hia_agent_namespace_store",args.directory/"namespace-values-reference.py",dep["namespace-values-reference.py"])
        module("tools.generate_hia_agent_namespace_objects",args.directory/"namespace-objects-reference.py",dep["namespace-objects-reference.py"])
        guard=module("tools.hia_namespace_dms_fixed_header_builder",args.directory/"namespace-dms9-fixed-header-builder-r2.py",dep["namespace-dms9-fixed-header-builder-r2.py"])
        helper=module("tools.hia_namespace_exact_byte_helpers",args.directory/spec["transform"]["name"],spec["transform"])
        expected_helper_names=("read64","get","put")
        assert helper.NAMES==expected_helper_names
        for item in spec["roles"]:
            role=item["role"];left=item["original"];right=item["candidate"]
            old=pin(args.directory/left["name"],left).decode("utf-8")
            new=pin(args.directory/right["name"],right).decode("utf-8")
            old_text=item["old_text"];new_text=item["new_text"]
            assert old.count(old_text)==new.count(new_text)==1
            assert old.replace(old_text,new_text,1)==new
            assert new.replace(new_text,old_text,1)==old
            before=module("namespace_original42_author_"+str(role),args.directory/left["name"],left)
            after=module("namespace_candidate42_author_"+str(role),args.directory/right["name"],right)
            original=before.source_program();assert after.source_program()==original
            nodes=ast.parse(original).body
            if role==4:
                # The actual original guard validates the original source first.
                original_origins=normalized(guard.fixed_header_origins(original,nodes))
            transformed=helper.transform(original)
            assert transformed.replace(helper.NEW,helper.OLD,1)==original
            changed_nodes=ast.parse(transformed).body
            actual_changed=[a.name for a,b in zip(nodes,changed_nodes,strict=True)
                if ast.dump(a,include_attributes=False)!=ast.dump(b,include_attributes=False)]
            assert tuple(actual_changed)==expected_helper_names
            dms=None
            if role==4:
                # Only after the complete source inverse has been checked, run
                # the same origin dataflow over the new AST. The first argument
                # remains the already checked original source; this is a proof
                # comparison, not a relaxed digest gate in production.
                expanded_origins=normalized(guard.fixed_header_origins(original,changed_nodes))
                assert expanded_origins==original_origins
                try:guard.fixed_header_origins(transformed,changed_nodes)
                except ValueError as error:
                    assert str(error)=="DMS fixed-header proof requires the exact reviewed source"
                else:raise AssertionError("original DMS9 guard unexpectedly accepted expanded source")
                dms=dict(original_guard_before_transform=True,origins_bindings_exact=True,
                    direct_expanded_source_still_refused=True,
                    production_guard_source_unchanged=True)
                save(args.output/"original-DMS9-origins.json",original_origins)
            old_path=args.output/("role-"+str(role)+"-original.dsl.py")
            new_path=args.output/("role-"+str(role)+"-candidate.dsl.py")
            old_path.write_text(original);new_path.write_text(transformed)
            assert old_path.read_text()==original and new_path.read_text()==transformed
            rows.append(dict(role=role,original_author=left,candidate_author=right,
                original_DSL=dict(bytes=len(original.encode()),sha256=sha(original.encode())),
                candidate_DSL=dict(bytes=len(transformed.encode()),sha256=sha(transformed.encode())),
                changed_helper_names=actual_changed,all_other_HIA_functions_exact=True,
                exact_source_inverse=True,source_program_function_unmodified=True,
                function_names_order_and_signatures_exact=True,total_scalar_classification_exact=True,
                original_DMS9_proof=dms))
        assert [r["role"] for r in rows]==[1,2,3,4,5,6]
        builder=spec["builder"]
        old=pin(args.directory/builder["original"]["name"],builder["original"]).decode()
        new=pin(args.directory/builder["candidate"]["name"],builder["candidate"]).decode()
        restored=new
        for previous,current in reversed(builder["edits"]):
            assert restored.count(current)==1
            restored=restored.replace(current,previous,1)
        assert restored==old
        raw=before.source_program()
        mutations=[
            ("not_string",b"bytes"),("missing_helpers",raw.replace(helper.OLD,"",1)),
            ("duplicate_helpers",raw+helper.OLD),("already_expanded",helper.transform(raw)),
            ("extra_nonfunction",raw+"\nUNRELATED=0\n"),
            ("duplicate_function_name",raw+"\ndef read64(s:readbuf, index:u64) -> u64:\n    return 0\n"),
            ("changed_loop_bound",raw.replace(helper.OLD,helper.OLD.replace("while i < 8:","while i < 7:",1),1)),
            ("changed_helper_signature",raw.replace("def put(w:mutbuf, index:u64, value:u64) -> u64:",
                "def put(w:mutbuf, index:u64, value:u32) -> u64:",1))]
        for name,changed in mutations:
            assert changed!=raw
            try:helper.transform(changed)
            except ValueError as error:controls.append(dict(name=name,refused=True,error=str(error)))
            else:raise AssertionError(("source transform accepted altered input",name))
        assert len(controls)==8
        report.update(status="PASS_SOURCE_PROOF_ONLY",roles=rows,negative_source_controls=controls,
            exact_candidate_builder_only_six_author_pins_and_helper_dependency=True,
            unchanged_original_42_suite_and_VM_replayers=True,no_all_VM_fuel_equivalence_claim=True,
            actual_42_results_inherited=False)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc(),
            roles=rows,negative_source_controls=controls)
        traceback.print_exc()
    finally:
        # Pin all exact reference code used by scalar classification, before
        # verifying that both original and candidate source files stayed fixed.
        for value in tuple(sys.modules.values()):
            name=getattr(value,"__file__",None)
            if name:
                path=Path(name).resolve()
                if path.is_relative_to(args.reference.resolve()) and path.suffix==".py":
                    try:pin(path)
                    except BaseException as error:
                        report.setdefault("after_errors",[]).append(dict(path=str(path),error=repr(error)))
        after={};errors=report.setdefault("after_errors",[])
        for path,before in pins.items():
            try:
                p=Path(path);st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink()
                raw=p.read_bytes()
                after[path]=dict(path=path,bytes=len(raw),sha256=sha(raw),blob=git(raw),mode=stat.S_IMODE(st.st_mode))
                assert after[path]==before
            except BaseException as error:errors.append(dict(path=path,error=repr(error)))
        elapsed=time.monotonic_ns()-started
        if not 0<=elapsed<30_000_000_000:errors.append(dict(scope="source-proof-wall30",elapsed_ns=elapsed))
        report.update(source_before=pins,source_after=after,source_unchanged=bool(pins) and pins==after,
            elapsed_ns=elapsed,actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        if errors or not report["source_unchanged"]:report["status"]="FAIL"
        save(args.output/"summary.json",report);signal.alarm(0)
        print("NAMESPACE_ISSUED42_EXACT_BYTE_SOURCE "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_SOURCE_PROOF_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
