"""Actual native proof-port faults for the two original host-mock NDU cases.

The final rank engine is unchanged. A small, explicit QA-only ELF supplies captured
proof records at its real process effect port. It is never admitted by the default
immutable proof context or packaged as a product. The complete original rank
reference/check functions compare all fields and key order using actual clocks.
"""
from pathlib import Path
import argparse,ast,copy,hashlib,importlib.util,json,os,struct,subprocess,sys,time

def digest(raw):return hashlib.sha256(raw).hexdigest()

ASSEMBLY=r"""
.intel_syntax noprefix
.global _start
.section .text
_start:
    mov eax,257
    mov rdi,-100
    lea rsi,[rip+counter_path]
    mov edx,2
    xor r10d,r10d
    syscall
    test rax,rax
    js failed
    mov rbx,rax
    mov eax,17
    mov rdi,rbx
    lea rsi,[rip+counter]
    mov edx,8
    xor r10d,r10d
    syscall
    cmp rax,8
    jne failed
    mov r13,[rip+counter]
    cmp r13,2
    jae failed
    inc QWORD PTR [rip+counter]
    mov eax,18
    mov rdi,rbx
    lea rsi,[rip+counter]
    mov edx,8
    xor r10d,r10d
    syscall
    cmp rax,8
    jne failed
    xor r12d,r12d
input_more:
    cmp r12,1048576
    jae failed
    xor eax,eax
    xor edi,edi
    lea rsi,[rip+input]
    add rsi,r12
    mov edx,1048576
    sub rdx,r12
    syscall
    cmp rax,-11
    je input_more
    cmp rax,-4
    je input_more
    test rax,rax
    js failed
    jz input_done
    add r12,rax
    jmp input_more
input_done:
    cmp r12,64
    jb failed
    mov rax,0x313052504e414948
    cmp [rip+input],rax
    jne failed
    mov [rip+length],r12
    mov eax,257
    mov rdi,-100
    lea rsi,[rip+log_path]
    mov edx,1025
    xor r10d,r10d
    syscall
    test rax,rax
    js failed
    mov rbp,rax
    mov eax,1
    mov rdi,rbp
    lea rsi,[rip+length]
    mov edx,8
    syscall
    cmp rax,8
    jne failed
    mov rdi,rbp
    lea r14,[rip+input]
    mov r15,r12
    call write_all
    test r13,r13
    jnz second
    lea r14,[rip+reply0]
    mov r15,reply0_end-reply0
    jmp reply
second:
    lea r14,[rip+reply1]
    mov r15,reply1_end-reply1
reply:
    mov edi,1
    call write_all
    mov eax,3
    mov rdi,rbp
    syscall
    mov eax,3
    mov rdi,rbx
    syscall
    mov eax,60
    xor edi,edi
    syscall
    ud2
write_all:
    test r15,r15
    jz write_done
write_more:
    mov eax,1
    mov rsi,r14
    mov rdx,r15
    syscall
    cmp rax,-11
    je write_more
    cmp rax,-4
    je write_more
    test rax,rax
    jle failed
    add r14,rax
    sub r15,rax
    jnz write_more
write_done:
    ret
failed:
    mov eax,60
    mov edi,66
    syscall
    ud2
.section .rodata
counter_path:
    .asciz "COUNTER_PATH"
log_path:
    .asciz "LOG_PATH"
reply0:
    .incbin "REPLY0"
reply0_end:
reply1:
    .incbin "REPLY1"
reply1_end:
.section .bss
.align 8
counter:.skip 8
length:.skip 8
input:.skip 1048576
.section .note.GNU-stack,"",@progbits
"""

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--original-gates",type=Path,required=True)
    parser.add_argument("--default-report",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    a=parser.parse_args();S,G,D=a.source,a.original_gates,a.output
    D.mkdir(mode=0o700);sys.path.insert(0,str(S));sys.dont_write_bytecode=True
    captured={}
    def take(p):
        raw=p.read_bytes()
        if p in captured:assert captured[p]==raw
        captured[p]=raw;return raw
    for name,pin in json.loads(take(S/"docs/HIA_NATIVE_NDU_RANK_BUILD.json"))["source_files"].items():
        assert digest(take(S/name))==pin
    for name in("hepta/hia_ndu_optimizer.py","hepta/hia_ndu_rank_native.py","hepta/hia_ndu_native_policy.py","tests/test_hia_ndu_optimizer.py"):
        take(S/name)
    take(Path(__file__))
    gates=json.loads(take(G/"terminal.json"))
    assert gates["passed"]is True and gates["original_order"]["count"]==44
    original_raw=take(G/"original-order.py").decode()
    actual=take(G/"current-order-controls.py").decode()
    stop=actual.index("\n\n# Complete products")
    prefix=actual[:stop]
    marker="D=T/'order-controls'"
    assert prefix.count(marker)==1
    prefix=prefix.replace(marker,"D=Path("+repr(str(D/"records"))+")")
    # Only the initial physical source/qualification destinations change.
    old=str(G.parents[1]/"rank-release-current-source-v4")
    prefix=prefix.replace("P=Path("+repr(old)+")","P=Path("+repr(str(S))+")")
    def functions(raw):
        return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body
                if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    assert functions(prefix)==functions(original_raw)
    (D/"original-complete-check-functions.py").write_text(prefix)
    p=G/"original-optimizer-034.py";take(p)
    spec=importlib.util.spec_from_file_location("hepta._ndu_rank_fixed_original",p)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    scope={"__name__":"ndu_original_native_fault_control","__file__":str(D/"original-complete-check-functions.py")}
    exec(compile(prefix,scope["__file__"],"exec"),scope)
    os.environ["HEPTA_NDU_BRIDGE"]=str(S/"hepta/_hia_ndu_evaluator.elf")
    bridge_fixture=D/"bridge";bridge_fixture.mkdir()
    leaf_receipt=take(S/"hepta/_hia_ndu_evaluator_build.json")
    (bridge_fixture/"build-receipt.json").write_bytes(leaf_receipt)
    take(S/"hepta/_hia_ndu_evaluator.elf")
    os.environ["HEPTA_NDU_BUILD"]=str(bridge_fixture)
    import tests.test_hia_ndu_optimizer as tests
    from hepta.hia_ndu_rank_native import _baseline_bytes
    case=tests.NativeProofGatedRankingTests("test_real_ndu_selects_only_a_freshly_proved_candidate")
    case.setUp()
    args={"candidates":case.candidates,"observations":case.observations,"function":"calculate",
          "bridge":case.bridge,"objective":case.objective,"generation":1,
          "timeout_ms":2000,"bridge_timeout_s":10.0}
    assert args["objective"]["resource_cap_ns"]==5_000_000_000
    rawbase=_baseline_bytes(case.baseline)
    previous=json.loads(take(a.default_report/"actual-rank-returns.json"))
    candidates=[v for v in previous["calls"]if v["method"].startswith("test_real_ndu_selects_only_a_freshly_proved_candidate ")and v["return_kind"]=="result"]
    assert len(candidates)==1
    positive=candidates[0]["value"]
    assert positive["admitted"]is True and positive["selected_id"]=="cancel"
    good=copy.deepcopy(positive["candidate_reports"][0]["proof"])
    assert good["status"]=="proved"and good["scope"]=="selected_public_scalar_function"
    # The real engine normalizes the input before invoking the proof process.
    # Bind the captured proof to both exact canonical subjects, not raw JSON order.
    verified_before=scope["verify_program"](rawbase)
    verified_after=scope["verify_program"](case.candidates[0]["program"])
    assert good["before_request_input_sha256"]==digest(verified_before.canonical_bytes)
    assert good["after_request_input_sha256"]==digest(verified_after.canonical_bytes)
    assert good["before_sha256"]==verified_before.sha256
    assert good["after_sha256"]==verified_after.sha256
    unknown=copy.deepcopy(good);unknown.update(status="unknown",reason="simulated_solver_unavailable")
    wrong=copy.deepcopy(good);wrong["scope"]="some_other_scope"
    # The real owner marks every undeclared descriptor close-on-exec.
    # QA-only process observations therefore use private owned files opened
    # by the actual provider; no product descriptor rule is changed.
    counter=D/"counter.bin";counter.write_bytes(bytes(8));counter.chmod(0o600)
    log=D/"requests.bin";log.write_bytes(b"");log.chmod(0o600)
    rows=[];started=time.monotonic()
    try:
        for label,replies,want_calls in(
                ("positive-real-effect-port",(good,good),2),
                ("fresh-selected-unknown",(good,unknown),2),
                ("wrong-proof-scope",(wrong,wrong),1)):
            folder=D/label;folder.mkdir()
            for i,value in enumerate(replies):
                body=json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
                frame=struct.pack("<8s7Q",b"HIAMVR01",2,0,len(body),0,0,0,0)+body
                (folder/("reply"+str(i)+".bin")).write_bytes(frame)
            asm=(ASSEMBLY.replace("REPLY0",str(folder/"reply0.bin")).replace("REPLY1",str(folder/"reply1.bin"))
                 .replace("COUNTER_PATH",str(counter)).replace("LOG_PATH",str(log)))
            (folder/"provider.S").write_text(asm)
            for argv in(
                    ["/usr/bin/as","--64",str(folder/"provider.S"),"-o",str(folder/"provider.o")],
                    ["/usr/bin/ld","-z","noexecstack","-o",str(folder/"provider"),str(folder/"provider.o")]):
                run=subprocess.run(argv,capture_output=True,timeout=30)
                if run.returncode:raise RuntimeError(run.stderr.decode())
            provider=(folder/"provider").read_bytes()
            os.close(scope["proof"]);scope["proof"]=scope["sealed"](provider)
            counter.write_bytes(bytes(8));log.write_bytes(b"")
            # check() is the full unchanged original all-field/order oracle.
            scope["check"](label,copy.deepcopy(args),rawbase=rawbase)
            result=json.loads((D/"records"/(label+".actual.json")).read_bytes())
            calls=struct.unpack("<Q",counter.read_bytes())[0]
            assert calls==want_calls,(label,calls,want_calls)
            raw=log.read_bytes();at=0;frames=[]
            while at<len(raw):
                assert len(raw)-at>=8
                n=struct.unpack_from("<Q",raw,at)[0];at+=8
                frame=raw[at:at+n];assert len(frame)==n and frame[:8]==b"HIANPR01";at+=n
                frames.append({"bytes":n,"sha256":digest(frame)})
            assert len(frames)==calls
            (folder/"requests.bin").write_bytes(raw)
            if label=="positive-real-effect-port":
                assert result["admitted"]is True and result["selected_id"]=="cancel"
            elif label=="fresh-selected-unknown":
                # These are every observable assertion of the original mock case.
                assert calls==2
                assert result["native_response"]["advisory_recommendation"]=="cancel"
                assert result["admitted"]is False
                assert result["reason"]=="selected_candidate_fresh_proof_failed"
            else:
                assert result["admitted"]is False
                assert result["candidate_reports"][0]["proof"]["scope"]=="some_other_scope"
                assert result["selected_fresh_proof"]is None
            rows.append({"case":label,"passed":True,"proof_process_calls":calls,
                         "request_frames":frames,"provider":{"bytes":len(provider),"sha256":digest(provider)},
                         "all_original_rank_fields_and_order_equal":True,
                         "result_sha256":digest((D/"records"/(label+".actual.json")).read_bytes())})
        assert all(p.read_bytes()==raw for p,raw in captured.items())
        report={"schema":"hepta.hia.ndu-real-proof-port-faults.v1","passed":True,
                "count":len(rows),"cases":rows,"source_unchanged":True,
                "original_full_check_functions_unchanged":True,"original_timeout_ms":2000,
                "original_rank_budget_ns":5_000_000_000,
                "qa_provider_is_default_admitted":False,"whole_installed_release":False,
                "scope":"actual native engine plus real child proof-port faults; context authority is independently tested and not bypassed in product",
                "inputs":{str(p):{"bytes":len(raw),"sha256":digest(raw)}for p,raw in captured.items()},
                "elapsed_s":time.monotonic()-started}
        (D/"report.json").write_text(json.dumps(report,indent=2)+"\n");print(json.dumps({k:v for k,v in report.items()if k!="inputs"}),flush=True)
    finally:
        for fd in(scope["normal"],scope["proof"],scope["source_root"]):
            try:os.close(fd)
            except OSError:pass
    return 0

if __name__=="__main__":raise SystemExit(main())
