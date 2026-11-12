"""Assembly-specific service table one gates over the frozen finite carrier.
Only table one's two-read mask and the allowed caller of its new semantic roles
change. Service table two and the entire bounded program/ordinary child graph
retain their original instruction text. This module does not parse HIA payloads.
"""
from hashlib import sha256
from pathlib import Path
import json
FINITE_SHA="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
def one(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
def section(text,start,end):
    begin=text.index(start);finish=text.index(end,begin+len(start))
    return text[begin:finish]
def compose(source,finite_source):
    original=bytes(source);finite=bytes(finite_source)
    assert sha256(finite).hexdigest()==FINITE_SHA
    text=original.decode("ascii");reference=finite.decode("ascii")
    begin=".equ svc_ROLE,2048\n"
    assert text[text.index(begin):]==reference[reference.index(begin):]
    identity="""    cmp rax,60
    jne svc_service_component_identity_checked
    cmp qword ptr [r15+svc_ROLE],56
    jne svc_abi_error
svc_service_component_identity_checked:
"""
    replacement="""    cmp rax,60
    jne svc_assembly_component_identity
    cmp qword ptr [r15+svc_ROLE],56
    jne svc_abi_error
    jmp svc_service_component_identity_checked
svc_assembly_component_identity:
    cmp rax,61
    jb svc_service_component_identity_checked
    cmp rax,63
    ja svc_service_component_identity_checked
    cmp qword ptr [r15+svc_ROLE],59
    jne svc_abi_error
svc_service_component_identity_checked:
"""
    text=one(text,identity,replacement)
    mask="""    bts rax,60
svc_service_mask_ready:
"""
    text=one(text,mask,"""    bts rax,60
    btr rax,63
svc_service_mask_ready:
""")
    assert text.replace(replacement,identity,1).replace(
        "    bts rax,60\n    btr rax,63\nsvc_service_mask_ready:\n",mask,1)==original.decode("ascii")
    # Complete exact mechanical closures, not a scan of only the A root's
    # direct invoke constants. All ROLE writes and transitions remain fixed.
    for start,end in (
        ("svc_controller_entry:\n","svc_op_call:\n"),
        ("svc_op_switch:\n","svc_op_create:\n"),
        ("svc_op_run_child:\n","svc_child_complete:\n"),
        ("svc_child_complete:\n","svc_range_view:\n")):
        assert section(text,start,end)==section(reference,start,end),(start,end)
    # Every nested non-edit component call is bounded to 1..28 or exactly 55.
    assert """    cmp qword ptr [r15+svc_KIND],2
    je svc_component_edit_roles
    cmp rax,55
    je svc_component_role_checked
    cmp rax,28
    ja svc_abi_error
""" in text
    # This is the unmodified finite graph. There is no arbitrary recursion.
    assert """    mov qword ptr [r10+svc_KIND],0
    mov qword ptr [r10+svc_PUB_ROLE],45
""" in text
    assert """    mov qword ptr [r10+svc_KIND],1
    mov qword ptr [r10+svc_PUB_ROLE],46
""" in text
    assert """    cmp rcx,2
    ja svc_abi_error
    mov [r10+svc_DEPTH],rcx
""" in text
    assert ".equ svc_TWO_READ_MASK,0xe0bf80bee2ac0462\n" in text
    report=dict(schema="hia-assembly-service-carrier-scope-v1",status="SOURCE_COMPOSED_ONLY",
        source_bytes=len(original),source_sha256=sha256(original).hexdigest(),
        finite_bytes=len(finite),finite_sha256=FINITE_SHA,
        output_bytes=len(text.encode("ascii")),output_sha256=sha256(text.encode("ascii")).hexdigest(),
        parent_metadata_and_publication_carrier_unchanged=True,
        service_two_original_component_mask="e0bf80bee2ac0462",
        service_one_component_mask="70bf80bee2ac0462",
        service_one_special_roles={"60":[56],"61":[59],"62":[59],"63":[59]},
        whole_program_and_ordinary_child_instruction_ranges_equal=True,
        descendant_components=list(range(1,29))+[55],
        descendant_controllers={"program":[44,46],"ordinary":[40,41,42,43,44,45]},
        new_roles_cannot_be_called_by_program_or_ordinary_context=True,
        E_actual_image_table_requires_separate_byte_identity_check=True,
        native_executions=0)
    return text.encode("ascii"),report
if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument("--source",required=True,type=Path)
    ap.add_argument("--finite",required=True,type=Path);ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args();raw=a.source.read_bytes();finite=a.finite.read_bytes()
    out,report=compose(raw,finite);a.out.write_bytes(out)
    assert a.source.read_bytes()==raw and a.finite.read_bytes()==finite and a.out.read_bytes()==out
    a.out.with_suffix(".scope.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
