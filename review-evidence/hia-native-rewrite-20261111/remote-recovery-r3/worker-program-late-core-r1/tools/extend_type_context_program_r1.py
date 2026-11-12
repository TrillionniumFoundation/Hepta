"""Preserve an actual lower-session type diagnostic through program admission.

The independent exact old driver must first reproduce the retained role46 HIA.
This authoring patch changes only the group2 nonempty error-view path.  It never
re-runs the source program or constructs error text in Python.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256
from tools.type_context_routes_common_r1 import (
 definitions,functions,expand,changed_inventory)

OLD_SOURCE_BYTES=161943
OLD_SOURCE_SHA="68c0ddba4e02d48ea1b205ff2f6e2ea65dbddb3aad0e35cfb19085960daf0816"
OLD_IMAGE_BYTES=221718
OLD_IMAGE_SHA="3b02302959d0f19503770db378360058ef81d354f856c256c4ce3d68b9731ba1"

BODY=r'''
def tcx_program_start(o:mutbuf, w:mutbuf) -> u64:
    if get(w, OBS + 32) != 2 or get(w, OBS + 144) != 40 or tcx_error(get(w, OBS + 40)) == 0:
        return refuse(w, 14100)
    target = get(w, M_CHILD_TARGET)
    extent = cap(w, target)
    if extent < 129 or extent > TC_MAX_EXTENT or cap(w, TC_SLOT) != 0:
        return refuse(w, 14101)
    if get(w, C_LEASE) > MAX - 2 or get(w, OBS + 16) != get(w, C_LEASE) + 2:
        return refuse(w, 14102)
    mirror_frame(w)
    put(w, TC_EXPECT_LEASE, get(w, OBS + 16))
    put(w, TC_EXPECT_ERROR, get(w, OBS + 40))
    put(w, TC_EXPECT_REQUEST, get(w, OBS + 48))
    put(w, TC_NEEDED, extent)
    return view(o, w, target, 0, 128, 820)

def tcx_program_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 820:
        if get(w, C_RETURN) != 0:
            return refuse(w, 14103)
        if tcx_header(w, OBS, get(w, TC_EXPECT_LEASE), get(w, TC_EXPECT_ERROR), get(w, TC_EXPECT_REQUEST), get(w, TC_NEEDED)) == 0:
            return refuse(w, 14104)
        tcx_copy(w, TC_PARENT_HEADER, OBS, 128)
        return grow(o, w, TC_SLOT, get(w, TC_NEEDED), 821)
    if phase == 821:
        return copy(o, w, get(w, M_CHILD_TARGET), 0, TC_SLOT, 0, get(w, TC_NEEDED), 822)
    if phase == 822:
        return protect(o, w, TC_SLOT, 1, 823)
    if phase == 823:
        return release(o, w, get(w, M_CHILD_TARGET), 824)
    if phase == 824:
        if cap(w, get(w, M_CHILD_TARGET)) != 0 or cap(w, TC_SLOT) != get(w, TC_NEEDED):
            return refuse(w, 14105)
        return finish(o, w, 2, get(w, TC_EXPECT_ERROR), get(w, TC_EXPECT_REQUEST))
    return refuse(w, 14106)
'''

def attach(base,constants,reader):
    shared,extra,rows=definitions(reader)
    assert not(set(extra)&set(constants))
    values=dict(constants);values.update(extra)
    old=functions(base);new=copy.deepcopy(old)
    step=new["program_step"]
    assert ast.unparse(step.body[0])==f'phase = get(w, {constants["C_PHASE"]})'
    step.body[1:1]=ast.parse(expand(
        "if phase >= 820 and phase < 825:\n    return tcx_program_step(o, w)",
        values)).body
    replaced=0
    class ChildError(ast.NodeTransformer):
        def visit_Return(self,node):
            nonlocal replaced
            if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=="child_error":
                assert ast.unparse(node)=="return child_error(o, w)"
                replaced+=1
                return ast.parse(expand(
                    "if get(w, OBS + 32) == 2 and cap(w, get(w, M_CHILD_TARGET)) != 0:\n"
                    "    return tcx_program_start(o, w)\n"
                    "return child_error(o, w)",values)).body
            return self.generic_visit(node)
    new["program_step"]=ChildError().visit(step)
    assert replaced==1,replaced
    child=new["child_result"]
    group=next(n for n in child.body if isinstance(n,ast.If) and ast.unparse(n.test)=="group != 0")
    branch=next(n for n in group.body if isinstance(n,ast.If) and ast.unparse(n.test)=="group == 8")
    assert len(branch.orelse)==1 and isinstance(branch.orelse[0],ast.If)
    tail=branch.orelse[0]
    assert ast.unparse(tail.test)=="extent != 0" and ast.unparse(tail.body[0])=="return 0"
    additions=ast.parse(expand(
        "if group == 2 and extent != 0:\n"
        "    if role != 40 or tcx_error(error) == 0 or extent < 129 or extent > TC_MAX_EXTENT:\n"
        "        return 0\n"
        "    put(w, CAPS + target * 8, extent)",values)).body[0]
    additions.orelse=branch.orelse
    branch.orelse=[additions]
    added=functions(expand(shared+"\n"+BODY,values))
    assert not(set(added)&set(new))
    result="\n\n".join(ast.unparse(n) for n in new.values())+"\n"+\
           "\n\n".join(ast.unparse(n) for n in added.values())+"\n"
    proof=changed_inventory(base,result,{"program_step","child_result"})
    proof.update(schema="hia-type-context-program-route-r1",
        retained_role=46,retained_HIA_bytes=OLD_SOURCE_BYTES,retained_HIA_sha256=OLD_SOURCE_SHA,
        retained_image_bytes=OLD_IMAGE_BYTES,retained_image_sha256=OLD_IMAGE_SHA,
        required_original_HIA_reproduction_before_extension=True,
        new_context_result_header_rebuilt=False,new_context_payload_rebuilt=False,
        complete_actual_reader_output_copied_verbatim=True,
        original_Core_group8_branch_AST_preserved_except_next_sibling=True,
        child_actual_role_required=40,type_errors=[1,5,6],
        expected_lower_lease_is_actual_program_lease_plus2=True,
        source_of_lease_rule="exact original run_child(lease=C_LEASE+1) and raw handoff +1",
        original_error_request_and_lower_digest_preserved=True,
        original_child_target_released_after_readonly_copy=True,
        output_slot57_retired_by_fixed_parent_transfer=True,
        arbitrary_external_context_authenticated=False,
        AST_generation_B3_native_executed_here=False)
    return result,proof
