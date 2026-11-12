"""P16 native rendering for the actual final Core snapshot/byte refusal.

This is a separate unexecuted extension.  It changes only the parent
prefix_failure dispatch after the existing actual child frame validation.
No lower visitor, source lease, output spool, admission order, executor mask,
program receipt, original public oracle or resource limit changes.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path

REFERENCE_SHA="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
SOURCE_EXPECTED={
    1:("_bounded_detached_snapshot","caller-owned tree exceeds snapshot budget"),
    2:("_bounded_detached_snapshot","caller-owned tree exceeds queued-node budget"),
    3:("_structure","program exceeds byte budget before encoding"),
}
BODY=r'''
def worker_late_core_start(w:mutbuf) -> u64:
    error = get(w, E_ERROR_CODE)
    if get(w, E_ERROR_GROUP) != 6 or error < 1 or error > 3:
        return refuse(w, 14300)
    if get(w, C_LEASE) == 0 or get(w, C_LEASE) > MAX - 3 or get(w, C_SEQUENCE) == 0:
        return refuse(w, 14301)
    if get(w, C_RETURN) != 128 or get(w, E_CHILD_EVENT) != EVENT_MAGIC or get(w, E_CHILD_EVENT + 8) != 7:
        return refuse(w, 14302)
    if get(w, E_CHILD_EVENT + 16) != get(w, C_LEASE) + 2 or get(w, E_CHILD_EVENT + 24) == 0:
        return refuse(w, 14303)
    if get(w, E_CHILD_EVENT + 32) != 6 or get(w, E_CHILD_EVENT + 40) != error:
        return refuse(w, 14304)
    if get(w, OBS + 128) != 0 or get(w, OBS + 136) != B_PROGRAM_FRAME or get(w, OBS + 144) != 46 or get(w, OBS + 152) != 0:
        return refuse(w, 14305)
    if get(w, E_ERROR_BYTES) != 0 or cap(w, B_PROGRAM_FRAME) != 0:
        return refuse(w, 14306)
    if cap(w, WD_OUTPUT) != 0 or cap(w, WD_WORK) != 0 or get(w, WD_ACTIVE) != 0:
        return refuse(w, 14307)
    if get(w, WP_RESULT_KIND) != 0 or get(w, WP_HAS_RECEIPT) != 0:
        return refuse(w, 14308)
    if get(w, E_CHILD_EVENT + 88) == 0:
        return refuse(w, 14309)
    if error == 3 and get(w, E_CHILD_EVENT + 88) <= 8388608:
        return refuse(w, 14310)
    size = worker_late_core_text(w, error)
    if size == 0 or size > 128:
        return refuse(w, 14311)
    return worker_result_begin(w, 4, 1, 0, 0, B_CONTROLLER, PREFIX_TEXT, size)
'''

def exact_messages(reference):
    path=Path(reference)/"hepta"/"hia_program.py"
    raw=path.read_bytes()
    assert len(raw)==45247 and sha256(raw).hexdigest()==REFERENCE_SHA
    definitions={node.name:node for node in ast.parse(raw,filename=str(path)).body
                 if isinstance(node,ast.FunctionDef)}
    result=[]
    for status,(function,wanted) in sorted(SOURCE_EXPECTED.items()):
        matches=[]
        for node in ast.walk(definitions[function]):
            if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                    and node.func.id=="_reject" and len(node.args)==2
                    and all(isinstance(x,ast.Constant) and type(x.value) is str for x in node.args)
                    and node.args[0].value==wanted):
                matches.append(node)
        assert len(matches)==1,(function,wanted,len(matches))
        message,code=(node.value for node in matches[0].args)
        assert code=="E_HIA_LIMIT"
        payload=(code+": "+message).encode("ascii")
        assert 0<len(payload)<=128
        result.append(dict(status=status,code=code,message=message,text=payload.decode("ascii"),
                           bytes=len(payload),reference_function=function,
                           reference_line=matches[0].lineno))
    assert path.read_bytes()==raw
    return result,dict(path=str(path),bytes=len(raw),sha256=REFERENCE_SHA)

def literal_source(rows):
    lines=["def worker_late_core_text(w:mutbuf, error:u64) -> u64:"]
    for row in rows:
        raw=row["text"].encode("ascii")
        lines.append("    if error == "+str(row["status"])+":")
        for at in range(0,len(raw),8):
            chunk=raw[at:at+8]
            if len(chunk)==8:
                lines.append("        put(w, PREFIX_TEXT + "+str(at)+", "+str(int.from_bytes(chunk,"little"))+")")
            else:
                for offset,value in enumerate(chunk):
                    lines.append("        store(w, PREFIX_TEXT + "+str(at+offset)+", "+str(value)+")")
        lines.append("        return "+str(len(raw)))
    lines.append("    return 0")
    return "\n".join(lines)+"\n"

def attach(generator,reference):
    original={name:ast.dump(node,include_attributes=False)
              for name,node in generator.working.items()}
    assembly_before=generator.expanded("assembly_service")[0]
    constants=dict(generator.CONSTANTS)
    assert constants["PREFIX_TEXT"]==17344
    assert constants["PREFIX_TEXT"]+128<constants["A_HEAD"]
    assert constants["WD_OUTPUT"]==47 and constants["WD_WORK"]==48
    assert "worker_fixed_diagnostic_start" in original
    rows,pin=exact_messages(reference)
    added=generator.functions(BODY+"\n"+literal_source(rows))
    assert set(added)=={"worker_late_core_start","worker_late_core_text"}
    assert not(set(added)&set(original))
    if "WC_ACTIVE" in constants:
        node=added["worker_late_core_start"]
        assert isinstance(node.body[-1],ast.Return)
        # A distinct context capsule can never be active on this empty-view
        # group6 branch.  This guard is emitted only in that composed revision.
        node.body[-1:-1]=ast.parse(
            "if get(w, WC_ACTIVE) != 0:\n"
            "    return refuse(w, 14312)\n").body
    generator.working.update(added)
    source=ast.unparse(generator.working["prefix_failure"])
    before="    elif group >= 1 and group <= 5:\n        return worker_fixed_diagnostic_start(w)"
    after=("    elif group == 6:\n        return worker_late_core_start(w)\n"+before)
    assert source.count(before)==1
    source=source.replace(before,after,1)
    generator.working["prefix_failure"]=ast.parse(source).body[0]
    assert generator.CONSTANTS==constants
    assert all(ast.dump(generator.working[name],include_attributes=False)==old
               for name,old in original.items() if name!="prefix_failure")
    assert generator.expanded("assembly_service")[0]==assembly_before
    assert all(path.read_bytes()==raw for path,raw in generator.INPUTS.items())
    return dict(schema="hia-worker-native-late-Core-diagnostics-r1",
        source_status="UNEXECUTED_NEW_COMPOSITION",
        changed_original_methods=["prefix_failure"],added_methods=sorted(added),
        every_other_method_AST_exact=True,assembly_service_bytes_exact=True,
        constants_and_executor_masks_unchanged=True,
        actual_empty_result_child_role46_only=True,
        parent_lease_plus2_terminal_error_complete_byte_count_bound=True,
        enum_origin="actual role23 ADMIT -> lower-main15020 -> program46 -> parent",
        messages=rows,reference=pin,
        original_snapshot_before_byte_order_unchanged=True,
        no_new_early_Core_check_or_semantic_owner=True,
        all_text_written_by_HIA=True,host_diagnostic_formatting=False,
        external_arbitrary_frames_authenticated=False,
        group1_to5_public_dynamic_diagnostics_unchanged=True,group9_still_open=True,
        public_group6_depth_reachability_not_claimed=True,
        new_B3_entries=0,new_native_entries=0)
