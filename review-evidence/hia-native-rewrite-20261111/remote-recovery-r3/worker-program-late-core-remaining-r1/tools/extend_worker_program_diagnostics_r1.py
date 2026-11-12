"""Worker P16 fixed diagnostic continuation, independent development r1.

Only exact retained method ASTs are adapted at authoring time. The native
controller consumes the actual program-child terminal, calls the shared
181-text HIA ROM twice, and publishes complete UTF-8 after exact correlation.
No hosted formatter or namespace/store authority is introduced.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256

FORMATTER_SHA="4c576e05b0c310d6f30858b5d983e4ba720503c91ae8750ff9591f9b6fbb74a0"
WORKER_OWNER_SHA="c7575f39085d09c05df5999087657f2825d9219e6d1512beba21d77c3551a3e4"
ROOT_OWNER_SHA="f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9"
BODY=r'''
def worker_fixed_diagnostic_start(w:mutbuf) -> u64:
    group = get(w, E_ERROR_GROUP)
    if group < 1 or group > 5 or get(w, E_ERROR_CODE) == 0:
        return refuse(w, 12100)
    if get(w, C_LEASE) == 0 or get(w, C_LEASE) > MAX - 3 or get(w, C_SEQUENCE) == 0:
        return refuse(w, 12101)
    if get(w, E_CHILD_EVENT) != EVENT_MAGIC or get(w, E_CHILD_EVENT + 8) != 7:
        return refuse(w, 12102)
    if get(w, E_CHILD_EVENT + 16) != get(w, C_LEASE) + 2 or get(w, E_CHILD_EVENT + 24) == 0:
        return refuse(w, 12103)
    if get(w, E_CHILD_EVENT + 32) != group or get(w, E_CHILD_EVENT + 40) != get(w, E_ERROR_CODE):
        return refuse(w, 12104)
    if cap(w, WD_OUTPUT) != 0 or cap(w, WD_WORK) != 0 or get(w, WD_ACTIVE) != 0:
        return refuse(w, 12105)
    if get(w, WP_RESULT_KIND) != 0:
        return refuse(w, 12106)
    put(w, WD_SEQUENCE, get(w, C_SEQUENCE))
    put(w, WD_ACTIVE, 1)
    wire8(w, WD_COMMAND, 1, get(w, C_LEASE), get(w, WD_SEQUENCE), get(w, E_CHILD_EVENT + 16), get(w, E_CHILD_EVENT + 24), 46, 0)
    copy_local(w, WIRE + 64, E_CHILD_EVENT, 128)
    put(w, C_PHASE, 87500)
    return 0

def worker_fixed_diagnostic_header(w:mutbuf) -> u64:
    if get(w, OBS) != WD_RESULT or get(w, OBS + 8) != 1:
        return 0
    if get(w, OBS + 16) != get(w, C_LEASE) or get(w, OBS + 24) != get(w, WD_SEQUENCE):
        return 0
    if get(w, OBS + 32) != get(w, E_CHILD_EVENT + 16) or get(w, OBS + 40) != get(w, E_CHILD_EVENT + 24):
        return 0
    if get(w, OBS + 48) != get(w, E_ERROR_GROUP) or get(w, OBS + 56) != get(w, E_ERROR_CODE):
        return 0
    if get(w, OBS + 64) != get(w, E_CHILD_EVENT + 48) or get(w, OBS + 88) != 0:
        return 0
    size = get(w, OBS + 72)
    if size == 0 or size > WD_MAX_TEXT or get(w, OBS + 80) != 128 + size:
        return 0
    at = 0
    while at < 32:
        if byte(w, OBS + 96 + at) != byte(w, E_CHILD_EVENT + 96 + at):
            return 0
        at = at + 1
    return 1

def worker_fixed_diagnostic_step(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if get(w, WD_ACTIVE) != 1:
        return refuse(w, 12107)
    if phase == 87500:
        return grow(o, w, WD_OUTPUT, 128, 87501)
    if phase == 87501:
        return grow(o, w, WD_WORK, WD_ROM_BYTES, 87502)
    if phase == 87502:
        return invoke(o, w, 51, B_CONTROLLER, WIRE, 192, WD_OUTPUT, 128, WD_WORK, WD_ROM_BYTES, WD_OUTPUT, 0, 128, 87503)
    if phase == 87503:
        if get(w, C_RETURN) != 4294967294 or cap(w, WD_OUTPUT) != 128 or worker_fixed_diagnostic_header(w) == 0:
            return refuse(w, 12108)
        put(w, WD_NEEDED, get(w, OBS + 80))
        copy_local(w, WD_HEADER, OBS, 128)
        return grow(o, w, WD_OUTPUT, get(w, WD_NEEDED), 87504)
    if phase == 87504:
        return invoke(o, w, 51, B_CONTROLLER, WIRE, 192, WD_OUTPUT, get(w, WD_NEEDED), WD_WORK, WD_ROM_BYTES, WD_OUTPUT, 0, 128, 87505)
    if phase == 87505:
        if get(w, C_RETURN) != get(w, WD_NEEDED) or cap(w, WD_OUTPUT) != get(w, WD_NEEDED):
            return refuse(w, 12109)
        at = 0
        while at < 128:
            if byte(w, OBS + at) != byte(w, WD_HEADER + at):
                return refuse(w, 12110)
            at = at + 1
        return protect(o, w, WD_OUTPUT, 1, 87506)
    if phase == 87506:
        return release(o, w, WD_WORK, 87507)
    if phase == 87507:
        if cap(w, WD_WORK) != 0:
            return refuse(w, 12111)
        return worker_result_begin(w, 4, 1, 0, 0, WD_OUTPUT, 128, get(w, WD_NEEDED) - 128)
    if phase == 87508:
        if get(w, WP_PAYLOAD_SLOT) != WD_OUTPUT or get(w, WP_PAYLOAD_AT) != 128 or get(w, WP_PAYLOAD_BYTES) + 128 != get(w, WD_NEEDED):
            return refuse(w, 12112)
        return release(o, w, WD_OUTPUT, 87509)
    if phase == 87509:
        if cap(w, WD_OUTPUT) != 0 or cap(w, WD_WORK) != 0:
            return refuse(w, 12113)
        put(w, WD_ACTIVE, 2)
        put(w, C_PHASE, 88007)
        return 0
    return refuse(w, 12114)
'''

def replace_once(text,before,after):
    assert text.count(before)==1,(before,text.count(before))
    return text.replace(before,after,1)

def attach(generator,catalog_module,reference):
    """Adapt three exact methods; never change the published input files."""
    original={name:ast.dump(node,include_attributes=False)
              for name,node in generator.working.items()}
    old_assembly_text,_=generator.expanded("assembly_service")
    assert sha256(generator.INPUTS[generator.ROOT/"tools/worker_program_service.py"]).hexdigest()==WORKER_OWNER_SHA
    assert sha256(generator.INPUTS[generator.ROOT/"tools/program_service_root_reference.py"]).hexdigest()==ROOT_OWNER_SHA
    rows,rom,pins=catalog_module.catalog(reference)
    assert len(rows)==181 and {r["group"] for r in rows}=={1,2,3,4,5}
    additions=dict(WD_COMMAND=catalog_module.COMMAND,WD_RESULT=catalog_module.RESULT,
        WD_OUTPUT=47,WD_WORK=48,WD_ROM_BYTES=len(rom),
        WD_MAX_TEXT=max(len(r["text"]) for r in rows),
        WD_SEQUENCE=79000,WD_NEEDED=79008,WD_ACTIVE=79016,WD_HEADER=79040)
    assert not(set(additions)&set(generator.CONSTANTS))
    assert additions["WD_HEADER"]+128<generator.CONSTANTS["MIN_WORK"]
    assert generator.CONSTANTS["WP_SAVED_CODE"]+64<additions["WD_SEQUENCE"]
    assert {additions["WD_OUTPUT"],additions["WD_WORK"]}.isdisjoint(
        {generator.CONSTANTS[n] for n in ("B_PROGRAM","B_PROGRAM_FRAME","B_CORE",
             "B_RESULT","B_SHA_INPUT","B_SHA_OUTPUT","B_SHA_WORK","AS_COMMAND",
             "AS_RENDER_WORK","AS_SYNTAX_WORK","AS_OBJECT_OUTPUT","AS_OBJECT_WORK",
             "AS_CANONICAL","AS_FINAL_CORE","AS_JSON_OUTPUT")})
    generator.CONSTANTS.update(additions)
    method=ast.unparse(generator.working["worker_program_service"])
    method=replace_once(method,
        "        elif phase == 87000:\n            result = worker_assembly_finish(w)",
        "        elif phase == 87000:\n            result = worker_assembly_finish(w)\n"
        "        elif phase >= 87500 and phase < 87510:\n"
        "            result = worker_fixed_diagnostic_step(o, w, phase)")
    generator.working["worker_program_service"]=ast.parse(method).body[0]
    method=ast.unparse(generator.working["prefix_failure"])
    method=replace_once(method,
        "    else:\n        return refuse(w, 2027)\n    size = prefix_message(w, message)",
        "    elif group >= 1 and group <= 5:\n"
        "        return worker_fixed_diagnostic_start(w)\n"
        "    else:\n        return refuse(w, 2027)\n    size = prefix_message(w, message)")
    generator.working["prefix_failure"]=ast.parse(method).body[0]
    method=ast.unparse(generator.working["worker_result_step"])
    method=replace_once(method,
        "        return copy(o, w, get(w, WP_PAYLOAD_SLOT), get(w, WP_PAYLOAD_AT), B_RESULT, get(w, WP_PAYLOAD_OUT), get(w, WP_PAYLOAD_BYTES), 88007)",
        "        if get(w, WD_ACTIVE) == 1:\n"
        "            if get(w, WP_PAYLOAD_SLOT) != WD_OUTPUT:\n"
        "                return refuse(w, 12115)\n"
        "            return copy(o, w, WD_OUTPUT, get(w, WP_PAYLOAD_AT), B_RESULT, get(w, WP_PAYLOAD_OUT), get(w, WP_PAYLOAD_BYTES), 87508)\n"
        "        return copy(o, w, get(w, WP_PAYLOAD_SLOT), get(w, WP_PAYLOAD_AT), B_RESULT, get(w, WP_PAYLOAD_OUT), get(w, WP_PAYLOAD_BYTES), 88007)")
    generator.working["worker_result_step"]=ast.parse(method).body[0]
    methods=generator.functions(BODY)
    assert not(set(methods)&set(generator.working))
    generator.working.update(methods)
    changed={"worker_program_service","prefix_failure","worker_result_step"}
    assert all(ast.dump(generator.working[name],include_attributes=False)==value
               for name,value in original.items() if name not in changed)
    assert generator.expanded("assembly_service")[0]==old_assembly_text
    assert all(path.read_bytes()==raw for path,raw in generator.INPUTS.items())
    constants={name:value for name,value in generator.CONSTANTS.items()
       if name.startswith(("WD_","WP_","C_","L_","E_","AS_")) or name in {
          "CAPS","WIRE","OBS","ARGS","EVENT_MAGIC","ACK_MAGIC","LOWER_MAGIC",
          "EDIT_STATE","A_MAGIC","A_STATE_MAGIC","B_PROGRAM","B_PROGRAM_FRAME",
          "B_CONTROLLER","B_RESULT","MAIN","ABI","MIN_WORK"}}
    return dict(schema="hia-worker-program-fixed-diagnostic-adaptation-r1",
        changed_exact_methods=sorted(changed),added_native_methods=sorted(methods),
        all_other_method_AST_equal=True,assembly_entry_expanded_bytes_equal=True,
        original_program_child_and_receipt_methods_unchanged=True,
        formatter_role=51,formatter_entry_mode="RWW",output_slot=47,workspace_slot=48,
        groups=[1,2,3,4,5],open_groups=[6,9],ROM_bytes=len(rom),
        complete_actual_child_terminal_copied=True,measurement_bytes=128,
        two_native_calls_required=True,original128_header_equal_after_growth=True,
        diagnostic_workspace_release_before_result_copy=True,
        diagnostic_output_release_after_result_copy_before_terminal=True,
        reference_pins=pins,constants=constants)

def compose_executor(original_composer,raw):
    prior=original_composer.compose(raw)
    old=b".equ TWO_READ_MASK,0x60bf80bee2ac0462"
    before=0x60bf80bee2ac0462;after=before&~(1<<51)
    new=(".equ TWO_READ_MASK,"+hex(after)).encode()
    assert prior.count(old)==1 and before&(1<<51)
    result=prior.replace(old,new,1)
    assert result.replace(new,old,1)==prior
    assert (before^after)==1<<51
    assert (before&~(1<<51))==(after&~(1<<51))
    proof=dict(schema="hia-worker-program-diagnostic-mask-r1",
        original_composed_bytes=len(prior),original_composed_sha256=sha256(prior).hexdigest(),
        source_bytes=len(result),source_sha256=sha256(result).hexdigest(),
        old_two_read_mask=before,new_two_read_mask=after,only_changed_bit=51,
        role51_has_writable_output=True,whole_assembly_reverse_restoration_equal=True,
        all_child_and_cleanup_instruction_bytes_unchanged=True)
    return result,proof
