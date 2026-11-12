"""Signed/unsigned conversion witnesses independently checked by general Core."""
from __future__ import annotations
from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_multi_results import _read_word,_write_results
from tools.hia_selfhost_signed_cases import wrap

WIDTHS={"u8":8,"u16":16,"u32":32,"u64":64,"usize":64,
        "i8":8,"i16":16,"i32":32,"i64":64,"isize":64}


def bounds(typ):
    bits=WIDTHS[typ]
    return (-(1<<(bits-1)),(1<<(bits-1))-1) if typ.startswith("i") else (0,(1<<bits)-1)


def program(source_type,target_type,mode):
    body=Body();value=_read_word(body,source_type,0)
    converted=body.value(target_type,"int.cast",[value],{"mode":mode})
    result=_write_results(body,[converted],[target_type])
    return HEADER+body.text()+"  ret("+result+")\nend\n"


def unbatched_cases():
    rows=[]
    for source in WIDTHS:
        lo,hi=bounds(source)
        for target in WIDTHS:
            if not source.startswith("i") and not target.startswith("i"):continue
            tlo,thi=bounds(target);bits=WIDTHS[target]
            values=sorted({lo,hi,0,1,*[v for v in (-1,tlo-1,tlo,thi,thi+1) if lo<=v<=hi]})
            for mode in ("wrap","checked"):
                asm=program(source,target,mode)
                for value in values:
                    if mode=="checked" and not tlo<=value<=thi:continue
                    expected=wrap(value,bits) if target.startswith("i") else value%(1<<bits)
                    name=source+"-"+target+"-"+mode
                    rows.append({"id":name+"-"+str(value),"program":name,"batch_group":"scalar-casts",
                        "source":asm,"source_hex":(value%(1<<64)).to_bytes(8,'little').hex(),
                        "initial_hex":"a5"*8,"expected_hex":(expected%(1<<64)).to_bytes(8,'little').hex(),
                        "expected_result":0,"expected_values":[expected],"owned_elf_only":False})
    return rows


def cases():
    from tools.hia_selfhost_batch import batch_cases
    return batch_cases(unbatched_cases())


def trap_cases():
    rows=[]
    for source in WIDTHS:
        lo,hi=bounds(source)
        for target in WIDTHS:
            if not source.startswith("i") and not target.startswith("i"):continue
            tlo,thi=bounds(target)
            values={v for v in (lo,hi,tlo-1,thi+1) if lo<=v<=hi and not tlo<=v<=thi}
            for value in sorted(values):
                rows.append({"id":source+"-"+target+"-"+str(value),"source":program(source,target,"checked"),
                    "source_hex":(value%(1<<64)).to_bytes(8,'little').hex(),"initial_hex":"a5"*8,"expected_hex":"a5"*8})
    return rows


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    from tools.hia_selfhost_loans import reference_source
    accepted,traps=[],[]
    for case in cases():
        result=execute_program(assemble_program(reference_source(case)),"reference_entry",[])
        expected=[0,*bytes.fromhex(case["expected_hex"])]
        if result.get("status")!="returned" or result["values"]!=expected:
            raise AssertionError({"case":case["id"],"actual":result,"expected":expected})
        accepted.append({**case,"reference_result":result})
    for case in trap_cases():
        try:result=execute_program(assemble_program(reference_source(case)),"reference_entry",[])
        except HIAProgramTrap as exc:result=exc.report
        if result.get("status")!="trapped" or result.get("error",{}).get("code")!="overflow":
            raise AssertionError({"case":case["id"],"actual":result})
        traps.append({**case,"reference_result":result})
    return {"cases":accepted,"refusals":[],"traps":traps,"before_B0":True,"all_input_correctness_proved":False}


def qualify(directory,compilers,checks,reference):
    from tools.hia_selfhost_signed_cases import qualify as qualify_scalar
    return qualify_scalar(directory,compilers,checks,reference,family="scalar-casts")
