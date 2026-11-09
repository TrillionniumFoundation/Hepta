"""Independent signed scalar witnesses, including full-width observations/traps."""
from __future__ import annotations

import json
from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_multi_results import _read_word, _write_results, _function

SIGNED_WIDTHS = {"i8": 8, "i16": 16, "i32": 32, "i64": 64, "isize": 64}


def wrap(value, bits):
    value %= 1 << bits
    return value - (1 << bits) if value >= 1 << (bits - 1) else value


def program(typ, opcode, unary=False):
    body = Body()
    left = _read_word(body, typ, 0)
    args = [left] if unary else [left, _read_word(body, typ, 8)]
    result_type = "bool" if opcode.startswith("compare.") else typ
    value = body.value(result_type, opcode, args)
    result = _write_results(body, [value], [result_type])
    return HEADER + body.text() + "  ret(" + result + ")\nend\n"


def unbatched_cases():
    rows = []
    def add(name, source, args, value):
        rows.append({"id": name + "-" + str(sum(r["program"] == name for r in rows)),
            "program": name, "source": source, "batch_group": "signed-arithmetic",
            "source_hex": b"".join((int(a) % (1 << 64)).to_bytes(8, "little") for a in args).hex(),
            "initial_hex": "a5" * 8, "expected_hex": (int(value) % (1 << 64)).to_bytes(8, "little").hex(),
            "expected_result": 0, "expected_values": [value], "owned_elf_only": False})
    for typ, bits in SIGNED_WIDTHS.items():
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        pairs = ((lo, -1), (hi, 1), (-1, 1), (lo, hi), (0, 0))
        for opcode, operation in (("int.add.wrap", lambda a,b:a+b), ("int.sub.wrap", lambda a,b:a-b),
                                  ("int.mul.wrap", lambda a,b:a*b), ("bit.and", lambda a,b:a&b),
                                  ("bit.or", lambda a,b:a|b), ("bit.xor", lambda a,b:a^b)):
            source = program(typ, opcode)
            for a,b in pairs:
                add(typ + "-" + opcode, source, [a,b], wrap(operation(a,b), bits))
        for opcode, operation in (("int.add.checked", lambda a,b:a+b), ("int.sub.checked", lambda a,b:a-b),
                                  ("int.mul.checked", lambda a,b:a*b)):
            source = program(typ, opcode)
            for a,b in ((lo,0),(hi,0),(-1,1),(-7,-3),(hi,1)):
                value = operation(a,b)
                if lo <= value <= hi:
                    add(typ + "-" + opcode, source, [a,b], value)
        for opcode in ("int.div.checked", "int.rem.checked"):
            source = program(typ, opcode)
            for a,b in ((lo,1), (hi,-1), (-7,3), (7,-3), (-7,-3), (0,-1)):
                quotient = abs(a)//abs(b)
                if (a<0) != (b<0): quotient = -quotient
                add(typ + "-" + opcode, source, [a,b], quotient if opcode=="int.div.checked" else a-quotient*b)
        for opcode,operation in (("compare.eq",lambda a,b:a==b), ("compare.ne",lambda a,b:a!=b),
            ("compare.lt",lambda a,b:a<b),("compare.le",lambda a,b:a<=b),
            ("compare.gt",lambda a,b:a>b),("compare.ge",lambda a,b:a>=b)):
            source=program(typ,opcode)
            for a,b in pairs: add(typ+"-"+opcode,source,[a,b],operation(a,b))
        for opcode in ("int.shl.checked", "int.shr.checked"):
            source=program(typ,opcode)
            for a,b in ((lo,0),(-1,bits-1),(-7,1),(hi,bits-1)):
                add(typ+"-"+opcode,source,[a,b],wrap(a<<b,bits) if opcode=="int.shl.checked" else a>>b)
        for opcode in ("bit.not", "int.neg.checked"):
            source=program(typ,opcode,True)
            for a in (lo,hi,-1,0):
                if opcode=="int.neg.checked" and a==lo:continue
                add(typ+"-"+opcode,source,[a],wrap(~a,bits) if opcode=="bit.not" else -a)

    # Every signed type participates in calls and ordered mixed result tuples.
    for typ,bits in SIGNED_WIDTHS.items():
        helper=_function("f1",[typ,"unit"],["unit",typ],"  ret(v1,v0)\n")
        body=Body();value=_read_word(body,typ,0);unit=body.value("unit","const",[],{"value":None})
        body.lines.append(f'  v1800:unit,v1801:{typ} = call({value},{unit}) {{"function":"f1"}}\n')
        result=_write_results(body,["v1801"],[typ])
        source=HEADER+body.text()+"  ret("+result+")\nend\n"+helper
        for value in (-(1<<(bits-1)),(1<<(bits-1))-1):add(typ+"-unit-tuple",source,[value],value)
    for typ,bits in SIGNED_WIDTHS.items():
        body=Body();condition=_read_word(body,"bool",0)
        left=_read_word(body,typ,8);right=_read_word(body,typ,16)
        selected=body.value(typ,"select",[condition,left,right])
        result=_write_results(body,[selected],[typ])
        source=HEADER+body.text()+"  ret("+result+")\nend\n"
        for condition in (False,True):
            for left,right in ((-(1<<(bits-1)),(1<<(bits-1))-1),(-1,1)):
                add(typ+"-select",source,[condition,left,right],left if condition else right)
    for typ,bits in SIGNED_WIDTHS.items():
        for value in (-(1<<(bits-1)),(1<<(bits-1))-1,-1,0):
            body=Body();literal=body.const(typ,value)
            result=_write_results(body,[literal],[typ])
            add(typ+"-literal",HEADER+body.text()+"  ret("+result+")\nend\n",[],value)
    body=Body();condition=_read_word(body,"bool",0)
    left=body.value("unit","const",[],{"value":None});right=body.value("unit","const",[],{"value":None})
    selected=body.value("unit","select",[condition,left,right])
    observed=body.value("u64","call",[selected],{"function":"f1"})
    result=_write_results(body,[observed],["u64"])
    helper=_function("f1",["unit"],["u64"],'  v1:u64 = const() {"value":57}\n  ret(v1)\n')
    source=HEADER+body.text()+"  ret("+result+")\nend\n"+helper
    for value in (False,True):add("unit-select-and-call",source,[value],57)
    return rows


def cases():
    from tools.hia_selfhost_batch import batch_cases
    return batch_cases(unbatched_cases())


def trap_cases():
    rows=[]
    for typ,bits in SIGNED_WIDTHS.items():
        lo,hi=-(1<<(bits-1)),(1<<(bits-1))-1
        for opcode,args in (("int.add.checked",[hi,1]),("int.sub.checked",[lo,1]),
            ("int.mul.checked",[hi,2]),("int.neg.checked",[lo]),("int.div.checked",[lo,-1]),
            ("int.rem.checked",[lo,-1]),("int.div.checked",[1,0]),("int.rem.checked",[1,0]),
            ("int.shl.checked",[-1,-1]),("int.shr.checked",[-1,bits])):
            source=program(typ,opcode,len(args)==1)
            for prior in (False,True):
                store='  v1900:usize = const() {"value":0}\n  v1901:u8 = const() {"value":77}\n  _ = buffer.store(v1,v1900,v1901)\n'
                if prior:source_case=source.replace('block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n','block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n'+store)
                else:source_case=source
                rows.append({"id":typ+"-"+opcode+"-"+"_".join(str(a) for a in args)+"-"+str(int(prior)),"source":source_case,
                    "source_hex":b"".join((a%(1<<64)).to_bytes(8,'little') for a in args).hex(),
                    "initial_hex":"a5"*8,"expected_hex":("4d" if prior else "a5")+"a5"*7,
                    "expected_code":"division_by_zero" if args[-1]==0 and opcode in {"int.div.checked","int.rem.checked"} else "overflow"})
    return rows


def refusals():
    rows=[]
    def reject(name,typ,value):
        source=HEADER+"  v3:"+typ+' = const() '+json.dumps({"value":value},separators=(",",":"))+"\n"
        source+='  v4:u32 = const() {"value":0}\n  ret(v4)\nend\n'
        rows.append({"id":name,"source":source,"general_core_expected":"rejected"})
    for typ,bits in SIGNED_WIDTHS.items():
        reject(typ+"-literal-above",typ,1<<(bits-1))
        reject(typ+"-literal-below",typ,-(1<<(bits-1))-1)
        reject(typ+"-bool-not-integer",typ,True)
    reject("unit-not-integer","unit",0)
    reject("unit-not-bool","unit",False)
    reject("integer-not-unit","i8",None)
    return rows


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program,HIAProgramRejected
    from tools.hia_selfhost_loans import reference_source
    from hepta.hia_program_runtime import HIAProgramTrap
    accepted,traps=[],[]
    for case in cases():
        result=execute_program(assemble_program(reference_source(case)),"reference_entry",[])
        expected=[0,*bytes.fromhex(case["expected_hex"])]
        if result.get("status")!="returned" or result["values"]!=expected:
            raise AssertionError({"case":case["id"],"actual":result,"expected":expected})
        accepted.append({**case,"reference_result":result})
    for case in trap_cases():
        try:
            result=execute_program(assemble_program(reference_source(case)),"reference_entry",[])
        except HIAProgramTrap as exc:
            result=exc.report
        if result.get("status")!="trapped" or result.get("error",{}).get("code")!=case["expected_code"]:
            raise AssertionError({"case":case["id"],"actual":result})
        traps.append({**case,"reference_result":result})
    rejected=[]
    for case in refusals():
        try:
            assemble_program(case["source"].encode())
        except HIAProgramRejected as exc:
            rejected.append({**case,"reference_result":{"status":"rejected","code":exc.code}})
        else:
            raise AssertionError({"case":case["id"],"unexpected_admission":True})
    return {"cases":accepted,"refusals":rejected,"traps":traps,"before_B0":True,"all_input_correctness_proved":False}


def qualify(directory,compilers,checks,reference,*,family="signed"):
    from tools.hia_selfhost_multi_results import qualify as observations
    from tools.qualify_hia_selfhost import compile_stage,invoke,digest
    rows=observations(directory,compilers,checks,reference,family=family)
    for label,compiler in compilers:
        images = {}
        for case in reference["traps"]:
            name=label+"-"+family+"-trap-"+case["id"]
            source = case["source"].encode()
            identity = digest(source)
            if identity not in images:
                images[identity] = compile_stage(directory,name+"-build",compiler,source)
            image,receipt = images[identity]
            result,output=invoke(directory,name,image,bytes.fromhex(case["source_hex"]),capacity=8,
                workspace_size=0,output_initial=bytes.fromhex(case["initial_hex"]),observe_trap_writes=True)
            checks[name]=bool(result.get("status")=="child_failed" and result.get("returncode")==-4
                and output.hex()==case["expected_hex"])
            rows.append({"case":case["id"],"build":receipt,"native":result,"actual_hex":output.hex()})
    return rows
