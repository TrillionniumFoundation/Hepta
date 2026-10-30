"""New authored contracts and development-only reference implementations.

Formal inputs are derived only after published registration. Public prompts
never receive this module, reference implementations, or private input seeds.
"""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json

SCHEMA = "hepta.hia.program.v8"
MASK = (1 << 32) - 1
RESOURCE_TASKS = frozenset({"mutate_borrow", "return_borrow", "conditional_release"})
BORROW_TASKS = frozenset({"mutate_borrow", "return_borrow"})
TASKS = (
    {"id": "signed_clamped_mix", "interface": "target",
     "description": "Implement target(x:u32,y:u32)->u32. Interpret each input as a signed two's-complement i32; compute 3*x+y in mathematical integers, clamp to [-1000000,1000000], then return that signed result as its u32 two's-complement encoding. Full u32 inputs are valid.",
     "public": [[4,7],[4294967290,3],[2147483647,1],[2147483648,4294967295],[333333,1],[4294633963,4294967295]]},
    {"id": "byte_window_checksum", "interface": "target",
     "description": "Implement target(x:u32,y:u32)->u32. Let bytes[k]=(x>>(8*k))&255 for k=0..3, n=y%5 and start=(y>>3)%4. Initialize h=2166136261. For i=0..n-1 set h=((h XOR bytes[(start+i)%4])*16777619) modulo 2^32. Return h, including the initial h when n=0.",
     "public": [[67305985,4],[67305985,12],[0,0],[4294967295,17],[305419896,31],[2147483648,33]]},
    {"id": "run_length_flags", "interface": "target",
     "description": "Implement target(x:u32,y:u32)->u32. Examine bits 0 through n-1 of x in that order, where n=y%17. Count ones and maximal nonempty runs of consecutive one bits, assuming a zero immediately before bit 0. Return (run_count<<16)|one_count. n=0 returns zero.",
     "public": [[255,8],[170,8],[85,8],[0,16],[65535,16],[13,4]]},
    {"id": "mutate_borrow", "interface": "task_step",
     "description": "Implement the borrowed helper task_step(view,x,y)->u32. The caller owns a zeroed byte buffer of n=3+x%11 bytes and lends it mutably. Write byte=((x>>3)+y) modulo 256 at index=(x XOR y)%n, then return the readback byte widened to u32. Modify that caller-owned buffer; allocating a substitute or scalar-only shortcut is invalid. The disclosed wrapper allocates once, calls your helper, checks its return against the actual buffer, ends the borrow and releases the owner; wrapper result is 256*n+byte. HIA interface: task_step(view:mutbuf,x:u32,y:u32)->(u32), effects(read,write,trap). Rust interface: fn task_step(view:&mut Vec<u8>,x:u32,y:u32)->u32, using the supplied audited Vec API.",
     "public": [[0,4],[10,251],[11,8],[4294967295,4294967294],[123,456],[4096,1]]},
    {"id": "return_borrow", "interface": "task_step",
     "description": "Implement task_step(view,x,y), returning a mutable borrow of the same caller-owned buffer. The caller owns a zeroed buffer of n=5+x%7 bytes. At index=(y>>2)%n, write byte=(x+3*y) modulo 256 and return the same mutable view. The disclosed caller reads through your returned view, XORs that byte with 165, writes and reads it back through the returned view, ends the returned and parent loans, then releases the owner. Wrapper result is 256*n+(byte XOR 165). HIA v8 requires return_loans([\"view\"]) (or the actual alpha-renamed formal). Rust interface: fn task_step<'a>(view:&'a mut Vec<u8>,x:u32,y:u32)->&'a mut Vec<u8>. No replacement allocation or unrelated borrow is permitted.",
     "public": [[0,4],[6,8],[7,1023],[4294967295,1431655766],[99,21],[4097,0]]},
    {"id": "conditional_release", "interface": "target",
     "description": "Implement target(x:u32,y:u32)->u32 with exactly one zeroed owned byte buffer of n=8+x%9 bytes allocated on every invocation, including the odd-y path. If y is odd, release the buffer without any indexed read/write and return zero. Otherwise write byte=(x XOR y) modulo 256 at index=n-1, read it back, release the buffer and return 256*n+byte. Every path must release the owner. Rust may use normal automatic Drop or explicit drop; HIA must satisfy its ordinary owner/loan contracts. A scalar shortcut without actual buffer work is invalid.",
     "public": [[0,1],[0,2],[8,254],[9,3],[4294967295,4294967294],[2048,0]]},
)


def task_for(name):
    return next(t for t in TASKS if t["id"] == name)


def signed(value):
    return value if value < (1 << 31) else value - (1 << 32)


def resource_contract(task_id, x, y):
    if task_id == "mutate_borrow":
        n = 3 + x % 11
        return {"length": n, "index": (x ^ y) % n, "first_byte": ((x >> 3) + y) % 256,
                "final_byte": ((x >> 3) + y) % 256, "failure_path": False,
                "minimum_matching_writes": 1, "returned_loan_required": False}
    if task_id == "return_borrow":
        n = 5 + x % 7
        byte = (x + 3*y) % 256
        return {"length": n, "index": (y >> 2) % n, "first_byte": byte,
                "final_byte": byte ^ 165, "failure_path": False,
                "minimum_matching_writes": 2, "returned_loan_required": True}
    if task_id == "conditional_release":
        n = 8 + x % 9
        return {"length": n, "index": n-1, "first_byte": (x ^ y) % 256,
                "final_byte": (x ^ y) % 256, "failure_path": y % 2 == 1,
                "minimum_matching_writes": 0 if y % 2 else 1, "returned_loan_required": False}
    raise ValueError("not a resource task")


def oracle(task_id, x, y):
    if task_id == "signed_clamped_mix":
        return max(-1000000, min(1000000, 3*signed(x) + signed(y))) & MASK
    if task_id == "byte_window_checksum":
        lanes = x.to_bytes(4, "little")
        selected = [lanes[((y >> 3) % 4 + i) % 4] for i in range(y % 5)]
        value = 2166136261
        for byte in selected:
            value = ((value ^ byte) * 16777619) % (1 << 32)
        return value
    if task_id == "run_length_flags":
        bits = "".join(str((x >> i) & 1) for i in range(y % 17))
        return (sum(part != "" for part in bits.split("0")) << 16) | bits.count("1")
    c = resource_contract(task_id, x, y)
    return 0 if c["failure_path"] else 256*c["length"] + c["final_byte"]


def cases(task, *, phase, seed, count=96, permit_formal=False):
    if phase == "public":
        return deepcopy(task["public"])
    if phase not in {"development", "formal"}:
        raise ValueError("explicit input phase required")
    if phase == "formal" and not permit_formal:
        raise ValueError("formal inputs must not be materialized before published registration")
    if phase == "development":
        # Fixed development edges are deliberately separate from formal inputs.
        return [[0,0],[MASK,MASK],[1,2],[2,1],[1 << 31,17],[MASK-1,32],
                [999999,1000001],[0x10203040,0x50607080],
                *[[int.from_bytes(sha256(f"dev:{seed}:{task['id']}:{i}".encode()).digest()[:4],"little"),
                   int.from_bytes(sha256(f"dev-y:{seed}:{task['id']}:{i}".encode()).digest()[:4],"little")]
                  for i in range(24)]]
    if type(count) is not int or not 1 <= count <= 256:
        raise ValueError("finite formal case count required")
    return [[int.from_bytes(sha256(f"formal:{seed}:{task['id']}:{i}".encode()).digest()[:4],"little"),
             int.from_bytes(sha256(f"formal-y:{seed}:{task['id']}:{i}".encode()).digest()[:4],"little")]
            for i in range(count)]


def p(name, typ="u32"):
    return {"name": name, "type": typ}


def op(name, args=(), output=None, typ="u32", **attrs):
    return {"op": name, "args": list(args), "out": [] if output is None else [p(output,typ)],
            "attrs": attrs}


def c(name, value, typ="u32"):
    return op("const", output=name, typ=typ, value=value)


def b(name, params, operations, term):
    return {"id": name, "params": [p(x) if isinstance(x,str) else p(*x) for x in params],
            "ops": operations, "term": term}


def ret(*names):
    return {"op": "ret", "values": list(names)}


def jump(name, *args):
    return {"op": "jump", "target": name, "args": list(args)}


def branch(cond, yes, no):
    return {"op": "branch", "cond": cond,
            "then": {"target": yes[0], "args": list(yes[1:])},
            "else": {"target": no[0], "args": list(no[1:])}}


def fn(name, params, returns, effects, blocks, origins=None):
    result = {"name": name, "params": [p(x) if isinstance(x,str) else p(*x) for x in params],
              "returns": list(returns), "effects": list(effects), "entry": blocks[0]["id"],
              "blocks": blocks}
    if origins is not None:
        result["return_loans"] = origins
    return result


def module(function, export=None):
    return {"schema": SCHEMA, "module": "v8_continuation_candidate",
            "exports": [] if function["name"] == "task_step" else [export or function["name"]],
            "functions": [function]}


def owned_setup(kind):
    if kind == "mutate_borrow":
        base, modulus = 3, 11
    elif kind == "return_borrow":
        base, modulus = 5, 7
    else:
        base, modulus = 8, 9
    return [c("modulus",modulus),c("base",base),op("int.rem.checked",["x","modulus"],"offset"),
            op("int.add.checked",["offset","base"],"n"),
            op("int.cast",["n"],"size","usize",mode="checked"),
            op("buffer.new",["size"],"owner","buffer")]


def wrapper(task_id):
    if task_id not in BORROW_TASKS:
        return None
    operations = owned_setup(task_id) + [op("borrow.mut",["owner"],"parent","mutbuf")]
    if task_id == "mutate_borrow":
        operations += [op("call",["parent","x","y"],"helper_byte",function="task_step"),
            op("bit.xor",["x","y"],"index_bits"),
            op("int.rem.checked",["index_bits","n"],"index"),
            op("int.cast",["index"],"pos","usize",mode="checked"),
            op("buffer.load",["parent","pos"],"observed_byte","u8"),
            op("int.cast",["observed_byte"],"observed","u32",mode="checked"),
            op("compare.eq",["observed","helper_byte"],"helper_ok","bool"),
            op("loan.end",["parent"]),op("owner.drop",["owner"])]
        blocks = [b("entry",["x","y"],operations,branch("helper_ok",("ok","n","observed"),("bad",))),
                  b("ok",["ok_n","ok_value"],[c("weight",256),op("int.mul.checked",["ok_n","weight"],"tag"),
                     op("int.add.checked",["tag","ok_value"],"answer")],ret("answer")),
                  b("bad",[],[],{"op":"trap","code":"user"})]
    else:
        operations += [op("call",["parent","x","y"],"returned","mutbuf",function="task_step"),
            c("shift",2),op("int.shr.checked",["y","shift"],"shifted"),
            op("int.rem.checked",["shifted","n"],"index"),
            op("int.cast",["index"],"pos","usize",mode="checked"),
            op("buffer.load",["returned","pos"],"first","u8"),c("mask",165,"u8"),
            op("bit.xor",["first","mask"],"changed","u8"),
            op("buffer.store",["returned","pos","changed"]),
            op("buffer.load",["returned","pos"],"final","u8"),
            op("loan.end",["returned"]),op("loan.end",["parent"]),op("owner.drop",["owner"]),
            op("int.cast",["final"],"value","u32",mode="checked"),c("weight",256),
            op("int.mul.checked",["n","weight"],"tag"),
            op("int.add.checked",["tag","value"],"answer")]
        blocks = [b("entry",["x","y"],operations,ret("answer"))]
    return fn("target",["x","y"],["u32"],["alloc","read","write","trap"],blocks)


def combine_candidate(candidate, task_id):
    result = deepcopy(candidate)
    extra = wrapper(task_id)
    if extra:
        if any(f.get("name") == "target" for f in result["functions"]):
            raise ValueError("borrowed helper cannot redefine the disclosed host wrapper")
        result["functions"].append(extra)
        result["exports"] = ["target"]
    return result


def reference_core(task_id):
    if task_id == "signed_clamped_mix":
        operations=[op("int.cast",["x"],"sx","i32",mode="wrap"),op("int.cast",["y"],"sy","i32",mode="wrap"),
            op("int.cast",["sx"],"a","i64",mode="checked"),op("int.cast",["sy"],"z","i64",mode="checked"),
            c("three",3,"i64"),op("int.mul.checked",["a","three"],"scaled","i64"),
            op("int.add.checked",["scaled","z"],"sum","i64"),c("lower",-1000000,"i64"),
            c("upper",1000000,"i64"),op("compare.lt",["sum","lower"],"too_low","bool")]
        blocks=[b("entry",["x","y"],operations,branch("too_low",("answer_block","lower"),("upper_check","sum","upper"))),
            b("upper_check",[("test_sum","i64"),("test_upper","i64")],[op("compare.gt",["test_sum","test_upper"],"too_high","bool")],
              branch("too_high",("answer_block","test_upper"),("answer_block","test_sum"))),
            b("answer_block",[("signed_answer","i64")],[op("int.cast",["signed_answer"],"encoded","u32",mode="wrap")],ret("encoded"))]
        return module(fn("target",["x","y"],["u32"],["trap"],blocks))
    if task_id == "byte_window_checksum":
        blocks=[b("entry",["x","y"],[c("five",5),c("four",4),c("three",3),c("zero",0),c("initial",2166136261),
            op("int.rem.checked",["y","five"],"count"),op("int.shr.checked",["y","three"],"ys"),
            op("int.rem.checked",["ys","four"],"start")],jump("loop","x","count","start","zero","initial")),
            b("loop",["lx","ln","ls","li","lh"],[op("compare.lt",["li","ln"],"more","bool")],
              branch("more",("body","lx","ln","ls","li","lh"),("done","lh"))),
            b("body",["bx","bn","bs","bi","bh"],[c("lane_count",4),c("eight",8),c("mask",255),c("prime",16777619),c("one",1),
                op("int.add.checked",["bs","bi"],"lane_sum"),op("int.rem.checked",["lane_sum","lane_count"],"lane"),
                op("int.mul.checked",["lane","eight"],"shift"),op("int.shr.checked",["bx","shift"],"shifted"),
                op("bit.and",["shifted","mask"],"byte"),op("bit.xor",["bh","byte"],"mixed"),
                op("int.mul.wrap",["mixed","prime"],"next_hash"),op("int.add.checked",["bi","one"],"next_i")],
              jump("loop","bx","bn","bs","next_i","next_hash")),
            b("done",["digest"],[],ret("digest"))]
        return module(fn("target",["x","y"],["u32"],["trap"],blocks))
    if task_id == "run_length_flags":
        blocks=[b("entry",["x","y"],[c("seventeen",17),c("zero",0),op("int.rem.checked",["y","seventeen"],"count")],
                  jump("loop","x","count","zero","zero","zero","zero")),
            b("loop",["lx","ln","li","lp","lo","lr"],[op("compare.lt",["li","ln"],"more","bool")],
              branch("more",("body","lx","ln","li","lp","lo","lr"),("done","lo","lr"))),
            b("body",["bx","bn","bi","bp","bo","br"],[c("one",1),op("int.shr.checked",["bx","bi"],"shifted"),
               op("bit.and",["shifted","one"],"bit"),op("int.sub.checked",["one","bp"],"not_previous"),
               op("int.mul.checked",["bit","not_previous"],"new_run"),op("int.add.checked",["bo","bit"],"next_ones"),
               op("int.add.checked",["br","new_run"],"next_runs"),op("int.add.checked",["bi","one"],"next_i")],
              jump("loop","bx","bn","next_i","bit","next_ones","next_runs")),
            b("done",["ones","runs"],[c("sixteen",16),op("int.shl.checked",["runs","sixteen"],"high"),
                 op("bit.or",["high","ones"],"answer")],ret("answer"))]
        return module(fn("target",["x","y"],["u32"],["trap"],blocks))
    if task_id in BORROW_TASKS:
        operations=[op("buffer.len",["view"],"size","usize"),
                    op("int.cast",["size"],"n","u32",mode="checked")]
        if task_id == "mutate_borrow":
            operations += [op("bit.xor",["x","y"],"bits"),op("int.rem.checked",["bits","n"],"index"),
               c("three",3),op("int.shr.checked",["x","three"],"shifted"),
               op("int.add.wrap",["shifted","y"],"value")]
        else:
            operations += [c("two",2),c("three",3),op("int.shr.checked",["y","two"],"shifted"),
                op("int.rem.checked",["shifted","n"],"index"),op("int.mul.wrap",["y","three"],"scaled"),
                op("int.add.wrap",["x","scaled"],"value")]
        operations += [op("int.cast",["index"],"pos","usize",mode="checked"),
            op("int.cast",["value"],"byte","u8",mode="wrap"),op("buffer.store",["view","pos","byte"])]
        if task_id == "mutate_borrow":
            operations += [op("buffer.load",["view","pos"],"observed","u8"),
                           op("int.cast",["observed"],"answer","u32",mode="checked")]
            return module(fn("task_step",[("view","mutbuf"),"x","y"],["u32"],["read","write","trap"],
                             [b("entry",[("view","mutbuf"),"x","y"],operations,ret("answer"))]))
        return module(fn("task_step",[("view","mutbuf"),"x","y"],["mutbuf"],["write","trap"],
                         [b("entry",[("view","mutbuf"),"x","y"],operations,ret("view"))],origins=["view"]))
    if task_id == "conditional_release":
        blocks=[b("entry",["x","y"],owned_setup(task_id)+[c("two",2),c("zero",0),
              op("int.rem.checked",["y","two"],"parity"),op("compare.ne",["parity","zero"],"fail","bool")],
              branch("fail",("failure","owner"),("success","owner","n","x","y"))),
            b("failure",[("failed_owner","buffer")],[op("owner.drop",["failed_owner"]),c("failed_answer",0)],ret("failed_answer")),
            b("success",[("live_owner","buffer"),"live_n","live_x","live_y"],[
              c("one",1),op("int.sub.checked",["live_n","one"],"index"),
              op("int.cast",["index"],"pos","usize",mode="checked"),
              op("bit.xor",["live_x","live_y"],"bits"),
              op("int.cast",["bits"],"byte","u8",mode="wrap"),op("borrow.mut",["live_owner"],"view","mutbuf"),
              op("buffer.store",["view","pos","byte"]),op("buffer.load",["view","pos"],"observed","u8"),
              op("loan.end",["view"]),op("owner.drop",["live_owner"]),
              op("int.cast",["observed"],"value","u32",mode="checked"),c("weight",256),
              op("int.mul.checked",["weight","live_n"],"tag"),op("int.add.checked",["tag","value"],"answer")],ret("answer"))]
        return module(fn("target",["x","y"],["u32"],["alloc","read","write","trap"],blocks))
    raise ValueError("unregistered task")


RUST_REFERENCES = {
    "signed_clamped_mix": "fn target(x:u32,y:u32)->u32 { let value=3*(x as i32 as i64)+(y as i32 as i64); value.clamp(-1000000,1000000) as u32 }",
    "byte_window_checksum": "fn target(x:u32,y:u32)->u32 { let mut h=2166136261u32; let start=(y>>3)%4; for i in 0..y%5 { let byte=(x>>(8*((start+i)%4)))&255; h=(h^byte).wrapping_mul(16777619); } h }",
    "run_length_flags": "fn target(x:u32,y:u32)->u32 { let mut previous=0; let mut ones=0; let mut runs=0; for i in 0..y%17 { let bit=(x>>i)&1; ones+=bit; runs+=bit*(1-previous); previous=bit; } (runs<<16)|ones }",
    "mutate_borrow": "fn task_step(view:&mut Vec<u8>,x:u32,y:u32)->u32 { let index=((x^y) as usize)%view.len(); view[index]=(x>>3).wrapping_add(y) as u8; view[index] as u32 }",
    "return_borrow": "fn task_step<'a>(view:&'a mut Vec<u8>,x:u32,y:u32)->&'a mut Vec<u8> { let index=((y>>2) as usize)%view.len(); view[index]=x.wrapping_add(y.wrapping_mul(3)) as u8; view }",
    "conditional_release": "fn target(x:u32,y:u32)->u32 { let n=(8+x%9) as usize; let mut data=vec![0u8;n]; if y&1!=0 { return 0; } data[n-1]=(x^y) as u8; 256*n as u32+data[n-1] as u32 }",
}


def reference(task_id, language):
    if language == "rust":
        return RUST_REFERENCES[task_id]
    if language != "hia-v8-text":
        raise ValueError("unknown language")
    from hepta.hia_agent_assembly import render_assembly
    return render_assembly(reference_core(task_id))


def rust_wrapper(task_id):
    if task_id == "mutate_borrow":
        return """pub fn invoke(x:u32,y:u32)->u32 {
            let helper:fn(&mut Vec<u8>,u32,u32)->u32=task_step;
            let n=(3+x%11) as usize; let mut data=vec![0u8;n];
            super::audited::helper_begin(); let value=helper(&mut data,x,y); super::audited::helper_end(); let actual=data[((x^y) as usize)%n] as u32;
            assert!(value==actual); drop(data); 256*n as u32+actual
        }"""
    if task_id == "return_borrow":
        return """pub fn invoke(x:u32,y:u32)->u32 {
            let helper:for<'a> fn(&'a mut Vec<u8>,u32,u32)->&'a mut Vec<u8>=task_step;
            let n=(5+x%7) as usize; let mut data=vec![0u8;n]; let index=((y>>2) as usize)%n;
            super::audited::helper_begin(); let returned=helper(&mut data,x,y); super::audited::helper_end(); let first=returned[index];
            returned[index]=first^165; let value=returned[index] as u32;
            drop(data); 256*n as u32+value
        }"""
    return "pub fn invoke(x:u32,y:u32)->u32 {let exact:fn(u32,u32)->u32=target;exact(x,y)}"
