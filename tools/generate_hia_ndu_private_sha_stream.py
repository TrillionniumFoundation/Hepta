"""Private canonical nonalias SHA stream for the NDU proof/context owners.

The public SHA transition and its arbitrary-state/alias contract are unchanged.
This private role is called only with disjoint slices held by the fixed HIA
owners. Its complete streaming state, guards and padding use the old ABI; the
canonical chaining and round constants are checked before each continuation.
Compression retains the existing SHA schedule and all 64 rounds, with an explicit
canonical-state-only eight-round loop with compile-time rotation of local names.
"""
from pathlib import Path
from hashlib import sha256
import ast, copy
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools import generate_hia_sha256_stream as original
from tools import generate_hia_native_scalar_proof_hash as private
from tools.generate_hia_sha256 import ROUND

ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_sha_stream_private.hepta"
ORIGINAL_SHA256="96beba869c4b7f692b3f79e41a68aa59771ada6af849240b60526968cdf7f58b"
COMPRESSION_SHA256="b9fd3a97ae237932f9408ea7423f685a056c751dc8acdb7520aaa101605196d3"


class Builder(private.Builder):
    def expr(self,node):
        if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                and node.func.id=="word_load" and len(node.args)==2
                and not node.keywords and isinstance(node.args[1],ast.Constant)
                and type(node.args[1].value) is int and 0<=node.args[1].value<=1184):
            # This author-only literal is already an exact native usize.
            # Keep the same checked load; omit its redundant wrapping cast.
            view=self.expr(node.args[0])
            offset=self.c(node.args[1].value,"usize")
            return self.op("buffer.load.u64.le",[view,offset],"u64")
        if (isinstance(node,ast.Call) and isinstance(node.func,ast.Name)
                and node.func.id=="word_store" and len(node.args)==3
                and not node.keywords and isinstance(node.args[1],ast.Constant)
                and type(node.args[1].value) is int and 0<=node.args[1].value<=1184):
            view=self.expr(node.args[0]);offset=self.c(node.args[1].value,"usize")
            value=self.expr(node.args[2])
            return self.op("buffer.store.u64.le",[view,offset,self.cast(value,"u64")])
        return super().expr(node)


def _compression_source():
    nodes=copy.deepcopy(ast.parse(private.COMPRESSION_SOURCE).body)
    compression=next(n for n in nodes if n.name=="compress")
    at=next(i for i,n in enumerate(compression.body)
            if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)
            and n.targets[0].id=="a")
    schedule=copy.deepcopy(compression);schedule.name="prepare_schedule"
    schedule.body=compression.body[:at]+[ast.Return(ast.Constant(0))]
    # Eight exact rounds fit one compact native loop. Compile-time name rotation
    # removes the six intermediate state copies; all 64 round constants remain
    # checked by the stream and read from its original canonical state.
    lines=["def compress(w:mutbuf)->u64:","    prepare_schedule(w)"]
    for i,name in enumerate("abcdefgh"):lines.append(f"    {name}=word_load(w,{1024+i*8})")
    lines+=["    i=0","    while i<64:","        round_at=i*8"]
    state=list("abcdefgh")
    for index in range(8):
        a,b,c,d,e,f,g,h=state
        statements=f"""cold_e={e}*4294967297
s1=(cold_e>>6)^(cold_e>>11)^(cold_e>>25)
choose_bits={g}^({e}&({f}^{g}))
t1={h}+s1+choose_bits+word_load(w,round_at+{index*8})+word_load(w,round_at+{512+index*8})
cold_a={a}*4294967297
s0=(cold_a>>2)^(cold_a>>13)^(cold_a>>22)
majority=({a}&{b})|({c}&({a}|{b}))
t2=s0+majority
{d}=({d}+t1)&4294967295
{h}=(t1+t2)&4294967295"""
        lines.extend("        "+v for v in statements.splitlines());state=[h,a,b,c,d,e,f,g]
    assert state==list("abcdefgh");lines.append("        i=i+8")
    for i,name in enumerate(state):
        lines.append(f"    word_store(w,{1024+8*i},(word_load(w,{1024+8*i})+{name})&4294967295)")
    lines.append("    return 0")
    nodes[nodes.index(compression)]=ast.parse("\n".join(lines)).body[0];nodes.append(schedule)
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])))+"\n"

def source_program():
    captured={Path(original.__file__):ORIGINAL_SHA256,Path(private.__file__):COMPRESSION_SHA256}
    if any(sha256(p.read_bytes()).hexdigest()!=pin for p,pin in captured.items()):
        raise ValueError("private NDU SHA source relation differs")
    stream=copy.deepcopy(next(n for n in ast.parse(original.source_program()).body
                              if isinstance(n,ast.FunctionDef) and n.name=="stream"))
    update=next(n for n in stream.body if isinstance(n,ast.If) and ast.unparse(n.test)=="op == 1")
    loop=next(n for n in update.body if isinstance(n,ast.While))
    assert ast.unparse(loop.test)=="i < length(s)"
    fast=[]
    for at in range(0,64,8):
        fast.extend(ast.parse(f"word_store(w, {1112+at}, word_load(s, i + {at}))").body)
    fast.extend(ast.parse("compress(w)\ni = i + 64").body)
    loop.body=[ast.If(test=ast.parse("used == 0 and length(s) - i >= 64",mode="eval").body,
                     body=fast,orelse=loop.body)]
    checks=[]
    for index,value in enumerate(ROUND):
        checks.extend(ast.parse(f"if get(w, {index*8}) != {value}:\n    return 4294967293").body)
    checks.extend(ast.parse("private_i = 0\nwhile private_i < 8:\n    if get(w, 1024 + 8 * private_i) > 4294967295:\n        return 4294967293\n    private_i = private_i + 1").body)
    at=stream.body.index(next(n for n in stream.body if isinstance(n,ast.Assign)
                              and isinstance(n.targets[0],ast.Name) and n.targets[0].id=="total"))
    stream.body[at:at]=checks
    result=ast.unparse(ast.fix_missing_locations(stream))+"\n\n"+_compression_source()
    if any(sha256(p.read_bytes()).hexdigest()!=pin for p,pin in captured.items()):
        raise ValueError("private NDU SHA source changed during generation")
    return result

def program():
    nodes=ast.parse(source_program()).body
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
                          "returns":[b.returns],"effects":["read","write","trap"],
                          "entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v9",
                                  "module":"ndu_rank_sha_stream_private","functions":functions})

def render():
    return render_assembly(program()).encode()

if __name__=="__main__":
    raw=render();(ROOT/OUTPUT).write_bytes(raw)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
