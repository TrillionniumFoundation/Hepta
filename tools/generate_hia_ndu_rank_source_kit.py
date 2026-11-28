"""Author an independent NDU source-kit transport for original rank packet bounds.

The original generic source-build template remains byte-for-byte unchanged.
This explicit profile keeps the original 1 MiB compiled-image/compiler workspace,
the original 64 MiB syscall wire bound, and the NDU policy's existing 32 MiB input
and 16 MiB output bounds. Its separate frame reservation carries the complete
native engine/proof packet instead of the generic three-object staging window.
Only this generated HIA packer is consumed by installed release/rebuild.
"""
from pathlib import Path
from hashlib import sha256
from types import FunctionType
from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_source_build as original
ROOT=Path(__file__).resolve().parents[1]
OUTPUT="examples/hia_bootstrap/ndu_rank_source_kit_packer.hepta"
POLICY_OUTPUT="examples/hia_bootstrap/source_ndu_rank_release_kit.hepta"
POLICY_ORIGINAL="examples/hia_bootstrap/source_release_kit.hepta"
POLICY_PIN="c7f634307652438f8fa4ded55d6a16fd018adb74b77526de49bdfaefd21c962b"
ORIGINALS={
 "tools/generate_hia_source_build.py":"00c50ee8bdcfaa7ea94cd0458b361da734dcfed3d47ce61865ff89fad44e0f00",
 "tools/hia_source_build_syscalls.S":"2170b208f14766b7c851dfc776fca618f691a11621fd85a6f254f00fb7f7f9fa",
}
FRAME_BYTES=32<<20

def capture():
    raw={name:(ROOT/name).read_bytes()for name in ORIGINALS}
    if any(sha256(raw[name]).hexdigest()!=pin for name,pin in ORIGINALS.items()):
        raise ValueError("fixed original source-build transport differs")
    return raw

def layout():
    values=dict(original.LAYOUT)
    if (original.IMAGE_LIMIT,original.COMPILER_WORK_BYTES,original.WIRE_LIMIT,
            values["FRAME_CAP"])!=(1<<20,1<<20,64<<20,3*(1<<20)+4096):
        raise ValueError("original source-build capacities differ")
    values["FRAME_CAP"]=FRAME_BYTES
    values["OUT"]=values["FRAME"]+values["FRAME_CAP"]
    values["WIRE"]=values["OUT"]+original.WIRE_LIMIT
    values["MAPSIZE"]=values["WIRE"]+values["WIRE_CAP"]
    return values

def current_template():
    return FunctionType(original.template.__code__,
                        {**original.template.__globals__,"LAYOUT":layout()})()

def render():
    before=capture()
    # These are the exact original function code objects with explicit local
    # globals; no process-global mutation of the original author is performed.
    template=FunctionType(original.template.__code__,
                          {**original.template.__globals__,"LAYOUT":layout()})
    packer=FunctionType(original.packer_source.__code__,
                        {**original.packer_source.__globals__,"template":template})
    source=packer()
    raw=render_assembly(original.document(source,"ndu_rank_source_kit_packer")).encode()
    if capture()!=before:
        raise ValueError("source-build transport changed during NDU authoring")
    return raw

def composer_source():
    """Keep complete original admission; bind only the distinct fixed template."""
    import re
    before=capture()
    prior=(ROOT/POLICY_ORIGINAL).read_bytes()
    if sha256(prior).hexdigest()!=POLICY_PIN:
        raise ValueError("fixed original source-kit policy differs")
    old,old_holes=original.template()
    current,current_holes=current_template()
    if len(old)!=len(current) or old_holes!=current_holes:
        raise ValueError("NDU template changed its original instruction geometry")
    text=prior.decode("ascii")
    start=text.index("\nfn f3(");stop=text.index("\nfn f4(",start)
    function=text[start:stop]
    covered=set();changed=[]
    blocks=re.split(r"(?=^block )",function,flags=re.M)
    for index,block in enumerate(blocks):
        constants={m.group(1):int(m.group(2)) for m in re.finditer(
            r"^  (v[0-9]+):u64 = const\(\) \{\"value\":([0-9]+)\}$",block,re.M)}
        calls=list(re.finditer(
            r"^  (v[0-9]+):u64 = call\(v[0-9]+,(v[0-9]+),(v[0-9]+)\) \{\"function\":\"f11\"\}\n"
            r"  (v[0-9]+):u64 = const\(\) \{\"value\":([0-9]+)\}\n"
            r"  v[0-9]+:bool = compare.ne\(\1,\4\)$",block,re.M))
        for call in reversed(calls):
            if call.group(2) not in constants or call.group(3) not in constants:
                raise ValueError("nonconstant template comparison")
            at=constants[call.group(2)];size=constants[call.group(3)]
            if size not in (1,2,3,4,5,6,7,8) or not 0<=at<=len(old)-size:
                raise ValueError("template comparison outside original prefix")
            expected=int(call.group(5))
            if int.from_bytes(old[at:at+size],"little")!=expected:
                raise ValueError("original fixed template comparison mismatch")
            covered.update(range(at,at+size))
            value=int.from_bytes(current[at:at+size],"little")
            if value!=expected:
                a,b=call.span(5);block=block[:a]+str(value)+block[b:]
                changed.append({"offset":at,"bytes":size,"old":expected,"current":value})
        blocks[index]=block
    differences={i for i,(a,b) in enumerate(zip(old,current,strict=True)) if a!=b}
    if not differences or not differences<=covered or not changed:
        raise ValueError("distinct template bytes are not fully checked")
    candidate=text[:start]+"".join(blocks)+text[stop:]
    old_header="hia-asm.v1 hepta.hia.program.v8 source_release_kit\n"
    if not candidate.startswith(old_header):
        raise ValueError("original source-kit header differs")
    candidate="hia-asm.v1 hepta.hia.program.v8 source_ndu_rank_release_kit\n"+candidate[len(old_header):]
    if capture()!=before or (ROOT/POLICY_ORIGINAL).read_bytes()!=prior:
        raise ValueError("source-kit authoring input changed")
    return candidate.encode("ascii"),{
        "original_policy_sha256":POLICY_PIN,
        "original_template_sha256":sha256(old).hexdigest(),
        "current_template_sha256":sha256(current).hexdigest(),
        "template_bytes":len(old),"holes":old_holes,
        "changed_bytes":len(differences),"exact_word_changes":changed}

if __name__=="__main__":
    raw=render();(ROOT/OUTPUT).write_bytes(raw)
    policy,review=composer_source();(ROOT/POLICY_OUTPUT).write_bytes(policy)
    print(OUTPUT,len(raw),sha256(raw).hexdigest())
    print(POLICY_OUTPUT,len(policy),sha256(policy).hexdigest())
    import json
    print(json.dumps(review,sort_keys=True))
