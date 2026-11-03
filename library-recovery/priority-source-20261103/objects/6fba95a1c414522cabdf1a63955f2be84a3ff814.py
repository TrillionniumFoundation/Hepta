"""One sound-by-explicit-algebra rewrite candidate, not generic SMT/LLVM refinement."""
from __future__ import annotations
from dataclasses import dataclass
from .core import Verified, Refused, verify, NUMBERS, readmit
from .runtime import run

@dataclass(frozen=True)
class TransformReceipt:
    rule: str
    source_digest: str
    candidate_digest: str
    candidate: Verified
    test_vectors: int
    notes: str

def eliminate_wrapping_add_zero(source: Verified) -> TransformReceipt | None:
    """For uN and constant zero, x+0 modulo 2**N == x for every uN.

    This rule has no resource operations, side effects or possible trap. It is
    *not* a proof of arbitrary backend equivalence or all optimizations.
    """
    source=readmit(source)
    doc=source.unpack()
    const_zero={}
    changed=False
    for instr in doc["function"]["ops"]:
        if instr["op"]=="const" and instr["value"]==0:
            const_zero[instr["out"][0]["name"]]=instr["out"][0]["type"]
        if instr["op"]=="int.add.wrap":
            a,b=instr["args"]
            t=instr["out"][0]["type"]
            if a in const_zero and const_zero[a]==t: preserve=b
            elif b in const_zero and const_zero[b]==t: preserve=a
            else: continue
            instr["op"]="scalar.copy"
            instr["args"]=[preserve]
            changed=True
    if not changed:
        return None
    # Pure dead literal elimination is necessary when the changed add was the
    # only use. Without it the generated native C fails strict -Werror, even
    # though the Core is otherwise well typed and behavior-preserving.
    live_names=set(doc["function"]["end"].get("args",[]))
    for instr in doc["function"]["ops"]:
        live_names.update(instr["args"])
    doc["function"]["ops"]=[instr for instr in doc["function"]["ops"]
        if not (instr["op"]=="const" and instr["out"][0]["name"] not in live_names)]
    candidate=verify(doc)
    fn=doc["function"]
    samples=[0,1,2,127,128,255,256,65535,2**32-1,2**64-1]
    n=0
    for first in fn["params"]:
        if first["type"] not in NUMBERS: continue
        for x in samples:
            if x >= 1<<NUMBERS[first["type"]]: continue
            if len(fn["params"])!=1: continue
            before=run(source,[x]); after=run(candidate,[x]); n+=1
            if (before.status,before.results,before.code,before.events)!=(after.status,after.results,after.code,after.events):
                raise Refused("E_TRANSFORM", "finite differential witness rejected candidate")
    return TransformReceipt("uN_wrapping_add_zero",source.core_digest,candidate.core_digest,candidate,n,
        "algebraic single-op equality in the verified integer domain; no native refinement claim")
