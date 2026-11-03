"""Reference interpreter for the bounded single-block HIA pilot.

Does not implement asynchronous cancellation, native stack, external failures,
physical RSS, program-wide scheduling or general Rust resource semantics.
"""
from __future__ import annotations

from dataclasses import asdict,dataclass
from .core import Verified, Refused, NUMBERS, _value, readmit

@dataclass(frozen=True)
class RunReceipt:
    status: str
    results: tuple
    code: str | None
    ticks: int
    allocations: int
    live_bytes: int
    peak_bytes: int
    events: tuple
    core_digest: str

    def json(self):
        return asdict(self)

def run(v: Verified, inputs: list, *, max_ticks: int=100000,
        max_heap_bytes: int=1048576, fail_allocation_at: int | None=None) -> RunReceipt:
    v=readmit(v)
    if not 1 <= max_ticks <= 100000 or not 0 <= max_heap_bytes <= 1048576:
        raise Refused("E_POLICY","invalid bounded runtime policy")
    if fail_allocation_at is not None and (type(fail_allocation_at) is not int or not 1<=fail_allocation_at<=1025):
        raise Refused("E_POLICY","allocation-failure index out of range")
    fn=v.unpack()["function"]
    if type(inputs) is not list or len(inputs)!=len(fn["params"]):
        raise Refused("E_INVOCATION","wrong argument count")
    data={}
    for p,x in zip(fn["params"],inputs):
        t=p["type"]
        if not _value(x,t):
            raise Refused("E_INVOCATION","scalar not representable in parameter type")
        data[p["name"]]=x
    heap={}; names={}; loans={}; events=[]
    allocations=0; live_bytes=0; peak=0; ticks=0
    def report(status, result=(), code=None):
        return RunReceipt(status,tuple(result),code,ticks,allocations,live_bytes,peak,tuple(events),v.core_digest)
    class Trap(Exception):
        def __init__(self,code): self.code=code
    def buf(name):
        if name in names:
            return heap[names[name]]
        if name in loans and loans[name][2]:
            return heap[loans[name][0]]
        raise Trap("stale_handle")
    def alloc(name,amount,fallible):
        nonlocal allocations,live_bytes,peak
        allocations+=1
        failed=(fail_allocation_at == allocations or live_bytes+amount>max_heap_bytes)
        if failed and not fallible:
            events.append("alloc_fail")
            raise Trap("allocation")
        payload=bytearray(0 if failed else amount)
        heap[name]=payload
        names[name]=name
        live_bytes += len(payload)
        peak=max(peak,live_bytes)
        events.append("alloc_fail_empty" if failed else f"alloc:{len(payload)}")
        return not failed
    for op in fn["ops"]:
        if ticks >= max_ticks:
            return report("budget_stop",code="max_ticks")
        ticks+=1
        name=op["op"]; a=[data.get(x,x) for x in op["args"]]
        output=[x["name"] for x in op["out"]]
        t=op["out"][0]["type"] if output else None
        try:
            if name=="const":
                data[output[0]]=op["value"]
            elif name=="scalar.copy":
                data[output[0]]=a[0]
            elif name in {"int.add.wrap","int.sub.wrap","int.xor","int.add.checked"}:
                x,y=a
                if name in {"int.add.wrap","int.add.checked"}: z=x+y
                elif name=="int.sub.wrap": z=x-y
                else: z=x^y
                if name=="int.add.checked" and z >= (1<<NUMBERS[t]):
                    raise Trap("overflow")
                data[output[0]]=z & ((1<<NUMBERS[t])-1)
            elif name in {"buffer.new","buffer.try_new"}:
                ok=alloc(output[0],a[0],name=="buffer.try_new")
                if name=="buffer.try_new": data[output[1]]=ok
            elif name=="buffer.len":
                data[output[0]]=len(buf(op["args"][0]))
            elif name in {"borrow.read","borrow.mut"}:
                src=op["args"][0]; key=names[src]
                loans[output[0]]=(key,"mut" if name=="borrow.mut" else "read",True)
                events.append("loan_mut" if name=="borrow.mut" else "loan_read")
            elif name=="buffer.load":
                target=buf(op["args"][0]); idx=a[1]
                if idx>=len(target): raise Trap("bounds")
                data[output[0]]=target[idx]
                events.append("load")
            elif name=="buffer.store":
                target=buf(op["args"][0]); idx=a[1]; byte=a[2]
                if idx>=len(target): raise Trap("bounds")
                target[idx]=byte
                events.append("store")
            elif name=="loan.end":
                src=op["args"][0]; old=loans[src]
                loans[src]=(old[0],old[1],False)
                events.append("loan_end")
            elif name=="owner.move":
                src=op["args"][0]; key=names.pop(src)
                names[output[0]]=key
                events.append("owner_move")
            elif name=="owner.drop":
                src=op["args"][0]; key=names.pop(src)
                amount=len(heap.pop(key));live_bytes-=amount
                events.append(f"drop:{amount}")
            else:
                raise Refused("E_UNREACHABLE","verified catalog contained unsupported opcode")
        except Trap as ex:
            events.append(f"trap:{ex.code}")
            return report("trap",code=ex.code)
    if ticks >= max_ticks:
        return report("budget_stop",code="max_ticks")
    ticks+=1
    end=fn["end"]
    if end["op"]=="ret": return report("return",[data[k] for k in end["args"]])
    if end["op"]=="cancel": return report("cancel",code=end["code"])
    return report("trap",code=end["code"])
