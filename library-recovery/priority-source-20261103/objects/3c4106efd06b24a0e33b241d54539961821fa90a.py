"""Bounded HIA pilot semantics. Separate from production Hepta; no authority claim.

The catalog is data, but typing/ownership rules here are a deliberately tiny
finite verifier. No external program, model or NDU receipt can bypass it.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
import re
from typing import Any

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "spec" / "opcodes.v1.json"
IDENT = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]{0,63}$")
NUMBERS = {"u8":8,"u32":32,"u64":64}
SCALARS = frozenset((*NUMBERS, "bool"))
RESOURCE_TYPES = frozenset({"buffer", "readbuf", "mutbuf"})
SCHEMA = "hepta.hia.pilot.scalar-owned.v1"

class Refused(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

def _no_duplicate(pairs):
    obj = {}
    for key,value in pairs:
        if key in obj:
            raise Refused("E_DUPLICATE_FIELD", f"duplicate JSON key {key}")
        obj[key] = value
    return obj

def _reject_float(_):
    raise Refused("E_FLOAT", "float or nonstandard JSON number is unsupported")

def _depth(obj, current=0):
    if current > 32:
        raise Refused("E_DEPTH", "nested input exceeds depth bound")
    if type(obj) is dict:
        for val in obj.values(): _depth(val,current+1)
    elif type(obj) is list:
        for val in obj: _depth(val,current+1)

def decode_bytes(data: bytes | str) -> dict:
    if type(data) is str:
        data = data.encode("utf-8", "strict")
    if type(data) is not bytes or len(data) > 262144:
        raise Refused("E_SOURCE_BUDGET", "source input must be <=256KiB bytes")
    try:
        obj = json.loads(data.decode("utf-8","strict"), object_pairs_hook=_no_duplicate,
                         parse_float=_reject_float, parse_constant=_reject_float)
    except Refused:
        raise
    except (UnicodeError,ValueError) as exc:
        raise Refused("E_JSON", "invalid strict JSON input") from exc
    _depth(obj)
    if type(obj) is not dict:
        raise Refused("E_JSON", "Core must be a JSON object")
    return obj

def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,allow_nan=False,
                      separators=(",",":")).encode("utf-8")

def catalog():
    return decode_bytes(_CATALOG_PATH.read_bytes())

def catalog_digest():
    return sha256(canonical_bytes(catalog())).hexdigest()

def _keys(obj: Any, required: set, code="E_SCHEMA", optional=frozenset()):
    if type(obj) is not dict or not required <= set(obj) or set(obj) - required - optional:
        raise Refused(code,"unknown or missing fields")

def _id(s):
    if type(s) is not str or not IDENT.fullmatch(s):
        raise Refused("E_NAME", "invalid or oversized identifier")
    return s

def _type(s):
    if type(s) is not str or s not in SCALARS | RESOURCE_TYPES:
        raise Refused("E_TYPE", "unsupported declared type")
    return s

def _value(v,t):
    if t == "bool":
        return type(v) is bool
    return type(v) is int and 0 <= v < (1 << NUMBERS[t])

@dataclass(frozen=True)
class Verified:
    core_bytes: bytes
    core_digest: str
    catalog_digest: str
    effects: tuple[str,...]

    def unpack(self) -> dict:
        # Each consumer gets a new immutable-source snapshot.
        return decode_bytes(self.core_bytes)

def verify(source: dict | bytes | str) -> Verified:
    raw = canonical_bytes(source) if type(source) is dict else source
    obj = decode_bytes(raw)
    _keys(obj,{"schema","module","function"})
    if obj["schema"] != SCHEMA:
        raise Refused("E_VERSION", "explicit registered Core schema required")
    _id(obj["module"])
    fn=obj["function"]
    _keys(fn,{"name","params","returns","effects","ops","end"})
    _id(fn["name"])
    if type(fn["params"]) is not list or len(fn["params"]) > 16:
        raise Refused("E_PARAMS","too many parameters")
    values = {}
    owner = {}  # resource name -> live/moved/dropped
    loans = {}  # loan name -> (owning buffer name, permission, active)
    for p in fn["params"]:
        _keys(p,{"name","type"})
        n=_id(p["name"]); t=_type(p["type"])
        if t not in SCALARS or n in values:
            raise Refused("E_PARAMS","params must be unique scalar inputs")
        values[n]=t
    if (type(fn["returns"]) is not list or len(fn["returns"])>4 or
        not all(type(t) is str and t in SCALARS for t in fn["returns"])):
        raise Refused("E_RETURNS","only <=4 scalar returns supported")
    if type(fn["ops"]) is not list or len(fn["ops"])>1024:
        raise Refused("E_OP_BUDGET", "too many operations")
    declared_effects=fn["effects"]
    if (type(declared_effects) is not list or not all(type(t) is str for t in declared_effects)
        or len(set(declared_effects))!=len(declared_effects)):
        raise Refused("E_EFFECT","effects must be unique strings")
    op_specs={o["name"]:o for o in catalog()["operations"]}
    observed=set()
    def typ(n):
        if type(n) is not str or n not in values:
            raise Refused("E_UNBOUND", "operand must be defined before use")
        return values[n]
    def owners_available(n):
        if typ(n) != "buffer" or owner[n] != "live":
            raise Refused("E_OWNER", "owner is no longer available")
        return n
    def active_loans(n):
        return [v for v in loans.values() if v[0] == n and v[2]]
    def define(outs, expected):
        if type(outs) is not list or len(outs)!=len(expected):
            raise Refused("E_ARITY", "operation result count mismatch")
        for x,t in zip(outs,expected):
            _keys(x,{"name","type"})
            n=_id(x["name"])
            if n in values or x["type"] != t:
                raise Refused("E_SSA", "SSA names must be unique and types exact")
            values[n]=t
    for op in fn["ops"]:
        _keys(op,{"op","args","out"},optional={"value"})
        name=op["op"]
        if type(name) is not str or name not in op_specs:
            raise Refused("E_OPCODE","unregistered operation")
        if type(op["args"]) is not list or any(type(s) is not str for s in op["args"]):
            raise Refused("E_ARGS","operands must be SSA names")
        if (set(op)-{"op","args","out"}) != set(op_specs[name]["attributes"]):
            raise Refused("E_ATTRIBUTES","opcode attributes mismatch")
        observed.update(op_specs[name]["effects"])
        args=op["args"]; outs=op["out"]
        def req(count):
            if len(args)!=count:
                raise Refused("E_ARITY","operand count mismatch")
        if name=="const":
            req(0)
            if type(outs) is not list or len(outs)!=1 or type(outs[0]) is not dict:
                raise Refused("E_ARITY","literal requires one result")
            t=outs[0].get("type")
            if type(t) is not str or t not in SCALARS or not _value(op["value"],t):
                raise Refused("E_LITERAL","literal not representable in declared type")
            define(outs,[t])
        elif name == "scalar.copy":
            req(1); t=typ(args[0])
            if t not in SCALARS: raise Refused("E_TYPE","copy requires scalar")
            define(outs,[t])
        elif name in {"int.add.wrap","int.sub.wrap","int.xor","int.add.checked"}:
            req(2); t=typ(args[0])
            if t not in NUMBERS or typ(args[1])!=t:
                raise Refused("E_TYPE","integer operands must have equal width")
            define(outs,[t])
        elif name in {"buffer.new","buffer.try_new"}:
            req(1)
            if typ(args[0]) != "u32":
                raise Refused("E_TYPE","buffer length requires u32")
            define(outs,["buffer"] if name=="buffer.new" else ["buffer","bool"])
            owner[outs[0]["name"]] = "live"
        elif name == "buffer.len":
            req(1); t=typ(args[0])
            if t == "buffer":
                owners_available(args[0])
                if any(x[1]=="mut" for x in active_loans(args[0])):
                    raise Refused("E_BORROW","owner cannot be read during exclusive loan")
            elif t in {"readbuf","mutbuf"}:
                if not loans[args[0]][2]: raise Refused("E_LOAN","loan ended")
            else: raise Refused("E_TYPE","length requires buffer or loan")
            define(outs,["u32"])
        elif name in {"borrow.read","borrow.mut"}:
            req(1); n=owners_available(args[0]); act=active_loans(n)
            if name=="borrow.mut" and act or name=="borrow.read" and any(x[1]=="mut" for x in act):
                raise Refused("E_ALIAS","borrow conflicts with active loan")
            expected="mutbuf" if name=="borrow.mut" else "readbuf"
            define(outs,[expected]); loans[outs[0]["name"]] = (n,"mut" if expected=="mutbuf" else "read",True)
        elif name == "buffer.load":
            req(2)
            if typ(args[0]) not in {"readbuf","mutbuf"} or not loans[args[0]][2] or typ(args[1])!="u32":
                raise Refused("E_LOAN","load requires live loan and u32 index")
            define(outs,["u8"])
        elif name == "buffer.store":
            req(3)
            if typ(args[0])!="mutbuf" or not loans[args[0]][2] or typ(args[1])!="u32" or typ(args[2])!="u8":
                raise Refused("E_LOAN","store requires live exclusive loan, u32 index, u8 value")
            define(outs,[])
        elif name == "loan.end":
            req(1)
            if typ(args[0]) not in {"readbuf","mutbuf"} or not loans[args[0]][2]:
                raise Refused("E_LOAN","loan is not live")
            define(outs,[])
            n,perm,_=loans[args[0]]; loans[args[0]]=(n,perm,False)
        elif name in {"owner.move","owner.drop"}:
            req(1); n=owners_available(args[0])
            if active_loans(n):
                raise Refused("E_LOAN","cannot move or drop borrowed owner")
            define(outs,["buffer"] if name=="owner.move" else [])
            owner[n]="moved" if name=="owner.move" else "dropped"
            if name=="owner.move": owner[outs[0]["name"]]="live"
    end=fn["end"]
    _keys(end,{"op","args"},optional={"code"})
    if type(end["op"]) is not str or end["op"] not in {"ret","trap","cancel"} or type(end["args"]) is not list:
        raise Refused("E_TERMINATOR","invalid terminator")
    if end["op"]=="ret":
        if "code" in end or len(end["args"])!=len(fn["returns"]):
            raise Refused("E_RETURNS","return arity mismatch")
        for name,t in zip(end["args"],fn["returns"]):
            if typ(name)!=t:
                raise Refused("E_RETURNS","returned scalar type mismatch")
    else:
        if end["args"] or type(end.get("code")) is not str or len(end["code"])>40 or not IDENT.fullmatch(end["code"]):
            raise Refused("E_TERMINATOR","trap/cancel needs stable code")
        if end["op"] == "trap": observed.add("trap")
        else: observed.add("cancel")
    if any(status=="live" for status in owner.values()) or any(t[2] for t in loans.values()):
        raise Refused("E_RESOURCE_EXIT","owner and loan must be explicitly settled at block exit")
    if set(declared_effects)!=observed:
        raise Refused("E_EFFECT","declared effects must exactly match instruction effects")
    core=canonical_bytes(obj)
    return Verified(core,sha256(core).hexdigest(),catalog_digest(),tuple(sorted(observed)))


def readmit(v: Verified) -> Verified:
    """Public receipts are never authority: check frozen bytes and catalog anew."""
    if type(v) is not Verified:
        raise Refused("E_ADMISSION", "Verified instance required")
    fresh=verify(v.core_bytes)
    if fresh != v:
        raise Refused("E_RECEIPT", "forged, stale, or source-mismatched verifier receipt")
    return fresh
