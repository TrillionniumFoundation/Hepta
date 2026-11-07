"""Pure builders for test fixtures; never trusted as a verifier."""
from .core import SCHEMA

def op(name,arguments=(),results=(),**attrs):
    return {"op":name,"args":list(arguments),"out":[{"name":n,"type":t} for n,t in results],**attrs}

def scalar(name="sample",args=(('x','u32'),),ops=(),results=("u32",),returns=("x",),effects=()):
    return {"schema":SCHEMA,"module":"candidate","function":{
        "name":name,"params":[{"name":n,"type":t} for n,t in args],
        "returns":list(results),"effects":list(effects),"ops":list(ops),
        "end":{"op":"ret","args":list(returns)}}}
