"""Explicit guarded reads for captured private native control-policy input.

Only the master and construction authors select this transform. Their readbuf
contents remain stable during each synchronous policy invocation; their source
capture, descriptor checks, repeated readback and scheduler remain unchanged.
"""
import ast
from hashlib import sha256

ORIGINAL_UINT_SHA256 = '3375566470419052969eeaf06df5b7d80a873251be8f2b3ae6fd4659162b4394'


def guarded_u64_read(source):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == "uint"]
    if len(nodes) != 1:
        raise ValueError("guarded cold read requires one original uint helper")
    node = nodes[0]
    original = ast.get_source_segment(source, node)
    if sha256(original.encode()).hexdigest() != ORIGINAL_UINT_SHA256:
        raise ValueError("original cold uint helper changed or was already guarded")
    lines = original.splitlines()
    prefix = ("    if count == 8 and at <= length(s) and 8 <= length(s) - at:\n"
              "        return word_load(s, at)\n")
    replacement = lines[0] + "\n" + prefix + "\n".join(lines[1:])
    return source.replace(original, replacement, 1)
