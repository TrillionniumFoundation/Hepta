"""Source fixtures for the native, bounded direct-call graph extension.

These are ordinary source bytes, never machine-code dispatch entries. Expected
outcomes are checked by the independent Core checker and native execution.
"""
from __future__ import annotations


HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")


def backward_bytesum_source(sample):
    return sample.replace(b'{"function":"f1"}', b'{"function":"f2"}', 1) + (
        b"fn f2(v0:u32,v1:u8) -> (u32) effects(read,write,trap) entry(b0)\n"
        b"block b0(v0:u32,v1:u8)\n"
        b'  v2:u32 = call(v0,v1) {"function":"f1"}\n'
        b"  ret(v2)\nend\n")


def scalar_function(number, target=None):
    prefix = (f"fn f{number}(v0:u32) -> (u32) effects(read,write,trap) entry(b0)\n"
              "block b0(v0:u32)\n")
    if target is None:
        return prefix + "  ret(v0)\nend\n"
    return (prefix + '  v1:u32 = const() {"value":1}\n'
            '  v2:u32 = int.add.wrap(v0,v1)\n'
            f'  v3:u32 = call(v2) {{"function":"f{target}"}}\n'
            "  ret(v3)\nend\n")


def backward_chain_source(function_count=128):
    if not 2 <= function_count <= 128:
        raise ValueError("the fixed profile admits at most 128 functions")
    source = (HEADER + '  v3:u32 = const() {"value":1}\n'
              f'  v4:u32 = call(v3) {{"function":"f{function_count - 1}"}}\n'
              "  ret(v4)\nend\n")
    source += scalar_function(1)
    for number in range(2, function_count):
        source += scalar_function(number, number - 1)
    return source.encode()


def recursion_refusals():
    root = (HEADER + '  v3:u32 = const() {"value":0}\n'
            '  v4:u32 = call(v3) {"function":"f1"}\n  ret(v4)\nend\n')
    unused = HEADER + '  v3:u32 = const() {"value":7}\n  ret(v3)\nend\n'
    return {
        "direct-recursion": (root + scalar_function(1, 1)).encode(),
        "mutual-recursion": (root + scalar_function(1, 2) + scalar_function(2, 1)).encode(),
        "unreachable-cycle": (unused + scalar_function(1, 2) + scalar_function(2, 1)).encode(),
    }


def call_graph_invalid_sources(sample):
    backward = backward_bytesum_source(sample)
    return {
        "backward-signature": backward.replace(b"call(v0,v1)", b"call(v1,v0)"),
        "missing-in-range-callee": backward.replace(b'{"function":"f1"}', b'{"function":"f127"}'),
        "out-of-range-callee": backward.replace(b'{"function":"f1"}', b'{"function":"f128"}'),
        "overflow-callee": backward.replace(b'{"function":"f1"}', b'{"function":"f18446744073709551615"}'),
    }
