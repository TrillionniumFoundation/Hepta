"""Independent general-Core fixtures for owned buffers and recursive chains.

These are input/reference fixtures, not additions to Selfhost-Core's admitted
inventory.  They use the existing canonical verifier/interpreter, including
distinct allocation-failure injection and evaluator-budget observations.
"""
from __future__ import annotations


def program(body, returns, *, effects="alloc,read,write,trap"):
    return ("hia-asm.v1 hepta.hia.program.v8 owned_reference\n"
            "fn f0() -> (" + returns + ") effects(" + effects + ") entry(b0)\n"
            "block b0()\n" + body + "end\n").encode()


def allocation_source(size, *, optional=True):
    output = "v1:buffer,v2:bool = buffer.try_new" if optional else "v1:buffer = buffer.new"
    returned = "v2,v3" if optional else "v3"
    return program(f'  v0:usize = const() {{"value":{size}}}\n'
        f"  {output}(v0)\n  v3:usize = buffer.len(v1)\n"
        f"  _ = owner.drop(v1)\n  ret({returned})\n", "bool,usize" if optional else "usize")


ZERO_THEN_FAILURE = program('''  v0:usize = const() {"value":0}
  v1:buffer,v2:bool = buffer.try_new(v0)
  v3:usize = const() {"value":1}
  v4:buffer,v5:bool = buffer.try_new(v3)
  v6:usize = buffer.len(v1)
  v7:usize = buffer.len(v4)
  _ = owner.drop(v1)
  _ = owner.drop(v4)
  ret(v2,v5,v6,v7)
''', "bool,bool,usize,usize")


CHAIN_ROUNDTRIP = program('''  v0:usize = const() {"value":37}
  v1:buffer = buffer.new(v0)
  v2:buffer = owner.move(v1)
  v3:mutbuf = borrow.mut(v2)
  v4:usize = const() {"value":0}
  v5:u8 = const() {"value":171}
  _ = buffer.store(v3,v4,v5)
  v6:usize = const() {"value":36}
  v7:u8 = const() {"value":205}
  _ = buffer.store(v3,v6,v7)
  _ = loan.end(v3)
  v8:chain = chain.empty()
  v9:chain,v10:buffer,v11:bool = chain.try_push(v8,v2)
  v12:usize = buffer.len(v10)
  _ = owner.drop(v10)
  v13:readbuf = chain.head_read(v9)
  v14:u8 = buffer.load(v13,v4)
  v15:u8 = buffer.load(v13,v6)
  _ = loan.end(v13)
  v16:mutbuf = chain.head_mut(v9)
  v17:u8 = const() {"value":99}
  _ = buffer.store(v16,v4,v17)
  _ = loan.end(v16)
  v18:chain,v19:buffer,v20:bool = chain.pop(v9)
  v21:bool = chain.is_empty(v18)
  v22:usize = buffer.len(v19)
  v23:readbuf = borrow.read(v19)
  v24:u8 = buffer.load(v23,v4)
  _ = loan.end(v23)
  _ = owner.drop(v19)
  _ = owner.drop(v18)
  ret(v11,v12,v14,v15,v20,v21,v22,v24)
''', "bool,usize,u8,u8,bool,bool,usize,u8")


CHAIN_FAILURE = program('''  v0:usize = const() {"value":1}
  v1:buffer = buffer.new(v0)
  v2:mutbuf = borrow.mut(v1)
  v3:usize = const() {"value":0}
  v4:u8 = const() {"value":173}
  _ = buffer.store(v2,v3,v4)
  _ = loan.end(v2)
  v5:chain = chain.empty()
  v6:chain,v7:buffer,v8:bool = chain.try_push(v5,v1)
  v9:bool = chain.is_empty(v6)
  v10:usize = buffer.len(v7)
  v11:readbuf = borrow.read(v7)
  v12:u8 = buffer.load(v11,v3)
  _ = loan.end(v11)
  _ = owner.drop(v6)
  _ = owner.drop(v7)
  ret(v8,v9,v10,v12)
''', "bool,bool,usize,u8")


EMPTY_POP = program('''  v0:chain = chain.empty()
  v1:chain,v2:buffer,v3:bool = chain.pop(v0)
  v4:bool = chain.is_empty(v1)
  v5:usize = buffer.len(v2)
  _ = owner.drop(v1)
  _ = owner.drop(v2)
  ret(v3,v4,v5)
''', "bool,bool,usize")


EMPTY_HEAD = program('''  v0:chain = chain.empty()
  v1:readbuf = chain.head_read(v0)
  _ = loan.end(v1)
  _ = owner.drop(v0)
  v2:u32 = const() {"value":0}
  ret(v2)
''', "u32")


CHAIN_LOOP = b'''hia-asm.v1 hepta.hia.program.v8 owned_reference
fn f0(v0:usize) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:usize)
  v1:chain = chain.empty()
  v2:usize = const() {"value":0}
  v3:usize = const() {"value":1}
  jump b1(v0,v1,v2,v3)
block b1(v4:usize,v5:chain,v6:usize,v7:usize)
  v8:bool = compare.lt(v6,v4)
  branch v8 b2(v4,v5,v6,v7) b3(v5)
block b2(v9:usize,v10:chain,v11:usize,v12:usize)
  v13:buffer = buffer.new(v12)
  v14:chain,v15:buffer,v16:bool = chain.try_push(v10,v13)
  _ = owner.drop(v15)
  v17:usize = int.add.wrap(v11,v12)
  jump b1(v9,v14,v17,v12)
block b3(v18:chain)
  _ = owner.drop(v18)
  v19:u32 = const() {"value":0}
  ret(v19)
end
'''


def positive_cases():
    return [
        {"name": "empty-try-allocation", "source": allocation_source(0), "expected": [True, 0]},
        {"name": "ordinary-try-allocation", "source": allocation_source(8192), "expected": [True, 8192]},
        {"name": "larger-than-compiler-workspace", "source": allocation_source(2 * 1024**2 + 17), "expected": [True, 2 * 1024**2 + 17]},
        {"name": "unsigned-object-size-refusal", "source": allocation_source(1 << 63), "expected": [False, 0]},
        {"name": "empty-does-not-consume-failure-sequence", "source": ZERO_THEN_FAILURE,
         "limits": {"allocation_fail_at": 1}, "expected": [True, False, 0, 0]},
        {"name": "chain-roundtrip-and-loans", "source": CHAIN_ROUNDTRIP,
         "expected": [True, 0, 171, 205, True, True, 37, 99]},
        {"name": "chain-node-failure-retains-payload", "source": CHAIN_FAILURE,
         "limits": {"allocation_fail_at": 2}, "expected": [False, True, 1, 173]},
        {"name": "empty-chain-pop", "source": EMPTY_POP, "expected": [False, True, 0]},
        {"name": "iterative-5000-node-drop", "source": CHAIN_LOOP, "arguments": [5000], "expected": [0]},
        {"name": "trapping-object-size-refusal", "source": allocation_source(1 << 63, optional=False),
         "expected_status": "trapped", "expected_code": "allocation"},
        {"name": "empty-chain-head-trap", "source": EMPTY_HEAD,
         "expected_status": "trapped", "expected_code": "bounds"},
        {"name": "heap-budget-is-not-allocation-failure", "source": allocation_source(8192),
         "limits": {"max_heap_bytes": 4096}, "expected_status": "budget_exceeded", "expected_code": "heap"},
    ]


def negative_cases():
    basic = allocation_source(1)
    result = {
        "live-owner-leak": basic.replace(b"  _ = owner.drop(v1)\n", b""),
        "double-owner-drop": basic.replace(b"  _ = owner.drop(v1)\n", b"  _ = owner.drop(v1)\n  _ = owner.drop(v1)\n"),
        "use-after-owner-drop": basic.replace(b"  v3:usize = buffer.len(v1)\n  _ = owner.drop(v1)\n", b"  _ = owner.drop(v1)\n  v3:usize = buffer.len(v1)\n"),
        "try-new-missing-result": basic.replace(b"v1:buffer,v2:bool =", b"v1:buffer ="),
        "try-new-swapped-types": basic.replace(b"v1:buffer,v2:bool =", b"v1:bool,v2:buffer ="),
        "try-new-duplicate-output-name": basic.replace(b"v1:buffer,v2:bool =", b"v1:buffer,v1:bool ="),
        "missing-allocation-effect": basic.replace(b"effects(alloc,read,write,trap)", b"effects(read,write,trap)"),
        "drop-live-buffer-loan": basic.replace(b"  _ = owner.drop(v1)", b"  v4:readbuf = borrow.read(v1)\n  _ = owner.drop(v1)\n  _ = loan.end(v4)"),
        "move-live-buffer-loan": basic.replace(b"  _ = owner.drop(v1)", b"  v4:readbuf = borrow.read(v1)\n  v5:buffer = owner.move(v1)\n  _ = loan.end(v4)\n  _ = owner.drop(v5)"),
        "use-consumed-chain": EMPTY_POP.replace(b"chain.is_empty(v1)", b"chain.is_empty(v0)"),
        "chain-pop-missing-result": EMPTY_POP.replace(b"v1:chain,v2:buffer,v3:bool =", b"v1:chain,v2:buffer ="),
        "chain-pop-missing-alloc-effect": EMPTY_POP.replace(b"effects(alloc,read,write,trap)", b"effects(read,write,trap)"),
        "push-while-payload-borrowed": CHAIN_ROUNDTRIP.replace(b"  _ = loan.end(v3)\n", b"").replace(
            b"  v12:usize = buffer.len(v10)", b"  _ = loan.end(v3)\n  v12:usize = buffer.len(v10)"),
        "pop-while-head-borrowed": CHAIN_ROUNDTRIP.replace(b"  _ = loan.end(v16)\n", b"").replace(
            b"  v21:bool = chain.is_empty(v18)", b"  _ = loan.end(v16)\n  v21:bool = chain.is_empty(v18)"),
        "conflicting-head-loans": CHAIN_ROUNDTRIP.replace(b"  _ = loan.end(v13)\n", b"").replace(
            b"  _ = loan.end(v16)", b"  _ = loan.end(v16)\n  _ = loan.end(v13)"),
        "chain-duplicate-edge-capability": b'''hia-asm.v1 hepta.hia.program.v8 owned_reference
fn f0() -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0()
  v0:chain = chain.empty()
  jump b1(v0,v0)
block b1(v1:chain,v2:chain)
  _ = owner.drop(v1)
  _ = owner.drop(v2)
  v3:u32 = const() {"value":0}
  ret(v3)
end
''',
    }
    return result


def run_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap, HIAProgramBudgetExceeded
    observations = []
    for case in positive_cases():
        checked = assemble_program(case["source"])
        try:
            observed = execute_program(checked, "f0", case.get("arguments", []), **case.get("limits", {}))
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as exc:
            observed = exc.report
        if observed["status"] != case.get("expected_status", "returned"):
            raise AssertionError((case["name"], observed))
        if observed["status"] == "returned":
            if observed["values"] != case["expected"]:
                raise AssertionError((case["name"], observed))
            resources = observed["resources"]
            if any(resources[key] for key in ("live_owners", "live_chains", "live_chain_nodes", "live_bytes", "live_local_loans")):
                raise AssertionError((case["name"], resources))
        elif observed["error"]["code"] != case["expected_code"]:
            raise AssertionError((case["name"], observed))
        observations.append({**{key: value for key, value in case.items() if key != "source"},
                             "source": case["source"].decode(), "observation": observed})
    rejected = []
    for name, source in negative_cases().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            rejected.append({"name": name, "source": source.decode(), "code": exc.code, "message": str(exc)})
        else:
            raise AssertionError("canonical verifier admitted negative owned fixture: " + name)
    return {"schema": "hepta.hia.selfhost-owned-reference.v1", "cases": observations, "rejections": rejected,
            "selfhost_owned_opcodes_admitted": False, "universal_refinement_proved": False}
