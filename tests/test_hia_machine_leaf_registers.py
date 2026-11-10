"""Independent VM/native, ABI and refusal checks for v4 leaf registers."""
from copy import deepcopy
import ctypes
import json
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_agent_contract import PLAN_SCHEMA, validate
from hepta.hia_machine_plan import (MACHINE_V4, LEAF_VALUE_OPS, MachinePlanRejected,
                                   preservation_checks, validate_plan)
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_native import compile_program_machine, emit_program_machine
from tools.qualify_hia_machine_registers import (_block, _const, _function, _op,
                                                _ret, explicit_plan, fixture)

NATIVE = platform.system() == "Linux" and platform.machine() == "x86_64" and shutil.which("ld")


def leaf_plan(program, assignments=None, **options):
    plan = explicit_plan(program, assignments, **options)
    plan["schema"] = MACHINE_V4
    return plan


def scalar_matrix():
    functions, cases, placements = [], [], {}
    for opcode in sorted(LEAF_VALUE_OPS - {"buffer.len", "buffer.load", "buffer.store"}):
        name = opcode.replace(".", "_")
        typ = "bool" if opcode.startswith("bool.") else "i64" if opcode == "int.neg.checked" else "u64"
        params = [("x", typ), ("y", typ)]
        result_type = "bool" if opcode.startswith(("compare.", "bool.")) else "u8" if opcode == "int.cast" else typ
        args, attrs = ["x", "y"], {}
        if opcode in {"int.neg.checked", "bit.not", "bool.not", "int.cast"}:
            args = ["x"]
        if opcode == "int.cast":
            attrs = {"mode": "wrap"}
        if opcode == "const":
            args, attrs = [], {"value": 65537}
        if opcode == "select":
            params.append(("condition", "bool")); args = ["condition", "x", "y"]
        operations = [_op(opcode, args, [("result", result_type)], **attrs),
                      _const("zero", "u64", 0), _const("one", "u64", 1)]
        # Reuse BOTH inputs after the operation. An implicit overwrite of r8
        # or r9 cannot hide behind an otherwise-correct operation result.
        for value, value_type in (("x", typ), ("y", typ), ("result", result_type)):
            if value_type == "bool":
                operations.append(_op("select", [value, "one", "zero"], [(value + "_wide", "u64")]))
            else:
                operations.append(_op("int.cast", [value], [(value + "_wide", "u64")], mode="wrap"))
        operations += [_const("factor", "u64", 65537),
            _op("int.mul.wrap", ["x_wide", "factor"], [("x_trace", "u64")]),
            _op("int.add.wrap", ["x_trace", "y_wide"], [("input_trace", "u64")]),
            _op("bit.xor", ["input_trace", "result_wide"], [("answer", "u64")])]
        functions.append(_function(name, params, ["u64"], [_block("entry", params, operations, _ret("answer"))], ["trap"]))
        placements[name] = {"x": "r8", "y": "r9"}
        if typ == "bool":
            values = [[a, b] for a in (False, True) for b in (False, True)]
        elif typ == "i64":
            values = [[-5, 7], [0, -2], [(1 << 63) - 1, -1]]
        elif opcode in {"int.add.checked", "int.mul.checked"}:
            values = [[17, 3], [0, 0], [(1 << 32) - 1, 1]]
        elif opcode == "int.sub.checked":
            values = [[17, 3], [5, 5], [(1 << 64) - 1, 1]]
        elif opcode in {"int.shl.checked", "int.shr.checked"}:
            values = [[17, 0], [(1 << 64) - 1, 1], [1, 63]]
        elif opcode in {"int.div.checked", "int.rem.checked"}:
            values = [[17, 3], [0, 1], [(1 << 64) - 1, 1]]
        else:
            values = [[0, 0], [17, 3], [(1 << 64) - 1, 1], [0, (1 << 64) - 1]]
        if opcode == "select":
            values = [v + [condition] for v in values for condition in (False, True)]
        cases.extend((name, args) for args in values)
    return {"schema": "hepta.hia.program.v8", "module": "leaf_register_matrix", "functions": functions}, placements, cases


class LeafRegisterValidationTests(unittest.TestCase):
    def test_v4_is_opt_in_and_v3_keeps_its_register_boundary(self):
        document, placements = fixture()
        checked = verify_program(document)
        plan = leaf_plan(checked, {"plus7": {"x": "r8", "seven": "r9"}})
        validate(plan, PLAN_SCHEMA); validate_plan(checked, plan)
        old = explicit_plan(checked, plan["value_registers"])
        with self.assertRaises(MachinePlanRejected):
            validate_plan(checked, old)
        with self.assertRaises(ValueError):
            validate(old, PLAN_SCHEMA)
        self.assertEqual(emit_program_machine(checked).object_bytes,
                         emit_program_machine(checked, machine_plan=leaf_plan(checked)).object_bytes)

    def test_entire_function_gate_rejects_calls_allocations_and_recursive_calls(self):
        document, _ = fixture(); checked = verify_program(document)
        for function, value in (("across_calls", "x"), ("memory_calls", "x"),
                                ("recursive_sum", "n"), ("pair_caller", "a")):
            with self.subTest(function=function), self.assertRaisesRegex(MachinePlanRejected, "leaf opcode whitelist"):
                validate_plan(checked, leaf_plan(checked, {function: {value: "r8"}}))
        # Even a call in a different, untaken branch invalidates the class.
        with self.assertRaisesRegex(MachinePlanRejected, "leaf opcode whitelist"):
            validate_plan(checked, leaf_plan(checked, {"recursive_sum": {"nothing": "r9"}}))

    def test_r8_swap_scratch_resources_and_overlapping_lifetimes_are_refused(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_cases import HEADER
        swap = (HEADER+'  v3:usize = const() {"value":0}\n  v4:usize = const() {"value":1}\n'
                '  _ = buffer.swap(v1,v3,v4)\n  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode()
        checked = assemble_program(swap)
        with self.assertRaisesRegex(MachinePlanRejected, "leaf opcode whitelist"):
            validate_plan(checked, leaf_plan(checked, {"f0": {"v3": "r8"}}))
        document, _ = fixture(); checked = verify_program(document)
        with self.assertRaisesRegex(MachinePlanRejected, "interfering values"):
            validate_plan(checked, leaf_plan(checked, {"plus7": {"x": "r8", "seven": "r8"}}))
        with self.assertRaisesRegex(MachinePlanRejected, "integer or boolean"):
            # A borrowed parameter is live but is a two-word capability.
            from hepta.hia_agent_assembly import assemble_program
            from tools.hia_selfhost_cases import HEADER
            borrowed = assemble_program((HEADER+'  v3:u32 = const() {"value":0}\n  ret(v3)\nend\n').encode())
            validate_plan(borrowed, leaf_plan(borrowed, {"f0": {"v0": "r8"}}))


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld required")
class LeafRegisterExecutionTests(unittest.TestCase):
    def test_every_leaf_scalar_opcode_keeps_live_r8_r9_against_vm(self):
        document, placements, cases = scalar_matrix(); checked = verify_program(document)
        covered = {b["ops"][0]["op"] for f in document["functions"] for b in f["blocks"]}
        self.assertEqual(covered, LEAF_VALUE_OPS - {"buffer.len", "buffer.load", "buffer.store"})
        with tempfile.TemporaryDirectory(prefix="hia-leaf-matrix-") as tmp:
            for select in ("branch", "cmov_scalar"):
                plan = leaf_plan(checked, placements, select=select, compact=True)
                witness = preservation_checks(plan, checked)
                self.assertTrue(any(row["choice"] == "caller_clobbered_leaf_values" for row in witness))
                output = Path(tmp) / (select + ".so")
                machine = emit_program_machine(checked, machine_plan=plan)
                compile_program_machine(machine, program=checked, output=output, linker="ld", machine_plan=plan)
                library = ctypes.CDLL(str(output))
                for name, arguments in cases:
                    fn = getattr(library, name)
                    fn.argtypes, fn.restype = [ctypes.c_uint64] * len(arguments), ctypes.c_uint64
                    with self.subTest(select=select, function=name, arguments=arguments):
                        self.assertEqual(fn(*arguments), execute_program(checked, name, arguments)["result"])

    def test_parallel_loop_edges_multi_result_and_unassigned_stack_values(self):
        document, placements = fixture(); checked = verify_program(document)
        selected = {name: {value: ("r8" if reg == "r12" else "r9" if reg == "r13" else reg)
                          for value, reg in placements[name].items()}
                    for name in ("plus7", "reuse", "choose", "swap_loop", "pair")}
        plan = leaf_plan(checked, selected, select="cmov_scalar", layout=True, compact=True)
        with tempfile.TemporaryDirectory(prefix="hia-leaf-edges-") as tmp:
            output=Path(tmp)/"leaf.so"; machine=emit_program_machine(checked,machine_plan=plan)
            compile_program_machine(machine,program=checked,output=output,linker="ld",machine_plan=plan)
            library=ctypes.CDLL(str(output))
            cases=[("swap_loop",[17,83,n]) for n in (0,1,2,63,127)]
            cases += [("pair_caller",[17,83]),("reuse",[(1<<64)-1]),("across_calls",[31])]
            for name,args in cases:
                fn=getattr(library,name);fn.argtypes=[ctypes.c_uint64]*len(args);fn.restype=ctypes.c_uint64
                self.assertEqual(fn(*args),execute_program(checked,name,args)["result"],(name,args))


    def test_borrowed_byte_addresses_lengths_returns_and_prewrite_traps(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.hia_selfhost_cases import HEADER
        from tools.qualify_hia_selfhost import invoke
        source=(HEADER+'  v3:usize = const() {"value":0}\n'
            '  v4:u8 = buffer.load(v0,v3)\n  _ = buffer.store(v1,v3,v4)\n'
            '  v5:usize = buffer.len(v1)\n  v6:u32 = int.cast(v4) {"mode":"wrap"}\n'
            '  v7:u32 = int.cast(v3) {"mode":"wrap"}\n  v8:u32 = int.cast(v5) {"mode":"wrap"}\n'
            '  v9:u32 = int.add.wrap(v6,v8)\n  v10:u32 = int.add.wrap(v9,v7)\n  ret(v10)\nend\n').encode()
        checked=assemble_program(source);plan=leaf_plan(checked,{"f0":{"v3":"r8","v4":"r9"}},compact=True)
        with tempfile.TemporaryDirectory(prefix="hia-leaf-bytes-") as tmp:
            root=Path(tmp);output=root/'leaf.so'
            machine=emit_program_machine(checked,machine_plan=plan,foreign_buffer_exports=(("f0",1<<20),))
            compile_program_machine(machine,program=checked,output=output,linker="ld",machine_plan=plan)
            good,raw=invoke(root,'good',output,b'\x9d',image_format='seed-shared',capacity=4,workspace_size=0)
            self.assertEqual((good['core_u32'],raw),(161,b'\x9d\xa5\xa5\xa5'))
            for label,data,capacity in [('bad-load',b'',4),('bad-store',b'x',0)]:
                bad,raw=invoke(root,label,output,data,image_format='seed-shared',capacity=capacity,
                    workspace_size=0,observe_trap_writes=True)
                self.assertEqual(bad['returncode'],-signal.SIGABRT)
                self.assertTrue(bad['shared_output_observation']['unchanged'])

    def test_checked_arithmetic_traps_after_placing_inputs_in_new_registers(self):
        params=[('a','u64'),('b','u64')]
        checked=verify_program({'schema':'hepta.hia.program.v8','module':'leaf_trap','functions':[
            _function('add',params,['u64'],[_block('entry',params,[
                _op('int.add.checked',['a','b'],[('answer','u64')])],_ret('answer'))],['trap'])]})
        plan=leaf_plan(checked,{'add':{'a':'r8','b':'r9'}})
        with tempfile.TemporaryDirectory(prefix='hia-leaf-trap-') as tmp:
            output=Path(tmp)/'leaf.so';machine=emit_program_machine(checked,machine_plan=plan)
            compile_program_machine(machine,program=checked,output=output,linker='ld',machine_plan=plan)
            script='import ctypes,resource,sys;resource.setrlimit(resource.RLIMIT_CORE,(0,0));f=ctypes.CDLL(sys.argv[1]).add;f.argtypes=[ctypes.c_uint64]*2;f.restype=ctypes.c_uint64;f((1<<64)-1,1)'
            result=subprocess.run([sys.executable,'-I','-B','-c',script,str(output)],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,-signal.SIGABRT)


if __name__ == '__main__':
    unittest.main()
