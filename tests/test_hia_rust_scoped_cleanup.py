"""Real Rust scoped cleanup, with unchanged independent Python prefix oracles.

The existing finite-heap matrix is deliberately reused, not called a new
holdout. Every inherited positive prefix runs the new pinned Rust mode and is
compared to the independent Python VM before checking explicit discharge.
Malformed replies appear only in consumer refusal controls.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

from hepta import hia_rust_byte_dag as route
from hepta import hia_rust_crosscheck as transport
from hepta.hia_rust_byte_cleanup import MAX_CLEANUP_ACTIONS
from tests import test_hia_rust_finite_heap as finite
from tests.test_hia_program import b, c, f, i, ret

wire = finite.wire


def stopped_store():
    params = [("size", "usize"), ("value", "u8"), ("offset", "usize")]
    entry = f("entry", params, [], ["alloc", "write", "trap"], [b("start", params, [
        i("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
        i("borrow.mut", ["owner"], [("view", "mutbuf")]),
        i("buffer.store", ["view", "offset", "value"]),
    ], {"op": "trap", "code": "user"})])
    return finite.v7(entry)


def aliased_formals_stop():
    helper_params = [("a", "readbuf"), ("b", "readbuf")]
    helper = f("helper", helper_params, [], ["read", "trap"], [
        b("start", helper_params, [i("borrow.read", ["a"], [("child", "readbuf")])],
          {"op": "trap", "code": "user"})])
    entry = f("entry", [], [], ["alloc", "read", "trap"], [b("start", [], [
        c("size", "usize", 3), i("buffer.new", ["size"], [("owner", "buffer")]),
        i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
        i("call", ["parent", "parent"], function="helper"),
        i("loan.end", ["parent"]), i("owner.drop", ["owner"]),
    ], ret())])
    return {**finite.v7(helper, entry), "schema": "hepta.hia.program.v8"}


def loaded_arithmetic_stop(op, value):
    entry = f("entry", [], ["u8"], ["alloc", "read", "write", "trap"], [b("start", [], [
        c("size", "usize", 1), c("offset", "usize", 0), c("value", "u8", value),
        c("one", "u8", 1), i("buffer.new", ["size"], [("owner", "buffer")]),
        i("borrow.mut", ["owner"], [("view", "mutbuf")]),
        i("buffer.store", ["view", "offset", "value"]),
        i("buffer.load", ["view", "offset"], [("loaded", "u8")]),
        i(op, ["loaded", "one"] if op == "int.add.checked" else ["one", "loaded"], [("answer", "u8")]),
        i("loan.end", ["view"]), i("owner.drop", ["owner"]),
    ], ret("answer"))])
    return finite.v7(entry)


class RustScopedAbortCleanup(finite.RustFiniteHeapAdmission):
    # This name describes the original observation profile, not this opt-in
    # cleanup phase. Reuse its precise prefix matrix under an explicit name.
    test_every_tick_stop_heap_stop_and_call_stop_is_bounded_without_unwind = None

    @classmethod
    def retain(cls):
        target = os.environ.get("HEPTA_RUST_SCOPED_CLEANUP_EVIDENCE_DIR")
        if target:
            directory = Path(target)
            directory.mkdir(parents=True, exist_ok=True)
            result = {"schema": "hepta.rust-scoped-cleanup.actual-corpus.v1",
                "build": cls.build, "executable_sha256": cls.digest,
                "programs": cls.programs, "processes": cls.native_processes,
                "isolated_child_processes": cls.isolated_children,
                "observations": cls.observations, "refusals": cls.refusals,
                "claims": {"positive_native_responses_are_actual": True,
                           "same_finite_heap_matrix_reused": True, "new_holdout": False,
                           "host_oom_panic_termination_cleanup_proved": False,
                           "whole_language_soundness_proved": False}}
            (directory / "actual.json").write_bytes(wire(result) + b"\n")
        print(f"Rust scoped cleanup actual processes: {len(cls.native_processes)}; "
              f"matched prefix+cleanup observations: {len(cls.observations)}; "
              f"raw refusal controls: {len(cls.refusals)}")

    def invoke(self, raw, entry, arguments, *, limit, static=finite.MAX_LIMITS, **policy):
        policy.setdefault("max_cleanup_actions", MAX_CLEANUP_ACTIONS)
        return super().invoke(raw, entry, arguments, limit=limit, static=static, **policy)

    def compare(self, *args, **kwargs):
        report = super().compare(*args, **kwargs)
        original, cleanup = report["runtime"]["execution"], report["cleanup"]
        self.assertEqual(report["profile"], route.CLEANUP_PROFILE)
        self.assertEqual(cleanup["before"], original["resources"])
        self.assertEqual(cleanup["status"], "not_needed" if original["status"] == "returned" else "completed")
        self.assertEqual(cleanup["call_formal_loans_after"], 0)
        for field in ("live_owners", "live_local_loans", "live_bytes", "live_chains", "live_chain_nodes"):
            self.assertEqual(cleanup["after"][field], 0, field)
        self.assertEqual(cleanup["after"]["owners_created"], cleanup["after"]["owners_dropped"])
        self.assertEqual(cleanup["after"]["loans_started"], cleanup["after"]["loans_ended"])
        self.assertEqual(cleanup["after"]["allocations"], cleanup["after"]["frees"])
        self.assertEqual(cleanup["after"]["peak_bytes"], original["resources"]["peak_bytes"])
        self.assertLessEqual(cleanup["actions"], report["cleanup_bound"]["action_bound"])
        self.assertFalse(cleanup["claims"]["host_panic_oom_or_termination_cleanup_guaranteed"])
        return report

    def refuse(self, source, entry="entry", arguments=(), *, code=None, limit=(1 << 63) - 1,
               cleanup_policy=None):
        raw = source if type(source) is bytes else wire(source)
        cleanup_policy = (wire({"max_cleanup_actions": MAX_CLEANUP_ACTIONS}).decode()
                          if cleanup_policy is None else cleanup_policy)
        completed = self.process(raw, ["--byte-dag-heap-cleanup-admit-run", entry,
            wire(arguments).decode(), wire(finite.MAX_LIMITS).decode(),
            wire({"max_live_heap_bytes": limit}).decode(), cleanup_policy,
            wire({"max_steps": 1, "max_heap_bytes": 0, "max_call_depth": 1,
                  "allocation_fail_at": "0x1"}).decode()])
        self.assertEqual(completed.returncode, 1, completed.stdout.decode())
        self.assertEqual(completed.stdout, b"")
        self.assertTrue(completed.stderr.startswith(b"E_HIA_"), completed.stderr)
        self.assertNotIn(b"panicked", completed.stderr)
        if code:
            self.assertTrue(completed.stderr.startswith(code.encode() + b":"), completed.stderr)
        type(self).refusals.append(type(self).native_processes[-1])

    def test_every_tick_heap_and_call_stop_retains_prefix_then_discharge(self):
        finite.RustFiniteHeapAdmission.test_every_tick_stop_heap_stop_and_call_stop_is_bounded_without_unwind(self)

    def test_actual_alias_formals_parent_graph_has_exact_order_and_counters(self):
        report = self.compare(aliased_formals_stop(), expected_bound=3)
        cleanup = report["cleanup"]
        self.assertEqual(report["runtime"]["execution"]["error"], {"code": "user"})
        self.assertEqual([event["loan"] for event in cleanup["events"][:-1]], [4, 3, 2, 1])
        self.assertEqual([event["call_formal"] for event in cleanup["events"][:-1]],
                         [False, True, True, False])
        self.assertEqual(cleanup["events"][-1], {"op": "drop_owner", "owner": 1, "bytes": 3})
        self.assertEqual(cleanup["call_formal_loans_before"], 2)
        self.assertEqual(cleanup["before"]["loans_started"], 2)
        self.assertEqual(cleanup["after"]["loans_ended"], 2)

    def test_legacy_mode_keeps_the_exact_stop_ledger_without_implicit_cleanup(self):
        raw = wire(aliased_formals_stop())
        actual = self.invoke(raw,"entry",[],limit=3)
        completed = self.process(raw,["--byte-dag-heap-admit-run","entry","[]",
            wire(finite.MAX_LIMITS).decode(),'{"max_live_heap_bytes":3}',
            wire(actual["request"]["execution_policy"]).decode()])
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        legacy = json.loads(completed.stdout)
        self.assertEqual(legacy["profile"],route.HEAP_PROFILE)
        self.assertNotIn("cleanup",legacy)
        self.assertEqual(legacy["runtime"],actual["runtime"])
        self.assertEqual(legacy["runtime"]["execution"]["resources"]["live_bytes"],3)
        self.assertFalse(legacy["claims"]["successful_return_or_cleanup_guaranteed"])

    def test_empty_failed_owner_bounds_user_and_loaded_arithmetic_traps_are_real(self):
        for arguments, fail, trap, payload in (([3, 7, 0], None, "user", 3),
                ([3, 7, 3], None, "bounds", 3), ([0, 7, 0], None, "bounds", 0),
                ([3, 7, 0], 1, "bounds", 0)):
            report = self.compare(stopped_store(), arguments=arguments,
                                  allocation_fail_at=fail, expected_bound=arguments[0])
            self.assertEqual(report["runtime"]["execution"]["error"], {"code": trap})
            cleanup = report["cleanup"]
            self.assertEqual(cleanup["before"]["live_owners"], 1)
            self.assertEqual(cleanup["before"]["live_bytes"], payload)
            self.assertEqual(cleanup["after"]["owners_dropped"], 1)
            self.assertEqual(cleanup["after"]["frees"], int(payload != 0))
        for op, value, error in (("int.add.checked", 255, "overflow"),
                                  ("int.div.checked", 0, "division_by_zero")):
            report = self.compare(loaded_arithmetic_stop(op, value), expected_bound=1)
            self.assertEqual(report["runtime"]["execution"]["error"], {"code": error})

    def test_reservation_boundary_and_malformed_policy_refuse_before_execution(self):
        # One allocator operation and five total ticks, no borrowed formals:
        # the deliberately conservative pre-execution reservation is 1+5=6.
        report = self.invoke(wire(stopped_store()), "entry", [3, 7, 0], limit=3, max_cleanup_actions=6)
        self.assertEqual(report["cleanup_bound"]["action_bound"], 6)
        self.refuse(stopped_store(), arguments=[3, 7, 0], limit=3,
                    cleanup_policy='{"max_cleanup_actions":5}', code="E_HIA_CLEANUP_EXCEEDED")
        for bad in (True, -1, 1.0, "6", MAX_CLEANUP_ACTIONS+1):
            with patch.object(transport, "_verified_executable_bytes") as executable:
                with self.assertRaises(route.HIARustByteDagRejected):
                    self.invoke(wire(stopped_store()), "entry", [3, 7, 0], limit=3, max_cleanup_actions=bad)
                executable.assert_not_called()
        for raw in ('{"max_cleanup_actions":6,"max_cleanup_actions":6}',
                    '{"max_cleanup_actions":6.0}', '{"max_cleanup_actions":true}',
                    '{"max_cleanup_actions":6,"trust_host_drop":true}',
                    '{"max_cleanup_actions":6}{}', ' ' * 1025,
                    '{"max_cleanup_actions":32769}'):
            self.refuse(stopped_store(), arguments=[3, 7, 0], limit=3, cleanup_policy=raw)
        with patch.object(transport, "_verified_executable_bytes") as executable:
            with self.assertRaises(route.HIARustByteDagRejected):
                route.execute_rust_byte_dag(wire(stopped_store()), "entry", [3, 7, 0], self.executable,
                    executable_sha256=self.digest, static_policy=finite.MAX_LIMITS,
                    max_cleanup_actions=6)
            executable.assert_not_called()

    def test_finite_heap_admission_does_not_imply_cleanup_reservation_admission(self):
        source = stopped_store()
        params = [(f"loan{n}","readbuf") for n in range(64)]
        source["functions"].insert(0,f("private_wide",params,[],[],[b("start",params,[],ret())]))
        source["functions"][-1]["blocks"][0]["ops"][:0] = [c(f"extra{n}","usize",n) for n in range(512)]
        raw = wire(source)
        # This whole module still has a finite heap proof. Its conservative
        # cleanup formula uses the complete module's formal-width maximum;
        # it deliberately refuses rather than minting an unlimited guarantee.
        completed = self.process(raw,["--byte-dag-heap-admit-run","entry","[3,7,0]",
            wire(finite.MAX_LIMITS).decode(),'{"max_live_heap_bytes":3}',
            '{"max_steps":1,"max_heap_bytes":0,"max_call_depth":1,"allocation_fail_at":null}'])
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        self.assertEqual(json.loads(completed.stdout)["runtime"]["execution"]["error"],{"code":"steps"})
        self.refuse(raw,arguments=[3,7,0],limit=3,code="E_HIA_CLEANUP_EXCEEDED")

    def test_rehashed_replay_wrong_bounds_policies_arguments_and_authority_reject(self):
        raw = wire(aliased_formals_stop())
        actual = self.invoke(raw, "entry", [], limit=3)
        def replay(report):
            with patch.object(transport, "_run_pinned_shadow", return_value=(wire(report)+b"\n", b"", 0)):
                return route.execute_rust_byte_dag(raw, "entry", [], self.executable,
                    executable_sha256=self.digest, static_policy=finite.MAX_LIMITS,
                    max_static_live_heap_bytes=3, max_cleanup_actions=MAX_CLEANUP_ACTIONS)
        replay(actual)  # identical successful envelope must be accepted first
        changes = [
            (["cleanup", "status"], "failed"),
            (["cleanup", "before", "live_bytes"], 0),
            (["cleanup", "after", "frees"], 0),
            (["cleanup", "after", "peak_bytes"], 0),
            (["cleanup", "after", "loans_ended"], 4),
            (["cleanup", "call_formal_loans_before"], 0),
            (["cleanup", "inventory_records_checked"], True),
            (["cleanup", "actions"], 0),
            (["cleanup", "events", 0, "root_owner"], 2),
            (["cleanup", "events", 0, "parent"], 4),
            (["cleanup", "events", 0, "call_formal"], True),
            (["cleanup", "events", 0, "mutable"], True),
            (["cleanup", "events", 2, "parent_kind"], "owner"),
            (["cleanup", "events", 4, "bytes"], 0),
            (["cleanup_bound", "action_bound"], 5),
            (["cleanup_bound", "max_borrowed_parameters"], 0),
            (["cleanup_bound", "arguments"], [1]),
            (["cleanup", "claims", "host_panic_oom_or_termination_cleanup_guaranteed"], True),
            (["claims", "native_execution_authorized"], True),
            (["runtime", "execution", "error", "code"], "unregistered_error"),
        ]
        for path, value in changes:
            bad = deepcopy(actual)
            target = bad
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(route.HIARustByteDagRejected):
                replay(bad)
        for order in ([4, 0, 1, 2, 3], [1, 0, 2, 3, 4], [0, 1, 1, 3, 4]):
            bad = deepcopy(actual)
            bad["cleanup"]["events"] = [bad["cleanup"]["events"][n] for n in order]
            with self.assertRaises(route.HIARustByteDagRejected):
                replay(bad)
        bad = deepcopy(actual)
        bad["request"]["cleanup_policy"]["max_cleanup_actions"] -= 1
        bad["request_sha256"] = sha256(wire(bad["request"])).hexdigest()
        with self.assertRaises(route.HIARustByteDagRejected):
            replay(bad)
        bad = deepcopy(actual)
        bad["runtime"]["request"]["arguments"] = [1]
        bad["runtime"]["request_sha256"] = sha256(wire(bad["runtime"]["request"])).hexdigest()
        with self.assertRaises(route.HIARustByteDagRejected):
            replay(bad)

    def test_no_python_semantic_modules_are_required_for_admission_or_refusal(self):
        code = """
import sys,json
for name in ('hia_program','hia_program_composite','hia_program_runtime','hia_heap_bound',
             'hia_static_budget','hia_source_bridge','hia_program_llvm'):
    sys.modules['hepta.'+name]=None
from hepta.hia_rust_byte_dag import execute_rust_byte_dag
result=execute_rust_byte_dag(sys.stdin.buffer.read(),'entry',[],sys.argv[1],
    executable_sha256=sys.argv[2],static_policy={
        'max_allocator_interactions':1000,'max_vm_ticks':1000,'max_call_depth':64},
    max_static_live_heap_bytes=3,max_cleanup_actions=32768)
print(json.dumps(result,sort_keys=True))
"""
        for invalid in (False,True):
            source = aliased_formals_stop()
            if invalid:
                source["functions"][-1]["blocks"][0]["ops"].pop()
            start = time.monotonic_ns()
            completed = subprocess.run([sys.executable,"-B","-c",code,str(self.executable),self.digest],
                cwd=finite.native.ROOT,input=wire(source),capture_output=True,timeout=30)
            type(self).isolated_children.append({"test":self.id(),"driver":code,
                "input":source,"rust_executable_sha256":self.digest,
                "returncode":completed.returncode,"stdout":completed.stdout.decode(),
                "stderr":completed.stderr.decode(),"outer_wall_ns":time.monotonic_ns()-start})
            if invalid:
                self.assertEqual(completed.returncode,1)
                self.assertIn(b"Rust rejected",completed.stderr)
            else:
                self.assertEqual(completed.returncode,0,completed.stderr.decode())
                self.assertEqual(completed.stderr,b"")
                report = json.loads(completed.stdout)["rust_report"]
                self.assertEqual(report["runtime"]["execution"]["error"],{"code":"user"})
                self.assertEqual(report["cleanup"]["status"],"completed")
                self.assertEqual(report["cleanup"]["after"]["live_bytes"],0)

