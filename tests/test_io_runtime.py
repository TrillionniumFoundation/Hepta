"""Owned source I/O, native cleanup and honest local-readiness qualification."""
import copy
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import compile_rust
from hepta.hmir import hmir_analysis
from hepta.pipeline import analyze, analyze_project, concurrent_ir_analysis, resource_ir_analysis
from hepta.runtime_io import IO_BUILTINS, IO_RUNTIME
from tests.test_task_groups import RUSTC
from tools.validate_io import (
    CLAIMS, CONTROLS, EFFECTS, MAIN, REJECTIONS, REQUEST, SCENARIOS, START, TAKE, VALID,
    QualificationFailed, digest, rejection_report, run_qualification, validate_io_report,
)

ROOT = Path(__file__).resolve().parents[1]


class IoSourceTests(unittest.TestCase):
    def reject(self, source, code):
        result = analyze(source, native=False).report
        self.assertFalse(result["ok"], result)
        self.assertIn(code, {item["code"] for item in result["diagnostics"]}, result)

    def test_source_owner_and_interface_rejections(self):
        for name, (kind, source, code) in REJECTIONS.items():
            if kind != "frontend":
                continue
            with self.subTest(name=name):
                self.reject(source, code)

    def test_every_io_builtin_checks_arity(self):
        for name in sorted(IO_BUILTINS):
            with self.subTest(name=name):
                self.reject(MAIN + f"{name}();" + "}", "E_ARITY")

    def test_take_requires_mutable_count_and_status(self):
        for field in ("count", "status"):
            with self.subTest(field=field):
                body = TAKE.replace("let mut " + field, "let " + field)
                self.reject(MAIN + START + REQUEST + body + "io_shutdown(move io);}", "E_IMMUTABLE")

    def test_types_do_not_coerce_ticket_ports_or_status(self):
        self.reject(MAIN + START + "io_close_port(mut io,true);io_shutdown(move io);}", "E_TYPE")
        self.reject(MAIN + START + "io_poll(mut io,false);io_shutdown(move io);}", "E_TYPE")
        self.reject(MAIN + START + REQUEST + TAKE.replace("status:u8", "status:u64") + "io_shutdown(move io);}", "E_TYPE")

    def test_buffer_cannot_be_used_while_in_flight(self):
        self.reject(MAIN + START + REQUEST + "let length=len(bytes);" + TAKE + "io_shutdown(move io);}", "E_USE_AFTER_MOVE")

    def test_cancel_does_not_discharge_request_or_buffer_obligation(self):
        self.reject(MAIN + START + REQUEST + "io_cancel(mut io,read request);io_shutdown(move io);}", "E_LINEAR_UNCONSUMED")

    def test_early_return_requires_explicit_owner_cleanup(self):
        self.reject(MAIN + START + "if true{return;}io_shutdown(move io);}", "E_LINEAR_UNCONSUMED")

    def test_loop_cannot_leave_request_unconsumed(self):
        self.reject(MAIN + START + "for i in 0..2{" + REQUEST + "}io_shutdown(move io);}", "E_LINEAR_UNCONSUMED")

    def test_runtime_owners_cannot_be_hidden_in_adts_or_arrays(self):
        for declaration in ("enum Hidden{Some(IoRequest),None}", "struct Hidden{x:Result<IoRequest,u8>}",
                            "struct Hidden{x:[IoRequest;2]}"):
            with self.subTest(declaration=declaration):
                self.reject(declaration + VALID, "E_NESTED_LINEAR")

    def test_opaque_types_reject_arguments_and_source_construction(self):
        self.reject("fn f(x:read IoReactor<u8>)->Unit effects {}{}", "E_IO_TYPE")
        self.reject(MAIN + "let request=IoRequest{};}", "E_UNKNOWN_TYPE")

    def test_side_effects_are_declared_and_snapshots_are_pure(self):
        self.reject(VALID.replace(f"effects {{{EFFECTS}}}", "effects {}"), "E_EFFECT")
        source = "fn inspect(io:read IoReactor,request:read IoRequest)->u8 effects {}{return io_request_status(read io,read request);}"
        result = analyze(source, native=False).report
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["effects"]["inspect"], [])

    def test_budget_contract_names_capacity_and_exclusions(self):
        result = analyze(VALID, native=False).report
        self.assertTrue(result["ok"], result)
        contract = result["resource_contracts"][0]
        self.assertEqual(contract["kind"], "bounded_io_reactor")
        self.assertEqual(contract["platform"], "x86_64_unknown_linux_gnu_hosted")
        self.assertEqual(contract["limits"], {"owned_ports": 2, "occupied_requests": 2, "admitted_buffer_capacity_bytes": 16})
        self.assertIs(contract["includes_completed_uncollected_requests"], True)
        self.assertEqual(contract["cancellation"], "serialized_at_explicit_pump_boundaries")
        for excluded in ("preadmission_buffers", "refused_submission_buffers", "allocator_metadata", "kernel_socket_buffers", "process_RSS", "CPU_time"):
            self.assertIn(excluded, contract["excludes"])

    def test_c_and_independent_ir_profiles_fail_closed(self):
        for source in (VALID, "struct Snapshot{report:IoReport} fn f()->Unit effects {}{}",
                       "struct Snapshot{pair:IoPair} fn f()->Unit effects {}{}"):
            current = analyze(source, native=False)
            self.assertTrue(current.report["ok"], current.report)
            for name, result in (("c", analyze(source, backend="c", native=False).report),
                                 ("resource", resource_ir_analysis(current)), ("concurrent", concurrent_ir_analysis(current)),
                                 ("hmir", hmir_analysis(current))):
                with self.subTest(profile=name, source=source):
                    self.assertFalse(result["ok"], result)
                    self.assertTrue(result.get("diagnostics"), result)

    def test_no_std_rejects_even_pure_opaque_io_references(self):
        source = "fn inspect(io:read IoReactor)->IoReport effects {}{return io_report(read io);}"
        result = analyze(source, no_std=True, native=False).report
        self.assertFalse(result["ok"], result)
        self.assertIn("E_NO_STD", {item["code"] for item in result["diagnostics"]})


@unittest.skipUnless(RUSTC, "requires the pinned native Rust compiler")
class IoNativeTests(unittest.TestCase):
    def runtime(self, source):
        with tempfile.TemporaryDirectory(prefix="hepta-io-unit-") as directory:
            output = Path(directory) / "run"
            built = compile_rust("#![allow(unused,dead_code,non_camel_case_types)]\n" + IO_RUNTIME + source,
                                 rustc=RUSTC, crate_type="bin", output=output)
            self.assertTrue(built["ok"], built)
            return subprocess.run([str(output)], text=True, capture_output=True, timeout=10)

    def test_native_rust_rejects_aliasing_and_consumed_operands(self):
        for name, (kind, source, code) in REJECTIONS.items():
            if kind != "native":
                continue
            with self.subTest(name=name):
                report = rejection_report(kind, source, RUSTC)
                self.assertFalse(report["ok"], report)
                self.assertIn(code, {item["code"] for item in report["diagnostics"]})

    def test_reactor_cannot_be_moved_between_threads(self):
        source = IO_RUNTIME + "\nfn main(){let io=__hepta_io_reactor(2,1,8);std::thread::spawn(move||{__hepta_io_shutdown(io);});}"
        report = compile_rust(source, rustc=RUSTC, crate_type="bin", check_only=True)
        self.assertFalse(report["ok"], report)
        self.assertIn("E0277", {item["code"] for item in report["diagnostics"]}, report)

    def test_cross_file_owner_return_and_error_cleanup_pass_rust(self):
        for name in SCENARIOS:
            with self.subTest(name=name):
                report = analyze_project(ROOT / f"examples/io/{name}.hepta", native=True, rustc=RUSTC, crate_type="bin").report
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["checks"]["rust_borrows_types"], "rustc_checked")

    def test_configuration_length_and_timeout_boundaries_preserve_input(self):
        result = self.runtime(r'''
fn main(){
    for (ports,requests) in [(0,1),(1,1),(257,1),(2,0),(2,1025)] {
        let mut io=__hepta_io_reactor(ports,requests,8);
        assert_eq!(__hepta_io_report(&io).h_status,6);
        assert_eq!(__hepta_io_local_pair(&mut io).h_status,6);
        assert_eq!(__hepta_io_poll(&mut io,0),Err(6));
        let request=__hepta_io_read(&mut io,0,vec![19;8],8,10);
        let mut count=1;let mut status=0;
        assert_eq!(__hepta_io_take(&mut io,request,&mut count,&mut status),vec![19;8]);
        assert_eq!((count,status),(0,6));
        let report=__hepta_io_shutdown(io);assert_eq!((report.h_open_ports,report.h_reserved_bytes),(0,0));
    }
    let mut io=__hepta_io_reactor(2,1,8);let pair=__hepta_io_local_pair(&mut io);assert_eq!(pair.h_status,0);
    for (length,millis) in [(9,1),(8,86400001)] {
        let request=__hepta_io_read(&mut io,pair.h_left,vec![23;8],length,millis);
        let mut count=1;let mut status=0;
        assert_eq!(__hepta_io_wait(&mut io,request,&mut count,&mut status),vec![23;8]);
        assert_eq!((count,status),(0,6));assert_eq!(__hepta_io_report(&io).h_occupied_requests,0);
    }
    assert_eq!(__hepta_io_poll(&mut io,86400001),Err(6));
    assert_eq!(__hepta_io_poll(&mut io,0),Ok(0));assert_eq!(__hepta_io_report(&io).h_poll_calls,0);
    __hepta_io_shutdown(io);
}''')
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(RUSTC, "requires the pinned native Rust compiler and private socketpair permission")
class IoQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_qualification(rustc=RUSTC, repeats=1)

    def test_actual_readiness_partial_io_and_resource_recovery(self):
        validate_io_report(self.report)
        self.assertEqual(len(self.report["source_cases"]), 3)
        self.assertEqual(len(self.report["rejections"]), 16)
        observed = self.report["native_controls"]["runs"][0]["metrics"]
        for key in CONTROLS:
            self.assertEqual(observed[key], CONTROLS[key])
        self.assertGreater(observed["blocking_poll_ns"], 10_000_000)
        self.assertGreater(observed["partial_write_bytes"], 0)
        self.assertFalse(any(self.report["claims"].values()))

    def test_strict_validator_rejects_scope_identity_execution_and_native_boundary_mutations(self):
        mutations = [
            lambda r: r.update(status="failed"), lambda r: r.update(failure="an earlier trial failed"),
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["source_files"].update({"hepta/runtime_io.py": "0" * 64}),
            lambda r: r.update(profile="aarch64-unknown-linux-gnu"),
            lambda r: r["host"].update(system="Darwin"), lambda r: r["host"].update(pointer_bits=True),
            lambda r: r.update(repeats=True), lambda r: r.update(repeats=2),
            lambda r: r["limits"].clear(), lambda r: r.update(created_utc="yesterday"),
            lambda r: r["toolchain"].update(executable_sha256=None),
            lambda r: r["source_cases"].pop(), lambda r: r["source_cases"].append(r["source_cases"][0]),
            lambda r: r["source_cases"][0]["analysis"].update(ok=False),
            lambda r: r["source_cases"][0]["analysis"].update(project={}),
            lambda r: r["source_cases"][0]["analysis"].update(resource_contracts=[]),
            lambda r: r["source_cases"][0]["analysis"]["claims"].update(whole_language_soundness_proved=True),
            lambda r: r["source_cases"][0]["analysis"].update(backend={}),
            lambda r: r["source_cases"][0]["analysis"].update(checks={}),
            lambda r: r["source_cases"][0]["analysis"]["backend"].update(check_only=False),
            lambda r: r["source_cases"][0]["build"].update(check_only=True),
            lambda r: r["source_cases"][0]["build"].update(artifact_bytes=0),
            lambda r: r["source_cases"][0]["build"].update(artifact_sha256="0" * 64),
            lambda r: r["source_cases"][0]["build"].update(flags=[]),
            lambda r: r["source_cases"][0]["build"]["flags"].append("overflow-checks=no"),
            lambda r: r["source_cases"][0]["build"]["flags"].append("opt-level=0"),
            lambda r: r["source_cases"][0]["build"]["flags"].append("sysroot=/unqualified"),
            lambda r: r["source_cases"][0]["build"].update(linker="/unqualified/linker"),
            lambda r: r["source_cases"][0]["build"].update(artifact="/not-the-executed-program"),
            lambda r: r["source_cases"][0]["build"].update(link_args=["unverified.o"]),
            lambda r: r["source_cases"][0]["runs"][0].update(returncode=True),
            lambda r: r["source_cases"][0]["runs"][0].update(timed_out=True),
            lambda r: r["source_cases"][0]["runs"][0].update(elapsed_ns=0),
            lambda r: r["source_cases"][0]["runs"][0].update(stderr="ignored warning"),
            lambda r: r["source_cases"][0]["runs"][0].update(stdout="success"),
            lambda r: r["source_cases"][0]["runs"][0].update(argv=["/not-the-executed-program"]),
            lambda r: r["source_cases"][0]["runs"][0].update(executable_sha256="0" * 64),
            lambda r: r["source_cases"][0]["runs"][0].update(executable_after_sha256="0" * 64),
            lambda r: r["source_cases"][0]["runs"][0].update(executable_bytes=True),
            lambda r: r["source_cases"][0]["runs"][0].update(stdout_base64="non-canonical"),
            lambda r: r["source_cases"][0]["runs"][0]["metrics"].update(admitted=True),
            lambda r: r["rejections"].pop(), lambda r: r["rejections"][0]["report"].update(ok=True),
            lambda r: r["rejections"][0]["report"].update(diagnostics=[]),
            lambda r: r["rejections"][9]["report"].update(backend={}),
            lambda r: r["native_controls"].update(source_sha256="0" * 64),
            lambda r: r["native_controls"].update(c_build=None),
            lambda r: r["native_controls"]["c_build"].update(object_bytes=False),
            lambda r: r["native_controls"]["c_build"].update(compiler_sha256=""),
            lambda r: r["native_controls"]["c_build"].update(compiler_sha256="0" * 64),
            lambda r: r["native_controls"]["c_build"].update(compiler="/not-the-qualified-compiler"),
            lambda r: r["native_controls"]["c_build"]["command"].__setitem__(0,"/not-the-qualified-compiler"),
            lambda r: r["native_controls"]["c_build"].update(command=[]),
            lambda r: r["native_controls"]["c_build"].update(target="aarch64-linux-gnu"),
            lambda r: r["native_controls"].update(linked_object_sha256="0" * 64),
            lambda r: r["native_controls"]["build"].update(link_args=[]),
            lambda r: r["native_controls"]["runs"][0].update(trial=True),
            lambda r: r["native_controls"]["runs"][0].update(elapsed_ns=1),
            lambda r: r["native_controls"]["runs"].clear(),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(readiness_cancel_races=0),
        ]
        mutations += [lambda r, key=key: r["claims"].update({key: True}) for key in CLAIMS]
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                changed = copy.deepcopy(self.report)
                mutate(changed)
                with self.assertRaises(ValueError):
                    validate_io_report(changed)

    def test_raw_native_transcript_cannot_inflate_or_omit_observations(self):
        mutations = {
            "blocking_poll_ns": 0, "blocking_thread_cpu_ns": 100_000_000,
            "blocking_real_poll_calls": 100, "partial_write_bytes": 2 * 1024 * 1024,
            "final_deadline_poll_millis": 250, "readiness_cancel_races": 0,
            "actual_fd_limit_refusals": 0, "metadata_refusal_sites": 2,
            "shutdown_fd_close_cases": 0, "final_tracked_buffer_bytes": True,
            "foreign_reactor_cases": 0, "hot_path_allocations": 1,
            "write_blocking_poll_ns": 0, "write_real_poll_calls": 0,
        }
        for key, value in mutations.items():
            with self.subTest(field=key):
                changed = copy.deepcopy(self.report)
                run = changed["native_controls"]["runs"][0]
                raw = json.loads(run["stdout"])
                raw[key] = value
                run["stdout"] = json.dumps(raw) + "\n"
                run["stdout_sha256"] = digest(run["stdout"].encode())
                run["stdout_base64"] = base64.b64encode(run["stdout"].encode()).decode("ascii")
                run["metrics"][key] = value
                with self.assertRaises(ValueError):
                    validate_io_report(changed)

    def test_producer_preserves_failures_timeouts_and_existing_reports(self):
        original_run = subprocess.run
        with tempfile.TemporaryDirectory(prefix="hepta-io-retention-") as directory:
            for label, timeout, returncode, stdout, stderr in (
                    ("failed", False, 77, b"partial", b"execution refused"),
                    ("timeout", True, None, b"\xffpartial", b"\xfetimeout evidence"),
                    ("non_utf8", False, 0, b"\xffpartial", b"")):
                target = Path(directory) / (label + ".json")
                def refuse(command, *args, **kwargs):
                    if len(command) == 1 and str(command[0]).endswith("/pipeline"):
                        if timeout:
                            raise subprocess.TimeoutExpired(command, 30, output=stdout, stderr=stderr)
                        return subprocess.CompletedProcess(command, returncode, stdout, stderr)
                    return original_run(command, *args, **kwargs)
                with patch("tools.validate_io.subprocess.run", side_effect=refuse):
                    with self.assertRaises(QualificationFailed):
                        run_qualification(rustc=RUSTC, repeats=1, output=target)
                saved = json.loads(target.read_text())
                self.assertEqual(saved["status"], "failed")
                observed = saved["source_cases"][0]["runs"][0]
                self.assertEqual(observed["stdout"], "partial" if label == "failed" else None)
                self.assertEqual(base64.b64decode(observed["stdout_base64"]), stdout)
                self.assertEqual(base64.b64decode(observed["stderr_base64"]), stderr)
                self.assertEqual(observed["stdout_sha256"], digest(stdout))
                self.assertEqual(observed["stderr_sha256"], digest(stderr))
                self.assertEqual(observed["argv"], [saved["source_cases"][0]["build"]["artifact"]])
                self.assertEqual(observed["executable_sha256"], saved["source_cases"][0]["build"]["artifact_sha256"])
                self.assertIs(observed["timed_out"], timeout)
                self.assertNotIn("metrics", observed)
                with self.assertRaises(ValueError):
                    validate_io_report(saved)
                previous = target.read_bytes()
                with self.assertRaises(FileExistsError):
                    run_qualification(rustc=RUSTC, repeats=1, output=target)
                self.assertEqual(target.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
