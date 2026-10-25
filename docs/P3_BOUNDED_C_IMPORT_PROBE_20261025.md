# P3: bounded native C header importer probe process

Hepta's C importer runs a generated native C program to measure ABI layouts
and constants. Previously both GCC's compiler/version requests and that
generated executable used unbounded `subprocess.run(capture_output=True)`,
creating a memory/resource denial-of-service risk on untrusted headers or
native compiler diagnostics.

All four native process entry points now use the existing file-backed
`hepta.clang_capture.run_bounded` with per-process wall time and output
limits. GCC version, target and compile use 64KB stdout and 512KB stderr;
the generated executable has a separate 4MB stdout allowance. All have
zero stdin and retain their original 30s/120s time bounds. Oversized output,
bad UTF-8, timeouts and tool launch failures surface
`E_C_IMPORT_PROBE_CAPTURE` rather than being counted as completed probes.

The unit suite `tests.test_c_import_capture` covers budget wiring,
error-path fail-closed behavior and a genuine GCC compile/execute probe.
An independent GCC 14.2 local test executed the same bounded capture on
compiler version, target identity, C compile and runtime output; each exited
zero and produced the expected int size/alignment row.

This captures and limits native stdout/stderr but **is not a sandbox**.
The compiler and executable may still perform unrelated filesystem effects;
actual host ABI compatibility, pointer provenance, foreign lifetime obligations
and multi-platform host execution require additional independent evidence.
`whole_project_blockers_closed=false`.
