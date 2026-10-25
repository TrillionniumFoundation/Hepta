# Hepta strict Clang resource-bounded capture (P2/P4/P7)

## Motivating defect

The strict scalar C migrator previously called `subprocess.run` with
`capture_output=True`, then checked its 32 MB AST limit after the entire
Clang stdout/stderr had already been materialized in Python memory.
The strict C++ L1 compiler path imports this same `_run` function.
A compiler/preprocessor with large output could consume unbounded memory
before the size check and could leave forked descendants after parent exit.

## New implementation

`hepta.clang_capture.run_bounded` uses file-backed stdin/stdout/stderr
and checks stdout/stderr byte quotas while the real child is running.
It uses a per-command wall-time budget and a new POSIX process group.
On success and on failure, it attempts to terminate descendants
inside that process group, including children outliving their parent.

Strict C and C++ migration retain the `_run(argv, input_text=...) -> str`
API and `MigrationRejected` errors. Defaults per child process:
stdout <= 32,000,000 bytes, stderr <= 1,000,000 bytes,
stdin <= 1,000,000 bytes, timeout = 30 seconds.
Missing compiler, timeout and invalid UTF-8 report `E_CLANG_ENV`;
stdout/stderr or stdin quotas report `E_CLANG_SIZE`;
compiler nonzero exit reports `E_CLANG_REJECT`.

## Reproduction and explicit evidence scope

    python -m unittest tests.test_clang_capture -v

The isolated prerequisite module in `/mnt/data/hepta_capture_lab`
was exercised locally with nine successful real subprocess tests:
native Clang preprocessing, byte quotas, timeout, invalid encoding,
nonzero compiler return, input quota and POSIX orphan-child cleanup.
The new integrated Hepta suite and full native builds are NOT counted
as passed without separate evidence on their exact source HEAD.

This is not a compiler sandbox, whole-process RSS/CPU bound or proof
of compilation correctness. It cannot protect against compiler plugins,
child-created sessions, malicious filesystem side effects, untrusted
linkers or external C/C++ library safety. Formal memory/provenance
semantics, L2/L3 C++ migration and P0–P7 production blockers remain open.
