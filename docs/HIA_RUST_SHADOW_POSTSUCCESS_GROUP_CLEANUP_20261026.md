# HIA P2: post-success Rust shadow process-group teardown (2026-10-26)

**Scope:** bounded opt-in Rust shadow transport only; the canonical Python
`hia_program.verify_program` remains the sole HIA admission authority.

## Reproduced failure and bounded correction

`hepta.hia_rust_crosscheck._run_bounded_shadow` starts a private session
for a pinned executable. Before this change, cleanup killed the group only on
unsuccessful transport. A launcher can spawn a child, have the child close
stdin/stdout/stderr, print a syntactically valid report, and exit zero. The
selector sees EOF and `Popen.wait` returns, while the child keeps running.

The corrected transport, after all pipes close, uses Linux
`waitid(P_PID, pid, WEXITED|WNOWAIT|WNOHANG)` until the leader is definitely
exited **but not reaped**. This keeps its PID/PGID from being recycled while
the entire dedicated process group is SIGKILLed. Only then is the leader
reaped and the scalar/Owner report delivered for normal validation.
Timeout/failure continues to kill the group and reject.

A new in-repo regression `test_successful_shadow_must_cleanup_pipe_closing_descendant`
creates precisely that process tree, verifies EOF and zero return, and
rejects a surviving child. The original inherited-pipes timeout regression
is retained. No change to Core JSON, Rust verifier, HIA LLVM, C/C++ migrators,
Agent editing or production final-use authorization.

## Acceptance

```sh
python -m unittest tests.test_hia_rust_crosscheck -v
python -m unittest tests.test_hia_rust_crosscheck_cli -v
python -m unittest tests.test_hia_rust_shadow tests.test_hia_rust_owned_shadow -v
```

The independent Linux `waitid(WNOWAIT)` control was executed locally and
observed that a child alive immediately before the kill was not running
afterwards; it was **not** an exact-head Hepta integration/native test.
No complete Hepta checkout or pinned Cargo/LLVM validation is available in
this environment; those steps remain **NOT RUN**.

### Security boundary

This is not hostile-code containment. A child may call `setsid`, detach
before the group cleanup, or exploit other OS surfaces. Real isolation
requires independently verified cgroup/namespace/seccomp policies and,
for production, hardware/OS-level receipts. Both `P0–P7` total acceptance
and `whole_project_blockers_closed` remain open/false. Remote CI scheduling
is not a development stop and is not a passing test.
