# HIA P2/P7 finite native differential: sealed artifact & ABI invocation

## Exact source boundary

This is a strict increment **on top of** PR #219 commit
`0f684f92f76669acaa488a7d866eb7c778e8bc16`. Reuse the original
`hepta.hia_native_differential` module; no new compiler, schema, LLVM
backend, owned-resource verifier or AI Agent admission authority.

The previous subprocess observer checked source file bytes before/after,
but passed the mutable pathname into `ctypes.CDLL`. A path replacement
between the check and the loader could execute *different* bytes. It also
allowed a finite verified HIA public ABI export to be tested with too many
or too few actual arguments because `ctypes` does not independently know
the verified HIA signature.

## Implemented changes

- Open a native artifact via `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, require
  a nonempty <=8MiB regular file with stable inode, size, mtime and ctime
  across a bounded read. Reject symbolic links and FIFOs.
- Write those exact bytes into a Linux `memfd`, seal it against writes,
  growth, shrinking and seal removal, and compare read-back bytes.
- Pass the sealed descriptor to the child with `pass_fds` and load the
  dynamic object **through `/proc/self/fd/N`**, never via the original
  pathname. Recheck the original artifact's inode and bytes before every
  invocation and after the corpus. Close the descriptor in a `finally`.
  No filesystem-path fallback when Linux sealing is unavailable.
- Require exactly the verified param count for every i32/u32 HIA exported
  function and every corpus vector, before calling any native library.
  Generic unbound oracles still do not claim fully proved parameter ABI.
- Limit both child stdout and stderr file sizes to 4096 bytes with the
  kernel's `RLIMIT_FSIZE`, in addition to file-backed bounded reading and
  the existing subprocess timeout; treat SIGXFSZ and an exact-limit partial
  write/ordinary failure as output-budget refusals.

These controls are for finite **native executable-byte identity** and
homogeneous scalar ABI corpus coverage on qualified Linux x86-64. They
do not make untrusted shared libraries secure: foreign constructors may
still use OS/network privileges without an external hardened sandbox.
Linux dynamic libraries requiring private `$ORIGIN` sibling dependencies
may now fail closed and need a separately qualified loading profile.

## Test and evidence commands

```sh
python -m unittest tests.test_hia_native_pinning \
  tests.test_hia_native_differential tests.test_hia_v6_differential -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

The new regression compiles two genuine small Clang libraries, checks the
original sealed library continues returning the original result after the
pathname is overwritten, checks the original path identity change rejects,
and refuses link/FIFO/empty inputs. A second HIA test demands strict
zero-argument ABI arity for a real verified Owner/Core exported function.

**Observed isolated native controls in this task**: Clang17 compiled a
real shared library loaded from a sealed memfd by Python ctypes (12+9=21).
A second compiled output-flood library hit 4096-byte stdout limit but exited
with code 120, not SIGXFSZ, confirming the extra bounded-output rejection.
No exact repository checkout, pinned Rust/Clang20, full compiler tests,
actual HIA source-native build, hardware test or real-model A/B was run.
The committed in-repository tests are unexecuted acceptance inputs, not
passing exact-head receipts.

All P0–P7 production gates remain OPEN/PARTIAL;
`whole_project_blockers_closed=false`. Remote CI queue never blocks
engineering, but its absence is not proof of correctness.
