# Internally admitted checksum artifacts with bounded leases

`hepta.hia_artifact_session.PreparedArtifactSession` extends the existing
private prepared-proof boundary for an explicit research profile. It allows
the fixed, finite-DP and NDU experiments to reuse the same independently proved
artifact without solving its unchanged equivalence theorem before every use.
It does not change the production publisher, default authority, NDU proposal
trust, or the conclusions of earlier experiments.

## Admission and execution boundary

Only a verified Core v1-v7 program with one nonrecursive scalar export,
`full_lifecycle(usize, u32) -> u64`, is admitted. The existing checker and LLVM
builder construct a baseline or a guarded candidate inside the session's new
private directory. The session does not accept a foreign DSO or deserialize a
prepared proof from an external receipt. Its private `_PreparedProof` is issued
only after the actual internal proof, build and sealed-byte binding succeed.

The record binds the canonical Core and resource state, original proof ancestor,
normalized proof policy, checker/emitter/session implementation, actual Z3
binding and library, Clang executable identity, build receipt, exact sealed
artifact bytes and session scope. Guarded verification now emits the same
explicit `policy_sha256` required by the existing prepared-proof issuer. The
issuer's checks are unchanged. Tool identity uses the existing bounded,
nonblocking stable-file reader; a FIFO, missing executable or oversized
compiler cannot enter a weaker identity path.

Each lease checks those bindings and the sealed descriptor's device, inode,
length, seal bits and bytes. Each actual run checks again. A prepared candidate
also retains and rechecks its baseline equivalence ancestor. A source, tool,
solver or policy mismatch permanently invalidates the session. Replacing a
publication pathname cannot replace the already admitted sealed bytes.

The host separately pins one trusted checksum driver by its expected digest.
Actual code runs in a fresh child process with the sealed driver and artifact
descriptors. The driver verifies the actual loaded ELF mapping. No effectful
kernel is invoked in the Python controller process. Scalar inputs, launch
timeout and total execution attempts have explicit finite caps. The experiment
must still validate each returned checksum against its independent oracle.

## Ownership and release

The session owns native descriptors and issues explicit, noncopyable leases.
Its finite entry, retained-byte and outstanding-lease budgets apply before
admission. A candidate retains a dependency on its baseline. Retirement removes
new lease eligibility; an active lease or dependent artifact prevents release.
Closing a session stops new admissions and leases while allowing already owned
leases to finish. A lease's run and close are serialized, so a concurrent close
cannot release the descriptor used by an active child launch.

Publication and accounting form one transaction under the session and
cancellation locks. An interruption after any parent-dependency, byte-charge,
admission-count, entry-publication or cancellation-commit transition removes
visibility and restores the old accounting before disposal. Final disposal
checks actual dictionary ownership, rather than a local success flag. A driver
or artifact acquires an unpublished release owner before metadata construction
can fail.

Every independently owned source-read, failed-pin, driver and admitted-artifact
descriptor has one release attempt. If close raises after possibly taking
effect, the outcome stays unknown and the reservation remains charged. Numeric
descriptor identities are never retried. An uncertain source-read close aborts
before a memfd can be created; failed memfd sealing is a later distinct failure
path. Separate failed preparations retain separate debt entries, which consume
the finite admission capacity. A cleanup report is complete only when entries,
debt, driver ownership, retained charges, reservations and leases all clear.

## Guarantee limits

The byte accounting covers retained canonical encoded metadata and sealed
artifact/driver image bytes. It does not bound Python object overhead, build
temporaries, child heap, allocator RSS, disk files, the entire process, or total
application resource use. Build files remain as evidence. Forgotten explicit
leases consume their bounded slots. This is a reviewed Python host runtime;
Python, the checker, compiler, linker, driver and OS are trusted. The change is
not a Rust implementation, a whole-language soundness theorem, or a proof of
Core-to-machine-code correctness.

The profile keeps `authority = DENY_ALL`, `safety_certificate = false` and
`serialized_receipt_authority = false`. Artifact reuse can reduce recurring
proof cost for every policy. That is not evidence that NDU beats complete DP.
Any such economic claim requires separately preregistered, source-bound actual
measurements that price admission, identity checks, launches, shutdown and
remaining debt equally for all policies.

## Verification command

Run with the qualified Clang and pinned Z3 environment on the actual Linux
process namespace:

```sh
HEPTA_RUN_ARTIFACT_SESSION=1 python -m unittest \
  tests.test_hia_artifact_session tests.test_hia_native_pinning -v
```

Tests exercise actual proof/build/child execution, unchanged-proof reuse,
different semantic modules, guard fallback, forged and mutated receipts,
cross-session tokens, policy drift, finite admission/lease/execution refusal,
cancellation, publication interruptions, driver metadata failure, concurrent
close/run, hostile compiler paths, and independent uncertain descriptor release.
Recorded outcomes and source identities belong in the measurement receipt;
this source document does not predeclare a passing result.
