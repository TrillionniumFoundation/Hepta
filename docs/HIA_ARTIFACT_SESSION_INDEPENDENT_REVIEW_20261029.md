# Independent review of bounded prepared artifact reuse

The reviewed implementation is commit
`3c547848a4e9e488b42de631bb29ba039c489093`. The three confirmed findings below
are corrected within the examined research boundary. The retained producer
run passed **24/24 actual native regressions, with zero skips**, in 17.363
seconds. The wrapper recorded 17.799 seconds and an unchanged source. These
shared-host durations are not performance qualifications.

The review receipt in
`experiments/hia_next_safety/artifact_review_20261029/REVIEW.json` records the
exact tree, twelve source hashes, retained regression log and limits. The
reviewer checked the recorded hashes against both the clean working tree and
the reviewed commit's Git blobs, and checked the retained log digest and result.

## Reviewed boundary

The new `PreparedArtifactSession` reuses the existing internal proof issuer,
Core verifier, guarded optimizer, native build boundary, sealed-image pinning
and single-attempt native release owner. It admits the narrow
`full_lifecycle(usize, u32) -> u64` checksum-driver profile. It does not import
serialized receipts as executable authority, accept a foreign DSO as a proved
image, or call an effectful kernel inside the controlling Python process.

This review inspected the implementation and adversarial tests independently
of their author. Regression execution remains separately attributed to its
recorded runner and source. No second execution or proof is implied by review
of a retained log.

## Findings resolved during review

| Finding | Implemented correction | Relevant adversarial evidence |
| --- | --- | --- |
| An interruption after inserting an entry could leave a visible admission while the outer failure path closed its descriptor. Parent references and charges could also be partially updated. | Publication is a transaction under the session and cancellation locks. Failure removes visibility and restores dependency, charge, admission and cancellation state. Final disposal checks actual session ownership. | Interruptions after each of the five real state mutations; the surviving baseline remains executable. |
| Driver identity construction could fail after pinning acquired a descriptor but before the session had a release owner for it. | Allocate the unpublished release owner before acquisition, bind the acquired descriptor immediately, and reconcile published or unpublished ownership on failure. | Actual pinned driver followed by identity failure, with both successful close and unknown close outcomes. |
| The new compiler identity route used an unbounded path read and could block on a FIFO before any operation deadline. | Use the established `which`/resolved-path compiler selection and bounded, nonblocking, stable regular-file identity reader for initial admission and subsequent checks. | Executable FIFO and oversized sparse-file refusal before creating a session directory. |

The author also corrected ownership of descriptors internal to pinning. A
failed source-read close aborts before memfd creation. A failed memfd pin has
its own single-attempt close owner. Unknown outcomes remain distinct debts,
consume the finite entry and byte budgets, and do not authorize a retry of a
numeric descriptor that the operating system may already have reused.

## Boundaries examined

- Private proof binding checks the actual canonical Core, state, policy,
  implementation, artifact and full build receipt. Guarded proof reuse retains
  the parent baseline dependency and the same root semantic identity.
- An existing lease retains its image and the parent it depends on. Retirement
  or session close prevents new leases; existing leases can finish. The lease
  lock serializes a run against its own close, and the session counts preserve
  both image and driver while the child is using them.
- The child loads the sealed image descriptor, not a mutable publication path.
  Descriptor identity, required seals and content digest are checked. The
  trusted driver also checks that the resolved function mapping belongs to the
  supplied sealed image before invocation.
- Preparation reservations precede proof/build/pinning. Successful admissions
  retain bounded encoded metadata and image bytes. Unknown release results
  stay charged. A complete-release receipt additionally requires zero charge,
  zero reservation and zero outstanding leases.
- Cancellation has one exact synchronization owner and cannot mint a token
  after a successful cancellation. An already committed cancellation owner
  cannot authorize another preparation.
- Source, solver, policy or compiler identity drift prevents reuse. In-memory
  prepared proof objects remain private capabilities; a JSON report is not a
  replacement for them.

## Limits retained

The examined resource bounds cover entry counts, outstanding leases,
execution attempts, retained encoded metadata and sealed artifact bytes.
They do not bound Python object overhead, proof/build working memory, child
heap, allocator RSS, execution descendants, or retained evidence files. The
trusted host driver, Python runtime, proof encoders/checkers, Z3, compiler,
loader and operating system remain assumptions. The runtime is not a general
hostile-code sandbox, a proof of arbitrary asynchronous exception safety, or
a whole-language memory/resource soundness theorem.

No performance benefit follows from reuse passing these checks. Fixed plans,
finite dynamic programming and NDU must receive the same reuse eligibility,
information and budget in any subsequent net-value experiment. Controller
decisions remain advisory, `DENY_ALL` remains the authority label, and
`safety_certificate` remains false.

## Retained execution and failed attempt

The producer executed the frozen implementation with the existing Clang and
pinned Z3 environment:

```sh
source /tmp/hepta-next-closure-20261028/env.sh
HEPTA_RUN_ARTIFACT_SESSION=1 /tmp/hepta-six-venv/bin/python -m unittest \
  tests.test_hia_artifact_session tests.test_hia_native_pinning -v
```

`PRODUCER_REGRESSION.json` and `PRODUCER_REGRESSION.log` retain the exact
command, source identity, measured outcome and log digest. Review of this
execution does not mean it was rerun by the reviewer. The host was shared
cloud scratch; no physical `dot` identity was observed.

`DEVELOPMENT_FAILED_03.log` preserves an earlier failed development run. Its
fault injection watched a publication-path descriptor before the actual pin
operation; after that descriptor closed, the operating system reused its
number for compiler temporary-directory cleanup. The injected close exception
therefore hit the wrong owner. The test was corrected to inject during the
real pin operation before the source was committed and the successful run was
performed. That failed attempt is not counted as qualification evidence and
is not reassigned to the later source commit.
