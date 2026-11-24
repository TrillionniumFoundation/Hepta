# Explicit borrowed-buffer lifecycle

The Agent service admits a separate invocation profile for programs such as the
actual self-host compiler's f0(readbuf, mutbuf, mutbuf) -> u32 entry. The existing
scalar hepta.hia.agent.workload.v1 contract is unchanged. A caller opts into
buffers by freezing hepta.hia.agent.workload.v2 in its context. No new MCP tool
or caller-selected executable is introduced.

## Frozen call contract

~~~json
{
  "schema": "hepta.hia.agent.workload.v2",
  "foreign_buffer_exports": [
    {"function": "f0", "max_buffer_bytes": 1048576}
  ],
  "cases": [
    {
      "function": "f0",
      "arguments": [
        {"bytes_hex": "686961"},
        {"byte_length": 8192, "fill_byte": 165},
        {"byte_length": 1048576, "fill_byte": 0}
      ]
    }
  ],
  "warmup_iterations": 0,
  "repetitions": 1
}
~~~

This example describes input bytes only; 686961 is not a complete compiler
input. Buffer arguments contain either exact lowercase hex or an exact integer
length and fill byte. They contain no address, path, alias, owner or retained
mutable-state handle. Scalars may be interspersed with buffer arguments. The
declared function must have one to eight borrowed buffers, supported scalars,
and exactly one u32 result. Each buffer is bounded by its frozen wrapper extent,
at most 1 MiB; all snapshots in a workload total at most 32 MiB.

The manifest is validated by the existing direct borrowed-byte ABI checker.
Its sorted function/extent pairs bind the context, emitted object, final ELF,
build receipt, executable signature, slot ABI and rollback compatibility.
Scalar-only workloads never expose borrowed entries implicitly. Nominal export
contracts, owned inputs, returned loans, unknown functions and incompatible
result types remain rejected.

## Execution and complete-byte observations

For each invocation, the disposable native process receives distinct live
allocations constructed by the runner from the frozen bytes. Each warmup and
measured repetition resets every allocation to its initial bytes. All inputs
remain private to that synchronous call. The normal resource owner still
applies wall, CPU, address-space and process-group termination checks.

The reference adapter calls the existing general Core VM using distinct
external roots. It does not change Core opcode semantics or introduce a native
compiler callback. External byte storage is counted separately from the Core
allocation ledger; both are bounded. The borrowed profile uses at most ten
million reference VM ticks, 16 MiB of local Core heap and 256 call frames.
Reference exhaustion is an incomplete evaluation, never a program proof.

Every normal return records the scalar and an ordered observation for every
buffer: parameter index, loan kind, complete byte length and SHA-256. The
baseline and candidate must match the reference over all these bytes, including
the entire output capacity and workspace. Return values alone cannot hide
wrong writes or writes beyond a returned logical prefix. Read-only bytes are
also checked for change. A workload may supply expected buffer observations;
otherwise its actual baseline VM observations determine that part of the
comparison.

The native process maps parent-created shared backing files for the external
buffers. After confirmed termination, the parent reads their complete actual
contents. This preserves writes before an abort. A trapping baseline and
candidate must agree on those bytes in addition to the existing VM first-trap
and resource observations. A timeout or unknown termination never becomes a
successful native observation. A wrapper's nonzero ABI status cannot masquerade
as the Core's u32 return.

Call latency measures the declared native call boundary. Input reset, mapping,
complete-byte hashing and process startup lie outside that narrow call timer
and inside the recorded subprocess wall cost. A call-time improvement does not
establish a total-cost improvement.

## Adoption and consumers

The existing hia_verify, hia_emit, hia_evaluate, hia_adopt and hia_rollback
operations retain their independent decisions. All required claims in the
frozen objective must be satisfied by exact receipts. Generation and epoch
checks, replay ownership, old-generation retention, leases and future-call-only
rollback continue to apply.

The authorized consumer protocol acquires a lease for an admitted slot,
invokes the named function with these same immutable snapshot values, and
releases that lease. Acquisition binds the selected generation; invocation
cannot replace it by naming a different executable or mutable pointer. Use the
discovered consumer wire contract and the installation's actual role identities.

A completed invocation returns each exact external byte snapshot as a retained
invocation-buffer artifact, together with its digest, size and argument index.
Clients use the issued artifact reference through hia_read. The artifacts are
data, not executable authority or a reusable mutable buffer. A trapped call can
still return the actual pre-abort byte snapshots without claiming successful
execution. Leases acquired before rollback continue to invoke their retained
generation; released leases are rejected.

## Proof boundary

Core admission, exact-Core reflexivity and complete native rederivation retain
their stated scopes. Adding a buffer invocation path supplies no new universal
compiler theorem. The service's independent Safe Core supplied-ELF refinement
profile still excludes these foreign-buffer exports, multiple functions and
general compiler loops. Such a lowering_refinement request remains unsupported.
If a frozen objective requires it, evaluation/adoption remains blocked even
after successful finite native tests.

An isolated lifecycle continuation of an already frozen learner compiler is a
new observation under this new service profile. It does not recover missing
provider interactions, bills or original task timings, and it does not make a
live production deployment or a remote MCP endpoint qualified.

## Qualification and recovery evidence

The lifecycle qualification must retain the actual fixed-command Worker
requests and responses, immutable artifacts, complete compiler workload and
the dedicated slot's generation transitions. It records an unsupported
independent machine-refinement result separately. A consumer must compile and
execute an actual returned image; checking only its source or receipt is
insufficient. A same-compiler baseline is an activation check, not evidence of
a compiler optimization or an unfamiliar-agent study.

Restart controls reopen the same durable state. A lease acquired before
rollback must continue to identify its retained generation after its client
exits; a later acquisition must observe the selected generation; a released
lease must remain refused after another process opens that state. Request,
response and failure evidence remain part of the result. These observations
establish only the tested local recovery boundary, not cross-host recovery,
power-loss durability or deployment of a remote endpoint.

Use the current source-bound release and installed-interface evidence indexed
by [CURRENT.md](CURRENT.md). Earlier hosted lifecycle observations remain
historical provenance and cannot qualify a changed native implementation.
