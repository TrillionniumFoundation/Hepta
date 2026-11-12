# Retained native retirement policy and state

This development candidate moves the complete bounded retirement policy used by
`PathIdentityPin` and `NativeRetirement` into
`examples/hia_bootstrap/retirement_state.hepta`. Explicit selection uses
`HEPTA_HIA_RETIREMENT_STATE_MANIFEST`. The original hosted policy remains an
independent qualification reference. A selected native admission or transition
failure cannot retry that reference.

The component is imported from `5d5424a31caa33283a562defba9cb6b187deb99c`.
Its HIA bytes, state protocol, fixed syscall transport and native policy are
unchanged; current paths use `.hepta`. The integrated source is registered in
the shared source contract, package resources, source reproduction, native CI
and current qualification runner. Matching-source cold qualification and the
complete retained regression remain separate acceptance gates. A development
executable or a successful individual test does not satisfy those gates.

The selector is unselected only when its environment variable is absent. An explicitly present empty value is rejected before image loading or entry into the hosted reference. Remove the variable to use the unselected reference path; an empty assignment does not disable selection.

## State and effect boundary

Each pin has one retained 4608-byte HIA state block. Its 512-byte header records
the original expected and bound inode identities separately from later
observations; descriptor zero is distinct from an absent descriptor. The
remaining 4096 bytes retain the exact captured filesystem path and zero padding.
The original descriptor remains held to prevent inode-number reuse. This native
profile accepts captured filesystem path representations of at most 4096 encoded
bytes; actual syscalls can still reject a representation or individual component.
Longer diagnostic-only `Path` objects that the old constructor could hold are
refused before native effects. Arbitrary Python `Path` API equivalence is not
claimed. Tests retain the 4096/4097-byte constructor boundary.

HIA initializes this block once and guards every subsequent operation. The
Python adapter never reconstructs it from Python flags. An instance identity,
monotonic u64 sequence and action-specific pending claim bind every effect
outcome. State or token corruption and sequence exhaustion refuse subsequent
effects. The non-cryptographic checksum detects accidental state corruption; it
does not defend against malicious code in the same process recomputing it.
Every admitted cleanup decision consumes its observation token. A second
directory/file removal claim needs a fresh observation, including after a
previous pending, removed or failed result. A successful removal permanently
records path release, so later path recreation cannot restore deletion rights.

HIA owns original-pin admission, acquisition/rebinding refusal, the decision to
obtain another descriptor observation, owned/replaced/absent classifications,
one-time native and identity-close claims, outcome consumption, disk-retry
eligibility, and native/identity/complete predicates. A file pin can be attached
to exactly one retirement task. Directory pins use the same state owner but
cannot become artifact retirement tasks.

The fixed foreign adapter holds actual Python/loader objects and invokes
`open`, `fstat`, `lstat`, `close`, `dlclose`, `unlink` and `rmdir` only for the
operation selected by HIA. It retains exception and timestamp diagnostics. It
does not decide whether an owned resource may be released. The existing
multiversion lock, transfer from the live generation table, and capacity
accounting remain hosted and are outside this policy replacement.

The native-attempt claim precedes clearing function references. An interruption
therefore cannot manufacture a second native-release owner. Unknown `close` or
`dlclose` results remain unknown permanently, even if the numeric descriptor or
loader handle has since been reused. Native release and identity release remain
separate results. Only fresh identity-checked file cleanup can be retried.

The adapter checks its creator PID before acquiring an inherited lock. A forked
child cannot use another process's retained state. The image is trusted local
executable code, selected through the existing source/image manifest custody
loader, and stays pinned for the entire original owner's lifetime. Changing an
ambient selector or a source file cannot replace that existing state machine;
new owners must pass current installed custody again. It is not a sandbox for
user machine code or a cross-process resource manager.

The hosted reference's writable fields still forward to its actual backend;
the facade cannot shadow them. Selected native identity/state fields are read
only. Host code cannot create new native state by assigning Python attributes.
The foreign `library` and function objects remain in the adapter.

## Native-policy failure and returned descriptor custody

The fixed Linux x86-64 `openat` transport in
`tools/hia_retirement_open_syscalls.S` writes a started marker, the signed kernel
result and a completed marker into a retained 16-byte result slot before it
returns to Python. `hepta/hia_retirement_effects.py` carries its exact 45-byte
executable; an independent assembly check binds those bytes to the source. An
installed wheel needs no assembler or authoring tree. This primitive implements
no HIA policy. It accepts only the existing read-only, no-follow, non-blocking,
close-on-exec flags, with the directory flag when requested; embedded NUL is
rejected before the raw syscall.

Line and opcode interruptions between the foreign return and Python assignment
therefore cannot lose an actually returned descriptor. A completed negative
errno proves that no descriptor was returned. A completed negative `EINTR` can
retry inside the same foreign `open` operation, preserving `os.open` behavior
and allowing Python signal handlers to raise between calls. A positive result
or an incomplete syscall result never retries. An incomplete result remains
explicitly unknown; absence of a Python descriptor field is never evidence of
release. The original effect fault-injection surface is retained through a
module-local os facade; it does not modify the process-global os module.

Failure before or after the HIA descriptor handoff retains the returned
descriptor, instance and claim as an unconfirmed result. It cannot be closed on
guessed native authority. The original exception also receives the retained
owner and detached diagnostics, without replacing the original exception.

A strong process-local quarantine keeps the owner alive even if a caller
stringifies or drops that exception. `retirement_quarantine_snapshot()` exposes
detached observations and grants no close/retry right. New selected owners are
refused while policy custody is quarantined; existing healthy owners can finish
their admitted cleanup. There is no production clear/forget/retry operation.
These records are foreign-handle custody after policy failure, not a hosted
policy fallback or a durable recovery journal.

The actual multiversion constructor checks this admission barrier, latches the
image and initializes the native pin for its exact prospective private path
before creating a runtime directory. Native state initialization failure
therefore creates no directory. The pin is assigned to the runtime before
`mkdir`, which runs inside the existing cleanup boundary. Directory construction
does not perform a second image selection. A later artifact-image admission
failure can clean the already-bound directory using its original immutable
image. Its existing failure route can report a fenced
directory pin without attempting deletion. A failed artifact preparation can
still register an inert, permanently incomplete retirement record in the
existing bounded pending table. Its resource metadata remains available, while
all effects stay refused. The generation-transfer and capacity algorithms have
not been replaced or relaxed. This does not establish a process-wide bound over
arbitrary already-admitted host runtimes.

The pin strongly retains the actual retirement resource holder before native
task attachment. An attachment interruption before or after the native
transition produces an inert incomplete holder, so the runtime can register it
and propagate an original preparation failure without losing the library,
function references or native descriptor. A repeat registration may recover
only that identical holder with identical original inputs; it cannot attach a
second task or substitute handles. Quarantine diagnostics expose this foreign
custody without manufacturing a release authority. Actual-runtime preparation
failure and garbage-collection controls exercise both attachment boundaries.

The original v67 development history recorded a compile refusal at 286 blocks,
an observation-token replay failure, foreign-library custody loss and a
returned-open interruption failure. These are historical findings from the
imported component, not new observations on this integration. The retained
source splits event branches into ordinary HIA helpers without changing the
256-block bound. Its current tests exercise the corrected boundaries with real
kernel descriptors, loader objects, dropped exception tracebacks, garbage
collection and interruptions before Python's descriptor STORE opcode. Any new
run retains its own exact source and original results.

## Remaining production owners found during the audit

Release selection identifies an immutable current and previous release. It
does not prove that an older release has no consumers. There is still no shared
release-consumer registry or launcher pin covering all existing workers. Agent
`versions` retain arbitrary generations; `leases` retain issued consumer
references; `release_slot` deactivates a lease and deliberately retains bytes.
Automatic release deletion is not implemented by this change.

The ordinary worker's native request kernel admits request payloads, then enters
the hosted `HIAAgentService`. `AgentStore` still owns ten SQLite/WAL tables:
artifacts, profiles, contexts, requests, costs, cursors, slots, versions, leases
and execution budgets. Adoption and rollback deliberately commit their slot
effect and exact replay response in one SQLite transaction. Moving only requests
to a second journal would lose that atomic boundary.

Execution-budget state is a separate owner. Integration must preserve cumulative
cost and every non-null uncertain owner in the original database. Its HIA policy
and matching-source qualification do not establish slot/lease ownership or
installed-release garbage collection.

The present owner is in-process and non-durable. It neither releases another
process's handles nor establishes installed-release garbage collection, a
complete native Agent journal, service activation, or whole-stack retirement.
