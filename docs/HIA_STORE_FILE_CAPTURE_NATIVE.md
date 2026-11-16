# Complete stable-read and path-capture control

## Status and scope

The owned-descriptor v2 successor is an explicitly versioned implementation.
Its source delta was reviewed against the R13b staged composition
`da40062fe6bfc088d97768fe0b0bc7c31a98e723`; the original v1 business definitions
remain frozen against index `65630a839d2dda471b7b03605ee21606de818421`.
The complete same-source generation, original/VM/native observations, real-OS
controls and installed-worker gates below determine component qualification.
This document defines their scope and does not establish a runtime PASS.
Earlier v1 observations and failures retain their original identities and status.

The proposed selector is `HEPTA_HIA_STORE_FILE_CAPTURE_MANIFEST`. One HIA image
owns both complete original functions, `stable_read(path, limit, *, dir_fd=None)`
and `capture_path(path, roots, limit)`. The existing complete functions remain
as explicit unselected references. A selected call never invokes either retained
whole function. A dynamically replaced global `stable_read` remains an original
callee; the selection layer does not override an administrator's Python value.

HIA controls all original branches, short circuits, root/component/close loops,
exception selection, with suppression, finally routing and terminal decisions.
Each of 73 foreign ports executes a literal expression, an interpreter protocol
action, or an observable ownership transfer. The original 71 numbered ports are
an exact prefix. Ports 72 and 73 issue the v2 stable-read descriptor close on
normal and exceptional paths respectively. The 40 capture-path control nodes
remain unchanged. After the final close-loop iteration HIA itself selects error
propagation or normal local release; there is no synthetic empty host cleanup
port.

Python still implements arbitrary-object attribute lookup, calls, operator
protocols, Path, stream and OS effects. The separate Linux descriptor primitive
has its own explicit ABI and qualification entry point. It is not installed as
an os/fdopen substitute and this owner does not claim a fully native OS stack.

## Original identity and observable boundaries

The frozen complete original definitions are:

| Function | Bytes | SHA256 |
| --- | ---: | --- |
| stable_read | 1018 | 56f8419c2343b5f6339fde0b42f92866e1c9d60b1cbe32bd24c54cda9ee40dfa |
| capture_path | 1720 | 67f6ce67d4ba5cb8619be15a5aeeb6dbbf4214c2c04a5300411b8e6ad0a1cdea |

Both v1 originals, AgentRejected, reject, exact local names, baseline file pins
and the complete static caller inventory remain packaged under
`tests/fixtures/hia_store_file_capture_original_65630/`. They are not rewritten
to make the corrected implementation appear byte-equivalent to v1.

The separately named reference directory
`tests/fixtures/hia_store_file_capture_owned_fd_v2/` contains the corrected
1,128-byte stable_read body, SHA256
`fb558447b44566c42011d0560d687043f45d8fee05099c4b20c1df5709eab181`.
Its capture_path, AgentRejected and reject bodies remain byte-identical to their
v1 counterparts. V2 expected observations must be produced from these explicit
v2 reference bodies in independent original processes; old v1 outputs are not
v2 expectations.

### Descriptor ownership correction

The preserved v1 real-OS failure is the directory case: os.open returned
descriptor 4, then os.fdopen(fd, "rb") raised IsADirectoryError before the with
statement acquired its context manager. Descriptor 4 remained open. The original
failure record is 1,378 bytes with SHA256
`5e7985e2c69128a54c3b1ef2b2aa7efb315a1722ea28abac817ace97ec40dcf8`.
Neither that failure nor the old fixture is replaced by this successor.

V2 makes the os.open result the caller's sole descriptor responsibility:

```python
fd = os.open(path, flags, dir_fd=dir_fd)
try:
    with os.fdopen(fd, "rb", closefd=False) as stream:
        # The existing regular-file, extent, read and identity checks.
        ...
finally:
    os.close(fd)
```

The stream still performs its original context-manager close, but closefd=False
keeps descriptor ownership with stable_read. Python documents os.fdopen as an
alias of open that accepts the same arguments, and documents closefd=False as
leaving the supplied descriptor open when the file object closes:
[os.fdopen](https://docs.python.org/3.14/library/os.html#os.fdopen) and
[open](https://docs.python.org/3.14/library/functions.html#open).
This is an explicit bug-fix contract, including an additional closefd keyword and
an explicit close event, rather than a claim of complete v1 effect equivalence.

stable_read still constructs flags before entering its OSError handler. Failure
of os.open does not issue a close. After a returned open, normal completion and
with suppression issue stable_close_normal; an unsuppressed fdopen, context
lookup, enter, body, exit or truth error issues stable_close_error before the
original outer OSError matcher. A failed close is propagated or matched once,
without a retry. If normal close cancels a pending return, its cancellation path
does not close the descriptor a second time. A normal-exit error before close
does still route through exceptional close.

Runtime special lookup order is observed using fixed private probe classes.
A failed enter never invokes exit; normal exit return values are discarded
without truth testing. An exception exit result is tested once, with the real
active exception still visible. Successful suppression resumes after leaving
that exception context. Original local-slot order and exception
identity/name/obj/context/traceback fields are retained.

Regular-file and size checks occur before reading. The read uses the original
`limit + 1` expression, with no new integer coercion, truncation or quota.
The second fstat follows the read. Length and the exact dev/inode/size/mtime_ns/
ctime_ns tuple retain their short-circuit order. OSError matching and wrapping
remain dynamically resolved; invalid except targets remain failures.

capture_path performs the exact absolute/string/traversal checks, constructs
Path twice, and preserves the first matching nonempty administrator root.
The relative.parts truth test and the subsequent tuple construction are separate
original reads. Root/component opens retain O_RDONLY, O_DIRECTORY, O_CLOEXEC
and O_NOFOLLOW. The final read receives the actual open directory descriptor.
Descriptors are appended only after successful opens. Finally uses the original
reversed list, and the first close failure stops later closes. No compensating
close is invented for an open whose subsequent list append failed.

## Continuation and lifetime contract

The protocol schema is `hepta.hia.store-file-capture.v2`, with state version 2.
The request, output and persistent state extents remain 80, 96 and 128 bytes.
Their v2 magic values are respectively `0x3243515041434948`,
`0x3252435041434948` and `0x3253435041434948`; v1 magic and observations remain
historical inputs, not alternate admissions to v2. Build and manifest schemas
also explicitly use v2.

Every call uses a fresh two-word nonce, exact mode/port/sequence/checksum and
guarded buffers. The events remain INITIALIZE, CLAIM, SUCCEEDED, RAISED, FINALIZE
and RESUME. Stable-read mode admits ports 1–31 and the new ports 72–73;
capture-path mode admits only ports 32–71. The appended stable ports do not
extend capture-path authority.

State word 9 records HIA's acquisition/issue state:

| Word 9 | Meaning |
| ---: | --- |
| 0 | No acknowledged stable-open return. Capture-path mode always retains 0. |
| 1 | The stable-open return was acknowledged; no close has been claimed. |
| 2 | HIA issued a CLAIM for stable_close_normal or stable_close_error. |

A close CLAIM changes 1 to 2. **State 2 is not evidence that os.close occurred,
returned, or was acknowledged.** A close result still requires the actual
receipt and guarded-buffer checks. Missing entry/ACK evidence remains
fenced/UNKNOWN; neither the field nor an error handler may guess descriptor
state, close it again, or retry. The state otherwise distinguishes an issued
effect, a claimed effect, an exception-context exit, ready-to-return/propagate
and a confirmed terminal.

A whole-method weak-registered foreign observation surrounds actual effects.
Each port has its own independent foreign observation. A port ACK retires that
port's facts, while the whole-method facts remain until the separate FINALIZE
ACK. Before each entry/effect, the exact record and whole borrowed resources are
checked again. No arbitrary descriptor is guessed to be a registered Store.

INITIALIZE happens before entering the observed whole method. Preparation
failure before the first original effect can be refused without inventing a
foreign exception. Once an original effect starts, a missing native receipt is
UNKNOWN and keeps the actual record and owned values. Ordinary provider
exceptions use a real RAISED acknowledgement; actual native loss is not
misclassified as a confirmed provider exception. A same-Frame recursive finish
fails before the active invocation's cleanup region. Fresh public recursion
creates a fresh Frame.

Original local slots are predeclared in a builtin dict. Fixed module probe
classes observe the runtime's frame/dict destruction direction; no per-call
types, finalizers or GC reset are added. Normal HIA release transfers ownership
to a preallocated empty dictionary. It does not clear a dictionary still held
by a handled traceback. Error paths leave original values owned by their real
tracebacks. The terminal result is transferred with a direct dictionary pop.
Public dispatchers release their argument copies before finish.

These mechanisms are candidates for equivalence, not evidence of equivalence.
Complete runtime observations must validate dynamic descriptor errors, exception
name/obj/context, lookup specialization, temporary release and explicit GC.

## Independent qualification

The original 124-case input file, seven declared bases and nine injected
exception families remain unchanged. The complete previously frozen 4,885
ordered inputs are copied byte-for-byte as legacy-complete-inputs.json:
930,463 bytes, SHA256
`51c47249ce3c66e434533086c63f67c200e8357956bfff98e7ad31e8d17b06b2`.
They must remain the exact ordered prefix of every v2 complete input domain.
They are input preservation, not a claim that v1 and v2 effects are identical.

The v2 original-only supervisor runs the complete 124-case base domain twice
in fresh processes. Its rederived legacy domain must exactly match the pinned
4,885 inputs. Every observed v2 owned-descriptor close lookup/call cutpoint in
the same seven bases is then expanded over all nine fault families and appended
after that prefix. The final additional-case count is determined by those
actual original observations; this static layer does not invent it.

The fake provider explicitly accepts and records closefd=False. New owned-fd
events remain in the complete event trace, with a separate owned_fd_hits target
namespace so they do not retarget the old capture-directory close occurrences.
Any prerequisite base fault and the new target fault remain distinct actual
exceptions, and the intended target must be hit. The complete expanded input
and its pin are frozen before two full original runs and any candidate run.
Expected data never comes from HIA or a candidate result.

Original and candidate observations preserve all declared outcomes, effect
order, exception fields/identity, descriptor actions, temporary lifetime and
explicit GC counts. Each record is deeply sealed at its declared endpoint.
Raw tracebacks remain separate complete records. Candidate original streams
are hashed as they are consumed, then checked against unchanged authority.
The complete expected and actual bytes and typed recursive differences remain
available, including on failure.

The existing complete three Source methods and eight Native methods retain
their identities and scopes. The v2 wiring selects the explicitly named
reference/oracle/observer; the Source graph assertion changes its two port-count
constants from 71 to 73. The other ten method bodies are unchanged. Native
qualification still requires exactly one matching-current-cold report or
explicit development compiler. DEV is never described as a current-cold pass.

Those methods continue to cover full originals/faults, actual VM/native
request/output/state buffers, all 124 packet cases, 12 real filesystem cases
and three controlled races, 48 actual lost native returns, reentry/thread
refusal, source/image drift, invalid packets, and a real installed worker with
all three expected installation-identity flags.

The additional complete class
`tests.test_hia_store_file_capture_owned_fd_v2.StoreFileCaptureOwnedFDV2NativeTests`
has two methods. It separately covers six real descriptor scenarios in two
fresh original/candidate lanes (12 children), and 24 actual native-return-loss
controls: two close ports × CLAIM/SUCCEEDED/RAISED × four transport-error
families. A lost close CLAIM must show no actual close; a lost result must show
one close and no replay. The controlled before-close failure may keep the
descriptor open until its owned process exits; the observer does not repair it
to make a cleanup assertion pass. These controls require complete execution
against the same frozen source; their presence alone does not qualify the owner.

Every unknown case has a fresh owned process; the shared registry is not cleared
to permit teardown. Original-child/candidate-body timeouts are 600/1800 seconds,
other new owned worker/control children retain 60 seconds, and cleanup is bounded
at three seconds. Installed wheel/install operations use their explicit 60-second
budgets. The new v2 children use 60-second body and three-second cleanup limits,
inside a separately declared 1,800-second class gate. Existing case IDs,
non-version assertions and all original budgets are preserved. No extra GC,
traceback clearing, exception-field normalization or observer descriptor close
is introduced.

The separate caller gate runs the original nine complete modules and exact
112 ordered identities with both retained complete file-capture bodies poisoned
in that test process. Existing administrator bundle/absence scopes, the full
17-module/240 inventory, separate128, TX61 and artifact130 remain distinct.
A new caller success never replaces those original gates.

## Reproducible execution order for the root coordinator

After composing the static source and reviewing the exact source delta:

1. Generate only the new HIA resource with
   `python -B tools/generate_hia_store_file_capture.py`.
2. Regenerate the existing source contract/coverage/inventory with their original
   tools; verify a stable fixed point and exact new source closure.
3. Run the complete StoreFileCaptureSourceTests class, preserving its independent
   `HEPTA_HIA_STORE_FILE_CAPTURE_SOURCE_EVIDENCE` directory.
4. Set matching `HEPTA_HIA_STORE_FILE_CAPTURE_COLD_REPORT` or explicit
   `HEPTA_HIA_STORE_FILE_CAPTURE_DEVELOPMENT_COMPILER`, and run the complete
   StoreFileCaptureNativeTests class with its own evidence directory.
5. Run the complete StoreFileCaptureOwnedFDV2NativeTests class using that same
   current-cold authority and its independent
   `HEPTA_HIA_STORE_FILE_CAPTURE_OWNED_FD_V2_EVIDENCE` root.
6. Run `tools/qualify_hia_store_file_capture_callers.py` with the same matching
   cold report and a fresh evidence root, then all original composition gates.
   The strict nine-source provenance review must restore the original complete
   AgentStore bytes from the explicit v2 delta; its other eight records and the
   original 21 definition pins stay fixed. The complete Store Source controls
   and 574 admission controls remain required.
7. Separately, if authorized, build/qualify the raw descriptor primitive described
   in the ABI document. That result cannot promote the hosted owner to full native.

Generation, official metadata, complete v2 Source/Native/real-OS/installed/caller
qualification and matching-cold readback are all pending. The existing artifacts
keep their full owned evidence directories; the separate v2 gate adds its own
directory and raw diagnostics without replacing an older report.

Full-suite Source discovery and explicit Source controls need separate owned
evidence roots. The whole harness must derive the new Source evidence only from
its two existing stage-owned markers. Do not reuse a previous stage's directory,
alter the old 35-stage order, or borrow another owner's cold evidence.
