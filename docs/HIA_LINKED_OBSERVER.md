# HIA policy for fresh linked ELF observations

This component replaces the per-call Python loader used by the self-host
qualifier's selected `linked-selfhost` phases. Each observation still execs a
fresh process, loads the complete original sealed shared object through the
real system dynamic loader, and calls its existing six-word byte ABI. The HIA
policy owns the request checks, exact resource-limit values, continuation
sequence, response header, snapshot permission, and final status. Fixed
Linux/SysV transport performs the requested foreign operations.

This is component development, not whole-source cold qualification, default
activation, proof for every foreign DSO, or authorization to delete the retained
loader. The independent `seed-shared` path, B0 trust boundary, generation
controls, and retained reference loader remain explicit dependencies. Whole
native, default, live migration, and legacy deletion flags remain false.

## One selected route

The qualifier uses `NATIVE_LINKED_OBSERVER`, phase input `linked_observer`, and
the exact `linked-observer.elf` produced by this candidate. Every phase manifest
binds the executable's current bytes and checks them before selecting it.
Selection is explicit for `linked-selfhost`; a selected missing or invalid
observer raises or refuses and never falls back to the Python loader. The
published general observer `invoke(..., image_format="linked-selfhost")`
delegates to the same implementation.

`tools/generate_hia_linked_observer.py` authors two checked HIA sources:

* `linked_observer_policy.hiaasm` contains the continuation state machine.
* `linked_observer_packer.hiaasm` receives the actual newly compiled policy
  image and emits every byte of a complete ELF64 x86-64 relocatable object.

The packer includes the full policy image in the executable text. It does not
substitute a digest or a prebuilt policy. The real system `ld` then resolves
the observer's fixed `__libc_start_main`, `dlopen`, `dlsym`, `dlerror`, and `exit`
imports. The interpreter path comes from the running interpreter's real ELF
`PT_INTERP`, whose bytes are bound before and after construction. No target
`.text` section is extracted as a replacement for shared-object loading.

The fixed bridge is independently described in
`tools/hia_linked_observer_bridge.S`. This is an authoring and test oracle;
construction does not run an assembler or read that file. Its complete machine
bytes and external relocation sites are checked against an actual GNU
assembler. HIA emits the whole object, and an independent ordinary Core VM
checks every emitted byte for synthetic policy inputs and the actual newly
compiled policy image.

## HIA and foreign mechanism boundary

The fixed bridge contains action dispatch and the mechanics of read, write,
mmap, sealing, time measurement, and calls through the system loader. It
returns the actual foreign values to HIA. It has no implementation of the
request-field limits or of the decision to call, commit, publish, or finish.
It reports bridge allocation/dispatch failures as the private transport
failure status. Kernel errno handling and short-write loops are physical
transport, not a replacement policy.

The HIA workspace and control buffers are each exactly 512 bytes. Workspace
word zero selects the next phase. Words at 16 through 56 carry actual foreign
feedback. HIA retains admitted request fields at 64 through 112. The ordinary
successful action sequence is:

| Action | Foreign operation authorized by HIA |
|---|---|
| 1 | Apply original process limits and read one complete request |
| 2 | Create, fill, and seal the complete target shared image |
| 3 | `dlopen` the actual owned descriptor with `RTLD_LOCAL | RTLD_NOW` |
| 4 | Resolve `f0`, then close the owned image descriptor |
| 5 | Prepare source, output, and workspace ABI storage |
| 6 | Measure and call the actual entry point |
| 8 | Write the ordinary return snapshot and then its completion marker |
| 7 | Publish the HIA-created header and complete ABI postimages |
| 0 | Enter actual libc exit with the HIA-selected status |

Action 9 obtains the real loader diagnostic after a failed lookup; its
continuation selects the final refusal. Successful completion never requests
an eager `dlclose`. Actual native policy tests compare each returned action,
the complete output buffer, the complete workspace, readonly input, and
surrounding canaries with the independent retained Core interpreter. Refusal
controls cover phase, feedback, framing, descriptors, and short state/output
storage, including negative errno values.

## Exact limits and input protocol

The previous byte ABI limits are unchanged: a nonempty target image no larger
than 4 MiB, source/output/workspace each no larger than 1 MiB, and a fill byte
from 0 through 255. The child keeps the original 20-second wall supervision,
10-second CPU limit, 256 MiB address-space limit, 8 MiB stack limit, 16 MiB file
limit, 32 descriptors, zero core limit, and nondumpable state. Every child is a
fresh exec; no successor process or loaded image is reused.

The private `HIAOBS03` request retains the 56-byte header. The last word holds
two transport-owned 32-bit descriptors: the optional live-output descriptor
(`0xffffffff` means absent) and the mandatory return-snapshot descriptor.
HIA validates their ranges and rejects collision. These descriptors are not
chosen by the target source. The complete original target bytes and source
bytes follow the header; length must be exact. The request read arena has
one extra byte so HIA can distinguish the unchanged admitted maximum from an
oversized request. No general Core-language or compiler-profile limit is
changed by this component.

## Target lifetime and two output observations

The observer enters through libc startup and registers the actual runtime
loader finalizer. The target remains loaded until actual process exit.
Constructors, process exit callbacks, finalizers, their stdout/stderr writes,
nonzero exits, and signals remain real foreign effects. A failed `dlsym`
after a successful constructor still reaches libc finalization. There is no
signal conversion or suppression of a target finalizer.

The original loader captures an ordinary return before finalization. A
finalizer can then alter a requested shared output mapping or exit
abnormally. These are two different observations and the implementation
keeps both:

* A parent-owned fixed-size snapshot memfd contains `8 + capacity` bytes.
  HIA authorizes its fill only after `f0` and the ending clock have returned.
  Native transport writes all output bytes before a `capacity + 1` completion
  word. A zero word means no completed call; marker one represents a
  completed zero-length output. A constructor's fabricated stdout frame
  cannot invent this completion.
* The optional live output mapping remains the actual shared map. When
  `observe_trap_writes` is requested, the parent reads it after process
  termination, including real finalizer writes. Otherwise ordinary output
  comes from the committed pre-finalizer snapshot, even if a later finalizer
  exits nonzero, traps, or prevents a valid stdout response.

All descriptors are explicitly retained through their required lifetime and
closed on prelaunch failures and normal/refused completion. The tests include
failure of the second parent-owned allocation while the first descriptor is
live. The bridge is a fixed foreign ABI mechanism, not an isolation boundary
against malicious native code in the same child.

## Output framing preserves original JSON boundary whitespace

`HIAOBR03` has a 24-byte header followed by exact source, output, and workspace
bytes. The host materializer accepts only the original JSON parser's four
ASCII whitespace bytes before the first magic byte and after the complete
fixed-size frame. It does not search for later magic, accept arbitrary noise,
strip payload bytes, or remove whitespace at the end of a legitimate binary
buffer. Successful stderr output remains allowed. Both response output and
committed snapshot must agree before a successful observation is reported.

## Qualification order and retained controls

The qualifier executes independent policy and packer VM observations before
B0. B1, B2, B3 and modified M1, M2, M3 remain in their original sequence and
use their original loaders and limits. The newly available compiler then
compiles the policy and packer. Actual-policy VM packing precedes native
emission and linking. The original 19 families and 38 phases remain; each
phase binds both flat and linked observers along with its other exact inputs.
No original check or deadline is removed to obtain a result.

The component fixture has mutually exclusive matching-source cold and
explicit development compiler inputs. A cold report must be admitted before
creating output directories and must bind all declared component sources.
Development uses the actual supplied retained bytes and labels its scope;
it does not inherit the compiler's historical cold report as current-source
qualification. The default isolated bootstrap path remains available.

The full component suite keeps the 24 r4 control methods and adds actual HIA
policy frame differentials, HIA refusals, process-exit callbacks, selected
no-fallback dispatch, phase input custody, packer transactionality, and real
timeout cleanup. The actual `F_GET_SEALS` negative control installs only an
additional child seccomp restriction returning `EPERM` for that syscall and
command. It verifies the real kernel error, refusal before target entry, no
snapshot, and descriptor cleanup. A separate deliberately altered executable
forges both foreign-feedback words as success and demonstrates sensitivity;
the production bridge and HIA policy are unchanged by that control.

## Provenance and preserved observations

This revision combines the HIA policy from pinned PR888
`acffa9262f31d073f8f0a6f0201eae201039f619` with the independently developed r4
libc lifecycle, snapshot, and framing behavior. A new bounded actual probe
compiled those exact PR888 policy/packer bytes and ran 24 paired foreign
objects against the retained original loader. It observed 20 differences and
four equal controls: whitespace/stderr refusal, shared postimage assertions,
lost ordinary output after finalizer failure, missing finalization after a
failed entry lookup, and omitted process-exit callbacks. That original report
is Git blob `816fd4bf710586b8c146712f5dd65e1fe53d8c9b`, SHA-256
`b5581a6752573c56bdd7040ae182781db7d38a4abc8a70b40a31105e25fd760c`.
This is a fixed component observation over an explicit minimal foundation,
not a verdict on the whole parallel PR or its qualification.

The first unified actual smoke retained all 24 cases and observed all 24
equal, with source and held inputs unchanged. Complete component-suite
results belong to their separately frozen raw receipts; this document does
not promote a development result into whole-source qualification.

The previous r4 six-source package and 24/24 development pass remain frozen
under Git blob `c518c727f6f2825bb7a0e8cef66eb8c2ecfa3684`; its raw archive is
`187cf02ef7a1acd067d45d8ecefe5125401bd618`. Its original 23-pass/one-ptrace-
refusal gate is preserved separately. Original r3 whitespace/snapshot
failures remain preserved. The old ai395 18-control attempt is still UNKNOWN
and was not rerun or relabeled. New local work uses Python 3.12.14 and the
retained 8aade CI B3 image, SHA-256
`81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109`;
it is a different-environment development qualification.
