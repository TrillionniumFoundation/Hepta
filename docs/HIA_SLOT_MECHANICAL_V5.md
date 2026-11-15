# Explicit v5 Slot mechanical executable custody

Status: STATIC CANDIDATE; uncompiled and unexecuted. The frozen R2 mechanical
diagnostic and every historical HOLD remain unchanged. This proposal is an
addition to actual R15a, tree 3ef2647bdc5df5b267f68f3d8a2bc624cf595e5d. It does
not prove original finite equivalence, GC counts, a cold build, or whole-stack
native closure.

## Authority and the exact executable

The existing worker options --native-helpers-manifest and
--expected-native-helpers-sha256 carry an explicitly new, closed v5 capsule.
It contains one explicitly pinned closed v1 helper bundle and exactly one
slot-mechanical record. The v5 record pins the canonical installed package
directory, complete paths and bytes/SHA256 of the compile receipt, executable
and eleven declared sources, and the runtime/ABI profile. The v1 helper
factories remain statically registered. The actual R15a 49-entry registry and
its final Service Verification helper are retained.

The operator supplies the complete expected capsule digest. Neither production
constructor nor loader derives its expected digest from a candidate file.
The emitting tool requires explicit prior base-bundle and compile-receipt
digests, records actual sources/executable, writes a fresh capsule, and reports
OPERATOR_MUST_PIN_THIS_DIGEST. A receipt by itself is not authorization.

Before any linker call on the selected production path, v5 checks its external
digest, captures all declared v1 manifests/source/image bytes, captures the
bridge receipt, eleven source files and exact executable, and rereads them.
The actual expected physical package/source/receipt/executable paths must
match, so a byte-identical different package or basename is not an authority.
Only the exact exclusive constructor receives a temporary pre-ACTIVE bridge
capability; its finally removes it. Current scope/PID/thread and selector
checks remain in force after publication.

Ordinary import does not preload an extension. A selected mechanical call
without live v5 authority fails. Existing v1 through v4 schemas are not widened,
upgraded, flattened or used as a failed-v5 fallback. A v1 that selects this new
Slot mechanical path is refused before mapping or business effects. Consequently
the original Native6 v1 installed method remains a real unsatisfied obligation;
the new v5 tests cannot turn that old result into PASS. No old Python transport
compatibility route is implemented in this package. Arbitrary caller-written
dlopen/importlib code outside the declared production entry is not a claimed
process-wide security sandbox.

## Sealed descriptor ownership

The loader reserves a small custody record before memfd_create, writes all
captured bytes, verifies all four seals and pread equality, then performs one
last full administrator/source recheck before module creation. Extension loading
uses the exact /proc/self/fd/N descriptor. It is kept open throughout loading
and for the accepted module's lifetime. Failure attempts close at most once.
An uncertain close remains an explicit CLOSE_UNCONFIRMED record and is never
retried on a potentially reused number. Partial linker initialization is
sticky and is not retried. Fork resets the lock/epoch; creator/scope checks and
the existing C session checks remain separate.

The exported actual built-in function objects, module ownership, ABI, mode/port
counts, binary bytes and seals are verified on later entry. A cached module
does not cache away complete source/receipt/administrator reads. The extension
uses only the frozen mechanical C boundary from R2; no new business control
graph is introduced here.

## Build and installed identity

The setup hook loads its exact local hepta/native/slot_mechanical_build.py.
That path is inside the original wheel staging's copied hepta tree and is
explicit package data. The hook never imports product policy or a runtime tools
module. The prior R2 tools-only hook remains frozen as a known staging gap.

All eleven sources, actual compiler argv/executable bytes and output .so bytes
are recorded by a forced actual build. The supported selected ABI is explicit:
GIL CPython 3.11–3.14 on Linux x86_64 with eight-byte pointers. It does not widen
the package's declared Python version claim and is not proof on all those
versions. Root must compile and run each supported profile before qualification.
Compiler receipt identity does not claim a hermetic sysroot or compiler proof.

The source-based installation_manifest contract remains unchanged. New Python
source files and package data enter the real wheel. The .so and compile receipt
are separately carried by the administrator executable capsule, never inserted
into the source digest to conceal source/wheel inequality. The independent
installed driver verifies the actual wheel RECORD and installed bytes first,
captures ordinary source/wheel identity, then explicitly pins that installed
receipt and makes a v5 test administrator capsule. These test-owned pins do not
authorize another production installation.

## Separate actual validation scopes

All original methods, fixtures, 7822 finite inputs and fields, public84,
handled12, Source3/Native6/resource4, Slot15, separate ordinary112/128, integration13
and TX61 remain mandatory and unchanged. Overlapping scopes are never summed.
The R2 original gate inventories remain part of the delivered evidence.

The four new Native methods are separate:
1. Full 248 + 7574. All fresh original lanes run twice and are byte-compared and
   frozen before any candidate. The unchanged original observer is reached
   through an explicit actual-v5 scope launcher with no expected rows passed to
   the candidate. Full observation/traceback/progress/post-seal/raw files remain.
2. Public84 and handled12. Each full group's two original lanes precede its
   candidate; original fields, metadata, GC values and release observations are
   retained. There is no label/TB/GC normalization.
3. Twenty-five fresh-process admission controls exercise actual linker entry,
   healthy cached reuse, missing/incorrect authority, exact-path/source/receipt/
   binary drift, the final pre-link recheck, real partial-write/seal/uncertain-close cleanup, loaded
   export drift, stale scope and wrong-thread access. Each negative requires its
   declared error class/message and actual zero/one linker count. These are a
   finite declared domain, not arbitrary runtime reflection hardening.
4. A real fresh wheel uses the unmodified original worker and original SQL-loss
   observer. The installed setup and every worker use the same installed v5
   capsule. Identity, normal/replay, actual SQL-return/ACK-loss/unknown replay,
   source+LF and extra-module refusal all keep full raw stdout/stderr, command,
   process-group receipts, database-state observations and independent readback.

The original child180/candidate1800/overall1800/cleanup5, original 60-second
installed child, VM 4M/16MiB/128 and all original test deadlines remain. The
new Native4 wrapper uses 1800 seconds per complete method and the workflow
retains the same 30-minute outer gate pattern. No passing prefix or results
from different source snapshots may be combined. The full original VM gate
remains separate; v5 explicitly maps native images and cannot impersonate it.

## Ownership limits still requiring actual evidence

Public continuation binding, borrowed Vectorcall argument owners, actual Python
f_back/handled exception lifetime, dynamic provider lookup, finally/with/iterator
cleanup and extension boundary allocation remain finite-observation obligations.
Fewer Python frames do not establish the original GC16 count. C cannot steal
borrowed caller argument references. There is no traceback clearing, synthetic
garbage, GC suppression, local-value normalization or hidden complete legacy body
callback. The existing HIA 15-mode/136-port graph and all original protocol
checks own business decisions.

The C source is not yet compiled. No new original, candidate, test, SQL, Native,
VM, GC, generator or qualification was executed while authoring this package.
Any actual source, installed staging, public ABI or timeout failure remains HOLD.
