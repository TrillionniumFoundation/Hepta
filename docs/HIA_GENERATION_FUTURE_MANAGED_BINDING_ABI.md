# Native sole-owner Future binding

This component statically joins the Runtime/Lease owner, source-bound callable
owner, and managed Future producer. Runtime, callable, Future and its resource
producer use one physical Value implementation and one Value arena. The old
HIAGLOP1/2/3 and HIAGFUP1/2/3 products remain independent.

This is component qualification. The full public ScalarMultiversionRuntime
constructor, immediate generation-cache pruning, the remaining Future protocol
methods, BackgroundOptimizer resource binding, and final native-only release
are not claimed by this receipt.

## Production layout and fixed imports

The new HIAGSCP2 flat capsule has five actual policies/products in this order:

1. generation_lease_owner_sidecar_future
2. native source-bound code-owner capsule
3. native owned-tempdir capsule
4. future_resource_owner
5. future_resource_registry

Its request contains the magic, count 5, five u64 byte lengths, and those exact
bodies; its header is 56 bytes. Each role and the complete capsule retain the
existing 4 MiB limit. This is a native HIA packer; Python reference bytes only
serve as an independent development oracle.

HIAGFUP4 takes the same 64 logical roles as the previous sidecar/Future fusion:
56 owner roles followed by the eight non-Value Future roles. The owner policy,
unique finalizer policy and sidecar capsule are replaced by the new fixed
variants. Both packers retain the original 16 MiB final text ceiling. Identical
immutable bodies may share their exact code bytes. The resulting image has
one Value body and one code-owner body.

The image exports hia_generation_lease_owner,
hia_background_optimizer_future_public, and
hia_generation_lease_owner_sidecar. The sidecar's Future and Value calls,
provider calls and registry target are static relative calls or addresses.
The finalizer's kind-7 entry points at that same provider. Production requests
never contain an entry pointer, context pointer, or binding nonce.

The provider's libc relocations precede the later tempdir relocation in the
ELF relocation table. This preserves the existing native linker's ordered
relocation contract. Both assembly bridges were assembled and checked to have
no unresolved assembler relocations before their fixed zero holes were used.

## Actual initialization

The original outer owner context remains exactly 2048 bytes. The original
sidecar mapping remains 212992 bytes, allocated by native HIA. This profile
uses these existing private spans:

| Relative to the sidecar mapping | Extent | Ownership |
| --- | ---: | --- |
| 1024 | 256 | Actual source-bound code-owner context |
| 1280 | 256 | One actual Future global context |
| 1536 | 512 | Managed Future provider; its registry occupies the last 256 bytes |
| 2048 | 512 | Unbound BackgroundOptimizer reservation |
| 4096 | 204800 | Owned native tempdir context |

HIAGSCQ1 remains a 128-byte sidecar request: op 0 initializes, op 1 requests
close, op 2 retries, op 3 gets the owned tempdir, and op 4 returns facts. All
other request words must be zero.

Initialization performs the original code-owner initialization and retains its
real Value context token. It then performs Future HIABFP04/op0 against the
same captured Value context. Only after that actual token is owned does native
HIA install the fixed HIAFRCX2 provider prefix and call provider
HIAFRCQ1/op0. The provider generates its own nonce and initializes its actual
registry. The binder verifies the returned state, PID, self address, nonce,
registry state and Value nonce before publishing the provider binding.

The Value context's trusted slots 224/232/240/248 contain the actual provider
entry/context/512/nonce. They are captured only by this native initializer.
Support mask 190 enables kinds 1, 2, 3, 4, 5 and 7 after that initialization.
Kind 6 remains disabled. Duplicate initialization is refused. Copied and forked
outer contexts are rejected without output or context mutation.

The new binder has 35 HIA functions. Added Future phase handling is in a
separate internal HIA function to respect the unchanged compiler's per-function
block-name bound. No compiler bound or admission rule was increased.

## One native finalizer

The unique finalizer keeps the established Runtime/Lease paths for kinds 1/2
and source-bound code paths for kinds 3/4/5. For kind 7 it verifies the actual
Value binding and fixed provider identity, copies the private HIAVRFQ1 frame,
substitutes the provider's own captured nonce, and calls the fixed provider.
Its HIAVRFR1 reply is interpreted using actual known/consumed/pending facts.

The producer owns the real factory/future leases, Value context token and
registry capability. It publishes a true kind-8 instance of canonical class 37
only after the actual managed cell identity has been bound. No Boolean or
JSON stand-in grants Future identity. Self-result and list-mediated cycles
use the Value graph's managed edges and are reclaimed through the same native
finalizer.

The producer's HIAFRR02/HIAFRR03 delivery flag is independent of cleanup.
A concurrent operation may return status 11 with known=1, delivered=1 and
pending=1 after publishing a real strong cap. The receiver must retain and
release that cap even when unrelated retirement is still pending. The
qualification records these facts, does not use a pending borrowed pair,
and requires actual caps, queues, registry and descriptors to be empty after
the native drain.

## Close and retry order

The binder first retries code cleanup and acquires the code-owner close fence.
It then prepares the provider, commits actual provider registry close, and
calls Future HIABFP04/op29 to release the actual global context token.

A provider prepare refusal occurs before consumption. In that case the code
fence is rolled back and the fully initialized binder remains ready.

Once provider commit starts, close is irreversible. If a caller still owns a
raw factory, Future op 29 keeps its token and the binder remains closing at
stage 117. After actual factory release, retry completes that stage.

After provider and Future retirement are acknowledged, the binder clears the
Value provider binding and kind-7 support, releases its own token, drains
outside-lock cleanup and requests Value's actual destroy fence. If another
Value remains alive, the binder stays closing at stage 130. It does not
recreate a token or claim that the already-retired Future owner is ready.
Existing Value references can still be released, after which a native retry
continues cleanup.

The original tempdir, code context and sidecar mapping then retire in order.
Failed close_range/munmap calls preserve the actual mapping, descriptors,
fences and owner activity guard until a subsequent real retry. Unknown
ownership is quarantined instead of receiving a fabricated acknowledgment.

## Evidence boundaries

The qualification JSON records the exact component sources, product pins,
64-role frozen inputs, native packer checks, all current binding cases and the
unchanged original owner/resource assertions. Source-generation Python and
test oracles are development provenance; they are not production roles.

The successful binding campaign covers true constructor publication, class
identity, result survival, cycles, eight-thread creation/finalization,
concurrent initialization, both partial-close orders, private-domain guards,
fork/copy refusal, six actual initialization syscall failures and three
actual retirement syscall failures. It does not replace the remaining public
Runtime/Background constructor and dispatcher work.
