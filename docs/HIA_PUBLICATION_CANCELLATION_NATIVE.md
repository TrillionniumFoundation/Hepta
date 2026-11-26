# Native public PublicationCancellation owner

This component provides the original public token constructor, cancel,
cancelled, committed and copy/deepcopy rejection through a closed native HIA
owner. It also owns independent internal retain/drop references, concurrent
in-flight pins, failed-finalizer retention and explicit cleanup retry.

The actual product contains the unchanged native runtime-handle registry and
unchanged Future/token kernel from source revision
ecd688626409d1adcf4e04a7a535c1b2c45a13ce. The public facade and token-effects
adapter are HIA policies. A fixed mechanical prefix supplies only bounded
view admission, direct role calls, syscalls, atomics, owned memory movement
and the existing closed mmap allocator. No Python, assembler, libc import,
caller-selected function or external executable is used by the finished
364,751-byte image.

The public token does not expose commit. Its integration with the actual
multiversion selection/pointer swap remains a separate public-runtime gate.
The external qualification calls the real embedded token kernel to exercise
committed observations and commit/cancel races. That test does not qualify
the multiversion publication transaction. whole_native_runtime and
final_aggregate_claimed remain false.

## Public and ownership interface

hia_publication_cancellation(source, source_extent, output, output_extent,
context, context_extent) uses the standard six-word borrowed-buffer entry.
The enclosing source-bound native constructor owns the fixed image and a
zeroed, 8-byte-aligned persistent context of at least 256 bytes. It retains
both until context destruction completes. Each invocation owns a distinct
100,679,680-byte continuation/output view (96 MiB plus 16 KiB). Source is
exactly 64 bytes. All three views must be non-null, nonwrapping and disjoint.

The 64-byte little-endian request begins HIAPCQ01. Operation is at byte 8.
For operations 2 through 8, the actual registered reference capability
node/tag0/tag1 is at bytes 16/24/32. Every other word must be zero. No input
word carries proof, success, current generation, dependency address,
workspace address or permission to commit.

| Operation | Meaning | Capability input |
| --- | --- | --- |
| 0 | Initialize the dedicated context once | None |
| 1 | Original PublicationCancellation constructor | None |
| 2 | Retain as a distinct internal strong reference | Required |
| 3 | Drop exactly this internal reference | Required |
| 4 | Original cancel() | Required |
| 5 | Original cancelled() | Required |
| 6 | Original committed() | Required |
| 7 | Original __copy__() rejection | Required |
| 8 | Original __deepcopy__(memo) rejection; memo is unused | Required |
| 9 | Destroy an empty context | None |
| 10 | Retry one retained failed finalizer | None |

Retain/drop are native ownership operations. They do not add public methods
to PublicationCancellation. Retain does not copy the synchronization owner;
it creates another independently consumable reference to that same owner.

Successful structural completion returns zero and writes HIAPCR01. The
first 128 bytes contain the public result. Scratch outside this record is
private. A returned reference is an authenticated capability, not permission
to dereference the node address.

| Byte offset | Result |
| --- | --- |
| 8 | Status: 0 normal; 1 invalid capability; 2 allocation failure; 3 lifecycle refusal; 4 original MultiversionRejected; 5 dependency/internal/retained cleanup failure |
| 16 | Result kind: 0 None; 1 Boolean; 2 newly owned reference |
| 24/32/40 | New capability for successful construct/retain |
| 48 | Exact 0 or 1 for a Boolean result |
| 56 | Error JSON byte length; JSON begins at byte 128 |
| 64 | Actual child status |
| 72 | Context creation PID |
| 80 | Actual retained-cleanup flag |
| 88 | Actual failed-finalizer status |
| 96..127 | Zero |

Copy and deepcopy preserve the original exception class and exact message:

{"class":"MultiversionRejected","message":"E_HIA_MULTIVERSION: publication cancellation has one synchronization owner"}

The original ordering is retained: an open token starts with both
observations false; repeated cancel calls remain true; once the actual
kernel commits, cancel is false, cancelled is false and committed is true.

Malformed views or frames return 0xfffffffd. Invalid views write nothing.
With valid views, a malformed frame may reset only the private phase word
at output byte 256; it does not publish a public reply or touch the
persistent context.

## Actual ownership and failure behavior

The original multiversion_runtime_handles HIA registry is instantiated in
a dedicated token context. Each reference has its own 96-byte native node
and fresh 128-bit nonce obtained by the actual getrandom syscall. A supplied
node candidate is compared against owned registry nodes before it can be
dereferenced. Foreign, forged, stale and forked capabilities do not grant
access. The dedicated context prevents an ordinary MV runtime capability
from being interpreted as a cancellation token.

The registry pins operations before releasing its mutex, and releases a pin
only after the actual fixed token effect returns. There is no finite
reference counter. Last-reference cleanup invokes the real kernel destroy
operation; concurrent invocation pins delay destruction. Failed cleanup
retains the same owned object, refuses empty-context destruction and
permits explicit retry. The allocator is the existing closed mmap/munmap
adapter; invalid owned-free metadata or failed unmapping traps.

The token-effects HIA policy translates only init, cancel, cancelled,
committed and destroy into the existing Future/token kernel. It verifies
the actual returned magic and status. Both policies refuse incompatible
frames; neither interprets caller-supplied success as evidence.

## Native construction

The only compiler used in qualification is the already qualified native
hia-source-build ELF:

- Bytes: 813129.
- SHA256: 494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af.
- Invocation: hia-source-build compile, with the exact HIA source on stdin.
- Both actual native compilations of every policy and packer are identical.

Compile the following sources. The first four flat images are appended in
exactly this order to the native pack request.

| Role | Source path | Flat bytes | Flat SHA256 |
| --- | --- | --- | --- |
| public | examples/hia_bootstrap/publication_cancellation_public.hepta | 31502 | aa39d99738402a3d8c3145fe8fa4db8b5a46fb7a8c152e55d5a2fca87b6614ca |
| handles | examples/hia_bootstrap/multiversion_runtime_handles.hepta | 205384 | 5cbaa68b6699b636885b14bf163184d7fc2c5c8a915b072363ab478c32901310 |
| effects | examples/hia_bootstrap/publication_cancellation_effects.hepta | 17205 | fd6bfe461879497e3691f0fbcdeb83e6efc03d983d0297cd2ff5b155eada5131 |
| kernel | examples/hia_bootstrap/multiversion_future.hepta | 109044 | fc9f7300250caf65350b533da119e6cd5e22604e91ce67eb78220bb522f4a23d |
| packer | examples/hia_bootstrap/publication_cancellation_packer.hepta | 28914 | ac3d92f27c8b17d8a59147d7d28cd410f683896c05701ac3f8bd29729a3870a2 |

The packer's six-word entry is a pure HIA function. Its request is a 64-byte
header followed by the four actual flat images:

| Byte offset | Request |
| --- | --- |
| 0 | HIAPCPK1 |
| 8 | Role count, exactly 4 |
| 16 | Public facade flat length |
| 24 | Handles flat length |
| 32 | Token-effects flat length |
| 40 | Future kernel flat length |
| 48/56 | Zero |
| 64 | Concatenated public, handles, effects and kernel flat bytes |

Each role is nonempty and at most 4 MiB. Total source length must be exact.
Output needs 1616 plus the four flat lengths. Workspace is unused by the
packer policy. On success it returns the image length. All header, extent
and output-capacity refusals return 0xfffffffd without writing output.

The native packer copies the frozen 1616-byte prefix, appends actual role
bytes and patches four internal relative calls. Its output is the flat
public entry, with no ELF imports or dynamic symbols. The final image is:

- Bytes: 364751.
- SHA256: 6458c979f848747478e4fc0fdfb15d74adec63e849558a9e22c800cb3b94ffe0.
- Prefix SHA256: 77ac33cdad3278846252a0b72260cfbb9120cf782417b60e3e5349d33fe4b5d3.

Source-bound release composition must supply these actual compiled roles.
The private packer admits the fixed role shape; it does not authenticate
arbitrary machine code supplied by an untrusted user. No caller-selected
role table is part of the public request.

## Qualification and reproducibility

The companion JSON records current source/flat/compiler/image hashes and
all observed gates. Run the development qualification from the repository:

PYTHONPATH=. python tools/qualify_hia_publication_cancellation.py --compiler /absolute/path/to/hia-source-build --output /absolute/path/to/isolated-qa

Python and as/objcopy/readelf are external qualification tools. The test
uses as only to independently reproduce the readable fixed prefix and
prove it has no relocations. The actual product image is generated by the
compiled HIA packer. Compilation and normal product execution require
neither the assembler nor the development generator.

Passed gates include:

- 12 exact comparisons against the unchanged original
  PublicationCancellation class and rejection helper, plus complete
  construct/retain/drop/empty-destroy/repeated-destroy lifecycle.
- 42 forged/foreign-capability invocations, 16 invalid-view cases and
  10 malformed-frame guards, with view nonmutation and an outer canary.
- 25 native packer refusal boundaries with unchanged output.
- 2373 actual public calls in concurrency qualification, including
  16 independent retained references, 16 simultaneous drops of the same
  reference with exactly one success, and 80 last-drop/observation races.
  Both successful pinned observation and stale-reference refusal were
  actually observed.
- 80 actual embedded-kernel commit/public-cancel races. Each has exactly
  one successful outcome, and subsequent public observations agree.
- An actual pending kernel waiter makes finalization fail and retain its
  object. Destroy is refused; after the real waiter times out, retry
  finalizes the object and context destruction succeeds.
- A forked process cannot use the parent's token; the parent remains usable.
- Four isolated seccomp fault cases deny the actual object mmap, reference
  mmap, retained-reference mmap or getrandom syscall. No output capability
  is minted on failure; surviving references remain usable and the actual
  context is subsequently destroyed.

The internal-kernel probes are explicitly external QA. They derive a
workspace only from an already registered native reference and invoke
the actual kernel; they do not inject a fake committed bit, failed
finalizer, proof or success response.

## Remaining public-runtime composition

The three new HIA sources are registered in source-bound native release
stage 13 alongside the unchanged handles and Future sources. The stage
recompiles and packs the actual hia-publication-cancellation.core.bin product
and checks its complete image identity before publication. The fixed public
entry and dedicated context remain owned by the enclosing native constructor.
GenerationLease, ScalarMultiversionRuntime, their typed results/errors and
the same cancellation token's atomic participation in the real publication
pointer swap still require their own owner composition and validation.
The 11 public MCP tool schemas are unchanged.
