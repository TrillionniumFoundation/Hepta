# Independent native toolchain build entry

## Public invocation and scope

```
hia-cold-build --source ABSOLUTE_SOURCE --bootstrap ABSOLUTE_BOOTSTRAP --output NEW_ABSOLUTE_OUTPUT
```

The command accepts exactly these seven argument words. It reads a frozen source
tree, captures the seven independent HIA bootstrap executables, and executes the
source-declared construction graph under the native process owner. The source
tree is read-only. The output directory must be new; path components are opened
without following symlinks. Its owner must be the invoking uid and its mode is
0700. Existing output directories are refused.

This entry builds a source-bound independent toolchain. The separate `hia-cold`
entry executes the complete sixty-phase selfhost qualification. A successful
build receipt alone does not claim whole-selfhost qualification or installation
closure.

The production implementation is `cold_build_entry.hepta`, its native capsule
packer `cold_build_entry_packer.hepta`, and the fixed syscall/argv trampoline
`tools/hia_cold_build_entry_syscalls.S`. The trampoline implements the mechanical
ABI; path policy, source capture, recipe validation, graph execution, hashing,
publication and acceptance are implemented by HIA. The development author is not
a production runtime dependency.

## Bootstrap roots and capsule

The bootstrap directory supplies these fixed top-level executable names, in
this order:

1. `hia-seed-assembly`
2. `hia-seed-projector`
3. `hia-seed-backend`
4. `hia-seed-filter-pack`
5. `hia-cold-qualification-driver`
6. `hia-independent-subprocess`
7. `hia-cold-process-owner`

The native packer accepts `HIAQBE01`, followed by little-endian u64 policy and SHA
flat lengths, nine raw 32-byte SHA256 pins, and the two flat bodies. Pin order is
source authority, construction recipe, then the seven bootstrap roots above.
Policy and SHA bodies must each be nonempty and at most 1 MiB; the final ELF must
fit the original 1 MiB executable transport. All pins must be nonzero. Invalid
capsules and insufficient output capacity are refused before output mutation.

There is no entry-image self-hash cycle. The outer command opens the actual
kernel `/proc/self/exe`, captures and seals those exact bytes, then uses that
captured executable for the inner invocation. Recipe binding kind 5 exposes the
same captured entry to the final construction stage, which rebuilds the entry
from the captured HIA sources and the same nine pins and compares complete ELF
bytes before installation.

## Source authority

The fixed authority path is
`examples/hia_bootstrap/cold_build_sources.hiadat`. Its format is:

| Byte offset | Field |
| --- | --- |
| 0 | Eight-byte magic `HIATBS01` |
| 8 | u64 version 1 |
| 16 | u64 source count, 1 through 4096 |
| 24 | u64 reserved zero |
| 32 onward | Repeated u64 path length, relative path bytes, zero padding to eight-byte alignment |

Paths are strictly sorted, unique, printable ASCII, at most 4095 bytes, with
components at most 255 bytes. Empty, dot, dot-dot, `.git` and `__pycache__`
components are forbidden. The authority includes itself and the construction
recipe exactly once. The complete authority is at most 1 MiB. It contains names,
not hashes of its own contents. The command derives the actual source manifest
from captured file contents.

## Construction recipe

The fixed recipe path is
`examples/hia_bootstrap/cold_build_recipe.hiadat`. `HIATBR01` has a 128-byte
header: version, stage count, binding count, publication count, source count,
stage offset, binding offset, publication offset and total byte length at
successive u64 offsets 8 through 72. Bytes 80 through 127 are zero.

The stage table starts at byte 128. Each 64-byte stage contains eight u64 words:
ordinal, plan source index, binding start/count, publication start/count, and two
reserved zero words. Stages cover the binding and publication tables without
gaps. Plans are captured source files with the existing `HIAQPL01` format.

Each 128-byte binding contains alias length, kind, index, reserved zero, then a
96-byte zero-padded alias. Aliases are unique within a stage and at most 95 bytes.
Every stage binds `fast` and `cold`; their actual captured hashes must equal the
capsule's subprocess and owner pins.

| Kind | Binding value |
| --- | --- |
| 0 | One of the seven captured bootstrap roots |
| 1 | Captured source file by authority index |
| 2 | Sealed publication from a strictly earlier stage |
| 3 | Actual captured source `HIASXM01` manifest; index zero |
| 4 | Actual installed-tool `HIASXM01` manifest through prior stages; index zero |
| 5 | Actual captured entry ELF; index zero |

Each 320-byte publication contains eight u64 words (name length, installed path
length, mode, flags, maximum size, three zeros), a 64-byte zero-padded basename,
and a 192-byte zero-padded installed path. Modes are 0400 or 0500. Flag 0 denotes a
temporary sealed publication and requires an empty installed path. Flag 1
installs the publication to its unique declared relative path. The basename is
at most 63 bytes and the installed path at most 191 bytes. Maximum size is at most
64 MiB. Reserved output names cannot be used for installed publications.

There are at most 64 stages, 4096 total bindings, 4096 total publications, and
2–64 bindings per stage. The recipe is at most 2 MiB. Each plan is at most
64 MiB and 65536 nodes. At least one final publication must be installed.

## Capture, execution and final acceptance

Every root, source and entry image is captured into a fresh memfd. Capture checks
file type, hardlink count, size and stable file identity/timestamps, copies the
bytes, applies and reads back all four seals, hashes the sealed copy, independently
hashes the original and checks the original stat again. Pinned assets must match
their actual capsule SHA256. Ordinary files require one hardlink; the kernel's
actual executing memfd entry may have zero links.

The aggregate captured transport has an 8 MiB metadata prefix and at most 2 GiB
of total bytes. Its header, asset rows and source manifest are compared with the
outer command's private copies after sealing; every captured data segment is
also rehashed against its private digest. The inner entry validates the sealed
transport and recipe again. Every stage import is extracted into a fresh sealed
file descriptor and rehashed before use. Descriptor aliases do not share the
same numeric fd.

The existing native owner enforces the original 180-second deadline and
three-second cleanup budget. It receives only the sealed transport and a distinct
output-directory fd as passed capabilities. The outer command checks the actual
owner receipt, exact status, leader reap, empty process tree, ECHILD witness,
timestamps and bounded event counts. No shell or interpreter participates in
the public construction path.

Each stage uses the original native qualification driver and retains its physical
journal plus exact success receipt in `build-evidence/sN/`. Successful stage
publications are captured and sealed, installed from those sealed bytes when
declared, read back, hashed, chmodded and fsynced. Temporary stage files are
unlinked after capture. Evidence files are 0400 and sealed stage directories are
0500.

After the inner run and complete process cleanup, the outer command reopens all
original sources, bootstrap roots and its own executing image. It requires their
actual contents and stable identities to match the initial captures. It rereads
both published manifests, then recaptures every installed file and checks its
size, SHA256, declared mode and owner. A changed-and-restored original file is
rejected by the identity/timestamp checks even when its bytes again match.

Only after these checks does it write and read back `build.receipt`, fsync the
output directory, and emit the same 128-byte `HIATBOK1` receipt on stdout. The
receipt contains version 1, stage/source/installed counts, source/tool manifest
lengths, a reserved zero word, and the two actual manifest SHA256 values. The
inner-only `HIATBIK1` receipt is distinct and is never a public success receipt.

## Qualification boundary

The associated `HIA_COLD_BUILD_ENTRY_QUALIFICATION.json` records the exact HIA
source and native-flat identities plus 35 actual public-entry cases and 345
native numeric, owner-receipt and capsule checks. The actual two-stage positive
case exercises all six binding kinds, source capture, native filter construction,
execution of the produced ELF, temporary/prior-stage publication, installed
files, manifests and process cleanup. Refusals include malformed recipes,
forward bindings, duplicate aliases, incorrect pins, hardlinks, symlinks,
occupied output, real child failures, and mutations during execution.

The three live-mutation cases alter an original source, alter then restore it, or
alter an installed executable. The sealed inner construction succeeds in each
case, while the outer final verification refuses public success. Kernel syscall
delays are used only to expose deterministic observation windows; return values,
read data, native checks and budgets are unchanged.

The entry remains within the established compiler bounds: 95 functions, 1514
blocks, 7043 operations, with at most 89 blocks in any function. These component
checks do not replace the full seven-stage production construction, sixty-phase
cold qualification, native install or installed whole-rebuild gates.
