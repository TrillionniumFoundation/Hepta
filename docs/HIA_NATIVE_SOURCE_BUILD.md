# Native HIA source-bundle builder

`hia-source-build compile` reads one HIA assembly program on standard input and
writes its flat machine image on success. To rebuild the compiler from an
installed release, run the following command in the release directory.

```sh
./hia-source-build compile < selfhost.hepta > compiler.bin
```

The strict build checks these bytes against the cold-qualified compiler image.
The single-source command accepts up to 1 MiB of assembly. Empty, oversized
and rejected inputs produce no output. The raw image uses the selfhost calling
convention. The `pack` command below produces the standalone Linux executable.

`hia-source-build build` consumes an entire `HIAREL01` assembly source bundle on
standard input, within the retained qualified selfhost compiler profile. The
checked HIA policy admits every member before compiling any member,
then requests actual compilation by the embedded HIA compiler. It serializes
each original source and its produced image into a new `HIAREL01` bundle. The
first standard-output write occurs after every compilation and serialization
has succeeded. The runtime opens no files and runs no child programs.

`hia-source-build pack` constructs a standalone executable with the checked HIA
ELF packer. It accepts exactly the three image roles below, or exactly their
three sources plus three images in any order:

| Source role | Image role |
| --- | --- |
| `source_build_policy.hepta` | `source_build_policy.hepta.bin` |
| `selfhost.hepta` | `selfhost.hepta.bin` |
| `source_build_packer.hepta` | `source_build_packer.hepta.bin` |

For a six-member source kit, the currently embedded trusted compiler recompiles
all three sources and the HIA policy compares each produced image byte for byte
with its corresponding supplied image. A mismatch prevents publication. No
input image is executed to check identity. A three-image package deliberately
has no source-identity claim: it copies the explicitly selected opaque images
into an ELF without executing them. Packaging a machine image does not qualify
its semantics or authorize its later execution.

## Retained boundaries

Both commands use the existing release package envelope: a 24-byte little-endian
header `(HIAREL01, member_count, 0)`, then a 24-byte header
`(name_bytes, mode, payload_bytes)` and exact name/payload bytes for each member.
Names are ASCII `[A-Za-z0-9][A-Za-z0-9._-]*`, have no directory components, and
are unique. Every mode is `0400`. Build accepts 1–128 sources, each named with
the exact `.hepta` suffix and a name of at most 123 bytes. It appends `.bin` to
image names, preserving the installer's 127-byte limit and 256-member ceiling.

Every source and image has a nonzero extent of at most 1 MiB. Input and output
bundles are at most 64 MiB. The embedded compiler retains its qualified assembly
language, instruction, function, frame, source, image and workspace boundaries.
The common `.hepta` extension also names JSON Core documents elsewhere in the
project; this builder does not add a JSON frontend to the assembly compiler.
An actual valid JSON Core `.hepta` fixture is checked by the Core verifier and
then supplied to this builder in the tests: the assembly compiler refuses it
with exit 18, with no partial result even after an earlier member compiled.

`tools/qualify_hia_selfhost.py::compile_stage` uses a 1 MiB output and a 1 MiB
workspace. This standalone transport uses the same sizes and clears the entire
compiler workspace before each call. The input package becomes read-only after
EOF. Compiler output occupies a separate 1 MiB region inside the policy arena;
input, output, policy, pack frame and compiler workspace never overlap during a
call. The calculated anonymous mapping is 139,538,432 bytes (133 MiB + 76 KiB):

| Region | Extent |
| --- | ---: |
| Arguments and syscall metadata | 4 KiB |
| Policy state, member table and compiler result | 1 MiB + 64 KiB |
| Compiler workspace | 1 MiB |
| Three-image pack frame | 3 MiB + 4 KiB |
| Deferred output | 64 MiB |
| Captured input and oversize guard | 64 MiB + 4 KiB |

The ELF has one readable/executable load segment and a non-executable stack.
No writable/executable mapping is made. Input images are not mapped or called.
The fixed Linux x86-64 adapter performs only argument copying, anonymous mapping,
read-only protection, stdin/stdout transport, calls to embedded HIA entrypoints,
SIGPIPE handling and process exit. HIA owns the command, member, phase, compiler
result, pair identity, capacity and serialization decisions.

## Failure and custody

Policy failures poison the retained native invocation state. Exit 16 means an
argument, envelope, name, mode or phase refusal; 17 means the bounded input or
output does not fit; 18 means compilation or packing failed; 19 means a supplied
source/image pair differs; 15 means a kernel transport failure. Admission,
compile, identity and capacity failures leave stdout empty even after earlier
members compiled successfully. The process creates no files. An I/O error while
the final byte stream is being written can expose a prefix to the output device;
callers needing atomic filesystem publication should use the existing native
release installer's staged publication protocol.

`tools/build_hia_source_build.py` is an explicit hosted bootstrap and code-custody
tool. It requires the actual current complete cold qualification before creating
its output directory. It compiles the policy and packer with a captured compiler
image, checks actual call receipts including the compiler/image identity, source
hash/size, strict integer return/produced sizes, produced hash, unchanged source
and empty forbidden-module list, then rechecks the complete cold/source/image
inputs before publishing the final executable. Its native source-kit checks run
from a sealed executable descriptor, preventing a temporary pathname replacement
from selecting another program. Final publication writes captured executable
bytes to an `O_TMPFILE` anonymous inode and links that retained descriptor into a
captured destination directory without replacing an existing entry. It never
selects code by a replaceable staging pathname. The native-produced source kit is also passed as captured bytes to this
publication function. It receives its own retained anonymous descriptor and
`0400` no-replace link. The success receipt is emitted after both published
files have been read back through their descriptors; it records each actual
device, inode, mode, size and hash. The executable remains `0500`. Publication/receipt failure withdraws only entries still
bound to the invocation's own inode. This bootstrap publication requires Linux
`O_TMPFILE` support on the output filesystem and fails closed without it.
The published source kit is produced by the native builder, and native repacking
must reproduce the captured executable.

The bootstrap's Python generator, assembler, cold gate and receipt checks remain
declared host boundaries. The generated ELF has no Python, libc, source-generator,
assembler, external compiler, import path, current-directory or executable-name
dependency. This component closes native compilation of a supplied assembly
source bundle and native self-repacking. It does not establish whole-project
native delivery, rewrite the public frontend, replace the remaining nominal
normalization bridges, or justify removal of the retained reference tools.

## Validation and integration

The normal Core/Store release includes the native source builder and its three
HIA sources. From installed bytes the release job packs a source-only bundle,
recompiles it, uses the compiled sources and images to reproduce the installed
builder byte for byte, then repeats the build with that reproduced executable.
Both generations must emit an identical source kit. This checks the retained
assembly compiler and its bundle transport, not the rest of the product's
source build.

`tests.test_hia_source_build` contains complete source regeneration checks,
independent HIA VM policy/ELF byte oracles, strict receipt refusal controls, actual
B0/B1/B2/B3 development compilation, actual native two-round self-rebuilds,
changed-compiler-source causality (`M1 != M2 == M3`), source/image mismatch
refusals, max-name/member/source/image boundaries, a real late output-capacity
failure after many successful compilations, copied-executable/empty-PATH and
syscall observations, real private-path substitution at the publication syscall,
publication collision/receipt rollback, malformed input and kernel I/O failures.
The write-failure controls separately exercise `/dev/full` before any output and
an actual pipe receiver that reads a prefix then closes, with strace confirming
the following `EPIPE` and authoritative exit 15.

`HEPTA_HIA_SOURCE_BUILD_COLD_REPORT` selects the real strict builder and a new
independent output directory. It always takes precedence over any development
manifest. A development manifest must bind current exact source bytes and the
exact standalone ELF image composition; it is explicitly recorded as development
evidence and cannot substitute for cold qualification.

These new files are developed in an isolated worktree based on suffix migration
commit `20838a0a3e35493f4d96c74c3fca7ef86e4c529a`. Public source manifests, the
source contract, inventories and CI registrations are intentionally integrated
by the main development task, followed by a new complete cold qualification.
Earlier lost-worktree results are not evidence for this implementation.

The v67 integration additionally validates a normal captured sourcekit/executable
publication: it reads the two actual files and receipt, checks their inode, mode,
size and complete hashes, and uses the published executable to repack the
published kit back to identical ELF bytes. This is a positive product-integrity
control. It does not claim an observed sourcekit substitution counterexample.
The private publisher retains its original three positional arguments; the
sourcekit is an optional keyword for existing executable-only test callers.

## Building native filter release members from the installed seed

The default native Store release builder uses this path for the complete native filter and packaged Agent stdio inventories. It captures the selected seed and each generated member builder before execution. Each input source must match its SHA-256 in the cold qualification contract.

`source_filter_member.hepta` rebuilds the standalone Store filters that take an application and a role packer. The cost ledger and run plan also take the canonical renderer `worker_request.hepta`. Every compiler and packer call below uses the qualified, installed `hia-source-build` or an ELF produced by that seed. HIA checks the source and image names, recompiles each source and compares all image bytes, builds the role's frame, and admits the packer's ELF before the first stdout write.

For example, to rebuild `hia-evaluate-measurements`, set `sources` to the absolute path of `examples/hia_bootstrap`, `release` to the qualified Store installation and `work` to a new private directory. The two directories below stage the exact bytes under the names expected by the seed.

```sh
mkdir -m 700 "$work/tool" "$work/input"
install -m 400 "$sources/source_filter_member.hepta" "$work/tool/source_build_policy.hepta"
install -m 400 "$sources/selfhost.hepta" "$work/tool/selfhost.hepta"
install -m 400 "$sources/evaluate_measurements_packer.hepta" "$work/tool/source_build_packer.hepta"
install -m 400 "$sources/evaluate_measurements.hepta" "$work/input/evaluate_measurements.hepta"

"$release/hia-directory-package-build" "$work/tool" > "$work/tool.sources" &&
"$release/hia-source-build" build < "$work/tool.sources" > "$work/tool.images" &&
"$release/hia-source-build" pack < "$work/tool.images" > "$work/member-builder" &&
chmod 500 "$work/member-builder" &&
"$release/hia-directory-package-build" "$work/input" > "$work/member.sources" &&
"$release/hia-source-build" build < "$work/member.sources" > "$work/member.images" &&
"$work/member-builder" build < "$work/member.images" > "$work/hia-evaluate-measurements"
```

For budget-observation, budget-store, cost-ledger, cost-ledger-flow, measurements, native-report, paired-batch, publication, reference-batch, reference-report, report-flow, run-plan, and settlement, use the corresponding `evaluate_<name>.hepta` and `evaluate_<name>_packer.hepta`, replacing hyphens in the name with underscores. For cost-ledger and run-plan, also stage `worker_request.hepta` as a mode-0400 input. The other supported release members use these source names.

| Release member | Application | Packer |
| --- | --- | --- |
| `hia-evaluate-projector` | `evaluate_reference_wire.hepta` | `evaluate_reference_wire_filter_packer.hepta` |
| `hia-execution-budget-session` | `execution_budget.hepta` | `execution_budget_session_packer.hepta` |
| `hia-safe-core-loader` | `safe_core_elf_inventory.hepta` | `safe_core_loader_filter_packer.hepta` |

`HIA_TEST_NATIVE_FILTER_RELEASE` selects an installation for the full source-to-ELF comparison in `tests.test_hia_source_filter_member`. The test accepts an explicitly selected matching source directory in `HIA_TEST_NATIVE_FILTER_SOURCES`.

## Building installed Agent stdio roles

The same HIA member policy rebuilds the Agent stdio executables. Bootstrap one builder with `mcp_stdio_packer.hepta` in the packer slot to build all single-image Agent stdio roles. For `hia-agent-journal`, bootstrap a second builder with `agent_journal_stdio_packer.hepta` and include `agent_journal_transport.hepta` in the input directory.

The production release sends each single-source Agent stdio recipe and each single-source Evaluate, execution-budget session and Safe Core loader filter directly to its builder. Two-source filters must supply their canonical companion. The request starts with the eight bytes `HIASRC01`, followed by three little-endian 64-bit integers holding the source count (one), the filename length and the source byte length. The filename and source follow without padding. The HIA policy admits the filename and declared module and invokes its embedded compiler. It sends the image in its workspace to the embedded ELF packer, then checks the bytes in the final ELF against that image before publication.

The builder also accepts the source-and-image packet produced by the installed seed. Stage the role's HIA application under the public release name plus `.hepta`. For example, `hia-agent-read-page` takes `agent_read_page.hepta` under the name `hia-agent-read-page.hepta`. The kernel selects the wire mode from the exact public filename and checks the source's declared HIA module. It recompiles the sources and verifies that the original application and optional codec bytes occur at their expected positions in the finished ELF. The directory, compiler and `member-builder build` stages use the same commands as the filter example above. The `VARIANTS` data in `tools/build_hia_agent_read_page.py` identifies the original source basename for every existing public role.

## Building Worker carriers and launchers

The standard Store release builds the Worker carriers and launchers through
the same HIA member policy. Each carrier uses its own checked packer.
The 20 carriers and launchers that require one source compile and pack it
inside their member builder. The other eight require their companion sources.
Emit, Adopt, Verify and the Evaluate proof carrier also take their two ordered
companion images. The native, Evaluate intake, replay and full launchers take
the separately compiled capsule authority. The read, read-only and Context
control launchers use their own authority as the primary source.

The public filename selects the build recipe. The policy checks the primary
module and any required companion identities, recompiles all supplied sources,
then frames and checks the resulting ELF. The installed-role tests compare
each output against a separately built release and exercise changed images
and missing companion inputs.

## Linking and transport tools

The release uses HIA source recipes for the static, direct shared and
verified shared ELF linkers, Worker request preparation, the CNF solver,
direct calls, job receipts and the scalar reference executor. Supply the
application under the target filename plus `.hepta`. The HIA member policy
checks that the name matches the source module and rebuilds the image before
running its packer. Direct-call, job-receipt and scalar-reference builds also
verify their original syscall adapter source, relocated call and full embedded
image against the finished executable.

## Rebuilding release management and Core programs

The HIA member builder constructs `hia-release`, `hia-select`,
`hia-patch-result`, `hia-totality-core`, `hia-core-proof-wire` and the
four-image `hia-core` suite. Each recipe names all required components and
their positions in the packed executable. Source directories can list those
files in any order. Missing, extra or mismatched source/image pairs prevent
publication. The Core patch-result packer retains its two-image plus 4 KiB
output bound.
