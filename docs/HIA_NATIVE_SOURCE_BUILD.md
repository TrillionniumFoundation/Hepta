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

`hia-source-build sources` compiles a group of named assembly sources in one
native process. Its binary input starts with the eight ASCII bytes `HIANAM01`
and an unsigned 64-bit source count in little-endian order. Each record has
two little-endian unsigned 64-bit lengths, followed by the ASCII name and the
source bytes. It accepts 1 through 128 distinct names ending in `.hepta` and
up to 1 MiB per source. The compiler checks the entire input, sorts the names
by ASCII byte order and emits the same source/image pairs as a directory
package passed to `build`. A malformed record or a rejected source yields
empty stdout. The Store release, standalone Core builder and batched helper
builder use this entry point.

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

The qualified compiler contract uses a 1 MiB output and a 1 MiB
workspace. This standalone transport uses the same sizes and clears the entire
compiler workspace before each call. The input package becomes read-only after
EOF. Compiler output occupies a separate 1 MiB region inside the policy arena;
input, output, policy, pack frame and compiler workspace never overlap during a
call. The calculated anonymous mapping is 143,732,736 bytes (137 MiB + 76 KiB).

| Region | Extent |
| --- | ---: |
| Arguments and syscall metadata | 4 KiB |
| Policy state, member table and live compiler result | 1 MiB + 64 KiB |
| Retained group objects | 4 MiB |
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

The release builder also runs `hia-source-build inventory` on the member names
and SHA-256 identities it captured from source. The input starts with
`HIAINV01`, the little-endian u64 member count and the u64 package length.
Each row contains the u64 name and digest lengths, the ASCII name and exactly
64 lowercase hexadecimal digest bytes. The HIA policy validates and orders the rows and writes the
binary inventory and `HIAATT01` footer consumed by `hia-release attest`.
The release package stays outside the inventory compiler's input buffer.

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

The native public bootstrap entry is:

```sh
hia-source-bootstrap --source ABS_SOURCE --cold ABS_COLD --bootstrap ABS_BOOTSTRAP --output NEW_ABS_OUTPUT
```

Its source authority and production recipe are captured with the admitted
bootstrap roots. The cold input contains the actual `qualification/base/B3.flat`
and `final-cold.json`. The recipe's first admission step binds the strict
complete cold report, current source inventory, support contract and exact B3
digest. B3 is executed only after that step returns the required admission
record. A named file, a report-shaped object or an old success receipt cannot
substitute for the actual complete cold run.

The HIA production plan constructs the source builder, builds and repacks its
source kit through two actual generations, checks complete source-kit and
executable byte identity, and independently rebuilds B3. It then constructs the
ordinary build capabilities and their exact entry binding. The public owner
captures and seals its inputs, retains child results, confirms process cleanup,
rechecks the original source, tool, B3 and report observations, and reads back
every installed file before publishing success. Changed bytes and change-then-
restore identity races cannot gain a final success receipt.

The source builder's installed evidence includes `cold-inputs.receipt` with
`HIASBIN1`, the actual B3 digest, actual cold-report digest and the strict
`HIAADC01` admission record. This binds cold inputs into the installed tool
manifest. The public `HIASBOK1` receipt separately binds source and tool
manifests. See [the bootstrap entry contract](HIA_COLD_SOURCE_BOOTSTRAP_ENTRY.md)
for exact transport, publication and refusal rules.

## Validation and integration

The ordinary release contains the native source builder and its three HIA
sources. From installed bytes, source-only build and source/image repack must
reproduce the executable, and a second rebuilt generation must emit the same
source kit. These checks cover the assembly compiler and its transport. The
ordinary whole-project build, package installation, Worker installation and
installed whole-source rebuild remain separately required acceptance stages.

Required refusal controls cover malformed envelopes, names, modes, phase and
capacity boundaries, rejected source, changed source/image pairs, late output
capacity failure and kernel I/O failure. The final write may encounter a full
device or a reader that closes after receiving a prefix; that is a transport
failure, not an atomic successful publication. Product publication uses the
native owner's retained descriptors and final readback checks.

All reports must name their actual source, installed bytes and executed scope.
A development component result or historical build cannot stand in for the
complete current cold and installed release gates. [CURRENT.md](CURRENT.md)
indexes that acceptance evidence.

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

Member qualification compares the complete source-produced ELF with the exact admitted installation using the matching source authority. A different source directory requires fresh identity and execution evidence.

## Building installed Agent stdio roles

The same HIA member policy rebuilds the Agent stdio executables. Bootstrap one builder with `mcp_stdio_packer.hepta` in the packer slot to build all single-image Agent stdio roles. For `hia-agent-journal`, bootstrap a second builder with `agent_journal_stdio_packer.hepta` and include `agent_journal_transport.hepta` in the input directory.

The production release sends each single-source recipe directly to its member builder. Recipes with companion sources must supply those companions. The request starts with the eight bytes `HIASRC01`, followed by three little-endian 64-bit integers holding the source count (one), the filename length and the source byte length. The filename and source follow without padding. The HIA policy admits the filename and declared module and invokes its embedded compiler. It sends the image in its workspace to the embedded ELF packer, then checks the bytes in the final ELF against that image before publication.

For a tool with a separately checked syscall adapter or transaction layout, the release requests the compiled object with the eight-byte tag `HIAIMG01` and the same source fields. The builder checks the final ELF, appends the object directly from the compiler workspace, then writes the ELF length and object length as two little-endian 64-bit integers followed by `HIAOBJ01`. The release consumer uses that object to check the adapter placement.

For recipes with two to four sources, the release uses `HIAMUL01` followed by the source count and the same length-prefixed filename and source for each input. The member builder checks the declared module of every input and matches the required companion identities. It compiles each source once and saves up to four 1 MiB objects outside the live compiler output region. It passes the objects to the packer in the order required by the primary module and compares their bytes in the finished ELF. The response contains the ELF and each compiled object in request order. Its footer holds the ELF length, one length per object, and the object count as little-endian 64-bit integers, followed by `HIAOBJS1`. The source-less Worker port retains its existing `HIAWPRT1` request.

The builder also accepts the source-and-image packet produced by the installed seed. Stage the role's HIA application under the public release name plus `.hepta`. For example, `hia-agent-read-page` takes `agent_read_page.hepta` under the name `hia-agent-read-page.hepta`. The kernel selects the wire mode from the exact public filename and checks the source's declared HIA module. It recompiles the sources and verifies that the original application and optional codec bytes occur at their expected positions in the finished ELF. The directory, compiler and `member-builder build` stages use the same commands as the filter example above. The HIA member policy and source-bound ordinary recipe identify the admitted source basename and companions for each public role.

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

## Native job release members

The ordinary release recipe includes `hia-job-launch` and
`hia-job-observation`. Both are rebuilt from named HIA sources with the same
source-role admission used by the other native release members.

| Program | Primary source alias | Exact companion sources | Packing envelope | ELF ceiling |
| --- | --- | --- | --- | ---: |
| `hia-job-launch` | `hia-job-launch.hepta` from `job_launch.hepta` | `job_launch_json.hepta`, `sha256_stream.hepta` | `HIAJLNK1` and three little-endian image lengths | 4 MiB |
| `hia-job-observation` | `hia-job-observation.hepta` from `job_observation.hepta` | `job_observation_json.hepta` | `HIAJOK01` and two little-endian image lengths | 2 MiB |

The source module names must match each admitted role. Input order does not
change the emitted executable. Missing, extra or mismatched sources fail
before any output is published. The shared persisted-metadata authoring helper
is compiled into each HIA policy; it is not a separately executable runtime
component or an additional packing image.

Native job qualification drives the source kit with an empty `PATH`,
compares retained and embedded images with independent source compilations,
reverses named-source order, and exercises role refusals. Full
cold qualification, ordinary source release, installation and public job
routing remain separate gates. Including these two programs in the release
does not itself establish that a running MCP service uses them.

The complete job bundle additionally registers hia-job-entry (SHA companion),
hia-job-cancel (the exact job_observation_json and SHA companions), and
hia-job-submit (job_submit_launch, job_submit_json, SHA, in that pack order).
Auxiliary roles 30 and 31 retain their original launch/observation JSON identities;
32 and 33 name the two submit companions. Primary-role admission now starts at
64. The auxiliary source table occupies bytes 2048 through 3071, independently
of retained-image cursor 1024 and all existing fixed control fields. No compiler,
source-count, extent, image or negative-control budget is increased by this
namespace extension. Native member qualification separately compiles all four
submit sources and verifies source order independence and both new missing or
mismatched companion refusals.
