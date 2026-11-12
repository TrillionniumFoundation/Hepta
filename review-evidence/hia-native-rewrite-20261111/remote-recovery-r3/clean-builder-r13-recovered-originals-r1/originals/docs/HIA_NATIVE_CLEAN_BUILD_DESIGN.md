# Native immutable release-kit build: implementation scope

This is a new independent development component. It does not activate a default
installation or replace the complete 16-action hosted `hia` command. The first
implemented delivery slice reproduces the existing five-command native stdio tool
and native release installer, including their complete build recipe. All source
and image admission, build-order decisions, frame construction and package
contents belong to HIA. A fixed Linux x86-64 executor owns only captured buffers,
W/X mappings, calls, descriptor I/O and cleanup.

## Authority and cold evidence

The operator supplies an expected SHA-256 of a complete immutable source kit.
This is an explicit input trust root, analogous to the existing native release
installer's expected package digest. The kit is not allowed to authorize its own
bytes. HIA computes that digest before loading its compiler or using metadata.
The kit includes the original raw completed cold report, the complete declared
source closure including its support contract, and the exact flat compiler.
The native gate checks the existing eleven required checks, exact true values,
returncode zero, exact schema/profile/status, three generation hashes equal to
the actual compiler digest, the complete source manifest, all actual source
hashes and the support contract's full source identity. No extra source entry,
omitted source or duplicate path can disappear in a host-side projection.

The existing support-contract policy itself remains operator-authorized data in
the immutable source kit, rather than a claim that a HIA parser has independently
re-proved the qualification. The original 180-second/two-worker cold execution
and all its required phases remain a separate unchanged qualification gate.
Native build execution is not cold evidence. The new builder code needs its own
matching-source qualification before a delivery promotion.

The initial source-kit protocol is explicitly a new private native release
format. Its JSON metadata profile is UTF-8 ordinary JSON with distinct integer,
boolean and floating tags, parsed by the existing general HIA decoder; all actual
cold reports and support contracts are included verbatim. It does not claim to
replace `json.loads` for arbitrary private UTF-16/UTF-32 report objects. Existing
hosted interfaces remain available as references until their complete ordinary
entry contract is replaced and accepted.

## Kit byte layout

A fixed input begins with 64 bytes: `HIABIN01`, version 1, expected kit digest
(32 raw bytes), exact kit byte count, zero. The operator digest is outside the
hashed kit. The immutable kit starts with 64 bytes of eight little-endian u64:
`HIABKT01`, version 1, stdio profile (0 flat / 1 object / 2 executable), file count,
compiler byte count, cold-report byte count, zero, zero. Compiler bytes and raw
cold report follow. Each source row is `[pathBytes, contentBytes, 0, 0]`, followed
by exact path bytes and complete content bytes. The support contract is an
ordinary row named `docs/HIA_SELFHOST_CORE_SUPPORT.json`. Complete row membership
must match the cold report and the contract. Rows may be in any order; HIA owns
path comparison, duplicate detection and source lookup.

The source kit is captured once and made physically readonly. It is the input
snapshot, rather than a set of paths reopened during compilation. The caller
must authenticate the desired kit digest independently. This protocol makes no
claim about later mutation of a separate source checkout. The executor does not
interpret source paths or traverse a source tree.

## Native gate and execution protocol

The gate entry takes three regions: the complete readonly fixed input, an actual
readonly peer reply, and an owned growable mutable workspace. All persistent
references are offsets. An event at workspace offset 1024 has 128 bytes. The
gate uses actual JSON decoder requests and grow requests; SHA-256 computation
and source comparisons are HIA functions. The complete controller continues
directly into the native build recipe after the gate accepts.

Peer replies have a 64-byte header: `HIABRP01`, command sequence, peer kind,
actual return, exact payload bytes, actual wait status, elapsed nanoseconds,
zero, followed by the actual peer bytes. Decoder replies use zero wait status
and zero elapsed fields and retain the whole native arena through the exact
reported used extent. A malformed reply permanently poisons a valid workspace.
Growth retains the same immutable input and actual reply, does not issue a second
peer call, and does not advance its command sequence. A caller encountering BAD
must dispose of the lease even if the supplied workspace was too short to safely
write poison state.

The gate's completed workspace contains exact source and compiler offsets plus
validated cold/contract arenas. The subsequent HIA build controller must consume
that private issued state; arbitrary external workspaces are not authenticated
by magic. It compiles the admitted selfhost source and requires the result to
match the admitted compiler byte-for-byte before compiling application sources.
The existing compiler limits and each original application packer's limits are
preserved. Each fresh compilation starts with zeroed compiler workspace/output.
Produced packers execute only after their source and actual compiler-result
association is established. Native HIA constructs every packer input frame.

## Delivery recipe and remaining owners

The implemented first package contains native `hia`, native `hia-release`, the
source kit, compiler image, an HIA build receipt, and the pinned native build
bootstrap executable. `hia` retains the five existing operations: capabilities,
verify, compile, render-assembly and assemble, including their original profile
and failure behavior. The HIA release pack follows existing `HIAREL01` naming,
modes and no-replace native installer semantics. The executable package and
source kit have distinct digest identities, both emitted by HIA.

Still separate after this slice: all 16 hosted CLI actions and their publication
wrappers; complete runtime/proof targets; arbitrary project/library dependency
resolution; installed worker/ref/state migration and upgrade rollback; building
the bootstrap trust root from a different machine toolchain; and the newly added
builder's own matching-source cold and complete retained qualification. No old
production owner is removed by this component.

## Complete fixed executor and controller ABI

The public invocation is `hia-build EXPECTED_KIT_SHA256 < source-kit.hiabuild`.
The syscall executor captures stdin and a bounded first argv value. HIA checks
the exact argument count, 64 lowercase hexadecimal characters, and produces the
64-byte input prefix. The executor copies that prefix with the captured kit and
makes the resulting mapping physically readonly. It never parses source paths,
JSON, hashes, recipe choices or package metadata.

An event at workspace offset 1024 is sixteen little-endian u64 words. Words 0,
1, 2 are `HIABBE01`, action and sequence. The remaining fields are interpreted
only for the indicated fixed action:

| Action | Mechanical operation | Important fields |
| --- | --- | --- |
| 0 | Write final package, then terminal event | words 3/4 workspace offset/bytes; words 12–15 package SHA-256 |
| 1 | Call fixed native general JSON decoder | words 3/4 input view; 5/6 output/work capacity; 8/9 node/depth configuration |
| 2 | Grow own workspace and retry same input/reply | word 5 required capacity; sequence does not advance |
| 3 | Publish semantic refusal event; exit 2 | word 6 refusal category |
| 4 | Discard private invocation; exit 126 | no package publication |
| 5 | Compile in a fresh child | words 3/4 input source; 5/6 fixed one-MiB capacities; 8/9 code offset/bytes; 10 code owner |
| 6 | Run a compiled application packer in a fresh child | same fields; source view is in workspace |
| 7 | Return exact running bootstrap executable bytes | reply kind 4; no source semantics in executor |
| 8 | Continue same HIA controller without a peer | no foreign planning |
| 9 | Capture HIA-issued input prefix | words 3/4 workspace view, exactly 64 bytes |

Peer kinds are 1 decoder, 2 compiler, 3 packer and 4 running executable. Compile
and pack replies retain the complete one-MiB output region; HIA checks the actual
returned used extent. Nonzero child wait status has an empty payload and becomes
a HIA build refusal. Successful replies that require workspace growth pin the
whole header and used payload bytes before the retry. Actual immutable decoder
reply custody is held by the executor across gate growth; the native arena is
not an authenticated external parser result.

Each real decoder/compiler/packer call forks a new child, uses fresh zero output
and scratch mappings, protects a copied source as readonly and a dynamic code
mapping as RX, and observes that child's actual return and wait status. The
child installs the unchanged 10-second CPU, 20-second wall alarm, 256-MiB address,
8-MiB stack and zero-core limits. Parent-death SIGKILL and a parent-PID check are
mechanical lifetime controls. The parent retains the reply as readonly, then
unmaps per-call source/code/output/scratch/result. This is a syscall adapter and
is not claimed to be a security sandbox.

## Recipe, reproducibility and bootstrap boundary

HIA compiles seven source images in this exact order: selfhost, Core JSON
frontend, stdio dispatcher, stdio packer, release policy, release packer and
SHA-256 stream. The new selfhost result must match the admitted compiler in full
before it can compile the remaining six. HIA constructs both packer inputs,
validates their actual complete ELF headers, computes every input/output digest,
and creates the native receipt and `HIAREL01` package.

The six installed files are `hia`, `hia-release`, `hia-build` (mode 0500) and
`compiler.bin`, `source-kit.hiabuild`, `build.json` (mode 0400). The new application
images and compiler are rebuilt by HIA. `hia-build` itself is a retained copy of
the exact running bootstrap. Reproducing the complete package from that retained
bootstrap demonstrates a native application rebuild; it does not demonstrate
source reconstruction of the new builder or removal of its bootstrap trust
root. The separate compiler/packer development build records retain that boundary.

The current native gate binds all kit contents to an operator-supplied digest,
checks cold metadata and source identity, and checks the full source inventory.
It does not regenerate the hosted `support_contract()` policy object or run a
new qualification. The independently checked original kit was also admitted by
the unchanged matching-source hosted gate before development execution. Neither
a correctly formed report nor this new native build upgrades development code
to a new matching-source cold qualification.

## Actual development verification and retained failures

The final production controller has 107 functions, 1,258 blocks and 5,800
instructions, within the original limits. Its first actual full build refused a
wrong constant in its own strict `PT_GNU_STACK` check. That failing executable,
source and raw terminal are retained as `native-whole-r1`; only that HIA constant
changed before `driver-compile-r3` and the successful `native-whole-r2`.

The successful complete fixed ELF produced a 19,525,785-byte package with SHA-256
`c00431ad64b6cef4a2d4d8c59d3ca930d0ef9da5f2d8478680beee15dd7d4460`.
The seven actual compilations include a byte-identical new B3; actual stdio and
release packer outputs are fully byte-identical to the independently invoked
old native builders. Native installation verified all six contents and exact
modes, no-replace refused with its original status 14, and the installed native
installer verified the published release. Eleven installed stdio success/refusal
cases matched complete stdout, stderr and exit status, and an installed compiled
sample was actually executed. The installed builder and installed kit, under an
empty PATH and isolated HOME, rebuilt the complete package byte-for-byte.

The installed test's first run completed build and installation, then collided
with its own evidence-directory name. Its first resume incorrectly expected the
old installer's intentionally retained failed stage to be absent. Both failures
are retained. The corrected third test revision verifies that entire retained
stage and completes command/rebuild checks; it does not relabel the two earlier
runs as passing or alter production code.

`controls-r1` records 36 private malformed/semantic reply controls, two successful
actual metadata controls, exact compiler growth/retry, and two complete real ELF
kit refusals: wrong operator digest and a re-digested changed source with a stale
cold source map. All 76 recorded controller entries preserve full raw buffers in
lossless content-addressed storage. These private checkpoint controls do not
claim external arena/workspace authentication.

`executor-mechanics-r2` uses an explicitly separate development HIA controller
and observation image with the exact production executor. Six actual children
prove distinct fresh PIDs, zero output/scratch, actual resource-limit values and
armed wall timer, and real SIGSEGV on writes to copied readonly source and RX
code. The initial test import-path failure is retained. This fixture is never
included in the release kit. All component evidence remains development evidence;
the 16-action CLI and full worker, runtime and proof closure remain open.
