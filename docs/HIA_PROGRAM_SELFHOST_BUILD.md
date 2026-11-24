# Ordinary builds with the native HIA compiler

`hia build --backend selfhost` connects the ordinary CLI to the retained HIA
Core JSON frontend and HIA selfhost compiler. The selected executable lowers
Core JSON into assembly, performs the compiler profile's semantic checks, and
emits the complete Linux x86-64 ELF relocatable object. This route does not
import the Python machine emitter or Python ELF writer and does not invoke a
host compiler, assembler, or linker.

The standalone native package runs this route without the Python CLI, using
the source-matched HIA dispatcher and selected selfhost component together
with Linux syscall adapters. The hosted entry point still supplies its own
public verification, compiler selection, process ownership and publication
orchestration. This route does not replace the default `--backend native`,
`AgentService._compile`, or the Agent durable state and worker interfaces.

## Build and select a compiler

First complete the repository's source-matched cold qualification. The strict
builder accepts its actual outer report and produced B3 image, checks the
report against the current source bytes, and emits an adjacent selection
manifest only for the ELF object profile:

```sh
python -B tools/build_hia_core_json_cli.py \
  --compiler /absolute/qualification/B3.image.bin \
  --cold-report /absolute/qualification/cold.json \
  --output /absolute/new-compiler-directory \
  --output-profile elf
sha256sum /absolute/new-compiler-directory/compiler-manifest.json
```

Review and pin the resulting manifest bytes. Pass its exact lowercase SHA256
as an explicit CLI argument:

```sh
hia build /absolute/program.core.hepta \
  --backend selfhost \
  --selfhost-manifest /absolute/new-compiler-directory/compiler-manifest.json \
  --selfhost-manifest-sha256 <reviewed-64-character-lowercase-SHA256> \
  --output /absolute/existing-output-directory/program.o
```

The selected executable accepts primitive Core v6 through v9 JSON, with scalar
exports. The hosted build entry also accepts canonical composite v1 through v4 through the
explicit complete HIA lowering owners described below. Use `hia import-assembly`
to convert assembly source to Core JSON before building. Native compilation receives canonical Core JSON with the
exact chosen scalar export list. Output must be a new pathname under an
existing directory; existing files, dangling symlinks, and parent symlinks are
refused. No compiler is selected from an environment variable, discovered
through `PATH`, or substituted when this selection fails. Both manifest
arguments are required for `selfhost` and are rejected with `native`.

The emitted `compiler-manifest.json` uses
`hepta.hia.program-selfhost-compiler.v1`. It pins the executable basename,
length and SHA256; compiler, frontend and packer image digests; cold report
digest; and these exact resource bytes:

- `examples/hia_bootstrap/selfhost.hepta`
- `examples/hia_bootstrap/core_json_frontend.hepta`
- `examples/hia_bootstrap/core_json_cli_packer.hepta`
- `docs/HIA_SELFHOST_CORE_SUPPORT.json`

Those resources are packaged for installed use. Runtime selection does not
import authoring tools or look for a different checkout. Source, manifest and
executable files must be ordinary, singly linked files owned by the current
user or root and not writable by group or others. Every path component is
opened without following symlinks. Files are read completely with bounded
reads and their inode, metadata and bytes are rechecked before publication.

An operator pin authorizes executable bytes; it is not an independent proof
of their provenance or semantics. `cold_report_sha256` records declared build
provenance. A developer-created selection can use `null`, which is explicitly
not a cold qualification. The ordinary build receipt never promotes either
kind of selection into a whole-product or production qualification.

## Supported profile and refusal behavior

The route has its own profile,
`hepta.hia.program.selfhost-elf-linux-x86_64.v1`, and requires Linux x86-64,
little-endian LP64, executable sealed memfds, and `/proc` descriptor access.
It accepts the retained bounded primitive compiler language. Exact opcode,
resource, effect, call and ownership rules remain specified by the selected
`HIA_SELFHOST_CORE_SUPPORT.json` and enforced by the native compiler.

Key bounds are:

| Item | Bound |
| --- | --- |
| Canonical Core JSON input | 8 MiB |
| Rendered assembly and generated ELF object | 1 MiB each |
| Functions / total blocks / blocks per function | 128 / 1536 / 256 |
| Instructions / SSA names per function | 8192 / 2048 |
| Public scalar exports | 1 to 128 |
| Parameters per export | 0 to 16 non-unit scalars |
| Results per export | Zero or one scalar, including unit |
| Compiler stderr capture | 64 KiB |
| Compilation wall-time deadline | 30 seconds in the CLI |

The Python API can set an explicit finite compilation deadline in `(0, 3600]`
seconds. This covers child execution and complete pipe draining; it does not
claim a deadline for public verification, source custody or publication.

Explicit exports retain their exact set. If the input omits exports, the
existing public verifier's scalar entrypoints are used. Internal owned and
borrowed resources remain subject to the native compiler's limits. Primitive
v1–v5 schemas, machine-plan overrides, foreign-buffer public exports, other targets,
and other output kinds are outside this route. Such inputs are refused; they
are not retried with the direct Python backend. Public Core admission can
succeed for a program that the narrower selfhost compiler subsequently refuses.

Compilation runs the captured executable through its actual sealed descriptor,
with an empty `PATH`, a private working directory, and a new process session.
The adapter drains both output streams concurrently under byte bounds, enforces
the original monotonic deadline, terminates the process group and confirms
leader reaping. Nonzero exit, stderr, incomplete output, truncated input or a
stream limit prevents publication. This is ownership of the trusted compiler
process; it does not turn arbitrary operator-selected machine code into a
security sandbox.

The completed object is independently inspected as ELF64 for machine 62. Its
defined symbols must exactly match the requested exports; its undefined
symbols may only be the supported `calloc` and `free` runtime imports. The
adapter holds the original output directory descriptor throughout compilation,
staging and no-replace publication. Parent-directory substitution is refused
and cannot redirect output writes into the substituted directory. A failure
after publication withdraws only the link still belonging to this stage.
The existing optional native artifact publisher composes with this descriptor
anchor. These are point-in-time consistency checks, not crash recovery or
protection against later edits by another process with the same authority.

## Selected canonical nominal lowering

The hosted `build_program_selfhost` entry accepts composite v1–v4 through one
complete HIA executable. Constructor, type, function, helper and outer lowering
run inside that process, including the HIACTR and HIAOTR continuation loops.
The adapter does not call `elaborate_program_native` or retain a Python loop
between native semantic owners. The hosted CLI uses the same entry for its
initial input check. Input reading and verification still precede output
publication checks.

Build the complete program with the same current-source cold report and B3
compiler used for the object compiler:

```sh
python -B tools/build_hia_nominal_constructor.py \
  --compiler /absolute/qualification/B3.image.bin \
  --cold-report /absolute/qualification/cold.json \
  --output /absolute/new-nominal-directory
```

For an explicit selection, set `HEPTA_HIA_NOMINAL_PROGRAM_MANIFEST` to the
resulting `program-manifest.json` and set
`HEPTA_HIA_NOMINAL_PROGRAM_MANIFEST_SHA256` to its exact reviewed SHA256.
The paired selection pins the executable and its complete packaged HIA source
set. It uses profile `hepta.hia.nominal.complete-linux-x86_64.v1`. A matching-source
wheel can instead supply its own `hia-nominal-constructor`, bound to the exact
installed wheel RECORD and native package pin. No PATH lookup selects this
program. An active explicit request bundle must also select its complete
program explicitly; the adapter does not supplement it from a package default.

Selections must agree on the actual compiler bytes and complete support-contract
source identity. Separate source-matched cold runs retain their own report
hashes as distinct provenance; timing-dependent report bytes are not a compiler
identity.

The selected ELF executes from a sealed memfd with empty PATH. The process
owns nominal admission, canonicalization, primitive admission and public
semantic diagnostics. A successful HIAVCF01 frame preserves the original and
Core byte strings separately. On refusal, the same selected program renders
the public error code and message, including the original type/name/shape
location. The second diagnostic invocation shares the admission deadline.
Every source, inventory, manifest and executable snapshot is rechecked before
returning either a successful result or a semantic rejection.

The existing public bounded decoder supplies a detached document. The HIA
owners preserve the existing schema mapping: composite v1 produces primitive
v6, v2/v3 produce primitive v7, and v4 produces primitive v8. Public Core
admission rechecks that complete result before the selected native JSON
frontend/compiler runs. A caller-supplied
`VerifiedProgram` retains both original nominal bytes and canonical Core bytes;
the entry repeats HIA elaboration and rejects a mismatching pair. Nominal public
aggregate or borrowed signatures do not become scalar exports after flattening.

This route supports up to six internal scalar, owner or parameter-bound loan
results. The original returned-loan pair, mutable-to-read child and cooperative
task with six flattened results compile and execute against the original Core
VM cases. A seventh result remains outside this bounded ABI. The original stored-loan,
enum, cooperative-task and partial-record programs also retain their original
canonical Core fingerprints across all four nominal schemas.

The six-result compiler keeps the 1 MiB workspace and the original function,
block, instruction and source limits. The extra type/loan metadata uses the
previously unused final 48 bytes of each function record. Separate private
scratch vectors hold parsed output names and returned identities; a 128-byte
result stack area preserves both descriptor words without aliasing local values.
The public scalar-export and borrowed-buffer entry ABIs are unchanged.

The standalone compiler executable continues to accept primitive Core JSON.
The complete nominal constructor supplies its native session orchestration to
both the standalone package and this hosted adapter. Hosted bounded decoding,
sealed process custody, independent public Core admission and publication
remain explicit boundaries; neither the whole-language nor whole-CLI claim is
promoted. The private object-build launcher uses a separate reachability-derived
canonical-hash component, while public verification retains the full diagnostic
presenter. Both stay within the original compiler and static-link limits.

## Receipt and verification scope

Success returns `hepta.hia.program.selfhost-native.v1`, separate from the
direct backend's machine/frame schema. It records the input, canonical Core,
compiler wire, manifest, executable, source and object identities; actual
object import/export inventory; kernel seals; complete capture digests and
counts; child exit; and confirmed reaping. It reports
`native_emitted_not_executed`: the compiler ran, while the generated program
was not executed by `hia build`.

Its claims keep `python_emitter_used`, `external_linker_used`, `fallback_used`,
`generated_program_executed`, `whole_native_delivery_qualified` and
`production_activated` false. `hosted_cli_and_publication` is false for the
standalone native package. It remains true for the hosted entry point even
when that entry point selects the optional HIA artifact publisher.

`tests.test_hia_program_selfhost.SelfhostBuildSourceTests` checks CLI selection,
profile refusal, actual kernel seals, actual deadline cleanup and actual output
overflow. `SelfhostBuildNativeTests` exercises real compile/link/execution
against independent public interpreter observations, explicit exports, new
path publication, source and executable changes, symlink refusal, directory
substitution, post-publication withdrawal, and actual selected native
publication. It also builds and installs a wheel, then invokes the ordinary
CLI with authoring and Python codegen imports prohibited and `PATH` empty.

The native tests require exactly one explicit setup:

- `HEPTA_HIA_SOURCE_BUILD_COLD_REPORT` selects source-matched qualification and
  calls the strict native compiler and publisher builders. This is the retained
  qualification path. Missing, stale or invalid evidence fails the test setup.
- `HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER` supplies a captured compiler
  image for development observations only. Its manifests carry no cold digest.
  It never serves as an automatic fallback from failed cold qualification.

The nominal build tests build the complete program from all twenty-one HIA
components and its retained transport templates, using the same selected
compiler and cold report. Development mode compiles that same complete program
from its explicitly supplied compiler and records a null cold digest. It does
not infer cold qualification. Tests prohibit the old Python nominal owners and
continuation entry, compare exact original errors and Core bytes, and require
installed default selection to execute the packaged program.
`HEPTA_HIA_SELFHOST_NOMINAL_EVIDENCE` retains actual input/Core bytes, emitted
objects, linked images, execution observations, receipts and refusal captures.
The `nominal_capture` receipt records the complete executable and selection
identities, source set, kernel seals, process exit and confirmed reaping.

No implicit seed bootstrap is selected by this test module. Full native
delivery still requires the separate product-wide owner migration and its
source-matched qualification gates.

## Bounded native recursive calls

Native selfhost compilation admits non-tail direct calls, mutual recursion and
checked recursive functions unreachable from the public entry. All ordinary
signature, target, type, effect, ownership and loan checks still run before
output publication. The original malformed-call and compile-capacity witnesses
remain rejections. Previously refused valid recursive source bytes remain in
their original fixtures and now have actual compilation and execution records.

Only an immediate return of the exact call-result names, in order, selects the
existing direct self-tail optimization. A read-only lexical lookahead compares
all identifier bytes without interning or defining any name. Every token is
then reparsed by ordinary semantic admission. Other continuations, return
permutations, discarded void continuations and mutual calls use independent
native frames. Parallel argument staging and six-result descriptor transfer
are unchanged.

Each public invocation starts a private budget of 256 simultaneously live Core
frames and 6 MiB of generated private frame bytes. Each ordinary call charges
its generated local/argument/result frame plus 16 bytes for saved frame pointer
and return address. The small public ABI wrapper is outside that private-frame
charge. A packed budget travels through a private caller register and is saved
at `rbp-16` in every frame. External allocator calls may clobber registers;
subsequent Core calls reload the saved budget. Separate public invocations do
not share a counter. Exact tail self calls retain the same frame and budget.

Before stack allocation, stack probes or any callee effect, an exhausted budget
executes `UD2`, observed as `SIGILL` in the isolated native runner. This is a
specified native boundary, not a successful result and not the VM's
`HIAProgramBudgetExceeded` exception/report. Ordinary finite results are compared
with the independent VM. The VM's 256-frame call budget and the native depth
boundary agree for the finite depth witnesses, but the native 6 MiB byte budget
is additional: a valid VM program with 2048 live SSA slots per recursive frame
can hit it before 256 calls. The qualification records that difference
explicitly. Native consumers require sufficient host stack for the declared
profile; no claim is made for an arbitrarily small foreign-thread stack.

The source/output/workspace limits remain 1 MiB, with 128 functions, 1536 total
blocks, 256 blocks per function, 2048 distinct SSA names per function, 16 call
arguments and 8192 instructions. The compiler's HIA source remains within those
original bounds. The existing million-step exact tail recurrence still uses a
constant number of frames; general recursive termination is not proved.

The standalone owned-reference private entry uses the same v95 call budget.
Its syscall adapter initializes `edx` to `0xc0000100`; its source-owned linker
checks the 62-byte public wrapper and the private recursion-guard prefix.
All branch displacements, embedded adapter bytes and complete source pins are
regenerated together; the predecessor 78-byte-wrapper contract is not reused.

The x86 memory emitter uses a signed 8-bit displacement only when the exact
u64 displacement denotes -128 through 127; other operands retain the original
32-bit encoding. MOV and LEA addresses and effects are unchanged. This keeps
the enlarged native release within its original 8 MiB static-link wire bound.

The earlier 8-argument output-overflow witness (source SHA-256
`47ed45b537831c4353e7a735e2d9c51d63785fa78e331a3a3c7d4acb1947cec9`)
now compiles to 930,331 bytes with compact displacements. Its exact source is
retained and executed against an independent Core VM observation. The output
capacity refusal gate now also uses a 12-argument, 121-function valid Core
witness (571,398 source bytes), which still exceeds the unchanged 1 MiB native
output bound. The old overflow-refusal predicates are recorded as failing
under this profile; they are not reported as an unchanged predecessor pass.
