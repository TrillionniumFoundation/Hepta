# Ordinary builds with the native HIA compiler

`hia build --backend selfhost` connects the ordinary CLI to the retained HIA
Core JSON frontend and HIA selfhost compiler. The selected executable lowers
Core JSON into assembly, performs the compiler profile's semantic checks, and
emits the complete Linux x86-64 ELF relocatable object. This route does not
import the Python machine emitter or Python ELF writer and does not invoke a
host compiler, assembler, or linker.

The public CLI, complete public Core verification, canonical JSON transport,
compiler selection, process ownership, object inventory inspection and local
publication remain hosted. This is one explicit ordinary build route. The
default `--backend native` and `AgentService._compile` continue to use their
existing direct backend and identity contracts. The new route does not change
Agent durable state, evaluation, adoption, worker selection, or release
activation. It does not justify removing those existing owners.

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

The CLI accepts explicit assembly or standalone Core JSON through its existing
input path. The selected backend requires the resulting program to be
primitive Core v8. Native compilation receives canonical Core JSON including
the exact chosen scalar export list. Output must be a new pathname under an
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
borrowed resources remain subject to the native compiler's limits. Non-tail
self recursion, mutual recursion, nominal composite input, older primitive
schemas, machine-plan overrides, foreign-buffer public exports, other targets,
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
`production_activated` false. `hosted_cli_and_publication` remains true even
when the optional HIA publisher is selected, because hosted custody and
publication orchestration are still present.

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

No implicit seed bootstrap is selected by this test module. Full native
delivery still requires the separate product-wide owner migration and its
source-matched qualification gates.
