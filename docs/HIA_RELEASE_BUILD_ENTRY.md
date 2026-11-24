# Native source release command

The installed `hia-release-build` command is a HIA front end for the native
release owner. The normal interface is:

```text
hia-release-build --output PATH --compiler PATH --cold-report PATH [--source ROOT] [--timeout-seconds SECONDS]
```

The source root defaults to the current directory. The timeout defaults to
3600 seconds and accepts an integer from 1 through 604800. Output must not
already exist. The parent directory must already exist. The CLI creates a
private output directory and a private randomly named sibling workspace with
separate stage and work directories.

The command prepares descriptor capabilities, then forks and supervises the
native owner. The owner request names the front end as its exact parent. The
child installs a parent-death signal and rechecks that parent before executing
the sealed owner image. The front end waits for and reaps its child, forwards
normal exit status, and maps signal termination to 128 plus the signal number.
Successful stdout is the final owner's publication receipt. An entry component
fixture that substitutes a mechanical descriptor inspector for the owner is
not a completed release build.

On failure, the front end checks whether the output name still identifies the
empty directory it created. It removes that directory so a refused build can
be retried. It preserves a replacement directory or an output containing files;
an unexpected nonempty output returns an I/O failure. It never recursively
deletes output contents. The private workspace remains available for custody
and diagnostic inspection until release cleanup.

## Immutable dependencies

The front end contains four raw SHA-256 pins in its read-only ELF image, in
this order:

1. `hia-release-owner`
2. `hia-subprocess`
3. `hia-source-build`
4. `hia-source-capture`

It locates these exact names beside the executable. It opens the directory
and each file with descriptor-relative Linux operations that refuse symbolic
links and magic links, captures complete bytes into separate sealed memfds,
and independently hashes them before using the four embedded pins. File type,
size, permissions and before/after identity checks also apply.

Normal pathname execution uses the directory obtained from
`/proc/self/exe`. For execution from a sealed memfd, the absolute original
argv[0] supplies only the dependency directory. The four immutable content
pins remain mandatory in that case; argv[0] never supplies executable
authority or permits a different helper image. A sealed invocation without
an absolute original argv[0] is refused.

Compiler and cold report inputs are separately captured, hashed and sealed.
The compiler is admitted by its independent pin and the subsequent full cold
replay gate. The input paths cannot replace an already captured descriptor.
Each captured input is a nonempty regular file of at most 64 MiB.
Executable capabilities are mode 0500 and data capabilities mode 0400, all
with the four Linux write/grow/shrink/seal seals.

The CLI marks all inherited descriptors above stderr close-on-exec, then
explicitly passes the ten owner capabilities. The request itself is a
separate sealed memfd on fd 0. Parent identity is checked around the parent
death signal setup. The absolute monotonic deadline given to the owner
includes time spent preparing its inputs.

## Source inventory and admission

The CLI parses the captured cold report in HIA and converts its
`source_manifest` into the sorted binary `HIASPI01` source inventory.
Duplicate JSON keys retain last-value semantics. Paths must be safe ASCII
relative paths with nonempty components, and pins must be lowercase
64-character SHA-256 strings. Empty, absolute, dot and dot-dot components
are refused.

This extraction is not cold report admission. The native owner still
performs both full source AUDIT passes, compiles and runs the complete cold
admission policy, checks the independent compiler identity and full normative
support contract, executes every stage gate, and invokes the transactional
finalizer. A truncated or fabricated source manifest cannot bypass those
later gates.

The owner request is the existing `HIAOWN01` 128-byte header, five raw
32-byte pins for runner/seed/capture/compiler/cold, output basename, and the
complete `HIASPI01` inventory. The header binds source, stage, work, runner,
seed, capture, compiler, cold report, output parent and output directory
descriptors. The finalizer verifies that the output parent/name still names
the admitted output inode before publication.

## Binding without a circular package pin

The source member kit first creates an unbound front end from two compiled
HIA objects, policy and streaming SHA-256:

```text
HIAENPK1 | policy_bytes:u64 | sha_bytes:u64 | policy | sha
```

The unbound image has a zeroed 128-byte pin area. It cannot start a build.
The owner builds the ordinary helper members first, independently hashes the
four sealed helper products, and invokes the HIA binding leaf with:

```text
HIAENBD1 | owner_sha256:32 | runner_sha256:32 | seed_sha256:32 | capture_sha256:32 | unbound_ELF
```

The binder verifies the exact mechanical ELF prefix, the two call
displacements, segment extents, the `HIAENMT1` object lengths, and that all
configuration bytes are initially zero. It rejects any zero input pin and
changes only the 128 pin bytes. Only the resulting bound image is published
as `hia-release-build`. The binder is a build-time native leaf; it is not
an installed command and does not require a self-referential package digest.

## Source and verification

The business policy is `release_build_entry.hepta`.
`hia_release_build_entry_syscalls.S` provides bounded argv framing, syscall
argument relocation and fixed calls to that policy and the HIA SHA stream.
It does not parse options, choose paths, construct the owner request or decide
whether a captured input is admissible.

`generate_hia_release_build_entry.py --check` verifies all three authored
HIA sources against the current mechanical adapter. It is an authoring tool,
not an installed runtime dependency. The fixed-prefix checks are split into
bounded HIA functions; no compiler limit was raised.

The external portable qualifier accepts unbound image, binder, runner, seed,
capture and compiler paths plus a new output directory. It runs the actual
native images with an empty PATH. Its mechanical test owner reports the exact
received request and the real descriptor types, permissions, seals and open
descriptor bitmap. The component matrix covers exact binding, malformed
binding, direct and sealed execution, default source root, sorted inventory,
descriptor closure, all four helper pin failures, occupied output, symlinks,
invalid JSON and unsafe paths, and command-line refusals. Terminal fixtures
also check owner rejection, a replaced output directory, unexpected output
contents, signal termination, and parent death with independent child reaping.

These fixtures validate native entry custody. Full source replay, normal
owner construction, final publication, clean installation and public tool
acceptance remain separate required release qualifications.
