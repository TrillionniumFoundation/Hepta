# Native HIA source-bundle builder

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
selects code by a replaceable staging pathname. The success receipt is emitted
after the published inode and bytes are checked and records their device, inode,
mode, size and hash. Publication/receipt failure withdraws only entries still
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
