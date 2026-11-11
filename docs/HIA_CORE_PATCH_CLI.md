# Standalone native Core editing

`hia-patch-core` consumes one JSON array `[BASE, PATCH]` on stdin. It writes a
canonical candidate Core document only after both the original and the candidate
pass the complete native primitive Core verifier. The executable embeds two HIA
images, performs four calls, and requires no Python, payload parser, interpreter,
libc, dynamic loader, image sidecar or child executable at runtime.

## Execution contract

1. The HIA patch kernel strictly decodes the envelope and extracts canonical BASE.
2. The complete HIA Core admission image checks BASE, including every function's
   declarations, operations, effects, ownership, returned loans and CFG.
3. The patch image verifies the exact base SHA-256 and the patch contract, applies
   the selected edits and serializes the candidate.
4. The complete Core image checks the candidate before stdout becomes available.

An edit cannot repair an invalid original past the first admission. A valid
snapshot and valid edit structure cannot authorize an invalid candidate. No
output is produced on input, identity, patch or Core refusal. The edit contracts
remain the existing v1/v2 `replace_operation`, `replace_terminator`,
`replace_function` and `add_function` contracts with 1–64 edits and explicit v2
interface migration. There is no execution or publication operation in a patch.

The two image calls have private fresh scratch. The adapter retains the unchanged
input envelope for extraction and application. Candidate JSON occupies a region
disjoint from the complete Core state and its decode arena, so verification
cannot overwrite the candidate it is admitting. Code is RX; scratch is anonymous
RW. The platform-specific literal ISA contains syscall/ABI adaptation only;
HIA emits the ELF headers, resolves all four relative calls and copies both
source-bound native images.

## Build and use

```sh
python -B -m tools.build_hia_core_patch_cli \
  --compiler /qualified/B3.image.bin --cold-report /completed-cold.json \
  --output /new/private/core-patch
/new/private/core-patch/hia-patch-core < patch-envelope.json > candidate.core.json
```

The strict hosted builder checks the complete current source contract and cold
receipt, all cold gates, the three matching compiler generation digests and
unchanged source/image bytes before publishing its output. The output directory
also contains the patch `manifest.json` and fixed `admission-manifest.json` for
the explicit `HEPTA_HIA_CORE_PATCH_MANIFEST` hosted adapter. A missing or refused
selected image never falls back to the old edit implementation. The executable
contains its images and does not read either manifest at runtime.
Each selected image is independently bound to its exact HIA source and image
digest; putting two manifests in the same directory is not qualification.

## Bounds and failures

BASE and PATCH each retain their existing 8 MiB component limit. The raw array
framing ceiling is 16,777,219 bytes, with 524,289 combined JSON nodes and depth
129; individual Core admission retains its stricter original profile. The
candidate is at most 8 MiB. The patch output region is 64 MiB; scratch reserves
96 MiB and is reused sequentially as patch workspace (64 MiB) or complete Core
state (64 MiB) plus JSON arena (32 MiB). These private allocations do not reduce
accepted function/block/arity limits to the compiler's smaller input profile.

| Exit | Meaning |
| --- | --- |
| 0 | Both Core documents and the patch admitted; candidate output completed |
| 2 | Invalid JSON, stale snapshot, patch policy or Core semantic refusal |
| 3 | Wire, node, depth or candidate output capacity |
| 4 | Descriptor I/O, mapping failure or internal invocation-profile refusal |
| 64 | Unexpected command-line arguments |

Stderr is empty. EINTR is retried for stdin and stdout. A successful partial write
followed by a returned I/O error leaves a prefix and exits 4. The executable
inherits the caller's signal disposition: writing to a closed pipe with default
SIGPIPE disposition terminates by that signal before an exit code can be
returned. Stdout is a stream, not a durable file publication transaction. The
caller owns output-file custody and must handle either kind of failed process
accordingly. No implicit retry, adoption, journal reset or filesystem deletion
occurs.

## Qualification and remaining scope

Tests independently interpret the complete HIA packer before native construction,
compare all actual packed executable bytes and call relocations, execute all edit
actions, and reject invalid originals that an edit could otherwise repair and
invalid candidates. Copied empty-PATH execution, exact/plus-one framing,
real descriptor/mapping failures, syscall traces and injected EINTR are separate
controls. The full 1,024-function Core profile and an actual nonblocking partial
stdout failure are covered without reducing the user program to the compiler's
smaller own-source profile. Matching-source cold evidence remains necessary
after source changes.

This component replaces payload edit computation and admission on its explicit
path. Source authoring/build, hosted object custody, structured diagnostics,
composite normalization, durable Agent object/reference stores and SQLite intent
journals, crash recovery, adoption, installation and default runtime integration
are separate obligations. It is not whole-product native-only acceptance.
