# Native multiversion generation stages

This component runs the actual normalization, scalar-profile, fresh proof, native
build, loaded-image verification, independent VM probes, and retirement owners.
It is a private fixed companion of the in-process runtime. It is not the complete
runtime coordinator or a public receipt-admission interface.

The qualified image is 5,378,832 bytes, SHA256
`dedf69625c398a29776728a4d16a2bfe772742a952b41d67f03ba6d59ed5f2f9`.
All thirty roles are real HIA flat images; the native HIA packer produces the
closed ET_REL object and the native shared linker produces this image. The
mechanical adapter contains syscall/view dispatch only. It imports exactly
`dlopen`, `dlsym`, and `dlclose`.

## Interface

`hia_mv_runtime_generation` takes six borrowed-view words:
`(input, input_bytes, output, output_bytes, workspace, workspace_bytes)`.
Output is at least 4096 bytes. Workspace is at least 512 MiB, private to the
generation, and **must be a private mapping**: capture children use fork and
must not share their transient workspace writes with the parent. The runtime
holds the workspace through admission, preparation, and every retirement retry.
It must not allocate a second owner from a stale numeric descriptor.

Input starts with a 256-byte little-endian `HIAMVGX1` header:

| Offset | Meaning |
|---|---|
| 8 | Operation: 0 capture/admit, 1 profile and optional totality, 2 translation, 3 build/load/probe, 4 begin retirement, 5 query, 6 resume registered retirement |
| 16, 24, 32 | Captured normalizer, primitive-proof, and builder file descriptors |
| 40 | Original per-export proof timeout, 1..30000 ms |
| 48, 56 | Absolute capture and build transport deadlines |
| 64, 72 | Exact private Boolean totality-profile and baseline selectors |
| 80, 88, 96, 104 | Raw candidate, baseline canonical Core, baseline ABI, absolute artifact-path lengths |
| 112..127 | Zero |
| 128..223 | Captured normalizer, proof, builder SHA256 values |
| 224..255 | Zero |

Operation 0 tails are raw candidate, actual baseline canonical Core, actual
baseline ABI, and the absolute path. Baselines have empty baseline spans.
Other operations are exactly 256 bytes with only the magic and operation set.
The enclosing factory owns the sealed companions and their actual hashes;
passing this private frame is not authority to choose an arbitrary checker.
In particular the normalizer identity is retained for the enclosing closure;
the stage interface does not independently admit caller-supplied image pins.

The result is a 4096-byte `HIAMVGD1` header. Offset 8 is status; 16 is stage;
24 is the operation; 32/40/48 retain raw/nested status and detail; 56/64/72/80
are raw/original-canonical/primitive-Core/ABI lengths; 88 is export count;
96/104 transfer owned diagnostic FDs exactly once; 112/120 retain totality and
translation record extents. Offsets 128..255 contain the four input identities.
Offsets 512..2559 contain the actual 2048-byte preparation result, including
native image, probe, and retirement evidence. A normal structured completion
returns its status as u32. Private framing failure returns 0xfffffffd.

Status 0 means that the requested stage completed. Status 8 means retirement
is pending: the enclosing runtime **must register this same holder under its
selection lock before operation 6**. Status 1 is intake refusal, 2 ABI mismatch,
3 unproved/failing proof, 4 failed preparation, 5 a retirement-owner failure,
9 invalid stage order, and 10 malformed companion completion. An operation-6
status 0 does not by itself mean every filesystem resource is gone: the actual
retirement flags in the nested reply determine completeness and retained
uncertainty.

Stages are 1 admitted, 2 profile/totality and ABI complete, 3 translation
complete, 4 prepared, 5 retirement transition, 6 awaiting registration, and
7 failed or retired. Baselines build after stage 2; candidates build after
stage 3. Repeated retirement reuses the original attempt ledger. Artifact-pin
FD numbers remain audit fields after close; a numeric FD is not a new close
right.

## Order and custody

Optional totality proof precedes candidate ABI comparison, as in the original
`_admit`. ABI comparison ignores each record's original function-array index
while comparing the sorted exported name, argument types, result type, and
reserved bytes. Each actual preparation invokes the captured builder, validates
the produced bytes, loads the sealed image, resolves the actual symbols,
verifies their mappings, and executes the complete original probe vectors
against the independent VM. No caller-supplied success field replaces an
effect.

Generation workspace retention is private: totality and translation records
are at 336 and 352 MiB, raw/original/primitive inputs at 416/432/448 MiB, ABI at
456 MiB, and continuation state at 500 MiB. These offsets are composition
details, not a public persistence format.

## Qualification and limits

The exact image passed 27 integration cases, including all original 18
program groups, 283 signatures, and 16,547 actual VM/native comparisons.
Twenty-six additional gates cover private framing atomicity, totality-before-ABI
precedence, captured-builder hash refusal before any release, registration
before retirement, foreign path replacement, same-holder retry, and reused-FD
preservation. The thirty-role native packer passed 135 differential/bounds
gates, including each role's full 4 MiB domain and the original 16 MiB text
limit. Input and output guards are checked against the actual HIA image.

Three earlier QA failures remain recorded: a shared instead of private mapping,
an incorrect assertion that a retired audit FD number must be reset, and a
checked-add fixture that the original proved-total profile rejects. They were
fixture corrections; original expectations, profile domain, budgets, and
qualified product bytes were not relaxed. The final proved-total positive uses
checked division by one, which belongs to the original explicit div/rem profile.

Remaining runtime obligations include actual writer/selection/token/lease
coordination, public strong handles, directory custody, full observation and
measurement binding, and BG composition. This component's passing status does
not claim those obligations or final native-only activation.
