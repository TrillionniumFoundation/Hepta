# Native HIA release owner

`hia-release-owner` executes the complete source release recipe in HIA. Its
three retained flat images are `release_owner`, `release_dag`, and
`sha256_stream`. The Linux capsule performs the selected syscalls, translates
bounded state offsets into buffer addresses, and invokes those HIA images.

The owner admits five sealed capabilities, audits every admitted source,
rebuilds the native seed, checks the complete cold replay and source contract,
compiles ordinary members, executes the four special-stage DAGs, audits the
complete source set again, and invokes the native release finalizer. Each
subprocess is a sealed ELF executed by `hia-subprocess`; its bounded captures,
wait result, durable receipt and reaping are checked before use.

The installed command `hia-release-build` is the separate native front end.
The owner constructs that command after the special stages, then invokes a
native binder with SHA-256 pins for its freshly built owner, subprocess runner,
source seed and source capture executable. The unbound command is never
published. A later ordinary CLI invocation verifies those four installed
siblings against the pins in its immutable executable before preparing the
capability request. The capability API below is also available to a native
caller that already holds the input and directory capabilities.

## Capability request

The executable takes no arguments. Descriptor 0 is a regular memfd with all
four seals. Its complete request is at most 1 MiB. The 128-byte header is
`<8s15Q>` in little-endian order:

| Offset | Field |
| --- | --- |
| 0 | `HIAOWN01` |
| 8 | Expected parent PID; zero binds the observed parent and rechecks after `prctl` |
| 16 | Absolute monotonic deadline, nanoseconds |
| 24, 32, 40 | Source, stage and work directory descriptors |
| 48, 56, 64 | Sealed subprocess runner, source seed and source capture descriptors |
| 72, 80 | Sealed compiler flat image and actual completed cold report |
| 88, 96 | Held output parent and empty output directory descriptors |
| 104, 112 | Output basename length and complete source inventory length |
| 120 | Expected ordinary member count, or zero to use the checked recipe count |

Five raw 32-byte SHA-256 pins follow in runner, seed, capture, compiler and
cold-report order. They are followed by the output basename without a NUL and
then the source inventory. All ten passed descriptors are distinct and at
least 3. The five file capabilities must be regular, sealed, nonempty, and at
most 64 MiB. Executable capabilities use mode 0500. Source, stage and work
directories have different identities; stage and work are private and owned.
The stage is initially empty. Finalization additionally checks the held
output directory against its name under the held output parent.

The source inventory is `HIASPI01`, a count of 1 through 4096, and entries
`<Q path_length> + raw32_sha256 + ASCII_relative_path`. Paths are strictly
sorted and unique, with safe nonempty components and no `.` or `..` component.
The native cold checker binds this map to the entire compiled source path set,
the actual cold report, and the complete source contract metadata. Both source
audits read and hash every file, including resources and empty files.

Success is the finalizer JSON with a package SHA-256, exact package size and
member count, `published: true`, and `source_attested: true`. A protocol refusal
exits 65; an I/O or native invocation failure exits 74. A partial staging tree
is not a published release.

## Special-stage program

The four pinned `HIASTD01` resources run in Safe proof, constructor, Core,
additional-stage order. Each resource begins with its node count and exact
publication count. Nodes contain operation, result handle, argument count,
payload length, arguments and payload. Results may refer only to existing
handles. Effect operations 7 through 10 use result handle zero.

| Operation | Meaning |
| --- | --- |
| 1 | Capture the source-pinned named group, kit group, or one raw resource |
| 2, 3 | Compile a captured group or construct its native HIA kit |
| 4 | Select a source, compiled image, kit image, or codec bundle view |
| 5, 6 | Build the checked stage frame or execute a sealed native program |
| 7 | Publish an independently checked result into the held private stage |
| 8, 9 | Check exact byte equality or an independent SHA-256 pin |
| 10 | Run the native structural, binding, placement or manifest checker |
| 11 | Import an already validated product from this invocation's registry |
| 12, 13 | Materialize literal data or compute a native SHA-256 digest |
| 14, 15 | Query a native catalog schema or take a bounded immutable view |
| 16, 17 | Concatenate exact views or encode a view length as one little-endian word |
| 18 | Perform the native compression and exact decompression loop |
| 19 | Construct the indexed-image offsets and image body in HIA |

Operation 18 takes mode, source view, native encoder, codec builder kit,
decoder source, decoder image and encoded capacity. Mode 0 produces one
compressed view. Mode 1 accepts an implementation of 176 bytes through 8 MiB,
uses 512 KiB blocks and a 1 MiB encoded view per block, and produces the
`HIAECB01` bundle. The decoder for each exact block length is constructed by
the checked native codec policy. Every decoded byte is compared with the
source before the body and `HIAECP01` archive are retained. Bundle selections
0 and 1 expose the body and archive; no fixed number of blocks is assumed.

## Qualification

`tools/qualify_hia_release_owner.py` is an external fixture. It requires a
genuine completed cold qualification matching the current complete source
contract. It bootstraps the required native images with that compiler, seals
the independent capabilities, runs the owner with an empty `PATH`, and checks
the published package against its final receipt. A trace can establish the
native child process chain. The fixture does not perform release stages.

Component fixtures that preload a single DAG state qualify only that
component. They do not replace full cold admission, the two complete source
audits, or final publication qualification.
