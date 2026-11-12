# Explicit HIA ELF ET_REL owner

`HEPTA_HIA_MACHINE_ELF_MANIFEST` selects the HIA writer. With no selection,
the complete original `write_elf_object` remains the independent implementation
and test oracle. A selected writer never falls back after refusal. This owner
does not select a production default, migrate a live worker, or authorize
removing the original writer.

## Ownership

HIA owns the admitted ELF profile, validation and error order, retained symbol
and relocation state, stable sorting, section and table layout, bounds, and
every byte of the ET_REL result. It issues each physical operation with an
instance nonce, sequence, exact operands, and owning-stack disposition. A
second native entry consumes that claim before CPython executes the operation.
The bridge verifies the actual private issue snapshot rather than reconstructing
authority from public mutable booleans. Lost claims, malformed acknowledgements,
reentry and unknown returns fence the invocation; they do not permit retry.

The fixed bridge performs object iteration, dictionary access/copy, set
construction/comparison, truth conversion, arithmetic/comparison, indexing,
bytes transport and struct integer conversion. HIA decides when each operation
occurs. It does not call the old writer, Python `sorted`, or `list.sort`.
CPython object semantics, its allocator, the interpreter and the executable
mapping remain foreign dependencies. This is not a claim that the entire
backend, linker, runtime, or arbitrary object protocol is native.

The stable Powersort implementation follows the original CPython comparison
schedule, including separate 3.12 and 3.13/3.14 run detection. The physical
minor-version tag is admitted by HIA. Local development on 3.12 does not qualify
the other minor versions. The original public bounds remain 64 MiB, 65,536
symbols including ELF entries, 192-character admitted symbol names, and the
original alignment choices; no smaller development limits are substituted.

## Lifetime and exception delivery

Every retained foreign result has a separate owning slot. The temporary set
comparison consumes its slot at the original expression boundary. Comparison
and truth conversion form one fixed physical primitive, so a temporary truth
result is released before a failed conversion reaches the caller. A callback
exception is captured without changing its identity, admitted as an exact
terminal HIA outcome, then delivered outside the callback handler by the shared
HIA-generated CPython exception mechanism. Unknown error-outcome delivery keeps
the original error and state; a transport/packing failure cannot fabricate a
confirmed callback-error receipt.

The fixed mapping adapter closes a first allocated mapping if the second
allocation fails, preserving the original allocation error. It retains the
actual mapping objects across cleanup interruption. A later explicit close
checks their own `closed` state and retires only still-open objects; it does not
reuse a raw address or file descriptor as ownership. These cleanup controls do
not authorize replay of a business operation.

The exception mechanism uses a dedicated 128-byte workspace. Normal ELF state
has at least 4,096 bytes. This separates the mechanism's 64-byte input from
legitimate ELF machine-code inputs of the same size. Neither mechanism source
file is duplicated or modified by this owner.

## Source and executable custody

Every selection freshly reads the manifest, package-owned HIA source and image,
validates exact fields and hashes, then reads them back. A warm mapping only
reuses immutable code after those fresh observations. A pinned worker bundle
must contain the exact same source and image. Missing installed resources never
fall back to a checkout. An already returned owner retains its mapping; changing
an external file cannot replace it. The backend binds the selected ELF identity
and pins that selection for one complete emission, while preserving checker
identity and the other native owners' independent identity contributions.

## Building and evidence

Production `tools/build_hia_machine_elf.py --cold-report ...` accepts only a
complete current-source cold report and a compiler admitted by that report.
All component and shared mechanism sources must be present in its closure.
The strict compile receipt is checked both in memory and from its actual file;
the image, consumed inputs and every exclusive published output are read back.
The separate `--development` mode requires an explicit compiler and records
development authority only. It cannot satisfy a production cold input.

Tests use either `HEPTA_HIA_MACHINE_ELF_COLD_REPORT` or an explicitly retained
`HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST`, never both. Evidence goes under
`HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE`, with a distinct class directory.
The controls retain the original 55 cases, full output bytes, original backend
callers, actual public bounds, installed wheel execution without authoring
modules, fresh source/image refusal, native protocol/VM complete buffers, and
observable foreign ordering/lifetime probes. A passed subset is reported as
that subset, not as whole-source qualification.

## Reconstructed history

The fixed peer input is `acffa9262f31d073f8f0a6f0201eae201039f619`.
Its eight saved source texts and prior probe transcripts were recovered from
immutable Git blobs. The earlier lost peer executable and original local ZIP
were not recovered. This candidate is a new reconstruction on exact 7e9 source;
its current images are independently compiled from the retained 81b6 compiler
as development inputs. Earlier build errors, the Powersort comparison mismatch,
the 64-byte dispatch collision and the direct-comparison lifetime failure remain
separate original observations. Later successes do not overwrite those results.
