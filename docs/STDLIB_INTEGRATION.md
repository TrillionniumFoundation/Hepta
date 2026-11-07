# Experimental composed source-library gate

This draft composes four independently reviewed source-library increments on
main `125d11c5454835a7df1dc51915fc49901fbede5b`:

| Component | Frozen draft head | API contract |
| --- | --- | --- |
| Byte codecs, #692 | `98bde4d1a007f558c7ab5ef2f88a053fa280da11` | [Byte-order codecs](STANDARD_LIBRARY.md) |
| Ordering, #693 | `5fafb04d8e36b383778109d7bf2d0883016db3cb` | [Range sort and bounds](STDLIB_ORDERING.md) |
| Runtime UTF-8, #696 | `f994ff9f50e6060cb568de28b695f20065e41808` | [Unicode scalar validation](STANDARD_LIBRARY_UTF8.md) |
| Canonical Base64, #697 | `3c4bff56917ef30083ff33488ead78164bdc7d51` | [Strict padded codec](BASE64_LIBRARY.md) |

All 39 nonconflicting component files are byte-identical to those heads,
including library implementations, manifests, examples, locks, tests, oracles,
workflows and component docs. Their separate edits of `docs/BLOCKERS.md` are
replaced by one integration note on the unchanged main ledger. No compiler
production file changes. The snapshot inventory in
[`stdlib_integration_components.json`](../tools/stdlib_integration_components.json)
pins the inherited Git blobs and compiler/toolchain inputs. Intentional future
changes require a new reviewed inventory and fresh qualification, not relabeling
old evidence. The original component docs describe their original heads; those
historical passes are not evidence that this composition passes.

## A real consumer

[`indexed_text`](../examples/packages/indexed_text/src/packet.hepta) is an example
application protocol, not a new stable standard-library API. Its wire format is
canonical standard padded Base64 of a two-byte big-endian byte count followed by
that many UTF-8 bytes. The consumer:

1. Strictly decodes the selected wire range into caller-provided scratch storage.
2. Reads and verifies the byte-count header through `hepta_bytes`.
3. Validates the complete text and decodes Unicode scalars through `hepta_utf8`.
4. Sorts the scalar values with `hepta_ordering`, then returns lower/upper query
   bounds in the same caller-provided array.

The Base64 output therefore feeds byte decoding and UTF-8 validation; the UTF-8
scalar output feeds sorting and search. Expectations come from Python's standard
Base64, integer conversion, strict Unicode decoder, sorted and bisect operations,
not a Hepta encoder/decoder round trip. The example contains ASCII, NUL,
non-ASCII, astral and duplicate scalars. Package loading includes six real modules
under one content lock. Run it with the public CLI:

```sh
python -m hepta run examples/packages/indexed_text --locked --backend c --json
```

Scratch and scalar prefix index zero remain caller-owned. Writes start at index
one. Successful calls preserve every byte/element after their written ranges.
No heap allocation, blocking, suspension, spawning, unsafe operation or recursion
is introduced; the normal conservative panic/write effects remain declared.

### Result and failure contract

`stage = 0` returns the scalar count and absolute lower/upper indices, which may
equal the end of the sorted range. `stage = 1` reports invalid wire bounds,
noncanonical/invalid Base64 or insufficient scratch capacity; `2` is a short
header; `3` is a byte-count mismatch; `4` is invalid UTF-8; `5` is insufficient
scalar storage. All result count/bound fields are zero on failure. The ordering
of these checks defines precedence when more than one error is present.

Every ordinary failure preserves the entire scalar array. Stage 1 also preserves
scratch; stages 2–5 can leave successfully decoded bytes in scratch. The whole
multi-stage operation is **not** transactional. This is a single-threaded caller
contract, not crash atomicity or a concurrency guarantee. The protocol's two-byte
length limits payloads to 65,535 bytes; the tests do not allocate huge slices.
The public shared C profile uses nonempty fixed backing arrays, with empty
logical ranges represented inside them. Supplemental private native views also
exercise zero-size slices; these are not public ABI qualification.

## Reproducible integration gate

```sh
HEPTA_INTEGRATION_BACKEND=c python tools/stdlib_integration_gate.py
HEPTA_INTEGRATION_BACKEND=rust python tools/stdlib_integration_gate.py
python tests/stdlib_bytes_boundary_oracle.py
python tests/stdlib_ordering_oracle.py
python tools/stdlib_utf8_oracle.py
python tools/stdlib_base64_oracle.py
python tools/stdlib_integration_oracle.py
```

The gate requires exactly 60 unique public test methods: the original 48 plus
12 composition methods. Missing native tools fail; no skips, expected failures,
backend substitution or disabled assertions count as success. Public native
corpora run at O0 and O3, with nonrecovering UBSan on C. Full input/scratch/scalar
backing state is checked, including failure preservation and surrounding regions.
Other controls cover each component's stale content lock after relocation,
type/mutability/effect refusals, all inherited component bytes, both frontend
lowerings and a composed Rust no_std object. Frontend/no_std emission alone is
not native Rust execution; actual object compilation is required in Rust lanes.

The independent supplemental composition oracle uses compiler-private generated-C
ctypes bindings. It does not establish a public C ABI. Its distinct deterministic
corpus exercises 12,933 cases at each optimization level, including private empty
views, malformed packets, Unicode, duplicate searches, capacities, arbitrary
ranges and extreme indices. It preserves source/tool identities in its output.

The read-only [workflow](../.github/workflows/stdlib-integration.yml) checks out the
exact PR head, enforces the complete public gate plus 149 unchanged parser/checker
controls, and runs all five independent supplemental oracles in C lanes. Its
Linux x86-64/ARM64 matrix selects real C or pinned Rust 1.90.0 on Python 3.11/3.13.
It checks source cleanliness before and after and retains logs. Hosted passes
must be read for the actual published head; queueing or publication is not a pass.

## Limits

This is a finite composition gate, not a full-project, formal, performance,
release or production standard-library qualification. It does not provide a
registry, distribution/signing, network protocol I/O, Unicode normalization or
text ownership, generic/resource-owning algorithms, or cryptographic protection.
It does not close P12 or alter any other ledger condition. Native Rust/ARM and
other platform claims require their own observed exact-head execution. This
research draft does not merge, release, deploy or activate anything.
