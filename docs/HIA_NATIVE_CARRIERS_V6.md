# Explicit v6 mechanical carriers

The v6 worker capsule admits two small CPython carriers for existing HIA
components. `native-image` owns a copied executable image and three real writable
buffer exports. `cell-frame` owns actual Python cells and invokes the existing
Verification frame factory. HIA continues to own the component's decisions,
ports and transitions. Neither C file implements Artifact or Verification
business policy.

This is a new explicit input format. Existing v1 through v5 capsules retain
their formats and routes. An installed extension or a previous successful load
does not select a carrier. A caller supplies the complete v6 capsule digest
through the existing `--expected-native-helpers-sha256` worker option.

## Closed composition

The capsule schema is `hepta.hia.native-helpers.v6`; its ABI is
`hia-worker-native-carriers-v1`. It wraps one complete original v1 helper bundle.
The following bridge records are required exactly when that base selects their
owners. Records are ordered by bridge name and cannot name another module or
factory. At least one of the two new carriers must be present.

| Bridge | Existing HIA selector | Build receipt |
|---|---|---|
| `native-image` | `HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST` | `_native_image_build.json` |
| `cell-frame` | `HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST` | `_cell_frame_build.json` |
| `slot-mechanical` | `HEPTA_HIA_SLOT_OPERATIONS_MANIFEST` | `_slot_mechanical_build.json` |

The optional Slot composition uses the original Slot build and loader. It does
not alter the closed v5 capsule. The v2, v3 and v4 multi-owner formats are not
implicitly flattened into v6.

Every bridge record binds its canonical installed package path, exact running
CPython profile, complete build receipt, binary and source bytes. The entire HIA
and C input set is captured before loading any extension. Each loader repeats
the source checks, uses an actual sealed Linux memfd, and verifies its executed
exports. A lost, replaced or overlapping live scope is a refusal; it cannot
turn an explicit v6 selection into a legacy route.

## Build and installed preparation

The normal setuptools build compiles the original Slot extension and both new
extensions. `hepta/native/native_carrier_build.py` records each new extension
separately: actual compiler commands and executables, source digests, CPython
profile and output binary digest. The receipt explicitly says that a mechanical
build does not establish product qualification.

For an explicit source build:

```sh
python tools/build_hia_native_carriers.py --output /absolute/new-build --in-place
```

The creator is a data operation. Supply independently captured input digests;
it does not execute an HIA image, load a C extension or authorize its own output:

```sh
python tools/capture_hia_native_carrier_bundle.py \
  --package /absolute/installed/hepta \
  --helpers-bundle /absolute/helpers-v1.json \
  --expected-helpers-sha256 BASE_SHA256 \
  --cell-frame-receipt-sha256 CELL_RECEIPT_SHA256 \
  --output /absolute/new-helpers-v6.json
```

Add `--native-image-receipt-sha256` or
`--slot-mechanical-receipt-sha256` if the base selects those owners. Missing or
extra bridge receipts are refused. The resulting complete capsule digest is
an explicit administrator input to the worker, not a qualification result.

## Ownership and compatibility

The byte-image carrier keeps the receiver and every acquired buffer export
alive across the actual native call. Exports are released in reverse order.
Buffer and Image instances expose all Python references, including their heap
type, to CPython's cyclic collector. The cell carrier similarly traverses its
real cells, frame factory, image and captured namespaces. It never clears a
user cell's contents during its own cleanup.

Public Verification functions, signatures, captured namespaces and real lazy
generators retain their existing implementation. The private acyclic callback
uses a callable carrier in v6; arbitrary private FunctionType, code or frame
reflection is not promised for that new callback. Its actual observable
semantics still require the complete retained finite, cell, lazy and Native
domains.

Unused optional FFI dependencies are loaded only on their actual paths. UUID
provider access still returns the actual standard module, honors explicit
provider replacements and preserves deletion behavior after binding. The
complete original ID-producing method bodies remain retained.

## Qualification boundary

The compile guards admit ordinary GIL CPython 3.11 through 3.14 on Linux
x86-64. This guard does not establish equivalent business behavior on every
patch version. Each qualified runtime needs its own complete original and
candidate observations.

The retained mechanical controls include real buffer lifetime and callback
tests, the original 134 packet records, six real-cell controls and actual
source/binary/scope refusal controls. Artifact's complete 146-case observer
keeps both original replays, all actual buffers, entry counts and the original
collection observations. Verification keeps its complete 185 base cases,
1,344 declared derived cases, real-cell controls and twelve lazy controls.
No collection count is normalized and no extra collection or retained strong
root is added to make a comparison pass.

Source builds and development comparisons are separate from matching-source
cold, the original Native suites, actual installed workers and independent
terminal evidence readback. Old implementations and their authorities remain
until those separate obligations are complete.
