# Bounded affine targets in the existing x86 search

The separate `bounded_affine_program(a, b)` and
`search_bounded_affine_candidates(a, b)` APIs support the specification
`(a*x+b) modulo 2^64` for every `u64` input. The multiplier must be one of
`-1, 0, 1, 2, 3, 4`, and the offset must be an integer in `[-16, 16]`.
Booleans and non-integer values are rejected. Negative constants are encoded
as explicit wrapping `u64` values in HIA.

```python
from hepta.hia_x86_search import (
    bounded_affine_program, search_bounded_affine_candidates, build_candidate,
)

baseline = bounded_affine_program(3, -12)
search = search_bounded_affine_candidates(3, -12)
if search["finite_minimum_encoded_bytes_proved"]:
    build_candidate(
        baseline, search["selected_candidate"], "/tmp/new-affine-candidate.so",
        clang="clang-20",
    )
```

The existing `affine_program(offset=12)`, `search_affine_candidates`, search
receipt schema and fields, 146-recipe grammar, candidate IDs and encodings,
and old x+12 qualification protocol remain unchanged. The new search uses
the same exhaustive implementation but identifies its target with a separate
`hepta.hia.x86-bounded-affine-search.v1` receipt and target profile.

## What the finite certificate means

The search asks the existing translation validator to compare each of the
146 candidate HIA models against the affine specification for all `u64`
inputs. It retains every `proved`, `disproved` or `unknown` outcome and every
available counterexample. All 146 outcomes must be decided, at least one
candidate must be equivalent, and the implementation must remain unchanged
before the search can report a finite minimum. Selection uses encoded
function body bytes, including `ret`, then stable candidate ID for ties.

Some targets have no equivalent candidate in the unchanged grammar. For
example, `2*x+1` cannot be represented by any of the declared recipes. A
fully decided empty search has no minimum certificate. A search containing
an unknown also has no minimum certificate, even if another recipe was
proved equivalent. An unknown search may retain a best known candidate as
evidence; this does not authorize the native qualification phase.

The certificate is a minimum within these 146 declared recipes. The
instruction model and closed encoder, Z3, assembler/linker, ELF checks,
loader and host remain trusted. There is no ISA refinement proof, runtime
minimum, or unrestricted program optimum. The existing build path rebuilds
the recipe, independently re-proves equivalence to the supplied baseline,
locally assembles it, and checks the actual published ELF entry bytes before
returning an artifact receipt. A serialized search or proof receipt alone
cannot authorize construction or execution.

## Independent ten-target qualification

`tools/qualify_hia_x86_bounded_affine.py` defines a new frozen protocol for
the ten targets with `a` in `{-1, 0, 2, 3, 4}` and `b` in `{-12, 12}`. It
requires a clean committed source checkout, real Z3 and Clang 20+, and a new
artifact directory outside the source checkout:

```sh
python tools/qualify_hia_x86_bounded_affine.py \
  --clang /usr/bin/clang-20 --artifacts /tmp/new-affine-qualification
```

The runner records source commit, source hashes, compiler identity and the
complete protocol before searching. It persists all ten complete searches
and their selections before any native build or measurement. Unknown,
incomplete or empty searches refuse the native phase. It then builds every
proved candidate through the existing fresh-proof and byte gate, and builds
the same specification through the existing LLVM O3 backend.

The common compiled C-loop driver measures seven trials of 200,000 calls,
with 20,000 warmup calls per trial. Candidate order rotates by trial and
reverses on odd trials. All native outputs are checked against the affine
formula; eight boundary inputs are also checked separately. Every raw
sample and failure is retained. Failed samples cannot be removed or retried
to obtain a favorable case result. Timing never changes the preselected
candidate.

LLVM is not restricted to the grammar. The report includes its actual
exported function bytes, whether that body belongs to the grammar, and
whether it is shorter than the proved grammar minimum. A shorter LLVM body
is retained as such. The fixed byte-cost metric is not changed after that
comparison. The report also retains median batch timing differences, build
and proof costs, and the existing observed-deviation uncertainty measure.
These shared-host samples are observations, not a runtime improvement or
confidence guarantee. The new study does not replace any earlier protocol
or historical result.
