# Independent reviews and development evidence

These reports preserve their own source hashes and local review commit identities.
They do not qualify the subsequently integrated source snapshot. The complete final
release index is `../next_blockers_final/manifest.json`. No actual model coding trials
were performed by these scripts.

- `channel-deadlines`: independent native cancellation/deadline races, spurious
  sender wakes and failure wakeup, with the exact generated Rust source.
- `owned-generics`: independent source and polymorphic IR review, valid native
  programs and adversarial graph mutations. The replay uses the repository and
  compiler paths identified in its original report; adjust paths for a new checkout.
- `c-ring-pre-audit`: finite native differential qualification before independent
  review found signed relative cursor indexing and mixed-TU data-model defects.
  Its `ok=true` is the historical outcome of those finite tests, not a finding
  that the translator was correct. This evidence is superseded by the fixes and
  cannot satisfy final qualification. Generated derivatives retain the upstream license.
- `c-ring-fixed-feature`: targeted qualification after fixing those findings,
  prior to full integration. Its observed performance replaces the earlier
  feature measurements but remains distinct from the final source snapshot.
- `c-performance-exploration`: exploratory C compiler flag comparisons, all
  alternatives retained. These are not the final fixed four-implementation study.

The C ABI still has foreign allocation, pointer provenance and lifetime
obligations. Finite execution checks do not prove source equivalence.

`release-gates` retains the pre/post structural audit, the exact reviewed validator
source, and a later correction distinguishing 194 possible received messages from
the failure workers' return sum of 193. Those are evidence-validator tests, not
new native measurements. `model-access-preconditions.json` records the actual
credential-presence/DNS prerequisites without issuing an API request.

`reviewed-source-patches` reconstructs local review source snapshots from the
public base; each patch was actually applied to a clean temporary Git index and
all source blob hashes and modes matched the reviewed tree. This preserves
reproduction even when a local review commit ID is not published on the remote.
