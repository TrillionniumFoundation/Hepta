# HIA v6 atomic C/C++ L1 migration convergence (2026-10-26)

Parent is PR #196 exact `8d8f859323056df51c47f0a8df45298f82040c6e`, with its checked scalar+Owned
source→single HIA Core→LLVM pipeline, native compiler identity and bounded v6
memory semantics unchanged. Donor is PR #178 exact `da42019e4e5ab11210738de4136cfe6b9f8fae5b`, which
descends from the earlier PR #169 c2hia/cpp2hia line and incorporates the
PR #175 native receipt authenticity checks.

Seven exact **unchanged Git blobs** were transplanted from the donor where
their paths were absent in the recipient. Not an unreviewed whole-tree merge:
the LLVM backend, source bridge, Resource IR, parser, checker, Core and Agent
implementations remain byte-identical to PR #196.

- `hia_migrate` composes existing C/C++ L1 Clang translators and the
  source-qualified HIA scalar LLVM builder; requires real pinned Rust reference,
  generated source identity, HIA Core/source replay and strict LLVM artifact
  identities and rejects unsupported or unproved foreign profiles.
- `hia_bundle_atomic` uses Linux `renameat2(RENAME_NOREPLACE)`, file and
  directory descriptor checks, fsync and atomic directory publication. A
  post-rename error results in `recovery_required`, never destructive rollback
  of a possibly reader-visible bundle.
- Donor's unchanged test modules include adversarial receipt, symlink/rename
  race and process-interruption cases; corresponding design/qualification docs
  also preserved.

Donor #178 reported 12/12 isolated actual Linux publisher regression tests
for exact same publisher/test blobs. This is not an exact-HEAD full Hepta native
qualification of this new *combined* tree. CI queue status is ignored as a
development blocker; no green CI or unexecuted suite is called a pass.

```sh
python -m unittest tests.test_hia_bundle_atomic tests.test_hia_migrate -v
python -m unittest tests.test_c_migrate tests.test_cpp2hepta_l1 -v
python -m unittest tests.test_hia_source_bridge tests.test_hia_compiler_identity -v
python tools/release_check.py
```

P0 universal semantic authority and formally sound mappings remain open.
P1 generalized memory SSA/borrow/provenance and P2 source/native refinement
remain open. P3/P4 **bounded L1 atomic publication** is available, not arbitrary
C/C++ L2/L3 conversion/ABI proof. P5 GPU/long-tail performance, P6 Agent A/B,
P7 physical DMA/GPU/production hardware remain open.

`whole_project_blockers_closed=false`.
