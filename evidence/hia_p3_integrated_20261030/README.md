# P3 fresh integration regression at 50c4067

This package retains three fresh executions on the same clean, frozen Hepta source commit
`50c4067399989e7194028576c38c0e783b78cf06`: musl 1.2.5 capture and standalone native translation,
musl 1.2.6 subsequent-release maintenance, and the existing nlohmann/json 3.11.3 to 3.12.0 C++
bridge upgrade qualification. These are **same-matrix integration regressions**, with
`new_holdout=false`. The earlier branch qualifications are retained under their original
source identities and are not relabelled as tests of this integrated source.

## Actual observations and limits

| Route | Actual denominator | Observed result | Claim boundary |
| --- | --- | --- | --- |
| musl 1.2.5 C to HIA Core to direct LLVM | 386 fixed inputs × 3 allocation-refusal settings = 1,158 cases; 2,316 native observations and 1,158 VM observations | Every retained value/resource observation matches the finite oracle; final live native allocations and VM owners, bytes and local loans are zero | One unchanged 220-byte upstream function with explicit slice contracts and an authored finite scalar client, unsigned-char C11 Linux x86_64 LP64 |
| musl 1.2.6 maintenance | Fresh capture/build and the same 1,158 / 2,316 / 1,158 observations | Same translated Core; unchanged function and adapter bytes, updated complete upstream copyright file | Actual subsequent official release, but its function body is unchanged; this does not qualify adaptation to a changed body |
| nlohmann/json 3.11.3 C++ bridge | 98 ordinary input rows, two pointer guards, 17 actually calibrated allocation sites | 14 allocation failures caught and recovered; three foreign `noexcept` terminations | Library and adapter remain C++; five C exports and a native Hepta caller execute the generated boundary |
| nlohmann/json 3.12.0 C++ bridge | 98 ordinary input rows, two pointer guards, 17 actually calibrated allocation sites | 14 allocation failures caught and recovered; three foreign `noexcept` terminations | Same generated boundary identity and C export symbols; no source, contract or caller change for this upgrade |

The C HIA target links the generated LLVM object and its observer. It does not link the
original C implementation or use a Rust-codegen fallback. The original C implementation
is retained and compiled as a separate reference. Both official musl release archives,
complete selected upstream source and license bytes, authored support, captured AST,
HIA Core, LLVM text, object files and native executables are included.

The C++ result is a **retaining bridge integration, not a JSON library rewrite**. Its
ordinary 98 cases execute as rows in one cases process per version. On each version,
allocation sites 15, 16 and 17 actually exit with `-6` and `std::bad_alloc` diagnostics.
All six raw stderr/stdout files, process receipts, elapsed costs and native artifacts
remain in the archive. They are classified as `foreign_noexcept_termination`, with
`recovery_qualified=false`; `all_allocation_failure_paths_recovered=false` for each
version and for the combined result. The qualifier's top-level `passed` means that its
protocol observed and reported these paths, not that those paths recovered. Its rejected
signature and deliberately wrong compiled implementation controls are also retained.

No general C/C++ migration success, foreign-library memory-safety proof, all-input source
equivalence/backend proof, labor advantage or runtime performance advantage is claimed.
Initial adapter line counts are not measurements of human or model work. Complete
development effort and human effort remain `null` with status `unknown`.

## Provenance and costs

`launches/PLAN.json` was frozen before the runs. Its SHA-256 is
`5e155d460cfced64a08dbb7898e009973236ef18843a7ccc782c23429725708c`.
The launcher SHA-256 is
`25c652086dac56b824bb280850ebbfcd3c9a8756cf689c0d4b8f2cff7307b938`.
The fixed stage limits were 300, 300 and 900 seconds, respectively. Each launch captures
its exact command and environment, before/after source and selected tool identities,
all stdout/stderr bytes, retained output hashes, terminal status and outer cost. Later
stages also recheck earlier retained output identities. All three launches completed
on their first attempt without source/tool drift or a timeout.

| Measured interval | musl 1.2.5 | musl 1.2.6 maintenance | C++ upgrade |
| --- | ---: | ---: | ---: |
| Qualifier child process | 31.274950326 s | 32.172184760 s | 27.811680965 s |
| Whole outer launch, including its checks | 32.201699015 s | 32.943381907 s | 28.600450890 s |

The three outer launches total **93.745531812 seconds**. Qualifier, build, native,
VM and termination costs are nested within these intervals and must not be added to
the total again. The old acquisition receipt's six requests and 0.973545013 seconds
are retained as historical acquisition, with **zero new download requests** and no
second charge to this fresh execution cost. The host was not claimed to be exclusive.
Packaging/verification attempts have separate visible execution records and do not
alter the qualification denominator.

The original branch baseline source is
`46534e04ec874bd5681b9f38914e210c2ef813be`; the original maintenance source is
`f82d016e08431bf9c16d12a613bfab6151103d8a`; their historical evidence commit is
`712e926cbfa4fc7c14a9d2ee7be321b6f1a0961a`. All six historical evidence files,
including the original complete archive containing failed development attempts, are
retained byte-for-byte under `historical/`. They retain their own scope, costs and
source identities. Parent P0 full-suite and dependency-acquisition records are in a
separate package, not counted as new P3 migration observations here.

## Contents and offline verification

`MANIFEST.json` binds every archive member by byte length and SHA-256, the decoded
archive, the visible summary, and the packaging/verifier scripts. The base64-encoded
XZ archive contains the three complete fresh output trees, the launch plan/attempts
and console logs, 182 bound source/fixture files, the official upstream inputs and
the unchanged historical package. `cpp-report.json` and `maintenance-report.json`
are exact visible copies of the retained producer reports.

Run the read-only verifier with a local Python 3 standard library:

```sh
python3 verify_archive.py --directory .
```

It reads the archive in memory with explicit size bounds; it neither extracts nor
executes any archived source, object, binary or script. It checks member identities,
frozen source/launch bindings, actual C native/VM receipts and resources, actual C++
case/process/ABI receipts, calibration and unrecovered terminations, and preservation
of historical records. It is an integrity and finite-record consistency check, not
cryptographic signer authentication, an independent rerun, a physical execution
attestation or an all-input semantic proof. Source snapshots are the bound files,
not the whole repository. Complete host/toolchain binaries and dynamic-library
contents are not bundled or claimed to be hermetically attested.

The actual execution directories are preserved outside this transport package.
