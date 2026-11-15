# Upstream record/view code through independent HIA

> Historical finite Core/native observations; removed harnesses are not
> delivered product entry points or current-source qualification.

This application composes all nine function bodies from the pinned
`tests/fixtures/c_migration/ring_buffer` component with both generic comparison
bodies from pinned musl 1.2.5. The original C and header files are copied without
modification. Their existing provenance and license files accompany each
captured project.

The fourth translation unit is the authored bitwise CRC helper already used by
filecheck. The new authored Hepta client constructs three real owned buffers,
passes checked loans into the migrated functions, exercises a ring roundtrip,
compares its output, updates the CRC and drops the owners. Its C and RAII C++
counterparts call the unchanged C bodies. A separate safe Rust implementation
uses the same ring, comparison and CRC algorithms. The common file-reading host
continues to be C. None of that host or the authored client is counted among the
11 imported upstream bodies.

The migrated record's scalar fields are internal Core values, and its byte
storage is a Core loan. No external caller can construct those resource
descriptors. The public ABI is the scalar `legacy_checksum_chunk` entrypoint;
this does not establish original foreign pointer or record-layout ABI support.

`lower_c_project_views` uses the existing Clang project capture and record/view
translator, checks the combined client AST, and then invokes the ordinary
standalone Core verifier. Execution and native compilation consume only that
Core. The Rust bridge emitted by the existing migration frontend is unused.
Raw AST retention saves the exact text consumed by the translator, rather than
re-running Clang later to manufacture an equivalent-looking receipt.

The cursor checks use signed/unsigned 64-bit distances and check before
narrowing or adding. This removes a concrete composition blocker: the prior
generated `i128` helper could not enter the independent HIA source profile.
Negative relative indexes, one-past cursors, `INT64_MIN` and unsigned overflow
must still obey the mathematical `0 <= offset + index < length` rule.

The original prospective protocol is preserved at its
[fixed Git revision](https://github.com/TrillionniumFoundation/Hepta/blob/3424f6d116a087373b161b9970cad07c65a9e4c4/experiments/hia_legacy_queue/PROTOCOL_20261028.json).
The retired runner captured inputs and ASTs, built C/C++/Rust LTO/PGO arms,
ran scalar ABI and resource differentials (including the allocation failures),
migrated a fifth-unit API addition, and recorded the registered file-application
samples. All arms used the same small C launch supervisor, so the recorded
child peak RSS was not the Python driver's inherited high-water mark. RSS
remains a host observation, not a proven process bound.

Preparation mode executes build, ABI, resource and maintenance checks but does
not claim measured performance. A completed functional run also does not imply
a speed advantage, low total engineering labor, general C/C++ conversion,
complete soundness or execution on the user's unobserved dot machine.

## Historical records

The first trial's
[negative performance result](https://github.com/TrillionniumFoundation/Hepta/blob/3424f6d116a087373b161b9970cad07c65a9e4c4/experiments/hia_legacy_queue/results_20261028/README.md)
remains negative. The separately registered
[IR PGO follow-up](https://github.com/TrillionniumFoundation/Hepta/blob/3424f6d116a087373b161b9970cad07c65a9e4c4/experiments/hia_legacy_queue/irpgo_results_20261029/README.md)
also reported both `performance_advantage_gate=false` and
`performance_and_rss_gate=false`; it does not replace the earlier failure.

The 19 loose protocol, report, counter and index files have been retired from
the current tree. Their exact published paths, modes, Git blobs, sizes and
SHA-256 digests are recorded in the
[retirement ledger](../../review-evidence/hia-native-cleanup-20261111/retired-development-versions.json).
Before this cleanup, their indices already referred to 81 absent files;
the two `SUMMARY.json` files and Rust-shadow `RESULT.json` were also absent.
This cleanup preserves those missing-evidence findings and does not recover
the separately archived raw records or requalify the experiments. The C,
C++ and Rust example sources in this directory remain unchanged.
