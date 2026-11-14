# R19 Core and portable resource repair candidate

This is an authored, statically checked successor to the exact formal R19 source
tree d15d7a476fc3f711b2729236e84b7a9573da7a3d. The original 1,411-test run remains
1407 PASS / 3 FAIL / 1 ERROR. No product test, native compile, VM, or cold run has
been executed for this successor.

The Core-only scanner retains its original eight-entry explicit profile table.
The new optional table maps only native_file_roundtrip.hepta to the already
implemented roundtrip.v2 verifier. Every source still receives complete program
verification; an unregistered path receives ordinary Core verification.

The portable fixture constructs its default resource tuple from all twelve real
production roles and checks ordered equality with the original RESOURCES tuple.
The original 210-resource / 92-native / 19-entry, uniqueness and optional-disjoint
guards remain unchanged. The actual copy, wheel and readback paths consume this
constructor. All other portable definitions and original test methods remain
unchanged.

Three new Source controls are authored for real profile dispatch in assembly and
JSON, invalid effects and unregistered paths, and all twelve real role dependencies.
The exact IDs and pending original classes are in SPEC.json. Their execution is
pending a Root-coordinated focused run.

SOURCE-DELTA.json contains full before/after text for the two changed files and
the complete new test file. Source-file Git hashes in the packet are computed
identities; the packet preserves their bytes without claiming each source blob
has independently been posted. Only three source paths are materialized in this
overlay; the full successor tree is derived from the retained complete original
manifest. All original source/assets/tests and budgets remain frozen.
