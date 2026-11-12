# Type-context oracle import repair, revision 2

FOLLOW46 head 293e80c81056345b846c42005c45b980fbc5d6fc, run 43204248178,
job 131135272555, remains an actual FAIL. All three original-budget B3
compilations passed. All seven runtime groups then failed at the same original
test import, before a semantic entry, public-oracle predeclaration, or completed
case. Their original complete log, eight printed JSON panels, all three compiler
receipts and per-group failure reports are preserved without modification.

The exact reference is hepta.hia_program_composite, file
hepta/hia_program_composite.py: 68,738 bytes,
Git b06d009e403e77288a19eb929e6296bf68532db3,
SHA256 cc5ab4c8dc68214e8868aab30405820c3662572de63952dec5f1fd1aaf180951.
The old test expected this digest but named the nonexistent hepta.hia_composite.

The new test changes exactly its import and corresponding pinned file path.
Applying the inverse two spelling substitutions reproduces all 9,233 old bytes.
The source index corrects that path, names the new test, and records the unchanged
three observed source/image identities. The CI entry verifies the complete
reference composite and program files by existence, mode, bytes, SHA256 and Git
blob identity before any restore or B3 work; it saves exact frozen copies and a
receipt and checks them again afterward. This is the same oracle source identity
already required by the original test, moved earlier in the pipeline.

The native extension, native reader, build authoring, public corpus, mechanical
runner, private controls, and authoring dependency are unchanged. The new run
must recreate the same three HIA sources and images byte for byte before testing.
All seven original groups and 118 planned cases remain: 54 public-oracle scenarios
and 64 private reader controls. All 33 context tuples and all six type operations
are still required. The original 10 CPU / 20 wall / 256 MiB compiler limits,
90 CPU / 180 wall / 1 GiB group limits, aggregate process-tree CPU check and
native authoring limits are unchanged.

This repair itself has 0 AST / 0 new generation / 0 new B3 / 0 native execution.
The prior successful compilation does not prove runtime behavior. The binary
artifact 13937136975 has producer custody in the original log; this delivery
independently preserves and verifies the complete text log and panels, and does
not claim an independent download of that ZIP.

The public P16 context route, groups 6/9, namespace authority, whole Worker and
installed activation remain open. Only root publishes refs.
