# Fixed transport authoring repair after source83 failure

## Actual failure retained

The original operation is run 43261208151 / job 131332684167, source83 head
cde3642d238f7f89e8e0a7608b7a1542cc5f598a. Its worker exited naturally after
29.260002612 seconds with HOLD. Generators 1–31 completed; generator 32 attempted
to start GNU as and was refused by the unchanged source-child Popen poison.
Generator 32 took 0.131237931 seconds. The remaining generators and all 83
methods were not completed. This was not a native numeric comparison failure
or a timeout.

Root preserved the complete official artifact and all 129 non-source originals
in 31c026602c188ab03c737051ce2a4d91fd9fafee, tree
1dd503a248b2fb4f1e31dc9b6dfb253c56598ada, under
experiments/hia_native_source_merge_20261112/numeric83-actual-failure-and-cleanup-readback-r1/.
Artifact 13963368322 is 12,162,315 bytes, SHA256
4dabb0b7ddcf5c0cc8d4582c2da1ca5fa55e347a95fb010ea14cea4ef3b984d3.

## Four product-source changes

1. tools/generate_hia_artifact_publication.py.
2. tools/generate_hia_release_install.py.
3. tests/test_hia_artifact_publication_native.py.
4. tests/test_hia_release_install.py.

The two default template functions use fixed Linux x86-64 transport bytes and
three explicit rel32 call holes. This follows the existing linked_observer
authoring pattern. Each default template binds the complete .S source SHA,
transport size/SHA and exact hole map. A changed source or literal is refused.

The original assembler functions remain byte for byte as assembled_template,
apart from their function name. They are independent authoring oracles, not
part of the source-only generation path. The original policy sources,
packer_source functions, document construction and main functions are unchanged.

Three test imports now bind assembled_template as template. This preserves
the independent assembler behavior of the original native expected-output
helpers. The import statements change their enclosing method/helper AST;
the rest of those bodies, all method IDs and all limits remain unchanged.
The source83 class list does not include either native class.

## Provenance and actual static observations

The new literals were read from existing, pinned HIA packer constant-write
instructions. No assembler, HIA VM, image, or native program ran during this
extraction. DERIVATION.json retains every literal-write location and the five
subsequent extent/rel32 writes.

Publication has a 3,978-byte transport and 4,154-byte ELF prefix, with prefix
holes 425, 3751, 3797. Release-install has a 3,447-byte transport and 3,623-byte
prefix, with prefix holes 389, 3500, 3546.

The direct-local main call inventory of all 62 authoring modules reaches
external subprocess calls only in original generators 32 and 45. Generator
50 defines assembled_bridge for its independent oracle but its normal main
uses the already-stored BRIDGE literal. This static graph is not a proof about
arbitrary Python dynamic dispatch. The original Popen poison remains the
runtime enforcement in the next source qualification.

The two generator revisions have been AST parsed and reverse-projected to
their complete original bytes. The two test-import changes have likewise
been reverse-projected. This is not yet a claim that their new generation,
the independent GNU assembler oracle, or source83 has executed successfully.

## Separately frozen four source controls

The four FixedTransportSourceTests are:
- test_all_four_hia_outputs_reproduce_with_external_entries_poisoned
- test_assembler_oracle_and_hia_algorithms_are_preserved
- test_literal_transport_and_holes_match_frozen_packer
- test_source_transport_and_hole_drift_are_refused

The request uses the pinned local CPython 3.12.14 for these four controls only,
with the original process-owner implementation, one 180-second qualification
and 3-second cleanup budget. It poisons Popen, native image construction,
build_seed/compile_stage and ctypes callable/loading entry points, keeps all
four rendered HIA outputs as actual originals, and requires full input
before/after identity equality and zero test anomalies. It does not execute
the independent assembler oracle, original83, numeric native, Core39,
Core116, UNPACK18, installed, or matching-cold qualification.

The source dependency base for the four controls is Root's readonly
cc51db1c74c082572ae6183ebfa0c81cd36b0648 / tree
01bcbef40c31bd9aaf9f359ffca4ffa557fc8cd3 partial materialization: 1,653 source
files / 40,167,129 bytes. It is not a full 4,097-leaf checkout. The new two
generator modules are loaded from inputs; their output goes to fresh private
case directories, never to Root's sealed source.

## Next source83 request

After this separate four-control check, create a new namespace from the
1,653-file numeric-on-v89 base and apply these four files. Preserve the exact
62 ordered generators, four derive commands, four idempotence commands,
complete 83 IDs, original Popen/native/compiler poison and 180/3 owner.
The two derived documents begin with their v89 bytes and must be genuinely
regenerated and preserved before a new pure product commit is claimed.
No old request or execution is replayed or upgraded.

The fixed syscall transport remains a foreign OS/ABI primitive. Removing an
authoring-time external assembler dependency is not closure of the 19 hosted
families or of the complete Python/object/OS runtime.

