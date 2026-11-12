# P16 actual type-context join — dependency repair r2

## Execution status

This revision has 0 Python AST executions, 0 authoring generations, 0 B3 compilations and 0 target native entries at delivery time. It is an executable CI submission, not a successful qualification. FOLLOW48 job 131155364077 failed before its first B3 compile; its full log, process records and failure observation remain unchanged in delivery 96c1dbb914fd65e041975b8ec1d46624c5f86b4b.

The first failure was a missing Python authoring dependency. The exact lower-services source imports tools.hia_composite_lowering_driver_helper at the end of the module. The r1 private authoring directory did not contain that file. That job produced no native semantic result.

## Exact restoration

FOLLOW49 run 43215458125, job 131173449664 completed the independent read-only original R9/R10 archive reader. It verified both original archives, all 5,389 members, 4,391 files and 115,107,529 original file bytes, including modes and digests. It ran no target compiler, VM or native image.

The recovered helper is 15,664 bytes, SHA256 fb392ada8b16cfaeedbdbfb55b46786c5923a8959f3cc32057f13383b5fa75df, Git blob 78620bfaf2205c1112c63ccd6d84e1700a8c836a. Its original path is dependencies/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_helper.py. Both R9 and R10 contain the same bytes. Complete reader results and the five recovered sources are in delivery 3ef16cfee3607e5d1d61a25f229fb97f5b6c30ce. The helper is not attributed to R12.

## Code delta

The pipeline adds the helper to its fixed pins, copies it into the private tools directory, and explicitly loads it before services. It records and restores the prior sys.modules entry, as for the other private author modules.

Before loading the first original author module, a new gate parses the actual static and embedded imports in the selected original authoring closure. Every project import must resolve to an exact private copied source or the exact restored reference. Only the explicit standard-library import set is exempt from project-file binding. The gate validates the historical MODULES table and the selected main/services/ctor generation set. Retained stream role 42 is neither regenerated nor imported by this build.

The legacy driver is an exact byte dependency whose BODY the program author reads with ast.literal_eval. Its Python module and tools.legacy_authoring are not imported in this selected generation path. The gate records that distinction.

Exact original source reproduction for roles 8, 40, 41, 43 and 46 remains mandatory before any new B3 compile. Role 46 must also match the original diagnostic archive's frozen source, image and generated authoring. The existing R12 six-file restoration continues verifying all 8,355 original members and 99,770,153 file bytes before use.

The index adds the helper and updates the pipeline pin and repair metadata. The CI driver binds the new index, expects 48 project files rather than 47 and uses new private r2 directories. Native owner extensions, tests, original oracle, budgets, comparisons, count assertions and failure handling are unchanged.

## Complete immutable input set

The delivery has 53 required files totaling 838,074 bytes: 48 project sources/resources, three unchanged external restoration/accounting helpers, the source index and the CI driver. All 53 were independently fetched in full from Git and compared with their complete retained UTF-8 bytes, byte length, SHA256 and Git blob SHA. All use mode 100644. The active Python inventory has 47 files.

The old r1 sources, failure records and three unexecuted historical drafts remain at their existing paths. Replacing the active inventory does not delete them or activate the historical drafts.

## Unchanged execution plan

The tag remains worker-program-type-context-join. The new entry is worker_program_type_context_join_ci_r2.py, using common module 61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e, CPython 3.12.14 and the existing Ubuntu 24.04 x86_64 guard. The outer allowance remains 60 minutes to enclose independent original groups.

The plan remains 13 fresh B3 compiles, one actual HIA ELF packer entry, 31 retained images, 43 nonempty images in the 63-row table, 14 groups, 413 cases and 251 actual ELF processes. All 281 earlier P16 cases are reexecuted because this candidate changes the native type-context chain. The additional 100 public type-name/shape/order cases and 32 private context controls retain their complete plans.

The exact worker compiler remains 668,608 bytes, SHA256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8; substitution of the common 35ee compiler is forbidden. Each B3 invocation retains 10 CPU seconds, 20 wall seconds and 256 MiB. Each independent native group retains 90 CPU seconds, 180 wall seconds and 1 GiB, with aggregate measured process-tree CPU strictly below 90 seconds. HIA limits remain 128 functions, 1,536 blocks, 8,192 operations, 256 blocks per function, 16 block parameters and SSA numeric suffix below 2,048.

## Remaining boundaries

The independently completed FOLLOW49 64 private type-context controls and earlier component semantic groups supply no count to this join. This composition must produce its own original results.

Groups 6 and 9 diagnostic routing, untested public dynamic context, ordinary eleven-tool Worker composition, actual namespace Store/31-SQL authority, installed routing and whole-product activation remain open. A private context capsule or matching Graph header is not an externally issued namespace capability. No source or test result in this delivery claims those boundaries are closed.
