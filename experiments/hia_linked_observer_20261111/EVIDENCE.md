# Disposable HIA linked observer: development evidence

The exact source checkpoint is `42e3b7a6ef529e0f7209ab41184b6bbc89425b02`. This is development evidence, not a cold qualification result or a claim that the entire stack is native. The 180-second cold deadline, two qualification workers, independent seed loader and specialized allocator controls remain unchanged.

The new HIA policy and HIA ELF packer execute the actual GNU-ld-produced shared object in one fresh process per observation. The fixed bridge exposes Linux/SysV primitives and system `dlopen`, `dlsym`, and `dlclose`. System `ld-linux`, `libdl`, and `libc`, and the Python parent/reference oracles remain explicit dependencies.

## Actual controls

The new source and native suite passed 14 tests in 7.817 seconds, using its own fresh B0 and B1. The original flat-observer suite and three phase-inventory/process/merge controls separately passed 14 tests in 5.826 seconds. Both original logs are retained.

The first minimal shared-library probe passed, but its original `/tmp` image files were lost during a later cloud environment reset. Its workspace script and original stdout survive. Those missing image files are not claimed to have been retained. The first signed A/B launch exited during output-directory preparation, before running a phase; its original failure is preserved.

## Complete signed phase comparison

Each side ran the original complete signed phase in a separate isolated Python process: 458 fresh native invocations, all 326 original checks, and the same independently generated reference (52 cases, 18 refusals, 100 traps). All original check IDs, values, input/payload hashes, and pre-existing semantic observation fields match. Native linked receipts add an explicit `capture_origin` field; exact whole-dictionary equality is therefore not claimed. The first comparator refusal and the subsequent field-by-field audit are retained.

Original phase time was 13.591783677 seconds; the new phase took 12.295290283 seconds. The 52 actual linked invocations changed from a summed 1.735399496 seconds to 0.101399219 seconds. New helper construction and VM checks cost 2.226221666 seconds, paid once per complete cold run. These single-host development measurements do not establish the result of a complete 180-second CI cold run.

The archive `signed-phase-originals-r2.tar.gz` contains both complete original reports, both complete phase ZIPs, both helper-build ZIPs, controls, and logs. Its SHA-256 is `8c2600407db411407d3a8f1bcf95a2b104a6e1fffdf7b48f99f33cea9a676bb7`. All 18 outer members (16,096,428 bytes) were independently reread with hash/size/mode/UID/GID checks. The original phase archiver independently read each inner member before retiring the expanded stage directories. See the retention manifest for member identities.

## Original frozen-416 CI

The adjacent `hia_core_ci_4161_20261111` evidence preserves the successful exact-head push and failed same-tree PR independently. Push cold passed in 144.808616222 seconds (38 phases, 5,049 nested checks); PR cold failed at 180.178016991 seconds (34 completed phases). The synthetic PR checkout was `e0b22f1190121710c907ec96ef2c396b5cd12c06`, not the pushed head. Every member of both sets of completed original phase archives was independently read. Historical UID/GID are absent from those original ZIP manifests and are not claimed to be recovered.
