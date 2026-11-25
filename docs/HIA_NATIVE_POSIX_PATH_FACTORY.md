# Fixed native PosixPath factory

The actual fixed factory creates a class-backed PosixPath from an exact-string value capability. It obtains the real registry class, retains the raw path in an owned list, constructs and checks the instance, and publishes only after temporary-reference cleanup. It neither resolves paths nor closes the complete public Path constructor or all Path methods.

The qualified 336,135-byte native image has SHA-256 `3d6c58cb2219d867d03805cff206eedd017e7e562fcc8b5826a595387e29e076`. All 85 factory groups pass: 73 original path inputs, eight explicit dependency-failure controls, and four cleanup/quarantine controls. Both actual native packers also pass all 26 original groups. Dependency controls instrument the fixed role boundary; actual value-owner kernel-failure qualification is separate.

The first candidate entered the shared `begin` function as f0 and repeated getpid. The corrected generator emits `native_posix_path_factory` first and preserves the other selected functions' order. Three actual native observations of the original failure are retained. Request and cleanup ABIs are unchanged.

[HIA_NATIVE_POSIX_PATH_FACTORY_QUALIFICATION.json](HIA_NATIVE_POSIX_PATH_FACTORY_QUALIFICATION.json) records exact sources, both native compilations, actual HIA packaging, complete factory/packer reports, and the original failure. The separate object-ownership report is referenced with its complete-file hash and group/call counts; its per-call ledger remains in the captured QA artifact.
