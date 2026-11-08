# Recovered Core v10 execution evidence

This archive records a fresh execution after the earlier executor was replaced. The earlier raw evidence was lost; these files are newly generated evidence, not reconstructed historical logs.

- Source commit: `da101b30c35856b035c08c4fcd78168f11c5ea23`
- Source tree: `ddf48192c6f9da9a9748407f11a2f7186990695b` (identical to the original local `fc5e671bd9da6933e72c6aa407516d2637516312` tree).
- Profile: `selfhost-core-linux-x86_64-v10`; 37 of 50 general Core operation names.
- Local cold replay: 10/10 outer checks, 601/601 nested checks.
- Local language qualification: 744/744 checks; 824 scalar witnesses; 62 positive programs, 171 rejected programs and 136 traps per compiler.
- Bulk witnesses: 69 cases (36 successful, 33 traps), 45 refusals per compiler and 10 ELF text/flat-image comparisons across the two compilers.
- Archive SHA-256: `5cd9e0652d82949ee64080494783ac72a7677ea2d5489d680166015c3ae66c44`.

The archive contains 12,538 content-hashed files plus `files-manifest.json`: new reports, requests, compiler images, fixture input/output bytes, raw child logs, independent reference observations, and the exact cold source export. Every manifest entry was checked against the archived bytes before publication. The 24 source tests passed in this session, but their raw terminal log was not retained in the archive.

The original public source CI run stopped on one stale v8 test literal. The original NDU integration run passed. Follow-up `b43acb6dd25e1c7b363faf865d01570189c47787` replaces that literal with full equality against the current validated source contract; its focused local test passed and full CI is rerunning. See `recovery-summary.json` for the run links.

These are finite observations for the declared borrowed-buffer profile on Linux x86-64. Allocation, ownership, loans and owner chains remain outside the selfhost profile. The evidence does not establish all-input compiler correctness, whole-Core self-hosting, full ISA/loading correctness, stable economic benefit, or the live service installation identity. No merge, release entry change, or deployment is included.
