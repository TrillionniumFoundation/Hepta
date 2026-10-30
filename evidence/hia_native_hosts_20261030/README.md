# Captured C application on native Linux hosts

These are the original GitHub Actions artifacts from source commit
`e223932a8bf25521db4204883af925dd64acc57a`, not a local rerun or a
cross-architecture emulator result.

- Workflow: <https://github.com/TrillionniumFoundation/Hepta/actions/runs/41034190041>
- x86_64 job: <https://github.com/TrillionniumFoundation/Hepta/actions/runs/41034190041/job/123990877664>
- AArch64 job: <https://github.com/TrillionniumFoundation/Hepta/actions/runs/41034190041/job/123990878150>

Both jobs completed successfully. The two retained ZIPs are byte-for-byte
downloads of the GitHub artifacts; their SHA-256 digests match the Actions
artifact metadata. `SUMMARY.json` records those digests, the artifact IDs,
source identity, host observations, executable identities, and review scope.
The archives total 1,752,269 bytes and preserve the full qualification reports,
native executables, captured inputs, command output, ABI probes, and controls.

## What was checked

The review checked all 394 artifact-manifest members and ten executable ELF
headers/hashes across the two hosts. It checked the recorded functional results
and resource ledgers against each other; it did not execute the binaries again.

Each host ran 48 functional cases through the HIA, Clang C, and GCC C programs,
for 144 native entry calls. Each also ran 16 resource cases through the C and
HIA programs, for 32 native calls. Allocation-refusal indices were 0, 1, 2,
and 3. All recorded resource cases ended with zero live resources. The three
functional driver processes and 32 resource processes per host were launched
directly, with no cross-execution prefix.

The compiled ABI probes agree on 32-bit `int`, 64-bit pointers, `long`,
`long long`, and `size_t`. The exercised scalar interface is
`u64 (usize, u64, u32, u32)`. ELF machine numbers are 62 for x86_64 and 183
for AArch64. The workflow also checks the runner's `uname -m` and package
architecture before compilation. These observations establish the reported
native process architectures; they do not attest physical bare-metal hardware.

## Application and boundaries

The application combines the captured Ring Buffer implementation, the generic
musl `memcmp`/`bcmp` implementations, and an authored checksum integration.
The route is structural C AST translation to standalone HIA Core, target LLVM
object generation, and a scalar C ABI executable. The report records 12
translated bodies, including 11 upstream bodies, plus an authored HIA client.
The HIA target links the generated HIA object, without linking the original C
implementations behind its entry point. The maintenance edit in this workflow
changes the authored checksum loop; it is not an upstream maintenance cycle.

This evidence is separate from the new Ring Buffer maintenance qualification
that uses the Rust reference backend. In particular, these two native-host
profiles do not measure peak RSS, tail latency, concurrent memory behavior, or
device operations. They do not establish a general foreign-pointer/record ABI,
whole C/C++ migration, performance superiority, or a source/Core/native
refinement proof. The original reports retain those limits explicitly.
