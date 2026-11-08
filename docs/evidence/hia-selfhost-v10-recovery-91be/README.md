# Core v10 recovery and final source evidence

Final source: [`ec2c5c4171711b538f651960c5975b29c52705a5`](https://github.com/TrillionniumFoundation/Hepta/commit/ec2c5c4171711b538f651960c5975b29c52705a5), on `codex/hia-core-v10-recovered-91be-20261108`. The complete [source CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42505586193) and [NDU integration CI](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42505586144) both passed. No merge, default release entry change or deployment is included.

## Final CI evidence

`core-v10-final-ci-ec2c5c4.tar.xz` preserves all 12,708 entries from the final GitHub Actions artifact, plus a per-file SHA-256 manifest. ZIP entry contents were repacked without changing their bytes. Every archived file was checked against the manifest before publication. The original ZIP was downloaded and matched GitHub's published digest.

| Identity | Value |
| --- | --- |
| Final source tree | `3d7eeb3a0735fabb9b72164053b72a7088936ada` |
| Final CI artifact | `13626923542`, 17,032,494 bytes |
| Original ZIP SHA-256 | `949dbe37f6fdf278acc9852b60b5f2064f1024a8c65a87ed4271c281a1ed0a2b` |
| Retained tar.xz SHA-256 | `a266f082646cfbf0609bf4a54089345a587b856b909d58cc9bbb4dc41de313e0` |
| Frozen and verified release lock SHA-256 | `21e091f57dbd913e257cebc8218ce587d831add97d6cc294d786f8557886d643` |
| Exact runtime source | `4cd85c99c5f5a480832c48fbde8561bb365f67a9` |

The archived `source.txt` names the exact final commit/tree. The nested cold report's source manifest matches the final checkout. The release lock binds that source commit, the exact runtime, profile v10, the same compiler assembly hash, and the new bulk witness module. The original artifact's configured expiry is 2026-12-08; this branch retains the file contents separately.

| Final source check | Result |
| --- | ---: |
| Direct native / Core | 173 tests passed |
| Agent native tools | 83 tests passed |
| Scalar proof scope | 91 tests passed |
| Selfhost source contract | 5 tests passed |
| Safe Core | 39 checks passed |
| Release regression | 54 tests passed |
| Cost controls and repository trial | 101 tests passed |
| Selfhost source/input limits | 19 tests passed |
| Cold replay | 10/10 outer, 601/601 nested checks |
| Language qualification | 744/744 checks |
| Exact source/runtime release lock | freeze and check passed |

The language run retained 824 scalar witnesses and, per compiler, 62 positive programs, 171 rejected programs and 136 traps. Bulk qualification retained 69 behavior cases (36 returned, 33 bounds traps), 45 distinct refusal inputs per compiler and 10 ELF text/flat-image comparisons across the two compilers.

## Recovery history and corrected failures

The earlier executor lost local commit `fc5e671bd9da6933e72c6aa407516d2637516312` and its raw evidence. Recovery commit `da101b30c35856b035c08c4fcd78168f11c5ea23` exactly reproduced its complete Git tree `ddf48192c6f9da9a9748407f11a2f7186990695b`. The first new local cold/language run is retained in `core-recovery-evidence-91be.tar.xz` (SHA-256 `5cd9e0652d82949ee64080494783ac72a7677ea2d5489d680166015c3ae66c44`). Those files are newly executed recovery evidence, not recreated historical logs.

The first recovery run had 45 named refusal records but only 40 distinct input byte strings. An independent read-only review found the duplicate fixtures. Final source `ec2c5c4` uses different u64/u32 type errors and asserts that all 45 refusal inputs are distinct. The older archive remains unchanged and must not be described as containing 45 unique refusal inputs.

Two public failures are retained with their full job logs:

- `da101b30` / run `42504524354`: Agent discovery still asserted the historical v8 literal. Follow-up `b43acb6d` compares the entire served support document with the current validated source contract.
- `b43acb6d` / run `42504904322`: all compiler and language gates passed; release freezing rejected the omitted `hia_selfhost_bulk.py` dependency. Follow-up `ec2c5c4` adds the dependency and checks that the release inventory includes the complete Selfhost source list.

`recovery-summary.json` records the separate source commits, original and final archives, test counts, artifact digests and review limits. `final-ci-job.log` is the full successful job log; `first-ci-failure.log` and `release-closure-failure.log` preserve the earlier failures.

## Scope

Profile `selfhost-core-linux-x86_64-v10` accepts 37 of 50 general Core operation names. This extension adds `buffer.fill`, `buffer.copy`, `buffer.fill_range`, `buffer.copy_range` and `buffer.move_within` to the borrowed-buffer profile. The remaining 13 allocation, ownership, loan and owner-chain operations are outside the profile.

The independent review found no new implementation error in unsigned range checks, pre-access validation of both copy ranges, empty-operation handling, overlap direction, or malformed-signature refusal before emission. Its assumptions remain explicit: live valid buffers, the required non-aliasing, and stable compiler input. Successful bulk extents in these finite witnesses are at most 16 bytes, and the bulk scalar operands are fixture constants.

These observations do not establish all-input compiler correctness, full Core self-hosting, general ISA/loading correctness, live service installation identity or stable economic benefit. Integration with the separate Agent byte-lifecycle implementation requires a refreshed source contract and fresh qualification against the combined compiler source.
