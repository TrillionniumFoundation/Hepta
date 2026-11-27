# Native Core input migration: original artifact readback

This evidence records the native cold compiler from commit `32692030505f2e81e9d33e22dbf6857c65af83ed` and the input-reader repair that its real bytes required. It does not qualify the complete Core job, release, installation, or whole native stack.

## Actual CI observations

[Transport job 140566138025](https://github.com/TrillionniumFoundation/Hepta/actions/runs/46016875379/job/140566138025) completed the original native cold campaign, then failed in the compiler locator. Its artifact `15207225917` contains the unmodified native-v2 report and index retained here. All 60 phases and 14 exact checks passed, with 479882 retained nodes; the inner qualification took 177261055187 ns within 180 seconds, and cleanup took 4316338 ns within 3 seconds. The selected compiler generations were read completely from their ZIP members, including ZIP CRC validation and independent SHA256 calculation. Each is 641344 bytes with SHA256 `acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`. All three begin with the flat x86-64 prefix `554889e54883ec4048897dc0488975c8488955d048894dd84c8985e0ffffff4c`.

The prior locator incorrectly required an ELF header. The replay driver has always selected `B1.flat`, `B2.flat` and `B3.flat`. Removing that format assumption retains exact report/index/path/hash/length bindings, three distinct physical files with equal bytes, complete native admission, and terminal readback of all five inputs.

[Core native job 140566137711](https://github.com/TrillionniumFoundation/Hepta/actions/runs/46016875379/job/140566137711) failed its separate native cold command with return code 1. Its original chain report is retained alongside the passing transport cold report. Neither result substitutes for the other. Both jobs used the unchanged 180+3 limits. The preserved chain report alone does not establish the precise inner failure cause.

The 428607604-byte transport ZIP was inspected with bounded HTTP range reads. Its API archive digest is identified separately from the independently hashed selected members; the entire ZIP digest was not independently recomputed.

## Fresh local controls after executor recovery

The repository was restored at the exact public commit and tree `a96332537f0c75742fe646dc45f0a0aabbccf6a8`. Earlier lost-executor results were not inherited.

The native locator fixture now uses the real compiler's observed prefix with an explicit nonexecuted synthetic suffix. Eleven regression methods against the original product code produced 2 failures and 4 errors, with no skips. After the repairs, all 50 strict input, Git custody, bridge-domain, independent-reader and method-inventory controls passed with zero failures, errors, skips, expected failures or unexpected successes.

Bootstrap Source previously required the count six, although the current source contains the original six methods and two existing supplemental methods. The reader now pins the original six method IDs and both supplemental IDs. Omission, same-count replacement, duplication and extra-method cases are rejected. The native suite's 12-method requirement is unchanged.

The original full cold report and three actual compiler files were admitted again without mocking qualification. The original locator rejected these same bytes; the repaired locator passed complete admission and retained all five original inputs. Only paths in a separate location-only index were relocated for the local readback. The original report, original index and compiler bytes were unchanged. This is a readback of the original native cold evidence, not a newly run cold campaign or new machine-code compilation.

Two predecessor failures remain visible in `retained-predecessor-controls.log`: the existing Store delivery successor inverse rejects the current historical service bytes, and the caller terminal source setup rejects the existing evaluation source successor. The source suite actually ran five methods, with two errors including the separate caller class setup; no methods were skipped. These independent predecessor repairs are outside this patch.

The first local readback harness wrote a literal backslash-n after its relocated index; neither of its failed actual-admission attempts is qualification evidence. The first method-inventory repair also passed a set to a JSON-based equality helper and failed. Both defects were corrected, and fresh controls were run. `validation.json` retains the earlier attempt's hash and limitations.

## Files and boundaries

`transport-cold.original.json`, `transport-generations.original.json` and `core-failure-chain.original.json` are the selected original artifact bytes. `artifact-readback.json` records their origin and all three fully read compiler hashes. `validation.json` records code hashes, strict control counts, real-byte admission before and after, and the remaining predecessor failures. The executable observation scripts record the local procedure; their temporary paths are development evidence, not installed native source authority.

All synthetic fixture data is explicitly nonexecuted. This patch neither fabricates hosted-v1 fields nor changes the 60-phase, 14-check or 180+3 requirements. The C/CPython transport remains an explicitly scoped development observation component. It is not a native release component.
