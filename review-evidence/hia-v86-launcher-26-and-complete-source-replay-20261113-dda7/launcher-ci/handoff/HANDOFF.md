# Selected-release native launcher: development handoff

The explicit `hia-run-selected` entry completed all 26 exact controls on CPython 3.14.4 in run 43397081929. This is a standalone development result. Matching-source cold, a positive production-builder run, default CLI/worker/MCP replacement, and whole-native delivery are not established.

## What executes

The new HIA policy consumes an explicit selected-release sequence and release identity, selects one admitted executable by name and its independent SHA-256, validates the static ELF profile, and authorizes one terminal execution. Fixed Linux syscall ports copy only that captured slice into an executable memfd, apply and read back all six seals, read back and hash every executable byte, perform the original final state/lock/root checks, and enter the same process through `execveat(AT_EMPTY_PATH)`. Business stdin/stdout/stderr and inherited SIGPIPE disposition remain available to the payload. No pathname fallback, child supervisor, retry, or old verify-success receipt is introduced.

The original `hia-select verify` still only verifies. Payload identity is not a proof that arbitrary payload code was produced by HIA. A separately generated 962,031-byte HIA Agent executable actually ran all six existing primitive/assembly commands through the launcher; that narrower fact is retained separately from arbitrary static-ELF execution.

## Actual controls and original failures

The final run executed the 21 source/VM/native-frame/kernel/Agent controls and all five ptrace controls, with exact loaded/executed ID equality, no skip or expected failure, and all 2,990 source bytes/modes unchanged. Full independent VM/native frames include canaries. Real kernel cases cover admission refusal, file/symlink/hardlink/replacement changes, exact return code, signal termination and cancellation, same-process identity, stdin/environment/private descriptor behavior, seals and immutable readback, EINTR, short-write and seal-readback faults, unavailable kernel features, and failed exec without fallback.

R1 remains FAIL: 25 controls passed and the remaining trace method could not start because two groups shared a fixture output directory. R2 remains FAIL: all26 ran, with25PASS and a required trace assertion failing because the strace category filter omitted close_range. R3 only adds that syscall to the observation filter. Every assertion and deadline remains in place; all five implementation/HIA files are byte-identical to the original frozen owner packet. Local ptrace EPERM and all earlier development failures remain preserved.

## Integration boundary

Six new paths are in source packet a1ae809c255bd05ab163ba0574c8a950b74e9780, based on exact e295431ac7bfb71058de8b940c8e7457c8100750. Final source tree is c22da5f1cba08c7dec45185f2185d6caf61618db. The packet retains every original base source and contains the full source and mode manifest.

The proposed SOURCE_FILES registration includes the new generator, fixed syscall port, strict builder, test module, and two .hepta assets. Both assets must enter NATIVE_SOURCE_FILES and installed package custody without losing any of the existing eleven groups. The baseline-only resource arithmetic is88→90 and187→189; recompute against the actual integration tree. The generation command is `python -B -m tools.generate_hia_release_launch`. Source tests are `tests.test_hia_release_launch.ReleaseLaunchSourceTests` (5); the explicit complete development module has26 methods.

The production command is `python -B tools/build_hia_release_launch.py --compiler COMPILER --cold-report COLD --output NEWDIR`. It rejects unqualified or missing-source authority before creating output. Positive builder qualification awaits a cold report for the actual integrated tree. The CI development bootstrap is not a substitute.

No console entry, product/default ref, old implementation, installation workflow, or external MCP runtime was changed. The existing Python CLI, installed worker coordinator, build tooling, and separately pinned external MCP adapter remain distinct migration work.
