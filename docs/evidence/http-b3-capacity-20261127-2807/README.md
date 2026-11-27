# HTTP source-build capacity checkpoint

The actual ordinary-release source builder refused HTTP dispatch with native
failure 54 at 8192 instructions and HTTP events with failure 37 at the 2048
per-function value limit. The compiler and every capacity remain unchanged.

This source change packs the pinned first 908 Unicode ranges into 32-bit
initialization records, expands them backwards within the original 7272-byte
table, and retains the last wide range and the original lookup. It also moves
the intact fourteen contiguous event replay phase bodies to a private function.
The stdio dispatch receives the same diagnostic initializer.

The original captured twelve-unit sources bundle was rebuilt by the exact
813129-byte source-build ELF (SHA256
494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af).
Only the two rejected source members were replaced. All twelve now compile,
and every other source member and native product remains byte-for-byte equal.
The full original failure, compiler, original input, changed input and complete
24-member output are retained here. These are independent component evidence,
not a new cold-source or whole-release qualification.

Native Unicode/phase controls and complete public regression are continuing.
This checkpoint does not qualify the separate metadata batch or pending index
work. No new native source identity is introduced. Shared source authority and
release identities must be regenerated from the eventual integrated HEAD.
