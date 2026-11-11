# CLI reconstruction components r1

This package contains newly reconstructed and newly executed development
components after the previous local workspace became unavailable. It is not a
restoration of the missing R15 capture, pretty, file, or CLI-wire raw packages.

## Exact recovered inputs

The published R14 argv/formatter archive was reconstructed from its five
published parts. Archive SHA256:
37ed85a727a2c18f08e0a5b3c473556db14a51e376cb62ce4c62169c7f311d9e.
All 27,046 files, 85,599,523 bytes and modes were reread. Its 26,842 original
zlib CAS objects were decompressed and checked, totaling 750,459,170 bytes.
Recovery attempt 1 used the wrong CAS suffix and failed after file extraction;
the complete original request and logs remain separate. Recovery r2 corrected
the recovery harness. No original native test was rerun or relabeled.

The R6 Graph wire archive SHA256 is
31b4b7ce104d0ff611891abe43a4131d7fd94d342aba9686c4c789d6d485f25b.
All 823 files / 70,930,366 bytes and modes were reread. Its original images are
the independent old-flags oracle in the new differential.

## New native components and evidence

- OS capture: 19 functions / 200 blocks / 1,151 instructions. New HIA source
  SHA256 3c9c3f558e25ea29fc726bbba1e22eb10c2b9edac5f7c18e23fe9b908af1f87c.
  Actual image SHA256
  960aef38158d4fda7ee171ec61d8496bf1cd5130508cb5b4dca3fc10d4b4abf7.
  New run: 358 cases (344 ordinary input cases, 14 private controls),
  1,061 actual entries; durable process exit 0. The Unicode and int reference is
  CPython 3.12.14 / Unicode 15.0.0. Actual OS exec/TTY capture remains a later
  fixed-entry integration step; these inputs are mechanically formed raw OS
  byte packets.

- CLI Graph scan: 42 functions / 591 blocks / 2,420 instructions.
  Source SHA256
  7ac81329c5bcaea0bfd4a2a31f9efdfb1d24590307ec90fa72250371b16f3d2e.
  Image SHA256
  bbd4d6c19b3159c3a64c5be4e2f77a943eb057696fe00ded55e8b4bd70a5e4c4.

- CLI Graph emit: 56 functions / 783 blocks / 2,981 instructions.
  Source SHA256
  1eb4e4236a7caf222254f3d10d510bf650074ce666ddf68f7423a374245e05ea.
  Image SHA256
  9498c83fab2af063bfa15ebee750b60bae9aa1ad21e03443f788891b69d054fd.
  Old flags 0..3 retain their policies. Dedicated flag 6 requires exact
  maximum (1<<61)-1; the first pass measures output without writing it and the
  second pass writes the exact measured size. This is for the already admitted
  CLI program/metadata projections, not arbitrary foreign object admission.
  The existing 129-frame implementation domain is unchanged.

- CLI pretty: 24 functions / 403 blocks / 1,261 instructions.
  Source SHA256
  15e1c050b52b29948c7cde357684cc71c3837f93216756f2c5c2201133e62ac6.
  Image SHA256
  fdf6b79b307cbe9169edccf50ad81871511f9193e411420ed9e56d0d6697cdf2.
  This owner consumes privately issued compact JSON with canonical scalar
  spellings and already sorted keys; it owns indentation and string escaping.
  It does not claim to replace arbitrary json.dumps object capture or sorting.

The combined new run has 397 cases and 2,395 actual entries: new scan 464,
new emit 567, recovered old scan 307, recovered old emit 408, pretty 649.
Durable process exit 0. Coverage includes 264 old-flags cases with complete
workspace equality, 96 CLI wire plus both pretty policies, a 9 MiB result and
270,000-node display, unchanged worker refusals, malformed frames and permanent
poison, and exact measurement/GROW state controls. Full before/after buffers
are losslessly zlib content-addressed and read back; no buffers are truncated.

All four new images were compiled by the retained actual B3 image SHA256
35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b under
the original 10 CPU seconds / 20 wall seconds / 256 MiB compile bounds.
The combined native test retains 90 CPU seconds and 1 GiB process bounds.
These are development builds, not new matching-source cold qualification.

## Still open

The missing bounded-file owner must be reconstructed and newly verified.
The fixed CLI executor/controller/packer are the separately published
NEW/UNEXECUTED interruption drafts until the actual entry integration runs.
No old Python owner was deleted. Full 15-action CLI + version, business services,
publication, installed dispatch, arbitrary Python startup encoding profiles
and whole-stack native qualification are not claimed by this package.
