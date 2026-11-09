# Complete original scalar CI member bytes

This package preserves all 475 file-member byte streams from
[run 42565807348](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807348),
artifact `13651783665`, head `6ecd8023615a6e0b2dc269379fb059c656b38b6f`.
The original 8,087,254-byte ZIP was checked against its
original official SHA256 `829735b11f5a4be9eb30e0eaee180dc7cca6b1fc3f93797e2d343b3c8d2dfad0`.

The original members contain 37,748,567 bytes. Identical byte strings
were compared before deduplication, leaving 408 distinct
objects with 34,739,768 bytes. The retained archive contains
1,319,532 compressed bytes, in 2 ordered parts;
its SHA256 is `f77f5091463e901b8db144165f16c4e068c10ba07d1927f44c6a86503d5dc39f`. Every archived object was read back and
hashed, and every original member mapping was verified.

This preserves original file-member contents and ZIP attributes, **not the
original ZIP byte stream**. The archive digest is not the official ZIP digest,
and this representation does not reconstruct GitHub's original compressed ZIP.
The original ZIP identity was checked before this preservation step.

Run `python3 -B verify.py` with the complete directory present. The reader checks
the compressed index, ordered parts, archive, every object and original member
mapping, including CRC values. It streams data without filesystem extraction and
executes no project compiler, solver or native image. Its result establishes
retained-byte integrity only; it does not rerun or strengthen original proofs,
performance claims, Agent acceptance, or overall source qualification.
