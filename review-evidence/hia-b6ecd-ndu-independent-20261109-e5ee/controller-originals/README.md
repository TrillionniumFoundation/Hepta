# Complete original controller CI member bytes

This package preserves all 577 file-member byte streams from
[run 42565807356](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807356),
artifact `13652586985`, head `6ecd8023615a6e0b2dc269379fb059c656b38b6f`.
The original 1,695,614-byte ZIP was checked against its
original official SHA256 `d46fb19432aea914534506a81f44b2d86786adbc0bb26fdd5c61911f6f7fefb6`.

The original members contain 5,354,779 bytes. Identical byte strings
were compared before deduplication, leaving 567 distinct
objects with 5,286,655 bytes. The retained archive contains
933,680 compressed bytes, in 1 ordered parts;
its SHA256 is `07f210f0a9495787d8ca885cedddf8b393efe863071a36725b97d3d695b52229`. Every archived object was read back and
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
