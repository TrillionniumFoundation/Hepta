# Complete original source CI member bytes

This package preserves all 28,122 file-member byte streams from
[run 42565807355](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42565807355),
artifact `13652892138`, head `6ecd8023615a6e0b2dc269379fb059c656b38b6f`.
The original 36,367,360-byte ZIP was checked against its
original official SHA256 `819cdb66f6fd7cb1de3c02f52bdabfbb27f009f30f849778d132df29f83ea8cc`.

The original members contain 1,885,015,870 bytes. Identical byte strings
were compared before deduplication, leaving 16,121 distinct
objects with 1,007,950,656 bytes. The retained archive contains
7,366,924 compressed bytes, in 8 ordered parts;
its SHA256 is `eb4dcb78a6d57df35a6e231bb4835516ca67d5576176fddf3bb48fdec931eb54`. Every archived object was read back and
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
