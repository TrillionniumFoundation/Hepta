# Complete original source-CI member retention

This directory preserves the bytes of all **23,715 original file members** from
[exact-source run 42558245653](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42558245653),
artifact `13649338156`, head `6a8c297b3f8f21506d11c2cb093c1c58d84ffe55`.
The original 32,401,939-byte ZIP was downloaded and its SHA256 independently
matched to GitHub's official artifact metadata:
`0de6b5217abcb1568b06f4e9f5c95eb30d9c487678d51007c57f9ddc6e3c7169`.

The original members total 1,614,719,391 bytes. Deduplication preserves 13,657
distinct byte strings totaling 874,130,212 bytes; repeated members refer to the
same SHA256-addressed object. Every original byte string was compared during
construction, every archived object was read back and hashed, and every member
mapping was checked. No compiler, solver or native image was executed.

The resulting tar.xz is **6,611,612 bytes**, SHA256
`c01ff8f5f0c8093b58120fb87bfbfc4dc2e88b8e599acf2458ae7583b5be7a10`.
It is retained in seven ordered parts. `summary.json` binds the parts and the
compressed member index. `original-members.json.gz` records each original name,
order, byte count, SHA256, CRC and ZIP attributes, plus the official provenance.

**This representation preserves original file member bytes, not the original
ZIP byte stream.** It does not recreate the original compressed member streams or
central-directory bytes, and cannot be compared directly with the official ZIP
digest. The original ZIP digest was checked before retention; the independently
checked per-member mapping connects that observation to this representation.

## Verify the retained bytes

With all files in this directory present, run:

```sh
python3 -B verify.py
```

The reader verifies the compressed and uncompressed index, each part, the joined
archive, every unique object's SHA256 and CRC, and all original member mappings.
It streams the archive without filesystem extraction and does not execute any
retained image or import project code. It reports only member-byte integrity;
it does not rerun proofs, native checks or the original CI qualification.

The original reports and all their failures, scope restrictions, strict Agent
HOLD and deployment flags remain in the retained member bytes. Their substantive
review is in the [independent source audit](../hia-6a-source-independent-20261109-e5ee/README.md).
Retaining these records does not promote a later commit, public entry or online
installation to the original source's qualification.
