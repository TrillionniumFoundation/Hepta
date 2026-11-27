# Exact R20 original evidence recovery

This recipe preserves the completed formal Source run43553551892/job132321186937 and its separate bounded62 artifact. It does not grant current-source cold or whole-Native qualification.

## Source original archive

Read the237 Git binary blobs in source-archive/chunk-0000.bin through chunk-0236.bin in numeric order. These are raw decoded bytes, not Base64 text. Concatenate without separators. Require124111735 bytes, SHA256 ffc5945b5c231eb4faa09e57c7e5f8472d3dcc991338962b0a4336da881793f5 and Git blob741d9cb3e0e290aa80048bbc7e9df4d0cb63b597. The original producer performed complete GET readback for each; the independent custody verifier matched each actual downloaded archive span to those receipts. No new independent connector binary GET is claimed.

The exact EVIDENCE-MANIFEST.json is inside the metadata capsule at original/custody-stream-r1/combined-source/EVIDENCE-MANIFEST.json:3387484 bytes, Git c2b851d6a1e2357a4ea7d16458e944f600f663a6. Verify its bytes before restoring. Validate every7856 regular file, every1295 directory and recorded root mode493 against that manifest; reject absolute/escaping/duplicate names, symlinks, hard links and unrecorded members. Preserve actual recorded modes. The original archive was already streamed through complete gzip CRC and member-byte/hash/Git/mode checks. Its recorded fixed Git input references remain fixed; do not replace them with HEAD.

## Lossless proof metadata

Concatenate the14 metadata-parts/part-####.txt Git files in exact index order as raw ASCII bytes, with no separators. Match METADATA-PARTS.json's full wrapper length/SHA/Git. Decode the wrapper JSON payload with strict Base64, verify compressed length/SHA/Git, zlib-decompress, and verify its full uncompressed length/SHA/Git. The decoded files array gives152 safe relative paths, exact bytes/hash/Git and original modes; its pool stores each distinct content as strict Base64. Check each decoded file against its record before writing into an exclusive directory. The complete logical map was already read back and compared byte-for-byte with all original metadata.

## Outer ZIP and bounded-raw boundary

combined-source.zip is383629576 bytes/SHA2567a6c07fb57593fd282fe4a2854bcd6ec0eb3ddca001b217c41c62f2843d570b9; parser-bounded.zip is48115943 bytes/SHA256efdca0795d327ff70cf27e2a4feddeb96cc78d14661226361b2ec6bf125c9b9e. Both original ZIPs remain in the local original directory and Actions artifacts14097884196/14098053733. Their full CRC/member/mode inventories and independent verifiers are preserved. This recipe is not a byte-exact replacement for either whole outer ZIP, and the complete bounded machine-frame/raw payload is not claimed to be in Git.
