# Actual-host evidence for the final implementation tree

These 17 successful CI artifacts bind publication e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4 to exact tree 9530e9feccf0077696d2e94746fda6bfb6854417, identical to original desktop source 3707b871ecbe563233ee9a3b69299fc627408936. The desktop composition and CI use separately recorded toolchains; these runs are not substituted for each other.

Every original ZIP size and SHA256 was checked. The complete inventory has 2,133 members: all 1,983 UTF-8 text/source members are retained byte-for-byte; the 150 native binaries are inventoried by original size and hash. No downloaded program was executed by the collection tools.

Equal member contents share backward TAR hardlinks after an exact byte comparison. All names, sizes and hashes were then independently read back. Run python verify_retained.py in this directory to verify every part and retained member without extraction or execution. ARCHIVE_PARTS.json gives the ordered gzip TAR parts.

The actual-host results cover the declared C ABI and stb_divide profiles, unchanged nlohmann/json 3.11.3 and 3.12.0 through the C++/Hepta bridge, captured C to direct HIA LLVM on Linux x86_64/AArch64, and finite standalone AArch64 execution. They do not establish general C/C++ translation, DMA/MMIO, arbitrary asynchronous cancellation, crash recovery or whole-language concurrent safety.

C++ lifecycle totals keep registry retention separate from ordinary live-owner deltas. Cancellation is cooperative at an admitted boundary. SUMMARY.json records the exact observed counts and scope for each artifact.
