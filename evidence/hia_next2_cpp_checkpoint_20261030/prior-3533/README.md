# Preserved P3/P6 qualification at 3533b95

This lightweight index binds the original successful finite checkpoint collector to `3533b95c53d23de2d22c91fcc05cb601b8448eb3`. The source-specific record remains unchanged while a separate CRC timing-profile change awaits a new source freeze. It is not relabelled as evidence for that later source.

The complete run contains 146 worker invocations, 34 measured allocation sites, 28 caught foreign exceptions and six foreign SIGABRT failures. Separate new requests observed 34 parent checkpoint reconstructions and 34 continuations. None of those six terminating foreign invocations is reclassified as an in-process recovery.

`INDEX.json` rehashes small formal metadata and carries the terminal receipt's retained-file inventory by reference. It does not claim that every payload file has been reread, compressed or archived in this indexing step. Original reports, raw streams and worker binaries remain at their recorded paths. Complete bounded archive verification will be performed only in an authorized packaging window.

Measured costs are nested and must not be added. This shared correctness window provides no performance comparison, complete environment proof or complete human/agent cost measurement.
