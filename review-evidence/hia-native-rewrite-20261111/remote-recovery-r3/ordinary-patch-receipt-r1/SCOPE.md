# Ordinary patch post-admission interface and receipt kernel

This is an unqualified development candidate. One local author-generation and assembly-roundtrip observation passed: 56 functions, 758 blocks, 3707 operations, maximum 87 blocks per function and 15 block parameters. Generated HIA assembly is 229,889 bytes, SHA-256 e0809903daba34e3fb5392627850077c45b2d2e0e7061ee1230e6886ace78334. New B3 and runtime entries at this checkpoint: 0.

Private input is JSON [original admitted canonical Core, freshly admitted candidate canonical Core, issued original-input SHA-256, patch version 1/2, preserve/migrate flag 0/1, actual edit count 1..64]. The native kernel compares the sorted union of all function interfaces, including declared parameter names, result types, effects and default/explicit return loans. Up to 1024 functions in each already admitted Core and the complete 2048-name union are retained.

Native code emits the exact first-eight-name migration diagnostic, or computes both canonical program hashes and constructs the complete original insertion-ordered receipt. Workspace/output GROW retries preserve immutable input. Its event/header and digest do not authenticate arbitrary Core input.

The ordinary coordinator must still perform original base admission, complete preparation, fresh candidate admission, this interface stage and final result custody in the original order. This checkpoint does not claim that coordinator, installed dispatch, complete patch qualification, or whole-stack closure. Differential tests and fresh bounded B3 execution are the next work.
