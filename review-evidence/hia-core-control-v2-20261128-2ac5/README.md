# Core39 explicit v2 source and actual development qualification

This candidate adds a disjoint Core control v2 profile. The original 32 control units plus literal pool, original ABI, policy, author, and continuation resources remain byte-for-byte unchanged. The new profile has 39 control units plus its pool (40 images), six Emitter modes, actual generator continuation, and native four-value unpack/call binding.

## Actual results

* Source controls: six passed, no skipped cases. These include exact original v1 source files and original in-process run body, complete original Function/Emitter AST, typed profile refusal, all 42 new HIA programs under the unchanged original caps, and v1 resource separation.
* ROG development execution: all 40 v2 images, the v2 continuation policy/packer and original guards, and three Core companion images compiled with the pinned B3. The original six UNPACK composition methods and four new native v2 methods ran: 10 passed, no skipped cases, 17.768283793 seconds internally / 21.969788834 seconds externally. All 7,422 captured source files and the compiler bytes were unchanged.
* Ordinary foreign StopIteration remains StopIteration; generator exceptions retain PEP 479 behavior. Partial iteration, send, throw and close are exercised through the native continuation.
* Original Core and Emitter source modules ran all eight methods: six passed and two failed because the not-yet-updated unified release source contract rejected before the requested matching-cold error text. Their complete original stderr is preserved. Their assertions, budgets and definitions were not changed.

## Qualification boundary

This is DEVELOPMENT_ONLY, matching_cold_qualified=false and production_activated=false. It uses the previously preserved B3 only as an explicitly selected compiler. It does not transfer that compiler's old source authority to these new sources. The final unified source registration, full current matching cold, Worker03 recipe/model and installed/rebuilt product gates remain required. The final default must explicitly choose Core39 v2; original Worker01/02 validation retains its original v1 domain.

## Evidence custody

The native archive contains all 392 files (160,453,396 uncompressed bytes), including full compile output buffers, every receipt, full linked aggregate, original-test evidence, actual driver and exact source pins. Its SHA256 is d8f79b750403f652d164ac7e55e25c2de527785afb2e8b9c8fcecc6a79592c25. The complete archive is split into ordered content-addressed chunks, with all member bytes, modes and SHA256 values verified on ROG and independently after transfer to Mac. Concatenate the chunks in native-complete-manifest.json order to recover the gzip tar.

The authoring-and-source directory contains individually compressed complete original logs, source predecessors, profile separation failures and successful controls. The original materialization Git pack, tar transport and duplicate overlay are not included; their exact metadata is retained and the candidate source bytes are preserved by this Git commit. No failed run is relabeled as passing.
