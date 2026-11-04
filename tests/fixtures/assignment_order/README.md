# Original assignment-order rejection controls

`baseline.json` was captured before editing source, at exact #610 head
`b3ed67874af8f6fcc5b9cd7756e6800edf047ed1` (tree
`c6957e4bfd9ae4a4ba2885eec8c185c23a58d82d`). It retains the three
unchanged `REJECTED` sources' hashes, generated Rust, and data-only resource
IR, plus original compiler/test file identities. The test pins the complete
fixture SHA-256 and binds each record to its original source.

The original real frontend accepted each source. To retain the rejected graph,
a recording wrapper copied the document passed to `verify_resource_ir`, then
called that same unmodified verifier and returned its actual result. Every
original lowerer invocation raised `E_RIR_USE_AFTER_MOVE`; none was converted
to success. Rust source was emitted from that original frontend result.

After the checker repair these source programs fail earlier. Tests continue to
require the independent verifier to reject every frozen graph and actual Rust
to reject every frozen Rust program with E0382/E0505. No production frontend
result is falsified to bypass the new rejection. These invalid fixtures are
negative controls, not accepted artifacts or semantic proof certificates.
