# Explicit deferred native GenerationInfo operations

HIABVQ14 is a new private Value domain. Only operations 60, 64, 65 and 66 are admitted. Their original Q05 frame, actual immutable record and cache algorithms, primary response, and error order are unchanged. Earlier Q01 through Q13 domains retain their original boundaries.

All frames have the original 128-byte header: magic at 0, operation at 8, A capability at 24/32/40, B at 48/56/64, tail length at 96, and actual captured runtime nonce at 104/112 where required. Reserved fields stay zero.

| Operation | Input and actual native action |
| --- | --- |
| 60 | Actual HIAMVIR2 detached Info blob in tail; nonzero runtime nonce pair. Import and intern actual GenerationInfo and ScalarABI objects. No A/B. |
| 64 | A actual Lease resource, B actual Info record, captured nonce. Attach the real strong Info edge to the Lease. |
| 65 | A actual Lease resource, no B, no tail, zero 104/112. Publish a fresh strong capability to the existing cached Info, or original status 6 if absent. |
| 66 | A actual Runtime or Lease resource, optional B actual Info, captured nonce, actual native snapshot JSON in tail. Atomically retain/prune real generation Info and runtime ABI cache. B zero is prune-only. |

The response retains the original HIABVR01 primary contract. In particular, 60 and 65 can publish a real capability; 64 and 66 do not consume input capabilities. Existing failures do not authorize dropping a previously delivered reference.

The fixed additional trailer is:

| Offset | Meaning |
| --- | --- |
| 128 | HIABVD01 |
| 136 | Pending snapshot known, captured under the actual Value mutex |
| 144 | Actual arena mapping pending |
| 152 | Actual resource or invocation queue pending |
| 160 | Exactly 1: this single entry deferred automatic finalizer draining |

No process-wide or arena-wide deferred flag is changed. Q05 60/64/65/66 continue their original automatic epilogue. A failed pre-lock syscall leaves trailer known zero. Queue-only pending does not undo a successfully completed Info or cache operation.

Native callable bodies reject the whole Q14 domain. Final public owners must also reject the whole private domain. The older enclosing fixture used for the Value component is not claimed to certify that public refusal or the new enclosing root-lock order. The separately owned Runtime integration supplies those gates.

The component gates obtain real carrier Runtime/Lease capabilities, query their actual getrandom-derived nonce through the trusted fixed native carrier entry, and use the real detached Info and runtime snapshot. They compare the actual record, fields, ABI, as_dict and identity against the original Python dataclasses. A real native code munmap EIO supplies pending resource custody: all four Q14 operations leave it pending until a later native drain. Wrong nonces, malformed live-generation snapshots, actual getpid EIO before lock, exact domain controls and native body refusal are tested. All original six components, twenty-three prior protocol gates and six full campaigns also pass with unchanged assertions and original timeouts.

This receipt certifies the private Value component. It does not claim completion of public Runtime mutation pruning, public LLVM build mode, arbitrary user hash/equality methods, or the whole rewrite.
