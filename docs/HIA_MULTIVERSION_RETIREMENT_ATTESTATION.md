# Last-attested native retirement diagnostics

The retirement effect owner retains the last 512-byte state header only after validating the actual HIA transition result, its event/action, sequence and owner nonce. If a later transition fails, it permanently fences the owner, clears all effect-authority flags and returns the saved header for diagnostics. It never repairs the damaged live state from this saved copy and never uses the copy to authorize another native release.

The original private HIAMVRT1 / HIAMVTR1 frame retains its 24-byte request, 768-byte output and zero reserved tail. The diagnostic HIAMVRT2 / HIAMVTR2 variant exposes whether a header was attested plus the immutable first failing return, event, fence reason and exact 64-byte policy reply. Both variants return the same last-attested header after a fence. Before any successful transition, the saved header is explicitly zero and its validity flag is false.

Actual qualification covers four damaged-state cases against the original RetirementState.query implementation: magic, checksum, nonce and sequence. Each also invokes the old native image as a counterfactual, proving its former damaged-header or nonzero-flags behavior. Repeated diagnostic calls preserve the first evidence even after additional corruption. The real unmodified holder retains its original file descriptors and is the only owner later allowed to perform cleanup.

The new image also passes all 9 original/native retirement pairs, 8 original private/fork/state guards and 10 actual EIO/EINTR syscall-fault pairs, including uncertain close and hostile descriptor-number reuse. Full results and construction pins are in HIA_MULTIVERSION_RETIREMENT_ATTESTATION.json.

This component does not yet capture the actual dlerror text, assemble the full locked public snapshot or close the complete runtime API. Those obligations remain explicit; no whole-product flag is asserted.
