# Workspace fields after refusal

This clarification applies to the unchanged source SHA256 7a49da7115945fe90a1672e379e1f06a7f7778ef9f402c73afdbf7ce8cbad216, frozen in control 7b3cce17334eae4d5590fc1fb367a537320f0c90. The queued native development workflow and all source bytes remain unchanged.

The entry resets output length and diagnostics after the 32-byte header, mode and original input byte limit have been admitted. A workspace shorter than 32 bytes is rejected without writing its header. If a sufficiently large workspace is rejected for invalid mode or excessive source length, the error offset/status are written but an earlier output length may remain. DESIGN.json's reset_by_entry fields describe the admitted initialization path, not every ABI refusal path.

For every nonzero return status, all output bytes and the output length are invalid and must be discarded. A public wrapper must check status before consuming length or publishing bytes. Only a successful measurement authorizes the exact output allocation, and only a successful emit authorizes its bytes. The 31 frozen development cases already use that order and do not inspect output length on failure; this clarification does not invent a native failure or change their result.

A later wrapper revision must also cover nonzero initial workspace and success followed by refusal. If the API is instead strengthened to promise a zero length on every complete-header refusal, that requires a separate HIA source edit and new source/image validation. No such result is claimed here.
