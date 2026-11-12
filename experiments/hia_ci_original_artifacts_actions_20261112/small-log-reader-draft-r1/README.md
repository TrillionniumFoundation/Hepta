# Small original archive to bounded log frames — draft only

This new read-only controller is not the currently queued archive operation. Its exact small-artifact ID, size, SHA256 and original FINAL digest must come from that completed run before any execution. No placeholder is a source pin. No workflow or trigger is added by this checkpoint.

The worker reuses the reviewed official API transport and unchanged original ZIP helper. It downloads only the new small artifact once, verifies the complete outer ZIP and every FINAL captured member, and independently reads the complete selected-original archives. It never downloads either original 600 MB artifact, executes project code, or reruns CI tests. Original HOLD states and missing files remain explicit.

The fixed output contains original FINAL; CUSTODY, SELECTED and OBSERVATIONS for each of two original artifacts; and eight original diagnostic/lifecycle paths per artifact. That is 23 present-or-missing logical targets. Up to five new read-only control records accompany them. The caller gate, original 51-test report, original owner/run-result, and both layers of stdout/stderr are preserved as raw bytes, not rewritten summaries.

Token-free finalization begins only after the bound original 900/3 guardian has closed. Every source is re-read and hashed, each 24 KiB frame carries a logical path, offset, length and SHA256, and the initial manifest binds each entire file. All framed data are limited to 8 MiB and all emitted framing lines to 12 MiB. A final terminal frame follows source-after verification and receipt fsync/readback; missing terminal or any mismatch cannot be accepted as complete custody. No unsafe original text is emitted as shell or workflow commands: raw bytes are base64 only.

No Python parser, runtime or fault control has executed for this draft. The current GitHub custody run remains separate and unmodified. Actual package pins and a separate reviewed workflow are still required.
