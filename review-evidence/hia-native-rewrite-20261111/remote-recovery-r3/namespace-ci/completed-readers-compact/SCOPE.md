# Completed namespace reader result extraction

This is a new, unexecuted read-only extractor. It imports no HIA, compiler, CoreVM or native image and starts no target job.

Download the two exact already completed reader artifacts described in input-artifacts.json. The official action materializes directories; outer ZIP size/SHA values remain GitHub declarations, not a claim that this script has read an original ZIP.

The prior standalone readers published per-target verified-members.json and original summaries, but no additional sealed index for their entire output directory. The extractor explicitly records this distinction. It hashes every downloaded regular file before and after; it verifies the existing per-target index against every original tar member, including complete bytes, mode, SHA256 and Git SHA1. All three original target archive SHA256 values are fixed in source.

For the two timeout ledgers, it independently replays the recorded gzip prefix without target execution and requires full equality with the previous reader interpretation. It saves complete first and last records, an incomplete trailing record when present, and byte CAS objects for every hexadecimal buffer field. Exact original summaries, stdout/stderr, source, canonical HIA and images, request/receipt budgets, and the full unchanged original archives remain in the new sealed output. Indeterminate in-flight calls stay UNKNOWN.

Console output is one complete JSON projection smaller than 900,000 bytes, or a small explicit FAIL_CONSOLE_BOUND report. It is never truncated. All projection integers are declared decimal strings; original JSON and u64 representations remain exact original bytes in the sealed files. The output seal independently checks every selected member again.

Required execution domain: CPython 3.12.14 on the existing Ubuntu 24.04 x86_64 workflow guard. Process CPU90 / wall180 / address1GiB / core0 remain. The workflow must additionally use timeout --signal=TERM --kill-after=5s 180s, with pipefail if tee is used. No common.prepare(), dependency installation, generation, compiler, VM or native target is required.

New AST and runtime counts are all zero until the actual CI job executes. Original failures and qualification HOLD are unchanged.
