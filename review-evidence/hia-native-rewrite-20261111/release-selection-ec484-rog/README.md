# Original ec484 release-selection fault observations

These are the original observations from `rog` for source commit
`ec4841212fa97ae98c576b48f8ba1b4815df6122`, tree
`ba5056defe3bfe2052afa16c5fb71c72374d4d8a`. The four existing fault tests
passed with six actual strace traces, including injected errors and SIGKILL.
All included files were checked against the remote size/SHA-256 inventory.
Native binary payloads are not copied into this source tree; their identities
remain in the original inventory and build receipts.

The complete declared 672-file sparse source closure, raw Git blobs and modes
were verified before and after the run. The fixture built real B0/B1/B2
images in explicit development mode. It did not use a cold qualification
receipt and does not qualify the later integrated source.

The original cloud ptrace-denied failures and original GitHub cold timeouts
remain separate observations. This record does not rewrite them as passes.
