# Isolated ELF development controls

This branch is a disposable CI harness, not a product branch. It checks out exact Hepta `7e9c5a796a29746d169f9db97392ec774f627c03` separately and applies the exact 18-path ELF candidate overlay recorded under `inputs/`.

The workflow uses Python 3.14.4 and the original pinned development dependencies, the retained `81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109` compiler only as a development compiler, the unchanged 20-second compiler child limit, all 37 component controls, and all original 51 ELF caller controls. It preserves every stdout, stderr, result, source map, artifact, and failure. No current-source cold, whole-project, default, deployment, or old-stack deletion qualification is inferred.

`original-evidence/ARCHIVE.json` identifies the exact 19,646,360-byte original r6/r7 development archive. Its 40 lossless JSON/base64 pieces preserve the original 2,247 members, including failed attempts and later independent corrections. The interrupted local session 28289 remains unknown; the later read-only reconciliation does not replace that acknowledgement. The earlier peer original executable and archive remain unrecovered.
