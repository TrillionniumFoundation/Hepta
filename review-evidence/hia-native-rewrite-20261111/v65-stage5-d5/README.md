# v65 stage5: observed interruption state and original GitHub logs

This checkpoint preserves the exact decoded GitHub job logs and raw GitHub metadata captured after run 42999809456 completed. The source group passed all 327 tests in 497.666 seconds. The native cold step failed with 6/11 outer checks, and all seventeen subsequent native groups were skipped. This candidate is not qualified for default activation.

`interruption-status-observations.json` is newly authored status metadata. It clearly separates already published source and retained evidence from results observed before the local workspace became unavailable. It is not a replacement for the unavailable original local reports, the ObjectToken r2 source, or the interrupted local cold result.

The current production main remains 5831f52fada45e076f8f68f198a15c0585e6104f. Candidate d5da1eb760454ef3df5153c5e80eb046ddb389d9 and recovery 3a27ddb5293d16740f57193a141529dffccb2133 remain separately identified. The whole native rewrite is OPEN, defaults remain off, and production/reference owners remain present.
