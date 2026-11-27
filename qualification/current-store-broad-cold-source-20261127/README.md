# CurrentStore broad cold source admission: complete source controls

This evidence preserves the complete source qualification for commit `77ebcfe1d149e4e24b9a908dac589f186b564f2f`, tree `9ccd4d4bbadf33dab13af1e135fe82c6c4f9dfae`.

The original 264 source tests and the additional 20 boundary controls all passed: 284 tests in 33.906 seconds, with a 34.143036084-second outer supervisor. There were no skipped tests, exclusions, or source changes. The Mac checkout retained its original base commit while its complete tested tree was independently checked against the published candidate tree; this is not a claim that its HEAD was rewritten.

The complete archive retains 70 original members, including the earlier Python-version and preparation failures, the first full run's five missing-jsonschema import errors, the final complete run, all current source bytes, and the actual import-time identity counterexample. The old helper accepted a post-import source replacement; the revised helper rejected the same physical mutation. No original test assertions, fixed historical fixtures, or native product source were changed to obtain this result.

The final run used Python 3.14 and the original declared dependency versions: setuptools 78.1.1, wheel 0.46.3, z3-solver 4.15.4.0, and jsonschema 4.26.0. All 11 candidate source files were checked by length, SHA-256, and Git blob identity before and after execution. Six dependency files were copied from their explicit source commits; the source commit does not claim that their entire development branches were merged.

`complete-source-evidence.tar.gz` is 391746 bytes, SHA-256 `554cf0547fb2bc7e29f2c02182bb07b8eb5f88d36dac0706517c98c86cfab1ab`. `manifest.json` records each archived file's path, length, SHA-256, and mode. Every member was independently reread and verified after archive creation.

This qualifies the stated source-history and admission controls. It does not qualify a new native cold build, installed Worker execution, whole native delivery, or retirement of the old implementation.
