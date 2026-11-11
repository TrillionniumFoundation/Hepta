# HIA continuation evidence

See `evidence-index.json` for byte counts, SHA-256 values, provenance and the
distinction between original observations and derived audit summaries.

* `baseline/` preserves the failed main cold wrapper, phase index and original
  GitHub job logs. The complete 41 MB GitHub artifact is identified in the index;
  its full phase reports are not duplicated here. GitHub retention applies.
* `runtime/` records issued discovery/artifact bytes. It is not a filesystem or
  process audit of every deployed host and does not claim a runtime cutover.
* `cold-isolated/` separates the failed first repair from the successful isolated
  second repair. Neither qualifies the later combined source.
* `worker-development/` retains the independent review, test output and image
  pins of the corrected development image.
* `release-development/` retains actual remote kernel logs, fault/kill traces,
  permission failures and corrected observations. The ZIP includes earlier
  failed iterations. Its receipt explicitly says development only.
* `joint/` retains the pre-merge v61 combined-source cold wrapper and process receipt,
  exact-source native builds and ordinary worker tests. The cold scope is the
  574 declared sources plus the contract, not the whole product.
* `v62/` retains the merged-main qualification, the original disk-full failure,
  new 577-entry cold success and independent archive replay, current native
  component builds/tests and the targeted old/new host-function differential.

Recorded absolute paths are original observations; copying a report does not
make those historical paths available in a new checkout. SHA-256 pins refer to
the exact original bytes, never a reformatted substitute. Test logs and
summaries are retained evidence, not authorization to skip the matching current
source and build gates. The full production stack remains partly hosted.
