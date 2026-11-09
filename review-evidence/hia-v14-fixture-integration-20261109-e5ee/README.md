# v14 fixture integration evidence

Parents are 2aa206882c7d6298d74ddc1ddf3a4ccb052e41a6 and 635c57bd7fd0b9f37480b4da091af4dddfd53a36. Source before this report/package is tree 9ff1b36fb59858145e0d46010289a15fb91a3437.

The complete report is docs/HIA_V14_FIXTURE_INTEGRATION_20261109.md. validation.json summarizes the evidence; archive-manifest.json lists original byte lengths and SHA256 for all raw archive members. Every member was reopened and rehashed.

The archive includes the eight-method harmless Python run, four explicitly injected identity observations (one positive and three expected assertion refusals), the 723-ID inventory check without executing methods, complete-tree provenance, parent CI snapshots and independent static review records. The two different earlier 108-method failed runs remain in their original inherited packages unchanged. These reports are separate, overlapping evidence, not additive test counts.

The new head requires its own applicable CI. No actual PID reuse, global safety, all-descendant termination or general compiler correctness is claimed.
