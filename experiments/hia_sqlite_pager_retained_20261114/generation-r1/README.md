# Pager retained-page generation: frozen controls

This directory freezes the 6,115-byte HIA retained-page component, its exact author dependencies, and a new generation-only request path. At this commit, neither metadata preparation nor the actual two-author generation has run.

The metadata preparation creates a fresh private namespace, reads every one of the current 4,136 source files, reconstructs the exact Git tree, joins all 901 frozen source-map entries, and revalidates the complete original 4,815-file system profile and aliases. It does not import the project, generate HIA, compile, run a VM, or pre-create the actual qualification output.

Only after Root closes the metadata job and frozen request may the clean-environment entry invoke the original owner. That owner has one 180-second qualification and 3-second cleanup budget for both author invocations and their original roundtrips. The 4 MiB physical file cap, nine compiler caps, and final 192-file / 384 MiB quota are unchanged. The CPython authoring tools remain explicit development dependencies.

Original four-case Pager R3 interoperability is unchanged and is not run here. No new native, VM, SQLite, AgentStore, default-entry, full-language or whole-stack qualification is implied.

The four-control independent static review found no definite false-PASS issue. The clean entry and metadata materializer were separately written and reviewed by Root; their first actual results are still pending. Future file identities are not fabricated.

The same commit appends GZIP-CLOSURE-v2 and GZIP-PRECISION-CORRECTION to the current CI diagnostic directory. They preserve the v1 derived copy and correct four nanosecond values rounded by ordinary JavaScript JSON parsing. Raw original report bytes and lossless ZIP/gzip verification are unchanged.
