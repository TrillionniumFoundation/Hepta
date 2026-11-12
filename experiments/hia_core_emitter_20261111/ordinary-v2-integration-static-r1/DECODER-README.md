# Diagnostic decoder controls

These are transport-data controls evaluated in the functions JavaScript isolate. They did not execute Python, generate HIA, or call any product or Actions API.

The decoder source returns a function accepting the complete original decoded job log and an API object with utf8, sha256, base64Bytes, bytesBase64 and utf8Text. The two helper source files return their helper objects when evaluated with new Function(source)(). All helpers used by the recorded 13 controls are preserved here byte-for-byte.

The controls source uses a load/store/text harness. Map core.lowering.bytehash.helpers to decoder-sha256-utf8.js, core.lowering.custody.decoder.js to decoder-base64-archive.js, and core.lowering.emitter.actions-r3.diagnostic.decoder.js to diagnostic-decoder.js. This makes the exact recorded control body reproducible without a repository import or native compiler.

Two positive controls include empty files, non-UTF8 bytes and an explicitly closed-boundary refusal. Eleven negative controls require rejection of changed identity, missing/repeated terminal, missing frame, offset drift, changed payload or hash, unexpected path, invalid closure and wrong aggregate/observation counts. The synthetic fixture uses the fixed operation identifiers to test the decoder schema, but its bytes are not represented as actual workflow originals.

Actual Actions originals remain pending. A future readback must preserve the complete original job log before decoding, each frame payload and whole-file SHA, and every missing observation. A decoder result alone must not be used as a native or source-authoring PASS.
