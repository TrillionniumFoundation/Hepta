# Agent Protocol v3 multi-file preview — read-only qualification

`hepta.patch.preview.v3` is a **read-only** proposal validator. It accepts up
to 32 function-body replacements in a single project snapshot, across one or
several loaded `.hepta` files, and validates **the combined candidate graph**.
It does not apply changes and **does not claim atomic multi-file writes**.

## Request

```json
{
  "schema": "hepta.patch.preview.v3",
  "expected_project_sha256": "<actual hepta.inspect.v1 project.sha256>",
  "expected_interface_sha256": "<actual hepta.inspect.v1 interface_sha256>",
  "edits": [
    {
      "target": "src/math.hepta",
      "symbol": "sum",
      "expected_source_sha256": "<actual source sha256>",
      "replacement_body": "{ return 42; }"
    }
  ]
}
```

Use the literal identities returned by `hepta inspect`; placeholder values
above are documentation only. Run:

```sh
python -m hepta patch path/to/project --request proposal.json
```

Do **not** pass `--apply`: it is rejected with
`E_PREVIEW_APPLY_UNSUPPORTED`, even if the proposal would otherwise validate.

## Validation steps

1. Require the exact request schema, SHA-256 identities, positive bounded edit
   count and complete edit fields; reject duplicate symbol edits.
2. Load one exact import/dependency graph and enforce path membership, original
   source hashes and unchanged interface identities.
3. Locate original function body spans, apply grouped replacements in-memory
   from right to left, and reparse to reject code inserted outside bodies.
4. Run a **single combined** `analyze_project(... source_overrides=...)` with
   the real pinned Rust native validation gate; no frontend-only success.
5. Compare all graph sources, resolved modules, symlink path bindings,
   package state and public interfaces; recheck that original bytes remain
   unchanged at completion.
6. Return candidate/source hashes, diagnostics, foreign assumptions and
   explicit `applied=false`, `write_capability=false`,
   `transaction_atomicity=not_implemented`.

Compiled metadata and external compiler invocation can have temporary side
effects. No user program is executed by this preview. Hashes detect changes;
they are not signatures or proof of behavior equivalence. The preview does not
grant authority for a later write. A fresh validation is mandatory after edits.

## Next P7 acceptance gates

- Design a durable multi-file publication journal with recovery/rollback and
  crash consistency, rather than independent rename calls.
- Recheck source and dependency graph under cooperative project-wide locks,
  document behavior with noncooperating writers and symlink races.
- Validate failure injection before every prepare, staging, commit and
  recovery point.
- Add real-provider Agent benchmark comparisons and OS/device resource
  capability enforcement; hardware qualification remains open.

**Stage P7: PARTIAL / PREVIEW ONLY.** No atomic multi-file commit, functional
equivalence, or whole-language soundness claim follows from this work.
