# C header logical-line inventory

## Reproduced failures

On unchanged integration base `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`,
the public importer accepted incomplete or fictitious declaration inventories:

1. The exact bytes `int before(void); // license\rint after(void);\r`
   produce only `before`; real GCC C11 preprocessing retains both functions.
   A leading line comment can similarly hide typedefs, records, constants or
   unsupported declarations without producing an import error.
2. This valid C header retains both functions under GCC, but imports only `kept`:

   ```c
   // continued \
   /*
   int lost(void);
   // */
   int kept(void);
   ```

   C forms logical lines before recognizing comments. The old regex instead
   treats `/*` as a block-comment start. A varargs declaration in the same
   location is silently omitted instead of receiving the required error.
3. `// disabled \\\nint getchar(void);\nint kept(void);\n` comments out
   `getchar` in C, but the old importer emits a binding for it. The native probe
   preincludes `stdio.h`, so its existing type-compatibility check can succeed
   using the unrelated preincluded declaration. The same issue occurs with
   C11 `??/` and GCC whitespace-continuation extensions inside comments.
   Independent review also reproduced the same ghost binding with a NUL between
   the raw/trigraph backslash and newline: GCC silently ignores that NUL.
4. Python `splitlines()` treated form feed, vertical tab and other non-C line
   separators as directive boundaries. A guarded `#define API_H` followed by
   such a separator and `int getchar(void);` could invent a binding even though
   GCC sees only an unused macro replacement, not a function declaration.

These are actual public-API results, not just regex examples. The tests compare
original headers with real `gcc -std=c11 -Werror -E -P`, and use real header
probes. No incompatible foreign call is needed to demonstrate the defect.

## Minimum repair and compatibility

Reject NUL-containing headers before parsing, including NUL inside comments.
Normalize CRLF and CR to LF in the parser's private text only. Before removing
comments, reject a raw backslash or `??/` followed by optional ASCII horizontal
whitespace and a newline. The error is `E_C_IMPORT_PREPROCESSOR`, before any
compiler process or binding publication. Flatten continued lines explicitly if
they are needed. Previously accepted continued comments may now reject; this is
intentional conservative admission, not new continuation support.
Split the resulting directives only on LF, not Python's broader line separators.

The original header bytes, native probe flags, type/layout checks, identity
hashes, effect assumptions, output schema and block-comment processing remain
unchanged. Neither a preprocessor nor a complete C parser is being introduced.
The [GCC initial-processing reference](https://gcc.gnu.org/onlinedocs/cpp/Initial-processing.html)
describes the newline, trigraph, continuation and comment ordering behind these
controls. The tests also check actual GCC behavior rather than relying solely
on the reference, especially its whitespace extension inside line comments.

## Repeatable checks

```sh
python -B tools/test_c_import_logical_lines.py
```

The strict runner requires real GCC and exactly 43 unique tests: 24 new logical
line controls and all 19 existing importer, typedef, prototype and bounded-probe
tests. It records planned/executed identities and rejects skips, expected
failures, unexpected successes and incomplete execution.

New controls cover CR/LF/CRLF/mixed headers, native declaration inventories,
unsupported active declarations, raw/trigraph/whitespace continuations,
comment delimiters, original-byte hashes, unchanged block-comment macro rules,
the public CLI, refusal before probing, absence of partial CLI files, and an
actual generated-C consumer linked and executed against the original CR header.
Subcases are not separate test methods.

The dedicated workflow runs the exact PR head on Linux x86-64 and ARM64 and
preserves compiler/source identities and original test output. These finite
native GCC controls are not Rust-backend, cross-target ABI, arbitrary
preprocessor, foreign-memory-safety or whole-project qualification. This change
does not compose other pending fixes or alter Part03 source/proof work.
