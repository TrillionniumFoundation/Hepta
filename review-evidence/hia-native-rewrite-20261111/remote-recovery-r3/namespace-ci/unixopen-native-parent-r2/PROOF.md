# UnixOpen parent: exact unsupported-break correction

Scope: new source revision only; no AST, HIA generation, B3, C, VM or native execution has occurred for this revision. FOLLOW45 remains FAIL.

The actual first failure in run 43201563676 / job 131126031828 was ValueError: Break() in the exact 0ef Builder.statements while generating author 3938a46974e38474a15a1f2b1816870590795532. The child completed in 365942258 ns with exit 1 and no timeout. All B3/C/VM/native counts in the returned original selected-fields report were zero. The complete original 4954-byte summary is retained in the original artifact; the console projection must not be relabelled as that complete file.

## Only semantic-source edit

The one loop in up_prepare changed from:

```python
        while pos + size < n:
            if byte(s, 512 + pos + size) == 0:
                break
            size = size + 1
```

to:

```python
        while pos + size < n and byte(s, 512 + pos + size) != 0:
            size = size + 1
```

The replacement is unique. Reversing it reproduces all 25163 original bytes, SHA256 bd38479ecb1532634e975c9a882b96bf03fb9c14c01d78e285b832443465ddb0, Git 3938a46974e38474a15a1f2b1816870590795532. New source is 25129 bytes, SHA256 85ef7614c08e85b15ccc585adabf0b6635a6ddc948e3409e3e9e475d98900bc4, Git 27868b292476e4049dd1b4194c3524041ea89953. The existing HIA logical module name and output filename remain unchanged; exact source and future produced-image pins distinguish revisions.

For each loop iteration, both forms first evaluate pos + size < n. If false, neither reads a byte. If true, both read exactly s[512 + pos + size]. A zero byte ends the loop without incrementing size; a nonzero byte increments size once and repeats. No store, syscall, continuation issue or error check moved. The unchanged size == n - pos rejection follows the same final size.

The exact reference Builder is Git 540de9366827900d0b82b4893922ffd383c44fef from 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5. Its BoolOp path permits eager evaluation only for inferred total scalar expressions. byte is a buffer.load intrinsic, is not a defined scalar function in source_program, and cannot enter total_scalar_functions. Therefore the right operand retains the explicit short-circuit CFG; no out-of-range read is introduced. Exact ObjectBuilder a188e9553b61ffc4293950908a71a93a3a9a27bb only overrides bulk copy/move calls and delegates this BoolOp to that Builder. These are source observations, not a generated-code or native proof.

The input manifest changes only this author's bytes/Git/SHA. The launcher changes only that manifest SHA and fresh r2 working/evidence directories; reversing these replacements reproduces the original launcher 71970abf47a972791fa572d794ad18773ad7211c exactly. The validator 33592c950e585eb37d7626ef2a9b2e7f76907421, fixtures feb06cbec0b1acf43ddbd43863cbf74a4bd55d28, exact six-body C reference 0836ba7d0a1a1817309a6ad54d902a5aa19786a9 and all dependencies remain byte-identical.

All original 85 semantic cases, 42 protocol controls and 88 expected C calls remain. The original aggregate 900 seconds, per-component 90 CPU / 180 wall / 1 GiB / core 0, VM 4000000 steps / 32 MiB / depth 64, B3 10 CPU / 20 wall / 256 MiB and 1 MiB output/workspace remain unchanged. No earlier result is inherited. Namespace effects remain explicit foreign providers; ordinary Store and real unixOpen peer closure remain OPEN.
