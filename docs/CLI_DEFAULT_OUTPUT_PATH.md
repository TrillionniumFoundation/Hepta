# Check the resolved default build destination

The default ordinary `build` output now goes through the same path resolution
as an explicit `-o` destination before the existing known-input check.

## Reproduced difference

On the original #668 source, a regular package could contain a local file
symlink at `src/build/main` pointing to its own `hepta.toml`. This was the
default output path for `src/main.hepta`.

```sh
python -m hepta build app --locked --backend c
```

The command reported success and replaced the manifest with an executable.
The equivalent explicit `-o app/src/build/main` correctly rejected it with
`E_DRIVER`, preserving the manifest. The same default-path omission affected
other protected inputs. A standalone source graph also demonstrated a build
directory alias selecting an imported source.

These observations used only self-created temporary projects and ordinary
local symlinks. There were no concurrent changes or access-control operations.
Actual GCC compiled the finite scalar fixture. The path-selection omission
predates #668; its green ordinary-output tests did not cover this case.

## Minimal correction

After choosing either the explicit or default destination, the driver calls
`Path.resolve()` and checks that resolved path against the unchanged protected
set. Both native backends already resolve their requested artifact paths, so
the correction makes the earlier driver check inspect the intended stable
destination instead of its unresolved spelling.

The input boundary, `E_DRIVER` diagnostic, exit status 2, and backend
publication behavior are unchanged. Ordinary new/existing default outputs and
aliases to permitted non-input outputs remain supported. Native validation can
still run before the output guard. Package source-directory symlink rejection
is preserved; the standalone directory-alias control does not alter that rule.

## Explicit limits

This is not a filesystem security or atomic-observation mechanism. Concurrent
retargeting between checking and use remains outside its guarantees. No
directory-descriptor or inode-bound publication protocol is added.

`Path.resolve()` does not identify different hardlink names as the same inode.
This change does not establish hardlink input protection, including for other
output commands. Ordinary build publication uses `os.replace`, so replacing a
single hardlink directory entry does not itself imply changing the contents
visible through its sibling links. That distinction is not a broader hardlink
qualification, and no hardlink or race experiments are added here.

The change does not expand low-level backend input guards, foreign-link input
inventory, whole-language soundness or production readiness. Tests and hosted
results must remain bound to this exact source rather than inherited #668 CI.
