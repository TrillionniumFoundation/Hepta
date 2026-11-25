# Native installer publication

The post-cold source bootstrap now constructs and publishes `hia-release` directly from HIA source. This closes the bootstrap extraction gap: installation can start from the public bootstrap output without a host language extracting an executable from `store.hiapack`.

## Construction and trust

The original seven-product graph remains recorded independently at 1,699 nodes and 43 imports. The extension has 1,832 nodes, 45 imports and eight products. It preserves the seven publication names and order, and appends `hia-release`. Its first seven actual output files are byte-for-byte equal to the qualified original graph on the same captured source.

The graph first executes the current-source, full-cold `HIACLD01` admission. Only then does the admitted B3 compile `release_install_policy.hepta`, `release_install_packer.hepta` and the existing `sha256_stream.hepta`. The HIA packer combines the actual resulting policy and SHA code in the existing `HIAINS01` frame and checks the resulting ELF. No extra initial trusted root is introduced. The installer policy, syscall adapter, package limits and receipt contract are unchanged.

After the extended public bootstrap has been qualified on its matching final source, the ordinary path is:

```sh
"$BOOT/hia-release" install "$DEPOT" "$PACKAGE_SHA256" < "$PACKAGE"
"$DEPOT/$PACKAGE_SHA256/hia-release" verify "$DEPOT" "$PACKAGE_SHA256" < "$PACKAGE"
```

The installation creates one content-addressed directory. It does not activate a service or change another provider.

## Actual qualification and limits

The complete new graph ran natively against the captured P2 source, including its actual cold admission, in 13.883 seconds with one initial `execve` and 246 sealed `execveat` calls. The driver retained and hashed the complete 39,109,876-byte journal. All original seven files matched the independently retained baseline. The new 185,462-byte installer also matched the separately native-constructed installer and the current package member exactly.

That native installer then installed and the installed copy verified the real 158,739,532-byte, 288-member P2 package. Every file, mode, ownership, link count and inventory entry matched the actual package. The QA reader inspected bytes for comparison; it did not write an installer extracted from the package.

These are component and isolated-depot results. The final aggregate must regenerate its source authority, recipes and strict contract, then execute the extended public entry using that exact source's complete cold report. The previous P2 cold report does not attest the changed recipe or a future aggregate. Worker registration, installed source rebuild and the remaining final HTTP/public-proof/MV/bounded integration have separate gates. Detailed hashes and the frozen baseline are in `HIA_NATIVE_INSTALLER_PUBLICATION.json`.
