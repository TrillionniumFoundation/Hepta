# Release depot directory capability

`hia-release install|verify|attest DEPOT PACKAGE_SHA256` accepts either its existing absolute depot path or `fd:N`. In the latter form the caller passes an already-open directory descriptor to the process. `N` is a canonical decimal integer from 3 through 2147483647; leading zeros, signs, whitespace, suffixes and standard input/output/error descriptor numbers are rejected by the HIA argument policy.

HIA chooses the root form and parses the number. The fixed Linux adapter uses `openat(N, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` to obtain an independently owned open file description. It leaves the borrowed descriptor open. Both a readable directory FD and an `O_PATH` directory FD are supported. A closed FD, a regular-file FD, or an `O_PATH | O_NOFOLLOW` FD referring to a symlink is rejected. Resolution starts from the supplied capability; the original path can be renamed without redirecting the held directory to a replacement pathname.

Both forms enter the same existing HIA directory ownership and mode gate, package hash admission, file mode and inode checks, publication rules, directory identity checks, content comparison, source inventory attestation and receipt writer. The path form still opens every path component with `O_NOFOLLOW`. Passing a descriptor grants no exemption from these checks. The root-mode and descriptor fields occupy installer workspace offsets 160 and 168; they are cleared by ordinary path admission.

The selection adapter already shares the installer's admitted root-opening code and installer policy. Its generated packer is therefore regenerated with this change; `hia-select` consumes the same depot capability form without introducing a separate path parser.

## Verification

`tests/test_hia_release_install_fd.py` includes independent HIA VM checks of numeric admission and real ELF filesystem checks. Set `HIA_TEST_RELEASE_INSTALL_FD` to a source-compiled `hia-release` to enable native checks, and `HIA_TEST_RELEASE_SELECTION_FD` to the corresponding `hia-select` to check the shared root path. Native checks compare exact receipts and installed bytes/modes for ordinary paths, readable directory FDs and `O_PATH` FDs. They also exercise renamed roots, refused symlink/regular/closed FDs, unsafe directory permissions, unchanged attestation refusal semantics and preservation of the caller's descriptor.

These component checks do not replace the complete matching cold qualification or the separate whole-product acceptance gates.
