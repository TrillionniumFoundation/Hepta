# Native release directory capabilities

The directory packager accepts either its existing absolute directory path or
fd:N, where N is a decimal inherited descriptor from 3 through 2147483647.
HIA parses the complete spelling; leading zeroes, signs, suffixes and embedded
NUL bytes are rejected. The descriptor must name a directory.

The fixed Linux transport opens "." relative to this descriptor with
O_DIRECTORY and O_NOFOLLOW. This creates an independent open file description,
so enumeration never changes the caller's directory offset. This interface
does not traverse /proc/self/fd and does not weaken the absolute path walk.

All existing HIA admission remains in force: owned private stage directory,
ordinary single-link members, permitted names and modes, bounded extents,
before/after identity checks, package layout and SHA-256. Admission completes
before package bytes are published. For the same directory, either entry mode
produces identical bytes and the same 65-byte digest receipt.

The input descriptor must survive the executable's launch. Native callers using
HIASUB01 list it in the HIAPFD01 trailer. No environment lookup, shell, Python,
libc or child process is required by the directory packager.

The descriptor slot is workspace offset 3104, outside the directory policy
metadata, entry table and syscall/SHA scratch slots. It is read only during
initial directory selection. The source and kernel tests compile the current
HIA policy and packer through the self-hosted compiler before exercising the
same byte comparison and refusal cases.
