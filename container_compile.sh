#!/usr/bin/env bash
set -euo pipefail
cd /hia-output
gcc -dumpfullversion > gcc-version.txt
test "$(cat gcc-version.txt)" = 15.2.0
gcc --version > gcc-version.stdout 2> gcc-version.stderr
gcc -v > gcc-configuration.stdout 2> gcc-configuration.stderr
ld --version > linker-version.stdout 2> linker-version.stderr
as --version > assembler-version.stdout 2> assembler-version.stderr
cp /etc/os-release container-os-release.txt
uname -a > container-uname.txt
hia_compiler=$(readlink -f "$(command -v gcc)")
hia_linker=$(readlink -f "$(command -v ld)")
hia_assembler=$(readlink -f "$(command -v as)")
hia_cc1=$(gcc -print-prog-name=cc1)
sha256sum "$hia_compiler" "$hia_linker" "$hia_assembler" "$hia_cc1" > toolchain-before.sha256
printf '%s\n' "$hia_compiler" -std=c11 -c -Os -fPIC -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fcf-protection=none -march=x86-64 -mtune=generic -Wall -Wextra /hia-input/original-note.c -o /hia-output/note.o > compile.argv.txt
timeout 30s "$hia_compiler" -std=c11 -c -Os -fPIC -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fcf-protection=none -march=x86-64 -mtune=generic -Wall -Wextra /hia-input/original-note.c -o /hia-output/note.o > compile.stdout 2> compile.stderr
printf '%s\n' "$hia_linker" -nostdlib -T /hia-input/original-note.ld -o /hia-output/note.elf /hia-output/note.o > link.argv.txt
timeout 30s "$hia_linker" -nostdlib -T /hia-input/original-note.ld -o /hia-output/note.elf /hia-output/note.o > link.stdout 2> link.stderr
timeout 30s objdump -d note.elf > disassemble.stdout 2> disassemble.stderr
sha256sum "$hia_compiler" "$hia_linker" "$hia_assembler" "$hia_cc1" > toolchain-after.sha256
cmp toolchain-before.sha256 toolchain-after.sha256
