#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP required}"
hia_prereq="$RUNNER_TEMP/hia-reference-prerequisites"
hia_prefix="$RUNNER_TEMP/hia-gcc15-host"
hia_lookup="$RUNNER_TEMP/hia-gcc15-host-bin"
mkdir -m 700 "$hia_prereq" "$hia_prefix" "$hia_lookup"
docker --host=unix:///var/run/docker.sock version > "$hia_prereq/docker-version.txt"
docker --host=unix:///var/run/docker.sock pull --platform=linux/amd64 docker.io/library/gcc:15.2.0-bookworm 2>&1 | tee "$hia_prereq/docker-pull.log"
docker --host=unix:///var/run/docker.sock image inspect docker.io/library/gcc:15.2.0-bookworm > "$hia_prereq/official-image-inspect.json"
hia_image_id=$(python3 -I -S -c 'import json,sys; d=json.load(open(sys.argv[1])); assert len(d)==1 and d[0]["Architecture"]=="amd64" and d[0]["Os"]=="linux" and d[0]["RepoDigests"]; print(d[0]["Id"])' "$hia_prereq/official-image-inspect.json")
hia_container_id=$(docker --host=unix:///var/run/docker.sock create --platform=linux/amd64 "$hia_image_id")
printf '%s\n' "$hia_container_id" > "$hia_prereq/extraction-container-id.txt"
trap 'docker --host=unix:///var/run/docker.sock rm "$hia_container_id" > "$hia_prereq/extraction-container-removal.log"' EXIT
docker --host=unix:///var/run/docker.sock cp "$hia_container_id:/usr/local/." "$hia_prefix"
test -x "$hia_prefix/bin/gcc"
ln -s "$hia_prefix/bin/gcc" "$hia_lookup/cc"
"$hia_prefix/bin/gcc" -dumpfullversion > "$hia_prereq/host-gcc-fullversion.txt"
test "$(cat "$hia_prereq/host-gcc-fullversion.txt")" = 15.2.0
"$hia_prefix/bin/gcc" -print-search-dirs > "$hia_prereq/host-gcc-search-dirs.txt"
hia_cc1=$("$hia_prefix/bin/gcc" -print-prog-name=cc1)
sha256sum "$hia_prefix/bin/gcc" "$hia_cc1" > "$hia_prereq/extracted-compiler-sha256.txt"
ldd "$hia_prefix/bin/gcc" > "$hia_prereq/host-gcc-dependencies.txt"
ldd "$hia_cc1" > "$hia_prereq/host-cc1-dependencies.txt"
