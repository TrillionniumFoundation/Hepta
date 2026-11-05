#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Reproduce the official out-of-tree application build. No installation.
# SOURCE, ARCHIVE, BUILD, CC, and (if not system-installed) PKG_CONFIG are inputs.
# DEP_PREFIX is the local extracted Ubuntu development dependency prefix.
set -euo pipefail
: "${SOURCE:?set SOURCE to the extracted official source}"
: "${ARCHIVE:?set ARCHIVE to the release tar.gz}"
: "${BUILD:?set BUILD to a new build directory}"
: "${CC:?set CC to the same Clang20 compiler as the HIA object}"
TASK_REPO=$(cd "$(dirname "$0")/../.." && pwd)
export SOURCE ARCHIVE
python3 - "$TASK_REPO" <<'PY'
import importlib.util,os,sys
from pathlib import Path
p=Path(sys.argv[1])/'tools/openvpn_hia_baseline.py'
s=importlib.util.spec_from_file_location('baseline',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=m.source_freeze(Path(os.environ['SOURCE']),Path(os.environ['ARCHIVE']))
print('verified official source files:',r['source_closure_files_verified'])
PY
if [[ -n "${DEP_PREFIX:-}" ]]; then
 export LIBCAPNG_CFLAGS="-I$DEP_PREFIX/usr/include"
 export LIBCAPNG_LIBS=/usr/lib/x86_64-linux-gnu/libcap-ng.so.0
 export LIBNL_GENL_CFLAGS="-I$DEP_PREFIX/usr/include/libnl3"
 export LIBNL_GENL_LIBS='/usr/lib/x86_64-linux-gnu/libnl-genl-3.so.200 /usr/lib/x86_64-linux-gnu/libnl-3.so.200'
fi
mkdir -p "$BUILD"
cd "$BUILD"
if [[ -e config.status || -e build.log ]]; then
 echo 'refusing to overwrite an existing build; choose a new BUILD' >&2
 exit 2
fi
BASELINE_CFLAGS='-O3 -g -fno-omit-frame-pointer'
BASELINE_LDFLAGS=''
if [[ "${PROFILE:-0}" == 1 ]]; then
 BASELINE_CFLAGS+=' -pg'
 BASELINE_LDFLAGS='-pg'
fi
"$SOURCE/configure" --disable-lzo --disable-lz4 --disable-plugin-auth-pam \
 --disable-plugin-down-root --disable-unit-tests "CFLAGS=$BASELINE_CFLAGS" \
 "LDFLAGS=$BASELINE_LDFLAGS" > configure.log 2>&1
make -j"${JOBS:-2}" > build.log 2>&1
"$BUILD/src/openvpn/openvpn" --version > version.log
python3 - "$BUILD" <<'PY'
from pathlib import Path
import hashlib,json,sys
p=Path(sys.argv[1]);c=(p/'config.h').read_text()
if '#define ENABLE_DCO 1' not in c: raise SystemExit('DCO compile support was not enabled')
files=['config.h','config.status','src/openvpn/openvpn','configure.log','build.log','version.log']
(p/'build-hashes.json').write_text(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in files},indent=2)+'\n')
print('official build completed; DCO compiled; runtime DCO not implied')
PY
