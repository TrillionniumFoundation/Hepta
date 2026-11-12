#!/usr/bin/env python3
"""Finite scalar witnesses for already validated, locally produced leaf images."""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import sys


def main():
    request = json.loads(sys.stdin.read())
    if set(request) != {"image", "image_sha256", "argument_count", "vectors"}:
        raise ValueError("unexpected native witness request")
    path = Path(request["image"]).resolve(strict=True)
    digest = sha256(path.read_bytes()).hexdigest()
    if digest != request["image_sha256"]:
        raise ValueError("exact validated image changed before native witness")
    count, vectors = request["argument_count"], request["vectors"]
    if type(count) is not int or not 1 <= count <= 6 or not 1 <= len(vectors) <= 256:
        raise ValueError("scalar witness budget exceeded")
    for vector in vectors:
        if (type(vector) is not list or len(vector) != count or
                any(type(word) is not int or not 0 <= word < 1 << 64 for word in vector)):
            raise ValueError("invalid scalar ABI word")
    library = ctypes.CDLL(str(path), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    function = library.choose
    function.argtypes = [ctypes.c_uint64] * count
    function.restype = ctypes.c_uint64
    results = [int(function(*vector)) for vector in vectors]
    if sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("native image changed during finite witnesses")
    print(json.dumps({"image_sha256": digest, "vectors": vectors,
                      "results": results, "finite_witnesses_only": True}, sort_keys=True))


if __name__ == "__main__":
    main()
