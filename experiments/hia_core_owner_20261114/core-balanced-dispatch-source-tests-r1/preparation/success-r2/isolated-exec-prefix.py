import os, sys
EXPECTED = {"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONHASHSEED":"0","PYTHONNOUSERSITE":"1"}
TARGET = ["/usr/bin/python3.14","-I","-S","-B","/home/qq/hia-rewrite-20261113-e26e-r1/core-balanced-dispatch-source-tests-r1-stage.py","--config","/home/qq/hia-rewrite-20261113-e26e-r1/core-balanced-dispatch-source-tests-r1-CONFIG.json","--sha256","d947170d1560e8b0709e68f9176db18263db22da1c7bfc11240ae1564395e84a"]
if (sys.executable != TARGET[0] or tuple(sys.version_info[:3]) != (3, 14, 4) or sys.flags.isolated != 1 or sys.flags.no_site != 1 or not sys.dont_write_bytecode or os.getcwd() != '/' or not all(os.environ.get(k) == v for k, v in EXPECTED.items())):
    raise SystemExit('isolated metadata launcher input mismatch')
os.execve(TARGET[0], TARGET, EXPECTED)
