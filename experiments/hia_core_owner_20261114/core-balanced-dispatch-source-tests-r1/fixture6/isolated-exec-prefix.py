import os, sys
EXPECTED = {"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","PATH":"","PYTHONDONTWRITEBYTECODE":"1","PYTHONHASHSEED":"0","PYTHONNOUSERSITE":"1"}
TARGET = ["/usr/bin/python3.14","-I","-S","-B","/home/qq/hia-rewrite-20261113-e26e-r1/core-balanced-dispatch-source-tests-r1/control/launch.py","--request","/home/qq/hia-rewrite-20261113-e26e-r1/core-balanced-dispatch-source-tests-r1/control/REQUEST-fixture6.json","--sha256","c2c9210d70ba2525b5b8418b8431a9bb03b7c67c449055d93d36cbd9110efb1a"]
if (sys.executable != TARGET[0] or tuple(sys.version_info[:3]) != (3, 14, 4) or sys.flags.isolated != 1 or sys.flags.no_site != 1 or not sys.dont_write_bytecode or os.getcwd() != '/' or not all(os.environ.get(k) == v for k, v in EXPECTED.items())):
    raise SystemExit('isolated metadata launcher input mismatch')
os.execve(TARGET[0], TARGET, EXPECTED)
