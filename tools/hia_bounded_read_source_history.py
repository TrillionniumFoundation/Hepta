"""Pure, exact historical views for declared caller and native-owner migrations.

The caller supplies physically captured current bytes. This function performs
no I/O and authorizes no compilation. Callers retain current bytes and hashes
for initial/terminal custody; only the named historical assertion uses this view.
"""
from hashlib import sha256

def prior_take(name, actual):
    if type(name) is not str or type(actual) is not bytes:
        raise TypeError("historical source view requires an exact path and bytes")
    if name in _NATIVE_OWNER_RELATIONS:
        return _native_owner_prior_take(name, actual)
    if name == "tests/test_hia_program_tools.py":
        current_sha = "3f637a36f31b92d014c846e61994741e251011e53b50dd1468e65c212f3482b5"
        prior_sha = "8e885163d57ec41e869d5b8cb206de1b9942e0c636bcacf3b362bd5e669317c6"
        old, new, count = b'.hia"', b'.hepta"', 6
    elif name == "tools/hia_core_reference.py":
        current_sha = "570ec458a3bd66a5b068cdd7132155e1860d87c48a839bdf402f93ecd2cc140f"
        prior_sha = "596b331db95ad2ebd3dba637fc4c34e8d2b0129bef63f8858edf02961e752aa4"
        old = b"stage = Path(temporary) / 'program.hiaasm'"
        new = b"stage = Path(temporary) / 'program.hepta'"
        count = 1
    else:
        raise ValueError("source path has no fixed original caller relation")
    if sha256(actual).hexdigest() != current_sha or actual.count(new) != count:
        raise ValueError("current physical caller bytes differ from fixed relation")
    prior = actual.replace(new, old)
    if sha256(prior).hexdigest() != prior_sha:
        raise ValueError("complete original caller bytes differ from fixed relation")
    return prior


_NATIVE_OWNER_RELATIONS = {'hepta/hia_program_tools.py': ('fa0d5f4dd465858c910f93afed7d309ae8a376b12904f714321860ebc91ae0ac', 'f25118745cd5eb4a9b9023f531812597b776196498591232f49d5bc93966c501', ((1993, 1993, b'', b'# Preserve the exact original function/code for fallback and environment\n# observation. The selected native owner never invokes its policy body.\n'), (2030, 2031, b'\n', b''), (2070, 2070, b'', b'\n'), (2641, 2641, b'', b'\n'), (6653, 6741, b"')\n    if selected == '':\n        raise ValueError('JSON wire selector must not be empty", b''), (23198, 23201, b'ept', b'i'))), 'hepta/hia_bounded_read_native.py': ('b8a9fe6b74679f0e4dbdef1f6c7432dee2886d634ddb4bb04bd664a158b9cbfb', '2fca4080ee7c87de9e5dbb3eeb0e8f80693715cfde993f88d82ffca2dd45f6d3', ((1259, 1262, b'ept', b'i'), (1263, 1263, b'', b'asm'))), 'tools/generate_hia_bounded_read.py': ('2f02ca3a5994b01e49d77f670813e976647558185cc738b99a76912556fbb2dc', '425244f1745d0ac028a752b69fff54d88451c265f435a7dde7fc72b02d42d378', ((10371, 10374, b'ept', b'i'), (10375, 10375, b'', b'asm')))}

def _native_owner_prior_take(name, actual):
    current_sha, prior_sha, edits = _NATIVE_OWNER_RELATIONS[name]
    if sha256(actual).hexdigest() != current_sha:
        raise ValueError("current physical native owner differs from fixed relation")
    result, cursor = [], 0
    for start, end, expected, replacement in edits:
        if not 0 <= cursor <= start <= end <= len(actual) or actual[start:end] != expected:
            raise ValueError("fixed native owner source relation differs")
        result.extend((actual[cursor:start], replacement))
        cursor = end
    result.append(actual[cursor:])
    prior = b"".join(result)
    if sha256(prior).hexdigest() != prior_sha:
        raise ValueError("complete original native owner bytes differ")
    return prior
