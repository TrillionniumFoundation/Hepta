"""Pure, exact historical view for two declared source-name migrations.

The caller supplies physically captured current bytes. This function performs
no I/O and authorizes no compilation. Callers retain current bytes and hashes
for initial/terminal custody; only the named historical assertion uses this view.
"""
from hashlib import sha256

def prior_take(name, actual):
    if type(name) is not str or type(actual) is not bytes:
        raise TypeError("historical source view requires an exact path and bytes")
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
