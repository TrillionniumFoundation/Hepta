"""Private eager legacy operations. No budget, persistent owner or public API.

Callers pass their current module-level parser/decoder callable explicitly so
legacy monkeypatch namespaces and Python evaluation order remain observable.
"""


class LegacyLoaderOps:
    def read(self, path, role):
        return path.read_bytes()

    def inventory(self, root):
        return root.rglob("*")

    def json(self, loads, data, path):
        return loads(data)

    def toml(self, loads, data, path):
        return loads(data.decode("utf-8"))

    def tokenize(self, tokenize, text, path):
        return tokenize(text, path)

    def parse(self, parse, text, path):
        # The legacy parser performs its own second lexing pass.
        return parse(text, path)


def dispatch(hook, original, implementation, ops, *args, **kwargs):
    """Preserve legacy replacement hooks, sharing ops only for original helpers.

    A replacement gets the exact old arguments, never an unexpected ops keyword.
    If it calls a captured public wrapper, that wrapper starts fresh stateless
    legacy operations. No custom-owner/budget guarantee is offered across hooks.
    """
    if hook is original:
        return implementation(*args, ops=ops, **kwargs)
    return hook(*args, **kwargs)
