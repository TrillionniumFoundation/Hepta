"""Private eager legacy operations. No budget, persistent owner or public API.

Callers pass their current module-level parser/decoder callable explicitly so
legacy monkeypatch namespaces and Python evaluation order remain observable.
"""


class LegacyLoaderOps:
    def hook(self, hook, original):
        """Private admission seam; legacy replacement behavior is unchanged."""

    def revalidation_hook(self, project, original):
        """Private admission seam before resolving a revalidation descriptor."""

    def edge(self, kind, depth):
        """Private graph-work admission; legacy traversal has no quota."""

    def node(self, kind):
        """Private admission before retaining a new traversal node."""

    def path(self, path, operation):
        """Preserve the original Path method; experimental ops may admit it."""
        return getattr(path, operation)()

    def deepcopy(self, deepcopy, value):
        """Preserve the captured copy callable and its original argument."""
        try:
            return deepcopy(value)
        finally:
            # Do not retain temporary callables/arguments in failure tracebacks.
            # Match direct call cleanup order: callable, then argument.
            del deepcopy, value

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

    def scan_receipt(self):
        # Do not retain legacy tokenize iterables or change their finalization.
        return None

    def parse_admitted(self, parse, text, path, tokens):
        # Legacy intentionally ignores scan tokens and performs its second lex.
        return self.parse(parse, text, path)


def dispatch(hook, original, implementation, ops, *args, **kwargs):
    """Preserve legacy replacement hooks, sharing ops only for original helpers.

    A replacement gets the exact old arguments, never an unexpected ops keyword.
    If it calls a captured public wrapper, that wrapper starts fresh stateless
    legacy operations. No custom-owner/budget guarantee is offered across hooks.
    """
    ops.hook(hook, original)
    if hook is original:
        return implementation(*args, ops=ops, **kwargs)
    return hook(*args, **kwargs)
