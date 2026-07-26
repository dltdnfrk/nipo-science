"""Serve the local front end from the listener's own origin.

The API guard requires every request to carry the exact session credential in
the custom `X-Nipo-Token` header. A browser cannot attach a custom header to a
top-level navigation, a `<link rel=stylesheet>`, or a `<script src>`, so the
page and its two assets are the one surface that credential cannot guard --
which is precisely why they must be served from the same origin as the API.
Any other arrangement puts the page on a foreign origin, where its `fetch`
calls become cross-origin, the custom header forces a preflight, and the guard
refuses every preflight. Same-origin is not a convenience here; it is the only
arrangement in which the credential works at all.

What replaces the credential on this surface
--------------------------------------------
Three of the guard's four controls still apply unchanged: loopback-only
binding, the pinned `Host` authority, and the accepted-`Origin` allow-list. In
place of the credential the guard applies `Sec-Fetch-Site` to *every* method
on these paths rather than only to state-changing ones, so a page on another
site cannot pull this document into an iframe, a script tag, or a top-level
navigation it controls. A cross-origin `fetch` could not read the response in
any case -- no `access-control-allow-origin` header is ever set -- and the
token this document carries is already readable by any process running as this
account, which SPEC-v0.5 section 11 discloses as the standing threat model.

Traversal is impossible rather than filtered
---------------------------------------------
There is no path parameter anywhere on this surface. :class:`StaticSurface`
enumerates the shipped directory once at startup, validates each leaf name,
confirms each resolved file really sits directly in the static root -- which
also rejects a symlink pointing out of it -- and hands `create_app` a fixed
mapping from exact request path to already-read bytes. A request path that is
not a key in that mapping never reaches the filesystem, so there is nothing
for `..`, an absolute path, a URL-encoded separator, or a symlink to traverse.

The document's CSP, and why it differs
---------------------------------------
API responses keep `default-src 'none'`, which is right for JSON that no
browser should ever load as a document. The document itself needs three
things and gets exactly those, each restricted to `'self'`:

* `script-src 'self'` and `style-src 'self'` load `app.js` and `styles.css`
  from this origin. There is no `'unsafe-inline'`, no `'unsafe-eval'`, and no
  remote host, so the page cannot execute a string and cannot reach a CDN.
* `connect-src 'self'` is what lets the page call its own API. Without it
  `default-src 'none'` would block every `fetch` and the UI would render an
  empty shell -- the page would load and nothing would work.
* `img-src 'self'` loads the shipped favicon and nothing else.

`base-uri 'none'` and `form-action 'none'` are added because an injected
`<base>` or form would otherwise be free to retarget relative URLs; both are
`'none'` because this page legitimately needs neither.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Final, final

__all__ = [
    "ASSET_MEDIA_TYPES",
    "DOCUMENT_CSP",
    "DOCUMENT_PATHS",
    "TOKEN_META_NAME",
    "StaticAsset",
    "StaticSurface",
    "default_web_root",
    "inject_token",
]

DOCUMENT_NAME: Final = "index.html"
DOCUMENT_PATHS: Final = ("/", "/index.html")
"""Both request paths that resolve to the credential-bearing document."""

TOKEN_META_NAME: Final = "nipo-local-token"  # noqa: S105 - a meta name, not a secret

# The exact anchor `index.html` ships. Matching the whole tag rather than the
# attribute alone means a document that lost the anchor fails loudly at
# startup instead of being served with an empty credential, which would look
# to a researcher like a launcher bug rather than a build one.
TOKEN_META_PATTERN: Final = re.compile(
    rb'<meta name="nipo-local-token" content="(?P<value>[^"]*)">'
)

# A single flat directory of ordinary asset names. No separator, no leading
# dot, no relative segment can satisfy this, so a name that matches cannot
# describe anything but a leaf inside the static root.
ASSET_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

ASSET_MEDIA_TYPES: Final = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}
"""Media types this surface will serve. A suffix absent here is not served."""

DOCUMENT_CSP: Final = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
"""The document policy. Every source is `'self'`; nothing is inline or remote."""

_MISSING_ROOT: Final = "local web root does not exist"
_MISSING_DOCUMENT: Final = "local web root has no index.html"
_MISSING_ANCHOR: Final = "index.html carries no nipo-local-token meta anchor"


def default_web_root() -> Path:
    """Return the shipped front-end directory beside this application.

    Resolved from this module's own location rather than from the working
    directory, so the served bytes are the ones installed next to the code
    that serves them no matter where the process was started.
    """
    return Path(__file__).resolve().parents[2] / "web" / "local"


@final
@dataclass(frozen=True, slots=True)
class StaticAsset:
    """One shipped file, its bytes, and the headers it is served with."""

    path: str
    media_type: str
    payload: bytes
    is_document: bool

    @property
    def content_security_policy(self) -> str:
        """Return this asset's policy.

        Only the document gets the relaxed policy. A stylesheet or script
        response carries the same `default-src 'none'` every API response
        carries, so nothing but the page itself is ever served under a policy
        that permits loading anything.
        """
        return DOCUMENT_CSP if self.is_document else ""


@final
class StaticSurface:
    """The fixed set of paths this listener serves outside `/api/v1`.

    Built once at startup. Every member is read from disk during construction,
    so a file added, replaced, or removed while the listener is running cannot
    change what is served, and no request ever performs a filesystem lookup
    derived from caller input.
    """

    __slots__ = ("_assets",)

    def __init__(self, root: Path | None = None) -> None:
        """Enumerate and read the shipped front end.

        Args:
            root: The directory holding `index.html`. Defaults to the shipped
                one beside this package.

        Raises:
            FileNotFoundError: The root or its document is missing.
            ValueError: The document carries no credential anchor, which
                would otherwise be served as a page that silently cannot
                authenticate.
        """
        directory = default_web_root() if root is None else root
        if not directory.is_dir():
            raise FileNotFoundError(_MISSING_ROOT)
        document = directory / DOCUMENT_NAME
        if not document.is_file():
            raise FileNotFoundError(_MISSING_DOCUMENT)
        payload = document.read_bytes()
        if TOKEN_META_PATTERN.search(payload) is None:
            raise ValueError(_MISSING_ANCHOR)
        assets: dict[str, StaticAsset] = {}
        for path in DOCUMENT_PATHS:
            assets[path] = StaticAsset(
                path=path,
                media_type=ASSET_MEDIA_TYPES[".html"],
                payload=payload,
                is_document=True,
            )
        for candidate in sorted(directory.iterdir()):
            asset = _readable_asset(directory, candidate)
            if asset is not None:
                assets[asset.path] = asset
        self._assets = assets

    @property
    def paths(self) -> frozenset[str]:
        """Return every request path this surface answers.

        `create_app` registers exactly these and the guard exempts exactly
        these from the credential check, so the two sets are one statement
        rather than two that could drift apart.
        """
        return frozenset(self._assets)

    def asset(self, path: str) -> StaticAsset | None:
        """Return the asset one exact request path names, or None."""
        return self._assets.get(path)

    def served(self) -> tuple[StaticAsset, ...]:
        """Return every asset this surface answers, in path order.

        The route builder iterates this rather than iterating `paths` and
        looking each one up, so it never handles an `asset()` that could be
        `None` -- there is no unreachable branch to leave unimplemented.
        """
        return tuple(self._assets[path] for path in sorted(self._assets))


def _readable_asset(root: Path, candidate: Path) -> StaticAsset | None:
    """Return one servable asset, or None when the entry is not one.

    Three independent conditions must all hold: the name is an ordinary leaf,
    the suffix is one this surface serves, and the *resolved* file sits
    directly in the resolved root. The third is what rejects a symlink
    pointing outside the tree, and it is checked after resolution rather than
    on the name, because a name cannot tell you where a link goes.
    """
    name = candidate.name
    if ASSET_NAME.match(name) is None:
        return None
    media_type = ASSET_MEDIA_TYPES.get(candidate.suffix)
    if media_type is None:
        return None
    resolved = candidate.resolve()
    if resolved.parent != root.resolve() or not resolved.is_file():
        return None
    return StaticAsset(
        path=f"/{name}",
        media_type=media_type,
        payload=resolved.read_bytes(),
        is_document=name == DOCUMENT_NAME,
    )


def inject_token(document: bytes, token: str) -> bytes:
    """Return the document carrying one session credential in its meta anchor.

    The meta element is preferred over a URL fragment: a fragment survives in
    the address bar until a script removes it, lands in browser history, and
    is readable over a shoulder. A meta value is never sent to a server, never
    appears in a `Referer`, and `app.js` blanks it the moment it is read, so
    the credential is not recoverable from the DOM afterwards.

    The value is HTML-escaped before substitution. A `secrets.token_urlsafe`
    credential contains nothing that needs escaping, which is exactly why the
    escape must be here rather than assumed: a future credential shape must
    not be able to close the attribute and inject markup.

    Args:
        document: The shipped `index.html` bytes.
        token: The per-run session credential.

    Returns:
        The document with the credential substituted into its anchor.

    Raises:
        ValueError: The document carries no anchor to substitute into.
    """
    if TOKEN_META_PATTERN.search(document) is None:
        raise ValueError(_MISSING_ANCHOR)
    replacement = (
        f'<meta name="{TOKEN_META_NAME}" content="{escape(token, quote=True)}">'
    ).encode()
    return TOKEN_META_PATTERN.sub(lambda _match: replacement, document, count=1)
