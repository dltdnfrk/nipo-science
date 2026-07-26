"""Tests for the shipped front end and how it is served.

Every literal here is written out rather than imported from `webui`. A test
that asserted `response_csp == DOCUMENT_CSP` would agree with any policy the
module happened to hold, including one that had grown `'unsafe-inline'`.

Nothing is asserted by searching a path for a substring either: `tmp_path`
embeds the test's own function name, which has silently satisfied assertions
in this repository before.
"""

import re
from pathlib import Path

import pytest

from nipo_local.webui import (
    StaticSurface,
    default_web_root,
    inject_token,
)

ANCHOR = re.compile(rb'<meta name="nipo-local-token" content="([^"]*)">')

SHIPPED_ROOT = default_web_root()

DOCUMENT = (
    b"<!doctype html><html><head>"
    b'<meta name="nipo-local-token" content="">'
    b"</head><body></body></html>"
)


def _root(tmp_path: Path, document: bytes = DOCUMENT) -> Path:
    directory = tmp_path / "web"
    directory.mkdir()
    _ = (directory / "index.html").write_bytes(document)
    return directory


def test_the_shipped_document_carries_exactly_one_credential_anchor() -> None:
    payload = (SHIPPED_ROOT / "index.html").read_bytes()

    assert len(ANCHOR.findall(payload)) == 1
    # It ships empty. A credential committed into the repository would be a
    # credential in every checkout.
    assert ANCHOR.findall(payload) == [b""]


def test_the_shipped_front_end_is_a_flat_directory_of_served_suffixes() -> None:
    entries = sorted(item.name for item in SHIPPED_ROOT.iterdir())

    assert entries == ["app.js", "favicon.svg", "index.html", "styles.css"]
    assert all((SHIPPED_ROOT / name).is_file() for name in entries)


def test_the_shipped_script_sets_no_inline_style_attribute() -> None:
    # `style-src 'self'` has no `'unsafe-inline'`, so a style attribute the
    # script sets is refused by the browser and the layout quietly breaks.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'style: "' not in source
    assert 'setAttribute("style"' not in source
    assert ".style." not in source


def test_injecting_a_credential_replaces_only_the_anchor_value() -> None:
    injected = inject_token(DOCUMENT, "abc-123_XYZ")

    assert ANCHOR.findall(injected) == [b"abc-123_XYZ"]
    assert injected.replace(b"abc-123_XYZ", b"") == DOCUMENT


def test_injecting_escapes_a_value_that_could_close_the_attribute() -> None:
    # A `secrets.token_urlsafe` credential contains none of these, which is
    # exactly why the escape must be proven rather than assumed.
    injected = inject_token(DOCUMENT, '"><script>alert(1)</script>')

    assert b"<script>alert(1)</script>" not in injected
    assert b"&lt;script&gt;" in injected
    assert len(ANCHOR.findall(injected)) == 1


def test_injecting_into_a_document_without_an_anchor_is_refused() -> None:
    with pytest.raises(ValueError, match="anchor"):
        _ = inject_token(b"<!doctype html><html></html>", "value")


def test_a_root_without_a_document_is_refused_at_construction(tmp_path: Path) -> None:
    empty = tmp_path / "web"
    empty.mkdir()

    with pytest.raises(FileNotFoundError):
        _ = StaticSurface(empty)


def test_a_missing_root_is_refused_at_construction(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _ = StaticSurface(tmp_path / "absent")


def test_a_document_without_an_anchor_is_refused_at_construction(
    tmp_path: Path,
) -> None:
    # Serving it would produce a page that silently cannot authenticate, which
    # reads to a researcher as a launcher bug rather than a build one.
    with pytest.raises(ValueError, match="anchor"):
        _ = StaticSurface(_root(tmp_path, b"<!doctype html><html></html>"))


def test_the_served_paths_are_the_document_plus_each_shipped_leaf(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")
    _ = (directory / "app.js").write_bytes(b"//")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html", "/styles.css", "/app.js"})


def test_an_unserved_suffix_is_not_reachable(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / "notes.txt").write_bytes(b"private")
    _ = (directory / "nipo.sqlite3").write_bytes(b"database")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html"})
    assert surface.asset("/notes.txt") is None
    assert surface.asset("/nipo.sqlite3") is None


def test_a_dotfile_is_not_reachable(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / ".env.js").write_bytes(b"SECRET=1")

    assert StaticSurface(directory).asset("/.env.js") is None


def test_a_symlink_pointing_outside_the_root_is_not_served(tmp_path: Path) -> None:
    # The name is an ordinary leaf and the suffix is served, so only the
    # post-resolution containment check can reject this.
    outside = tmp_path / "outside.js"
    _ = outside.write_bytes(b"secret")
    directory = _root(tmp_path)
    (directory / "leak.js").symlink_to(outside)

    surface = StaticSurface(directory)

    assert surface.asset("/leak.js") is None
    assert surface.paths == frozenset({"/", "/index.html"})


def test_a_subdirectory_is_never_a_served_path(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    nested = directory / "vendor"
    nested.mkdir()
    _ = (nested / "lib.js").write_bytes(b"//")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html"})
    assert surface.asset("/vendor/lib.js") is None
    assert surface.asset("/vendor") is None


def test_both_document_paths_serve_the_same_bytes(tmp_path: Path) -> None:
    surface = StaticSurface(_root(tmp_path))

    root = surface.asset("/")
    named = surface.asset("/index.html")

    assert root is not None
    assert named is not None
    assert root.payload == named.payload
    assert root.is_document is True
    assert named.is_document is True


def test_only_the_document_carries_the_relaxed_policy(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")

    surface = StaticSurface(directory)

    document = surface.asset("/")
    stylesheet = surface.asset("/styles.css")
    assert document is not None
    assert stylesheet is not None
    assert document.content_security_policy == (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    assert stylesheet.content_security_policy == ""
    assert stylesheet.is_document is False


def test_the_document_policy_permits_only_self(tmp_path: Path) -> None:
    surface = StaticSurface(_root(tmp_path))
    document = surface.asset("/")
    assert document is not None
    policy = document.content_security_policy

    directives = dict(
        item.strip().split(" ", 1) for item in policy.split(";") if item.strip()
    )
    assert directives == {
        "default-src": "'none'",
        "script-src": "'self'",
        "style-src": "'self'",
        "connect-src": "'self'",
        "img-src": "'self'",
        "base-uri": "'none'",
        "form-action": "'none'",
        "frame-ancestors": "'none'",
    }
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    assert "http" not in policy
    assert "*" not in policy


def test_the_surface_is_a_snapshot_and_a_later_file_is_not_served(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    surface = StaticSurface(directory)

    _ = (directory / "late.js").write_bytes(b"//")

    assert surface.asset("/late.js") is None
    assert "/late.js" not in surface.paths


def test_a_document_replaced_after_startup_does_not_change_what_is_served(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    surface = StaticSurface(directory)
    _ = (directory / "index.html").write_bytes(b"<html>replaced</html>")

    document = surface.asset("/")

    assert document is not None
    assert document.payload == DOCUMENT


def test_the_default_root_is_the_shipped_front_end() -> None:
    root = default_web_root()

    assert root.is_dir()
    assert (root / "index.html").is_file()
    assert root.name == "local"
    assert root.parent.name == "web"


def test_served_returns_every_asset_in_path_order(tmp_path: Path) -> None:
    # The route builder iterates this, so it never handles an optional asset:
    # there is no unreachable branch for a missing one.
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")
    _ = (directory / "app.js").write_bytes(b"//")

    served = StaticSurface(directory).served()

    assert [item.path for item in served] == [
        "/",
        "/app.js",
        "/index.html",
        "/styles.css",
    ]
    assert {item.path for item in served} == StaticSurface(directory).paths
    assert [item.is_document for item in served] == [True, False, True, False]
