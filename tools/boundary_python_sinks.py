"""Identify Python calls whose selected argument is a write destination."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, Final, NamedTuple

if TYPE_CHECKING:
    from tools.boundary_ast_rules import ImportAliases


class SinkSpec(NamedTuple):
    """The positional and keyword spellings of a destination argument."""

    position: int
    keyword: str


SHUTIL_METHODS: Final = frozenset({"copy", "copy2", "copyfile", "copytree", "move"})
OS_SPECS: Final = (
    ("mkdir", SinkSpec(0, "path")),
    ("makedirs", SinkSpec(0, "name")),
    ("remove", SinkSpec(0, "path")),
    ("unlink", SinkSpec(0, "path")),
    ("rmdir", SinkSpec(0, "path")),
    ("removedirs", SinkSpec(0, "name")),
    ("rename", SinkSpec(1, "dst")),
    ("replace", SinkSpec(1, "dst")),
    ("link", SinkSpec(1, "dst")),
    ("symlink", SinkSpec(1, "dst")),
    ("chmod", SinkSpec(0, "path")),
    ("chown", SinkSpec(0, "path")),
    ("truncate", SinkSpec(0, "path")),
)
OS_METHODS: Final = frozenset(name for name, _ in OS_SPECS)
PATH_RECEIVER_METHODS: Final = frozenset(
    {
        "chmod",
        "hardlink_to",
        "mkdir",
        "rmdir",
        "symlink_to",
        "touch",
        "unlink",
        "write_bytes",
        "write_text",
    }
)
PATH_TARGET_METHODS: Final = frozenset({"link_to", "rename", "replace"})


def call_argument(call: ast.Call, spec: SinkSpec) -> ast.expr | None:
    """Select a sink argument by its positional or keyword spelling."""
    if len(call.args) > spec.position:
        return call.args[spec.position]
    return next(
        (item.value for item in call.keywords if item.arg == spec.keyword), None
    )


def open_writes(call: ast.Call) -> bool:
    """Return whether a Python open call is statically write-capable."""
    mode_node: ast.expr | None = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return False
    if not isinstance(mode_node, ast.Constant) or not isinstance(mode_node.value, str):
        return True
    return any(flag in mode_node.value for flag in "wax+")


def os_spec(name: str) -> SinkSpec | None:
    """Look up an os mutation sink specification by method name."""
    return next((spec for method, spec in OS_SPECS if method == name), None)


def python_write_expression(  # noqa: C901, PLR0911 -- finite call-shape grammar.
    call: ast.Call, aliases: ImportAliases
) -> ast.expr | None:
    """Select the write-destination expression from a supported Python call."""
    if isinstance(call.func, ast.Name):
        if call.func.id == "open" and open_writes(call):
            return call_argument(call, SinkSpec(0, "file"))
        if call.func.id in aliases.shutil_functions:
            return call_argument(call, SinkSpec(1, "dst"))
        os_name = aliases.os_functions.get(call.func.id)
        spec = os_spec(os_name) if os_name is not None else None
        return call_argument(call, spec) if spec is not None else None
    if not isinstance(call.func, ast.Attribute):
        return None
    owner = call.func.value
    if (
        isinstance(owner, ast.Name)
        and owner.id in aliases.shutil_modules
        and call.func.attr in SHUTIL_METHODS
    ):
        return call_argument(call, SinkSpec(1, "dst"))
    if isinstance(owner, ast.Name) and owner.id in aliases.os_modules:
        spec = os_spec(call.func.attr)
        if spec is not None:
            return call_argument(call, spec)
    if call.func.attr in PATH_TARGET_METHODS:
        return call_argument(call, SinkSpec(0, "target"))
    if call.func.attr in PATH_RECEIVER_METHODS:
        return call.func.value
    if call.func.attr == "open" and open_writes(call):
        return call.func.value
    return None
