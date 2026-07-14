"""Shared typed AST primitives for Python boundary analysis."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Mapping


class ImportAliases(NamedTuple):
    """Imported names that may dispatch to filesystem mutation APIs."""

    shutil_modules: frozenset[str]
    shutil_functions: Mapping[str, str]
    os_modules: frozenset[str]
    os_functions: Mapping[str, str]


def python_import_aliases(  # noqa: C901 -- explicit import-shape grammar.
    tree: ast.AST, shutil_sinks: frozenset[str], os_sinks: frozenset[str]
) -> ImportAliases:
    """Collect shutil and os module and function aliases from a Python tree."""
    shutil_modules: set[str] = set()
    shutil_functions: dict[str, str] = {}
    os_modules: set[str] = set()
    os_functions: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name == "shutil":
                    shutil_modules.add(item.asname or item.name)
                if item.name == "os":
                    os_modules.add(item.asname or item.name)
        if isinstance(node, ast.ImportFrom) and node.module == "shutil":
            for item in node.names:
                if item.name in shutil_sinks:
                    shutil_functions[item.asname or item.name] = item.name
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for item in node.names:
                if item.name in os_sinks:
                    os_functions[item.asname or item.name] = item.name
    return ImportAliases(
        frozenset(shutil_modules), shutil_functions, frozenset(os_modules), os_functions
    )


def integer_expression(  # noqa: PLR0911 -- bounded operator grammar.
    node: ast.AST,
) -> int | None:
    """Evaluate the bounded integer expression grammar used for parent indices."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp):
        operand = integer_expression(node.operand)
        if operand is None:
            return None
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return operand
        return ~operand if isinstance(node.op, ast.Invert) else None
    if isinstance(node, ast.BinOp):
        left = integer_expression(node.left)
        right = integer_expression(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        return None
    children = tuple(ast.iter_child_nodes(node))
    return integer_expression(children[0]) if len(children) == 1 else None
