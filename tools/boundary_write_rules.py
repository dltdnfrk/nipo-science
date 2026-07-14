"""Resolve write destinations across supported source-language analyzers."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Mapping

from tools.boundary_ast_rules import integer_expression, python_import_aliases
from tools.boundary_node_rules import find_node_writes
from tools.boundary_path_values import (
    CONFINED_RELATIVE,
    TEMPORARY_ROOT,
    PathContext,
    PathValue,
)
from tools.boundary_python_sinks import (
    OS_METHODS,
    SHUTIL_METHODS,
    python_write_expression,
)
from tools.boundary_shell_rules import WriteFinding, find_shell_writes

SHELL_SUFFIXES: Final = frozenset({".bash", ".sh", ".zsh"})
NODE_SUFFIXES: Final = frozenset({".cjs", ".js", ".mjs", ".mts", ".ts", ".tsx"})
MKSTEMP_PATH_INDEX: Final = 1


def resolve_expression(  # noqa: C901, PLR0911, PLR0912 -- recursive AST grammar.
    node: ast.expr, values: Mapping[str, PathValue], context: PathContext
) -> PathValue | None:
    """Resolve a bounded Python path expression to its static path value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return context.value(node.value)
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return context.value(str(context.source))
        return values.get(node.id)
    if isinstance(node, ast.BinOp):
        left = resolve_expression(node.left, values, context)
        right = resolve_expression(node.right, values, context)
        if isinstance(node.op, ast.Div):
            return context.join(left, right)
        if isinstance(node.op, ast.Add):
            return context.concat(left, right)
        return None
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        base = resolve_expression(node.value.value, values, context)
        if node.value.attr != "parents" or base is None:
            return base if node.value.attr == "parents" else None
        if not base.complete:
            return PathValue(raw=base.raw, escapes=True, complete=False)
        index_value = integer_expression(node.slice)
        if index_value is None:
            return PathValue(raw=base.raw, escapes=True, complete=False)
        parents = tuple(Path(base.raw).parents)
        normalized_index = (
            index_value if index_value >= 0 else len(parents) + index_value
        )
        if normalized_index < 0 or normalized_index >= len(parents):
            return None
        return context.value(str(parents[normalized_index]))
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base = resolve_expression(node.value, values, context)
        if base is None or not base.complete:
            return base
        return context.value(str(Path(base.raw).parent))
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return values.get(f"{node.value.id}.{node.attr}")
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name) and node.func.id in {
        "Path",
        "PurePath",
        "PurePosixPath",
    }:
        result = context.value("")
        for argument in node.args:
            result = context.join(result, resolve_expression(argument, values, context))
        return result
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr == "TemporaryDirectory":
        return context.value(TEMPORARY_ROOT)
    if node.func.attr == "enterContext" and node.args:
        return resolve_expression(node.args[0], values, context)
    base = resolve_expression(node.func.value, values, context)
    if node.func.attr == "relative_to" and node.args:
        walk_up = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "walk_up"),
            None,
        )
        if not (isinstance(walk_up, ast.Constant) and walk_up.value is True):
            return context.value(CONFINED_RELATIVE)
    if node.func.attr in {"absolute", "resolve"} and base is not None and base.complete:
        path = Path(base.raw)
        return context.value(str(path if path.is_absolute() else context.root / path))
    if node.func.attr == "expanduser":
        return base
    if (
        node.func.attr == "cwd"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "Path"
    ):
        return context.value(str(context.root))
    if node.func.attr != "joinpath":
        return None
    joined = base
    for argument in node.args:
        joined = context.join(joined, resolve_expression(argument, values, context))
    return joined


def collect_values(  # noqa: C901, PLR0912 -- assignment-flow grammar.
    tree: ast.AST, context: PathContext, before: tuple[int, int]
) -> dict[str, PathValue]:
    """Collect path-valued assignments that precede a candidate write call."""
    assignments: list[tuple[str, ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if (node.lineno, node.col_offset) >= before:
                continue
            assignments.extend(
                (target.id, node.value)
                for target in node.targets
                if isinstance(target, ast.Name)
            )
            assignments.extend(
                (f"{target.value.id}.{target.attr}", node.value)
                for target in node.targets
                if isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
            )
            if (
                isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "mkstemp"
            ):
                assignments.extend(
                    (
                        element.id,
                        ast.Constant(value=TEMPORARY_ROOT),
                    )
                    for target in node.targets
                    if isinstance(target, ast.Tuple)
                    for element in target.elts[
                        MKSTEMP_PATH_INDEX : MKSTEMP_PATH_INDEX + 1
                    ]
                    if isinstance(element, ast.Name)
                )
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            if (node.lineno, node.col_offset) >= before:
                continue
            assignments.append((node.target.id, node.value))
    values: dict[str, PathValue] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.arg == "root":
            values["root"] = context.value("")
        if isinstance(node, ast.arg) and node.arg == "tmp_path":
            values["tmp_path"] = context.value(TEMPORARY_ROOT)
    for node in ast.walk(tree):
        if not isinstance(node, ast.With) or (node.lineno, node.col_offset) >= before:
            continue
        for item in node.items:
            call = item.context_expr
            target = item.optional_vars
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "TemporaryDirectory"
                and isinstance(target, ast.Name)
            ):
                values[target.id] = context.value(TEMPORARY_ROOT)
    for _ in range(len(assignments) + 1):
        changed = False
        for name, expression in assignments:
            value = resolve_expression(expression, values, context)
            if value is not None and values.get(name) != value:
                values[name] = value
                changed = True
        if not changed:
            break
    return values


def find_python_writes(path: Path, root: Path, text: str) -> tuple[WriteFinding, ...]:
    """Find escaping write destinations in Python source text."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ()
    aliases = python_import_aliases(tree, SHUTIL_METHODS, OS_METHODS)
    context = PathContext(
        path.resolve(strict=False), root.resolve(strict=False), aliases
    )
    found: list[WriteFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        expression = python_write_expression(node, aliases)
        if expression is None:
            continue
        values = collect_values(tree, context, (node.lineno, node.col_offset))
        target = resolve_expression(expression, values, context)
        if target is not None and target.escapes:
            found.append(
                WriteFinding(
                    node.lineno, "Python write path resolves outside target root"
                )
            )
    return tuple(found)


def find_outside_writes(path: Path, root: Path, text: str) -> tuple[WriteFinding, ...]:
    """Dispatch boundary write analysis according to a source file suffix."""
    if path.suffix == ".py":
        return find_python_writes(path, root, text)
    if path.suffix in SHELL_SUFFIXES:
        return find_shell_writes(text, root.resolve(strict=False))
    if path.suffix in NODE_SUFFIXES:
        return find_node_writes(root.resolve(strict=False), text)
    return ()
