"""Find statically escaping Node filesystem write destinations."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final, NamedTuple

from tools.boundary_shell_rules import WriteFinding


class NodeSink(NamedTuple):
    """Destination and optional write-flag positions for a Node filesystem API."""

    position: int
    flag_position: int | None = None
    fail_closed: bool = True


PATH_SINKS: Final = (
    "appendFileSync",
    "appendFile",
    "chmodSync",
    "chmod",
    "chownSync",
    "chown",
    "createWriteStream",
    "lchownSync",
    "lchown",
    "lchmodSync",
    "lutimesSync",
    "lutimes",
    "mkdirSync",
    "mkdir",
    "mkdtempSync",
    "mkdtemp",
    "mkdtempDisposableSync",
    "rmdirSync",
    "rmdir",
    "rmSync",
    "rm",
    "truncateSync",
    "truncate",
    "unlinkSync",
    "unlink",
    "utimesSync",
    "utimes",
    "writeFileSync",
    "writeFile",
)
DESTINATION_SINKS: Final = (
    "copyFileSync",
    "copyFile",
    "cpSync",
    "cp",
    "linkSync",
    "link",
    "renameSync",
    "rename",
    "symlinkSync",
    "symlink",
)
SINKS: Final = (
    *tuple((name, NodeSink(position=0)) for name in PATH_SINKS),
    *tuple((name, NodeSink(position=1)) for name in DESTINATION_SINKS),
    *(
        ("ftruncateSync", NodeSink(0, fail_closed=False)),
        ("ftruncate", NodeSink(0, fail_closed=False)),
        ("openSync", NodeSink(0, flag_position=1)),
        ("open", NodeSink(0, flag_position=1)),
    ),
)
OUTSIDE_RE: Final = re.compile(r"(?:^|[/\\\"'\s(,])\.\.(?:[/\\\"'\s),]|$)")
REQUIRE_RE: Final = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*require\([\"'](?:node:)?fs(?:/promises)?[\"']\)(?:\.promises)?"
)
STAR_IMPORT_RE: Final = re.compile(
    r"\bimport\s+\*\s+as\s+(?P<name>[A-Za-z_$][\w$]*)\s+from\s+[\"'](?:node:)?fs(?:/promises)?[\"']"
)
NAMED_IMPORT_RE: Final = re.compile(
    r"\bimport\s*\{(?P<names>[^}]*)\}\s*from\s*[\"'](?:node:)?fs(?:/promises)?[\"']"
)
DESTRUCTURED_RE: Final = re.compile(
    r"\b(?:const|let|var)\s*\{(?P<names>[^}]*)\}\s*=\s*require\([\"'](?:node:)?fs(?:/promises)?[\"']\)"
)
VALUE_RE: Final = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<quote>[\"'])(?P<value>.*?)(?P=quote)"
)
CALL_RE: Final = re.compile(
    r"\b(?P<callee>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((?P<args>.*)\)"
)


class NodeAliases(NamedTuple):
    """Resolved Node filesystem module, function, and static-value aliases."""

    modules: frozenset[str]
    functions: dict[str, NodeSink]
    values: dict[str, str]


def collect_aliases(text: str) -> NodeAliases:
    """Collect supported Node filesystem imports and static string values."""
    modules = {match.group("name") for match in REQUIRE_RE.finditer(text)}
    modules.update(match.group("name") for match in STAR_IMPORT_RE.finditer(text))
    sink_indexes = dict(SINKS)
    functions: dict[str, NodeSink] = {}
    for match in NAMED_IMPORT_RE.finditer(text):
        for raw in match.group("names").split(","):
            parts = raw.strip().split(" as ", maxsplit=1)
            if parts[0] == "promises" and len(parts) == len(("promises", "alias")):
                modules.add(parts[1])
            elif parts[0] in sink_indexes:
                functions[parts[-1]] = sink_indexes[parts[0]]
    for match in DESTRUCTURED_RE.finditer(text):
        for raw in match.group("names").split(","):
            parts = tuple(part.strip() for part in raw.split(":", maxsplit=1))
            if parts[0] == "promises" and len(parts) == len(("promises", "alias")):
                modules.add(parts[1])
            elif parts[0] in sink_indexes:
                functions[parts[-1]] = sink_indexes[parts[0]]
    values = {
        match.group("name"): match.group("value") for match in VALUE_RE.finditer(text)
    }
    return NodeAliases(frozenset(modules), functions, values)


def sink_for(callee: str, aliases: NodeAliases) -> NodeSink | None:
    """Resolve a call target to its Node filesystem sink specification."""
    parts = callee.split(".")
    if len(parts) == 1:
        return aliases.functions.get(callee)
    if parts[0] not in aliases.modules:
        return None
    promise_call_parts = 3
    method = (
        parts[2]
        if len(parts) == promise_call_parts and parts[1] == "promises"
        else parts[1]
    )
    return dict(SINKS).get(method)


def resolve_argument(
    arguments: tuple[str, ...], position: int, aliases: NodeAliases
) -> str | None:
    """Resolve a selected Node call argument to a static string value."""
    target = arguments[position] if len(arguments) > position else ""
    resolved = aliases.values.get(target)
    minimum_quoted_length = 2
    if (
        resolved is None
        and len(target) >= minimum_quoted_length
        and target[0] == target[-1]
        and target[0] in "\"'`"
    ):
        return target[1:-1]
    return resolved


def escapes_destination(raw: str, root: Path) -> bool:
    """Return whether a static Node destination escapes the target root."""
    candidate = Path(raw)
    if not candidate.is_absolute():
        return OUTSIDE_RE.search(raw.replace("\\", "/")) is not None
    try:
        _ = candidate.resolve(strict=False).relative_to(root)
    except ValueError:
        return True
    return False


def find_node_writes(root: Path, text: str) -> tuple[WriteFinding, ...]:
    """Find escaping Node filesystem calls in source text."""
    aliases = collect_aliases(text)
    found: list[WriteFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for call in (
            call
            for statement in line.split(";")
            for call in CALL_RE.finditer(statement)
        ):
            sink = sink_for(call.group("callee"), aliases)
            if sink is None:
                continue
            arguments = tuple(part.strip() for part in call.group("args").split(","))
            if sink.flag_position is not None:
                flags = resolve_argument(arguments, sink.flag_position, aliases)
                raw_flags = arguments[sink.flag_position]
                symbolic_write = any(
                    name in raw_flags
                    for name in (
                        "O_WRONLY",
                        "O_RDWR",
                        "O_CREAT",
                        "O_TRUNC",
                        "O_APPEND",
                        "O_EXCL",
                    )
                )
                symbolic_read = "O_RDONLY" in raw_flags and not symbolic_write
                if symbolic_read or (
                    flags is not None and not any(flag in flags for flag in "wax+")
                ):
                    continue
            resolved = resolve_argument(arguments, sink.position, aliases)
            if (resolved is None and sink.fail_closed) or (
                resolved is not None and escapes_destination(resolved, root)
            ):
                found.append(
                    WriteFinding(
                        line_number, "Node write path resolves outside target root"
                    )
                )
    return tuple(found)
