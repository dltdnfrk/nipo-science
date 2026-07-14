"""Find statically escaping write destinations in shell source."""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Mapping

OUTSIDE_COMPONENT_RE: Final = re.compile(r"(?:^|[/\\\s\"'])\.\.(?:[/\\]|$)")
ASSIGNMENT_RE: Final = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
VARIABLE_RE: Final = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
REDIRECT_RE: Final = re.compile(
    r"(?<![>&])(?:[0-9]*>>?)\s*(?![>&])(?P<target>\"[^\"]*\"|'[^']*'|[^\s;]+)"
)
COMMAND_MODES: Final = {
    "touch": "all",
    "cp": "last",
    "mv": "last",
    "mkdir": "all",
    "tee": "all",
    "rm": "all",
    "rmdir": "all",
    "chmod": "controlled",
    "chown": "controlled",
    "chgrp": "controlled",
    "ln": "linked",
    "install": "install",
    "truncate": "all",
    "mkfifo": "all",
    "mknod": "first",
    "rsync": "last",
    "dd": "dd",
    "sed": "in_place",
    "perl": "in_place",
}
VALUE_OPTIONS: Final = {
    "touch": frozenset({"-d", "-r", "-t", "--date", "--reference", "--time"}),
    "mkdir": frozenset({"-m", "--mode"}),
    "chmod": frozenset({"--reference"}),
    "chown": frozenset({"--from", "--reference"}),
    "chgrp": frozenset({"--reference"}),
    "install": frozenset(
        {"-g", "-m", "-o", "-t", "--group", "--mode", "--owner", "--target-directory"}
    ),
    "truncate": frozenset({"-r", "-s", "--reference", "--size"}),
    "mkfifo": frozenset({"-m", "--mode"}),
    "mknod": frozenset({"-m", "--mode"}),
    "rsync": frozenset(
        {"-e", "--exclude", "--include", "--rsh", "--rsync-path", "--temp-dir"}
    ),
    "sed": frozenset({"-e", "-f", "--expression", "--file"}),
    "perl": frozenset({"-e", "-I", "-M"}),
}
COMMAND_PREFIX: Final = r"(?:^|[;&|])\s*(?:command\s+)?(?:/usr/bin/|/bin/)?"
COMMAND_RE: Final = re.compile(
    rf"{COMMAND_PREFIX}(?P<command>{'|'.join(COMMAND_MODES)})\s+(?P<args>[^;&|]+)"
)


class WriteFinding(NamedTuple):
    """One source line whose write destination escapes the target root."""

    line: int
    detail: str


class _ParsedArguments(NamedTuple):
    paths: tuple[str, ...]
    option_targets: tuple[str, ...]
    explicit_program: bool


def expand_shell(raw: str, values: Mapping[str, str]) -> str:
    """Expand the bounded shell-variable grammar tracked by this analyzer."""
    expanded = raw.strip().strip("\"'")
    for _ in range(len(values) + 1):
        updated = VARIABLE_RE.sub(
            lambda match: values.get(match.group(1) or match.group(2), match.group(0)),
            expanded,
        )
        if updated == expanded:
            break
        expanded = updated
    return expanded


def _parse_arguments(
    command: str, arguments: tuple[str, ...], values: Mapping[str, str]
) -> _ParsedArguments:
    value_options = VALUE_OPTIONS.get(command, frozenset())
    operands: list[str] = []
    option_targets: list[str] = []
    explicit_program = False
    index = 0
    short_option_length = 2
    while index < len(arguments):
        argument = arguments[index]
        option = argument.split("=", maxsplit=1)[0]
        if command == "install" and option in {"-t", "--target-directory"}:
            raw_target = argument.split("=", maxsplit=1)[-1]
            if raw_target == argument and index + 1 < len(arguments):
                index += 1
                raw_target = arguments[index]
            option_targets.append(expand_shell(raw_target, values))
        if option in value_options:
            explicit_program = explicit_program or command in {"sed", "perl"}
            if (
                "=" not in argument
                and (len(argument) == short_option_length or option.startswith("--"))
                and index + 1 < len(arguments)
            ):
                index += 1
        elif argument == "--":
            operands.extend(
                expand_shell(item, values) for item in arguments[index + 1 :]
            )
            break
        elif not argument.startswith("-"):
            operands.append(expand_shell(argument, values))
        index += 1
    return _ParsedArguments(tuple(operands), tuple(option_targets), explicit_program)


def _select_targets(
    command: str, arguments: tuple[str, ...], parsed: _ParsedArguments
) -> tuple[str, ...]:
    mode = COMMAND_MODES[command]
    paths = parsed.paths
    selected = paths
    if mode == "dd":
        selected = tuple(item[3:] for item in paths if item.startswith("of="))
    elif mode == "in_place":
        enabled = any(
            argument == "--in-place" or argument.startswith("-i") or "i" in argument[1:]
            for argument in arguments
            if argument.startswith("-")
        )
        selected = (paths if parsed.explicit_program else paths[1:]) if enabled else ()
    elif mode == "controlled":
        uses_reference = any("reference" in argument for argument in arguments)
        selected = paths if uses_reference else paths[1:]
    elif mode == "linked":
        selected = paths[-1:] if len(paths) > 1 else ()
    elif mode == "install":
        selected = parsed.option_targets or paths[-1:]
    elif mode == "last":
        selected = paths[-1:]
    elif mode == "first":
        selected = paths[:1]
    return selected


def command_targets(
    command: str, raw: str, values: Mapping[str, str]
) -> tuple[str, ...]:
    """Return destination operands for a supported shell command."""
    try:
        arguments = tuple(shlex.split(raw, comments=True))
    except ValueError:
        return ()
    return _select_targets(
        command, arguments, _parse_arguments(command, arguments, values)
    )


def escapes_shell_target(target: str, root: Path | None) -> bool:
    """Return whether a shell destination is unknown or outside the target root."""
    if "$" in target:
        return True
    if target == os.devnull:
        return False
    candidate = Path(target)
    if candidate.is_absolute() and root is not None:
        try:
            _ = candidate.resolve(strict=False).relative_to(root)
        except ValueError:
            return True
        return False
    return OUTSIDE_COMPONENT_RE.search(target.replace("\\", "/")) is not None


def find_shell_writes(text: str, root: Path | None = None) -> tuple[WriteFinding, ...]:
    """Find escaping command and redirection destinations in shell text."""
    values: dict[str, str] = {}
    found: list[WriteFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        assignment = ASSIGNMENT_RE.match(line)
        if assignment is not None:
            raw_value = assignment.group(2)
            values[assignment.group(1)] = (
                ".boundary-temporary"
                if "mktemp -d" in raw_value
                else expand_shell(raw_value, values)
            )
        for redirect in REDIRECT_RE.finditer(line):
            target = expand_shell(redirect.group("target"), values)
            if escapes_shell_target(target, root):
                found.append(
                    WriteFinding(
                        line_number, "shell redirect resolves outside target root"
                    )
                )
        for command in COMMAND_RE.finditer(line):
            targets = command_targets(
                command.group("command"), command.group("args"), values
            )
            found.extend(
                WriteFinding(line_number, "shell command resolves outside target root")
                for target in targets
                if escapes_shell_target(target, root)
            )
    return tuple(found)
