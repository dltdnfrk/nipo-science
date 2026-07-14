"""Options-heavy shell mutation fixtures for boundary-checker tests."""

from __future__ import annotations

OUTSIDE = ".." + "/shared/out"
ABSOLUTE_OUTSIDE = "/Users/hyunjun/Documents/MUNI/shared/out"

MUTATION_COMMANDS = (
    ("rm", f"rm -rf {OUTSIDE}"),
    ("rmdir", f"rmdir --ignore-fail-on-non-empty {OUTSIDE}"),
    ("chmod", f"chmod -R 755 {OUTSIDE}"),
    ("chown", f"chown -R 1000:1000 {OUTSIDE}"),
    ("chgrp", f"chgrp -R staff {OUTSIDE}"),
    ("ln", f"ln -s source {OUTSIDE}"),
    ("install", f"install -m 755 source {OUTSIDE}"),
    ("truncate", f"truncate -s 0 {OUTSIDE}"),
    ("mkfifo", f"mkfifo -m 600 {OUTSIDE}"),
    ("mknod", f"mknod {OUTSIDE} p"),
    ("rsync", f"rsync -a source/ {OUTSIDE}/"),
    ("dd", f"dd if=source of={OUTSIDE}"),
    ("sed", f"sed -i.bak 's/a/b/' {OUTSIDE}"),
    ("perl", f"perl -pi -e 's/a/b/' {OUTSIDE}"),
    ("indented-rm", f"  rm -rf {OUTSIDE}"),
    ("chained-chmod", f"true &&   chmod -R 755 {OUTSIDE}"),
    ("absolute-rm", f"/bin/rm -rf {OUTSIDE}"),
    ("command-rm", f"command rm -rf {OUTSIDE}"),
    ("command-absolute-rm", f"command /bin/rm -rf {OUTSIDE}"),
    ("absolute-path-rm", f"rm -rf {ABSOLUTE_OUTSIDE}"),
)

SAFE_MUTATION_COMMANDS = (
    ("rm", "rm -rf artifacts/out"),
    ("rmdir", "rmdir --ignore-fail-on-non-empty artifacts/out"),
    ("chmod", "chmod -R 755 artifacts/out"),
    ("chown", "chown -R 1000:1000 artifacts/out"),
    ("chgrp", "chgrp -R staff artifacts/out"),
    ("ln", "ln -s source artifacts/out"),
    ("install", "install -m 755 source artifacts/out"),
    ("truncate", "truncate -s 0 artifacts/out"),
    ("mkfifo", "mkfifo -m 600 artifacts/out"),
    ("mknod", "mknod artifacts/out p"),
    ("rsync", "rsync -a source/ artifacts/out/"),
    ("dd", "dd if=source of=artifacts/out"),
    ("sed", "sed -i.bak 's/a/b/' artifacts/out"),
    ("perl", "perl -pi -e 's/a/b/' artifacts/out"),
    ("indented-rm", "  rm -rf artifacts/out"),
    ("chained-chmod", "true &&   chmod -R 755 artifacts/out"),
    ("absolute-rm", "/bin/rm -rf artifacts/out"),
    ("command-rm", "command rm -rf artifacts/out"),
    ("command-absolute-rm", "command /bin/rm -rf artifacts/out"),
    ("devnull", "printf x > /dev/null"),
)

BAD_SHELL_CASES = tuple(
    (f"shell {name} options", f"tools/shell_{name}.sh", f"{command}\n")
    for name, command in MUTATION_COMMANDS
)
SAFE_SHELL_CASES = tuple(
    (f"tools/safe_shell_{name}.sh", f"{command}\n")
    for name, command in SAFE_MUTATION_COMMANDS
)
