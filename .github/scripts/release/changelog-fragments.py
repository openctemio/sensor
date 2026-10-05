#!/usr/bin/env python3
"""Changelog fragments for sdk-go and sensor. Same file in both repos.

Every pull request used to add its entry under the Unreleased heading of
CHANGELOG.md, so any two open pull requests edited the same lines and
conflicted, and every merge made the next one rebase. Unreleased entries now
live one file per change in changelog.d/; no two pull requests touch the same
file. The release folds them into CHANGELOG.md once (prepare-release.sh).

Usage:
  changelog-fragments.py [--root DIR] check
      validate the fragments; refuse an entry ("### ") written under the
      Unreleased heading of CHANGELOG.md and merge-conflict markers in any
      tracked text file
  changelog-fragments.py [--root DIR] preview
      print the Unreleased section assembled from the fragments
  changelog-fragments.py [--root DIR] fold
      write the assembled fragments under the Unreleased heading of
      CHANGELOG.md and delete them (prepare-release.sh runs this; the
      Unreleased section then becomes the release section)

Fragment format (changelog.d/<short-slug>.md):

  ### <Category>: <one-line title>

  - what changed, for whom, and any upgrade note

"### <Category>" without a title is accepted too: such sections of one
category are printed under a single heading. A fragment may hold several
"### " sections. Categories, in release order: see CATEGORIES.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

CATEGORIES = [
    "Security",
    "Upgrade notes",
    "Behaviour change",
    "Removed",
    "Deprecated",
    "Added",
    "Changed",
    "Fixed",
    "Documentation",
]
HEADING = re.compile(r"^### (?P<cat>[^:\n]+?)(?:: (?P<title>\S.*))?\s*$")
MARKER = re.compile(r"^(<{7}|>{7})( |$)|^\|{7}( |$)")
UNRELEASED = re.compile(r"^## (\[Unreleased\]|Unreleased)[ \t]*$", re.M)
NAME = re.compile(r"[a-z0-9][a-z0-9._-]*\.md")
TEXT_SUFFIXES = {
    ".md", ".go", ".ts", ".js", ".json", ".yml", ".yaml", ".sql", ".sh",
    ".py", ".toml", ".txt", ".mod", ".proto", ".tmpl",
}


class Repo:
    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.changelog = root / "CHANGELOG.md"
        self.dir = root / "changelog.d"

    def fragments(self) -> list[pathlib.Path]:
        if not self.dir.is_dir():
            return []
        return sorted(p for p in self.dir.glob("*.md") if p.name != "README.md")


def sections(text: str) -> list[tuple[str, str | None, str]]:
    """Split a fragment into (category, title, section text) triples.

    Text before the first heading is returned with an empty category so the
    validator can refuse it."""
    out: list[tuple[str, str | None, str]] = []
    cur: list[str] = []
    cat, title = "", None
    for line in text.splitlines():
        if line.startswith("### "):
            if cur:
                out.append((cat, title, "\n".join(cur).rstrip() + "\n"))
            m = HEADING.match(line)
            cat, title = (m.group("cat").strip(), m.group("title")) if m else ("", None)
            cur = [line]
        elif cur:
            cur.append(line)
        elif line.strip():
            out.append(("", None, line))
    if cur:
        out.append((cat, title, "\n".join(cur).rstrip() + "\n"))
    return out


def outside_fences(text: str, pat: re.Pattern[str]) -> bool:
    """True when a line outside fenced code blocks matches pat."""
    fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
        elif not fence and pat.match(line):
            return True
    return False


def validate(repo: Repo) -> list[str]:
    errors: list[str] = []
    for p in repo.fragments():
        rel = p.relative_to(repo.root)
        if not NAME.fullmatch(p.name):
            errors.append(f"{rel}: name must be lowercase letters, digits, '.', '_' or '-'")
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel}: not UTF-8 text")
            continue
        if outside_fences(text, re.compile(r"^#{1,2} ")):
            errors.append(f"{rel}: only '### ' (and deeper) headings; '#'/'##' belong to CHANGELOG.md")
        secs = sections(text)
        if not secs:
            errors.append(f"{rel}: empty; add a '### <Category>: <title>' section")
        for cat, _title, body in secs:
            if not cat:
                errors.append(f"{rel}: every section starts with '### <Category>: <title>' "
                              f"(categories: {', '.join(CATEGORIES)})")
            elif cat not in CATEGORIES:
                errors.append(f"{rel}: unknown category {cat!r} (use one of: {', '.join(CATEGORIES)})")
            elif not any(l.strip() for l in body.splitlines()[1:]):
                errors.append(f"{rel}: section '{body.splitlines()[0]}' has no text")
    return errors


def conflict_markers(repo: Repo) -> list[str]:
    res = subprocess.run(["git", "-C", str(repo.root), "ls-files", "-z"],
                         capture_output=True, check=False)
    if res.returncode != 0:
        return [f"git ls-files failed in {repo.root}: {res.stderr.decode().strip()}"]
    hits: list[str] = []
    for name in res.stdout.decode().split("\0"):
        if not name or pathlib.PurePath(name).suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = (repo.root / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if MARKER.match(line):
                hits.append(f"{name}:{i}: merge-conflict marker")
                break
    return hits


def split_changelog(text: str) -> tuple[str, str, str] | None:
    """(head through the Unreleased heading line, Unreleased body, rest)."""
    m = UNRELEASED.search(text)
    if not m:
        return None
    head, rest = text[: m.end()], text[m.end():]
    n = re.search(r"(?m)^## ", rest)
    return (head, rest[: n.start()], rest[n.start():]) if n else (head, rest, "")


def assemble(repo: Repo) -> str:
    """The fragments as one Markdown block, by category in release order.

    Titled sections keep their own heading; untitled sections of one category
    share one heading, in file order."""
    titled: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    untitled: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    for p in repo.fragments():
        for cat, title, body in sections(p.read_text(encoding="utf-8")):
            if cat not in titled:
                continue  # validate() refuses these before any fold
            if title is None:
                untitled[cat].append("\n".join(body.splitlines()[1:]).strip("\n"))
            else:
                titled[cat].append(body.rstrip("\n"))
    blocks: list[str] = []
    for cat in CATEGORIES:
        if untitled[cat]:
            blocks.append(f"### {cat}\n\n" + "\n\n".join(untitled[cat]))
        blocks.extend(titled[cat])
    return "\n\n".join(blocks)


def report(errors: list[str]) -> None:
    for e in errors:
        print(f"::error::{e}" if "GITHUB_ACTIONS" in os.environ else e, file=sys.stderr)


def cmd_check(repo: Repo) -> int:
    errors = validate(repo) + conflict_markers(repo)
    if not repo.changelog.is_file():
        errors.append("CHANGELOG.md is missing")
    else:
        parts = split_changelog(repo.changelog.read_text(encoding="utf-8"))
        if parts is None:
            errors.append("CHANGELOG.md has no Unreleased heading")
        elif outside_fences(parts[1], re.compile(r"^### ")):
            errors.append("CHANGELOG.md: an entry was written under Unreleased. Put it in "
                          "changelog.d/<short-slug>.md instead (see changelog.d/README.md).")
    report(errors)
    if not errors:
        print(f"changelog: {len(repo.fragments())} fragment(s) OK, no conflict markers")
    return 1 if errors else 0


def cmd_preview(repo: Repo) -> int:
    print("## Unreleased\n")
    print(assemble(repo) or "_No unreleased changes._")
    return 0


def cmd_fold(repo: Repo) -> int:
    errors = validate(repo)
    if errors:
        report(errors)
        return 1
    parts = split_changelog(repo.changelog.read_text(encoding="utf-8"))
    if parts is None:
        report(["CHANGELOG.md has no Unreleased heading"])
        return 1
    head, body, rest = parts
    block = assemble(repo)
    if block:
        merged = "\n\n".join(x for x in (body.strip("\n"), block) if x)
        out = f"{head}\n\n{merged}\n\n{rest}" if rest else f"{head}\n\n{merged}\n"
        repo.changelog.write_text(out, encoding="utf-8")
    n = len(repo.fragments())
    for p in repo.fragments():
        p.unlink()
    print(f"CHANGELOG.md: folded {n} fragment(s) into Unreleased", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    root = pathlib.Path(__file__).resolve().parents[3]
    if len(argv) >= 2 and argv[0] == "--root":
        root = pathlib.Path(argv[1]).resolve()
        argv = argv[2:]
    cmds = {"check": cmd_check, "preview": cmd_preview, "fold": cmd_fold}
    if len(argv) != 1 or argv[0] not in cmds:
        print(__doc__, file=sys.stderr)
        return 2
    return cmds[argv[0]](Repo(root))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
