# Unreleased changes, one file per change

A pull request with a user-visible change adds **one new file** here instead of
editing `CHANGELOG.md`. No two pull requests touch the same file, so changelog
entries never conflict, whatever order the pull requests merge in.

## Add an entry

Create `changelog.d/<short-slug>.md` (lowercase letters, digits, `-`, `_`,
`.`; the branch name is a good slug):

```markdown
### Added: the sensor reports each tool's manifest digest

- What changed, who it affects, and what a user or operator must do.
```

A file may hold several `### ` sections. The category is one of, in release
order: `Security`, `Upgrade notes`, `Behaviour change`, `Removed`,
`Deprecated`, `Added`, `Changed`, `Fixed`, `Documentation`. A heading may
leave out the title (`### Fixed`); such sections of one category are printed
under one heading at release. Use only `### ` and deeper headings.

To change an entry that is not released yet, edit its file. To drop it, delete
the file.

## Checks

`python3 .github/scripts/release/changelog-fragments.py check` runs in CI (the
`changelog` job). It refuses:

- a fragment without a valid `### <Category>` heading or without text;
- an entry (`### `) written under `## [Unreleased]` in `CHANGELOG.md`;
- merge-conflict markers in any tracked text file of the repository.

`python3 .github/scripts/release/changelog-fragments.py preview` prints the
assembled Unreleased section.

## At release

**Release Prepare** (`.github/scripts/release/prepare-release.sh`) folds every
fragment under `## [Unreleased]`, deletes the fragments, and turns that section into
the release section of the release pull request. The run summary shows the
preview, also on a dry run.
