# bashedlogs - project instructions

Rules that only bite inside this repo. Global rules still apply.

## Code notation

This project follows the CODE NOTATION STANDARD, summarized in the README.
Every `.sh`, `.bats`, and `.bash` file carries the standard header and `# *--- Section ---*` headings.

Three documented extensions, per section 14 of the standard:

1. **`# shellcheck shell=bash` stays on line 1 of every `lib/` file, above the header.**
   These files are sourced, never executed, so that directive is their shebang: it is the only
   thing telling ShellCheck which dialect to parse. `tools/build.sh` also deletes it by exact
   line match (`sed '/^# shellcheck shell=bash$/d'`) when inlining libs into the release
   artifact, so the text must stay byte-identical.

2. **File-scope `# shellcheck disable=...` lines sit with it, above the header.**
   A file-scope directive only applies if it precedes the first command, and keeping the
   ShellCheck preamble in one block keeps that obvious. Inline `disable` directives are
   position-sensitive in a stronger way: they apply to the next line only, so moving one
   silently drops the suppression. Never relocate one to tidy a comment block.

3. **`bin/`, `tools/`, and `tests/*.bats` keep their real shebang on line 1**, header second.
   This is the standard's own rule, noted here because it differs from the `lib/` case above.

No file currently carries a TODO item, so no file carries a TODO list. Add both together
when one is needed, per section 7.

## Things that are code, not comments

- `# @BUNDLE-SKIP-START` and `# @BUNDLE-SKIP-END` in `bin/bashedlogs` are build directives.
  `tools/build.sh` slices the file on them to produce `dist/bashedlogs`. Both lines must
  survive byte-for-byte, and nothing may be inserted between them.
- A `#` inside an awk program, a heredoc, or `tests/fixtures/**` is data. `lib/formats/*.sh`
  is dense with awk; `tools/mkfixtures.sh` is mostly heredoc log data.
- A `@test "..."` name in a `.bats` file is code. Tests assert against it.

## Verification

Nothing is done until these pass:

```bash
shellcheck -x bin/bashedlogs lib/core/*.sh lib/formats/*.sh tools/*.sh
bash -n bin/bashedlogs
bats tests/
tools/build.sh && shellcheck dist/bashedlogs
```

Then run the standard's notation checker on every touched file.

A notation change must not alter a single executable line. The gate that proves it:

```bash
diff <(git show HEAD:<file> | rg -v '^\s*(#|$)') <(rg -v '^\s*(#|$)' <file>)
```

Empty output means comments only. CI runs the same checks on Linux, macOS, and bash 4.0 under busybox.
