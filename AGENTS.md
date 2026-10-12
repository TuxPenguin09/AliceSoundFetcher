# AGENTS.md

Working agreements for coding agents in this repository.

## Git: strictly read-only

Agents working in this repository **must not perform any Git operation that
writes to the repository, the index, the reflog, or the remote.** This includes
but is not limited to:

| Forbidden | Why |
| --- | --- |
| `git commit`, `git commit --amend` | Never create or rewrite a commit |
| `git add`, `git rm`, `git mv`, `git restore`, `git reset` | Never stage or move work |
| `git checkout` / `git switch` (any form that changes the working tree) | Never discard or move files |
| `git stash`, `git stash pop` | Never hide or restore work behind the user |
| `git rebase`, `git cherry-pick`, `git revert`, `git merge` | Never rewrite history or move commits |
| `git clean` | Never delete untracked files |
| `git tag`, `git branch -d/-m`, `git update-ref` | Never move refs |
| `git push`, `git pull`, `git fetch` | Never touch the remote |
| `git gc`, `git repack`, `git reflog expire`, `git filter-branch` | Never rewrite object storage |
| Editing `.git/` by hand (including writing `.git/COMMIT_EDITMSG`) | Never fabricate commit state |

The reason is that the history and the staging area are the user's to control.
An agent that commits, amends, rebases, or force-pushes can destroy work, bury
review feedback, or produce a rewrite that is hard to undo.

### What agents *may* run

Read-only inspection is encouraged and expected:

```
git status [--short] [-sb]
git diff [--stat] [-- <path>]
git log [--oneline] [-n <n>] [-- <path>]
git show <rev>[:<path>]
git blame <path>
git ls-files
git check-ignore -v <path>
git rev-parse --show-toplevel
git describe --always --dirty
```

`git diff` and `git log` in particular are the correct tools for inspecting
unstaged work; use them instead of trying to "clean up" the tree.

### What to do instead

When a change is ready:

1. Edit the working tree. Leave staging entirely to the user.
2. Report what changed — files added, modified, deleted — using
   `git status --short` plus `git diff --stat`.
3. Provide a ready-to-use commit message (title plus body) in your reply, and say
   explicitly that the user must stage and commit it themselves.

If a task genuinely requires a write operation, stop and ask rather than acting.

## Project facts

- **x86/Win32 only.** AliceSoft System-4 games are 32-bit, so both projects must
  stay on `Platform=Win32`. A 64-bit build cannot inject into the game.
- **Build:** `msbuild AliceSoundFetcher.slnx /p:Configuration=Debug /p:Platform=x86`
- **Layout:** `launcher/` (UI, injection, log tailer), `runtime/` (injected DLL:
  hook generation, RTTI discovery, logging), `parser/` (AFA archive reader),
  `AliceSoundFetcherDLL/` (the injected DLL project).
- **Third-party code lives in `external/` and is git-ignored.** It is fetched by
  hand; see `ACKNOWLEDGEMENTS.md` for licences. Do not vendor GPL-licensed code
  into this Apache-2.0 project — see the note in `ACKNOWLEDGEMENTS.md` about
  `alice-tools`.

## Verification expectations

This codebase contains hand-assembled machine code and binary-format parsing,
where a plausible-looking wrong answer is worse than no answer at all.

- **Do not report something as working because the output file has the right
  shape.** Verify the behaviour that was actually claimed. An earlier session
  reported the log tailer as verified when only the log *file* had been checked
  and the console output had never been displayed once.
- **Establish a baseline first.** Before attributing a crash or a misbehaviour to
  a change, confirm the unmodified target behaves the same way. Evenicle runs
  cleanly with no DLL attached.
- **Prefer bisection and instrumentation to theory.** The vtable hooks were
  broken for several iterations because a single wrong byte in a `rel32`
  displacement was reasoned about abstractly instead of disassembled.
- When a measurement can be invalidated by the environment (for example, Steam
  refusing to start a second copy of a game right after a force-kill), fix the
  measurement before drawing a conclusion from it.