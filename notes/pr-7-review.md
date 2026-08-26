# Review note: merged PR #7

Research only. Do not merge this branch.

PR: https://github.com/da-beda/ct-hulhu/pull/7
Merge: `bcab82bc317edfe56d395e2029ae44845a0099be`
Fix: `6182ec283da41720a5f24267301f7f822492c4ac`
Parent: `5439f3c5f314103cd608b2382728468afdaab1b7`

## What actually changed

One file: `internal/staticct/tile_test.go`. Production code, `go.mod`, CI, and pins are untouched.

The real bug was not Go 1.24-specific. Line 19 used a tab as a statement separator:

```
for i:=range fp{fp[i]=byte(i)}<TAB>tile:=append(...)
```

Go inserts semicolons only at newlines. Pre-merge, exact Go 1.24.7 reproduces the claimed error:

```
internal/staticct/tile_test.go:19:53: expected ';', found tile
```

The commit inserts that newline and gofmts the rest of the file. Test logic is the same. The broken line was introduced in `9ada1c1` (PR #2) and sat through PRs #3–#6.

On this machine (`go1.24.7`), HEAD now passes the commands the PR listed: `go vet ./...`, `go test -race ./...`, `CGO_ENABLED=0 go build ... ./cmd/ct-hulhu`, `ct-hulhu -h`.

## Thread vs envelope

The GitHub thread is the PR body only. No review comments, no reviews, no discussion. Created 22:55:51Z, merged by the author at 23:00:23Z.

The body is accurate about the parse error and the local fix. The extra claim is not in the envelope:

> UBBRK publication remains blocked until this PR is merged, UBBRK is repinned to the resulting exact fork commit, and the exact-main release artifact is regenerated and revalidated.

Nothing in this repo is named UBBRK or bounty-kit. `go.mod` was already `go 1.24.7` from `bacf76f`. No tags, no releases, no pin file moved.

If a bounty-kit / UBBRK pin still points at `5439f3c` or earlier, the gate still fails. That mismatch is outside this PR.

## Holes

- GitHub Actions still does not run on this fork. `statusCheckRollup` is empty. PR #4 already said the fork does not schedule workflows.
- Sibling compacted tests remain gofmt-dirty (`checkpoint_test.go`, `client_test.go`, `runner_test.go`, and others). They parse because they use semicolons. No second tab-between-statements bug.
- CI has no `gofmt` check, so the original one-liner style can come back.
- No `toolchain go1.24.7` line. PR #4 said the sandbox could not download the declared 1.24.7 toolchain. This environment already has it, which is why the local gate works here.
- `go vet ./...` and `go test ./...` would have failed since PR #2. Earlier "compile-oriented" / source-only claims did not catch this.
