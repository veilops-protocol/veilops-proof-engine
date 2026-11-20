# Mirror notice

`veilops-protocol/veilops-proof-engine` is a **read-only mirror**. During Phase 01 the single source of truth is [`veilops-protocol/veilops`](https://github.com/veilops-protocol/veilops), path `packages/proof-engine/`.

- Open issues and pull requests on `veilops-protocol/veilops`, not here. Pull requests on this repository are closed with a pointer to the monorepo.
- History here is generated with `git subtree split`, so commits touching `packages/proof-engine/` keep their authors and messages. A final commit overlays this repository's `README.md`, `LICENSE` and `MIRROR.md`.
- The branch `main` is **force-pushed** on every sync. Do not base work on it.

## How the mirror is published

Run from a clean checkout of the monorepo, with the satellite files available at `../veilops-github/veilops-proof-engine/`:

```bash
# 1. Extract the history of packages/proof-engine/ into a local branch (deterministic: same input, same commits)
git subtree split --prefix=packages/proof-engine -b mirror/veilops-proof-engine

# 2. Overlay the mirror's own README, LICENSE and MIRROR.md on top of the split
git worktree add ../_mirror-veilops-proof-engine mirror/veilops-proof-engine
cp ../veilops-github/veilops-proof-engine/README.md ../veilops-github/veilops-proof-engine/LICENSE ../veilops-github/veilops-proof-engine/MIRROR.md ../_mirror-veilops-proof-engine/
git -C ../_mirror-veilops-proof-engine add README.md LICENSE MIRROR.md
git -C ../_mirror-veilops-proof-engine commit -m "mirror: add veilops-proof-engine README, LICENSE and MIRROR notice"

# 3. Publish
git push --force git@github.com:veilops-protocol/veilops-proof-engine.git mirror/veilops-proof-engine:main

# 4. Clean up
git worktree remove ../_mirror-veilops-proof-engine
git branch -D mirror/veilops-proof-engine
```

The mirror is updated manually by a maintainer in Phase 01. Automating it (a workflow in the monorepo with a deploy key scoped to this repository) is planned.
