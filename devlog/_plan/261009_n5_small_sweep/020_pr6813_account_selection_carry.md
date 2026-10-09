# 020 — wp2: carry PR #6813, atomic explicit account selection

**Reader summary.** Selecting a Codex account (or pin) through the management API can report success while a
later whole-config reconcile adopts a newer disk value, so the next request routes and authenticates as a
different account. #6813 (hulkbig, fork PR) commits the selection through the scoped persisted-config
transaction first and only then adopts it and resets routing. Fork CI needs approval the lane does not
have, so the lane carries it onto current dev in a maintainer branch where repository CI runs.

## Facts (origin/dev 730d898457)

- Before: `src/codex/auth-api/routes.ts:269-280` mutates live selection, resets routing, then
  `saveRuntimeConfig` → whole reconcile (`src/codex/auth-api/runtime-config.ts:24-25`);
  `src/config/live-reconcile.ts:325-341` adopts disk when live equals baseline.
- PR head `8441b1bc68`: new `src/codex/auth-api/account-selection.ts` (107 lines) using
  `mutatePersistedConfig` (`src/config/persisted-mutation.ts:37-90`, SQLite `BEGIN IMMEDIATE` lock
  `src/config/mutation-lock.ts:104-152`); `routes.ts` -49/+10; `live-reconcile.ts` +17 (selection-only
  advance); `rebase-provenance.ts` +11; docs in five locales; structure `config.md`,
  `providers/openai-accounts.md`; new test `tests/codex-integration/codex-account-selection-atomicity.test.ts`
  registered in both layout files.
- Merge onto dev is clean (tree `a86859108a`); #6811 (merged `c3bbaaa342`) overlaps only on the layout
  registries and `structure/config.md` and does not change the transaction API; #6792 has no runtime overlap.

## Change map

| Path | Action | Note |
|---|---|---|
| branch `codex/n5-6813-account-selection` from origin/dev | NEW | worktree `opencodex-lanes/261009-N5-small-6813` |
| commits `91e24b0c30`, `8441b1bc68` | CHERRY-PICK | authorship (hulkbig) preserved; no content change expected |
| any conflict in layout registries / `structure/config.md` | MODIFY | keep both sides' entries |
| security-review folds (if any) | MODIFY | separate maintainer commit with `Co-authored-by: hulkbig` |

## Verification

- `bun test tests/codex-integration/codex-account-selection-atomicity.test.ts tests/codex-integration/codex-auth-api.test.ts tests/config/config-user-edits.test.ts tests/codex-integration/codex-pool-rotation.test.ts`
  (targets named directly).
- `bun test tests/test-layout.test.ts tests/test-layout-tooling.test.ts` (registration).
- `bun run typecheck`; `bun run structure:check` (structure docs changed); `bun run privacy:scan`.
- Activation scenarios to confirm in tests: same-value re-select of main against a newer disk snapshot
  (the original red case); persistence failure leaves routing untouched; post-publication exception
  reconciles to durable state.
- Independent gpt-6.1-sol security review (auth selection, races, credential exposure, error projection),
  then a general correctness review; exact-head hosted CI on the carry PR.

## Terminal

READY = carry PR exact-head CI green, both reviews PASS, MERGEABLE. After merge the coordinator closes #6813
with credit. Residual risks reported: recovery accepts any valid matching snapshot (observed-state, not
writer attribution); non-cooperating external writers after the final freshness check.
