---
name: mend
description: Fetch Mend vulnerability alerts for this repo, analyze direct vs transitive deps, list fixable/non-fixable, apply fixes, run build + tests, and stage all changes for the user to raise a PR
---

## Overview

You are fixing Mend (WhiteSource) security vulnerabilities for the `scriptless-mobile-backend` Node.js repo. The skill fetches alerts from the Mend API, triages by severity, applies fixes (direct bumps, parent upgrades, or `overrides` for unresolvable transitives), runs build + tests, and stages changes for a PR.

The skill runs in **interactive mode** by default (prompts the user for Jira ticket + scope) or in **auto mode** when invoked with `--jira` / `--scope` flags from CI (e.g. the scheduled / `workflow_dispatch` GitHub Actions workflow at `.github/workflows/mend-agent.yaml`, which shells out to `scripts/mend-agent.mjs`). See [Mode behavior](#mode-behavior-interactive-vs-auto) below.

## Execution rules

- **Do not ask permission to edit files or run commands.** Just do it and announce what you did in a short one-line status message. Edits to `package.json`, `libs/*/package.json`, `apps/*/package.json`, deleting `package-lock.json`, running `npm install`, running builds/tests, and `git add` all proceed without a confirmation prompt.
- **Only pause for the explicit user-input questions called out in the steps below.** Those are:
  1. Step 1 — the Jira ticket ID for the branch name.
  2. Step 5 — whether to fix `all` fixable CVEs or just `critical+high`.
- Transitive CVEs that no parent upgrade can resolve are fixed automatically by adding an `overrides` entry — **never ask the user**. Each override is recorded in the PR body with the reason it was required and the risk of skipping it (see Step 6 and Step 8).
- Everything else runs end-to-end autonomously from Step 1 through Step 8.

## Mode behavior (interactive vs auto)

The skill behaves differently in three steps depending on how it was invoked. At-a-glance:

| Step | Interactive (default)             | Auto (with `--jira` / `--scope`)              |
| ---- | --------------------------------- | --------------------------------------------- |
| 1    | Prompt the user for the Jira ID   | Use the `--jira=<value>` flag value           |
| 5    | Prompt the user for the scope     | Use the `--scope=<value>` flag value          |
| 8    | Stage only — user commits & PRs   | Commit, push, and run `gh pr create --draft`  |

In auto mode the skill must run **fully unattended** — both prompts are answered by flags and the run must finish by opening a draft PR.

Flag values:

| Flag      | Allowed values            | Effect                                                                                            |
| --------- | ------------------------- | ------------------------------------------------------------------------------------------------- |
| `--jira`  | `MOB-12345` or `none`     | Used in the branch name. `none` means "no Jira", same as the `no jira` reply in interactive mode. |
| `--scope` | `all` or `critical+high`  | Step 5 — which severities to fix. Skip the user prompt entirely.                                  |

If either flag is missing while the other is present, treat it as a malformed invocation: stop and print the expected flag set. Do not fall back to interactive prompts in CI — they will hang the workflow.

## Credentials

Stored in `~/.mend/credentials` (INI format). Never hardcode tokens.

```bash
ORG_TOKEN=$(python3 -c "
import configparser, os
c = configparser.RawConfigParser()
c.read(os.path.expanduser('~/.mend/credentials'))
print(c['saas-eu']['org_token'])
")
USER_KEY=$(python3 -c "
import configparser, os
c = configparser.RawConfigParser()
c.read(os.path.expanduser('~/.mend/credentials'))
print(c['saas-eu']['user_key'])
")
API_URL=$(python3 -c "
import configparser, os
c = configparser.RawConfigParser()
c.read(os.path.expanduser('~/.mend/credentials'))
print(c['saas-eu']['api_url'])
")
PRODUCT_TOKEN=$(python3 -c "
import configparser, os
c = configparser.RawConfigParser()
c.read(os.path.expanduser('~/.mend/credentials'))
print(c['saas-eu']['product_token'])
")
PROJECT_TOKEN=$(python3 -c "
import configparser, os
c = configparser.RawConfigParser()
c.read(os.path.expanduser('~/.mend/credentials'))
print(c['saas-eu'].get('project_token', ''))
")
```

If any variable is empty, stop and tell the user to populate `~/.mend/credentials`. The file must have a `[saas-eu]` section with `org_token`, `user_key`, `api_url`, `product_token`, and `project_token`. These can be found in the Mend web UI at **Integrate → Organization → API Key**, **Profile → User Keys**, and **Project → Project Vitals → Request Token** (for `project_token`).

## Procedure

### Step 1 — Create a branch from main

Before fetching alerts or making any changes, create a dedicated branch off the latest `main` by invoking the `/git create-branch` workflow (see [.claude/commands/git.md](../../commands/git.md)).

Get the Jira ticket ID (see [Mode behavior](#mode-behavior-interactive-vs-auto)). The interactive prompt to the user is: "What is the Jira ticket ID for this Mend fix? (e.g. MOB-12345) — reply `no jira` if there isn't one."

Then invoke the git create-branch subcommand with a `mend-vulnerabilities` description:
- With Jira ticket: `/git create-branch MOB-XXXXX mend vulnerabilities` → branch like `<username>/mend-vulnerabilities/MOB-XXXXX`
- Without Jira: `/git create-branch mend vulnerabilities` → branch like `<username>/mend-vulnerabilities`

Confirm the branch is created, checked out, and pushed to origin before continuing to Step 2.

### Step 2 — Fetch all vulnerability alerts

Response can be 2 MB+. Save to a temp file and always open with `encoding="utf-8"`.

```bash
export TMPFILE=$(python3 -c "import tempfile, os; print(os.path.join(tempfile.gettempdir(), 'mend_alerts.json'))")

curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{\"requestType\": \"getProjectAlertsByType\", \"userKey\": \"$USER_KEY\", \"orgToken\": \"$ORG_TOKEN\", \"projectToken\": \"$PROJECT_TOKEN\", \"alertType\": \"SECURITY_VULNERABILITY\"}" \
  -o "$TMPFILE"
```

`TMPFILE` is exported so Step 3 reads from the same path. If you run Step 3 in a new shell, re-run the `export` line first.

### Step 3 — Parse and triage

The API returns `"high"` for both critical and high. Derive critical from CVSS score >= 9.0.

The Mend `productToken` covers **every project** under that product (active, archived, snapshots, branch clones), so the API response includes alerts from sibling projects you do not want to fix here. Match the active project name **exactly** — substring matching lets stale siblings like `scriptless-mobile-backend-old` or `scriptless-mobile-backend-staging` leak in and produces phantom "vulnerabilities" that are not visible in the UI for the active project.

The active project name is `GH_scriptless-mobile-backend` (visible in the Mend UI breadcrumb under Products → `Perfecto_GHC` → Projects → `GH_scriptless-mobile-backend`). If that name ever changes, update the constant below.

> Note: once a `MEND_PROJECT_TOKEN` GitHub secret is available, switch the Step 2 API call to use `"projectToken": "$PROJECT_TOKEN"` instead of `"productToken": "$PRODUCT_TOKEN"`. Mend will then return only this project's alerts and the client-side filter becomes a redundant safety net (keep it anyway — defensive).

```python
import json, os, re, sys

ACTIVE_PROJECT = 'GH_scriptless-mobile-backend'   # exact match, not substring

tmpfile = os.environ.get('TMPFILE')
if not tmpfile:
    sys.exit("TMPFILE is not set — re-run the export line from Step 2.")

with open(tmpfile, encoding='utf-8') as f:
    alerts = json.load(f).get('alerts', [])

# Diagnostic: print the project breakdown so a stale sibling leaking through is obvious
project_counts = {}
for a in alerts:
    p = a.get('project', '')
    project_counts[p] = project_counts.get(p, 0) + 1
print('Alert counts by project (raw API response):', file=sys.stderr)
for p, n in sorted(project_counts.items()):
    marker = '  <-- active' if p == ACTIVE_PROJECT else ''
    print(f'  {n:4d}  {p}{marker}', file=sys.stderr)

# Scope strictly to the active project — exact match, no substring
alerts = [a for a in alerts if a.get('project', '') == ACTIVE_PROJECT]
print(f'Filtered to {len(alerts)} alerts for project {ACTIVE_PROJECT!r}', file=sys.stderr)

rows = []
for a in alerts:
    v = a.get('vulnerability', {})
    lib = a.get('library', {})
    sev = v.get('severity', 'unknown')
    cvss = v.get('cvss3_score', 0)
    if sev == 'high' and cvss >= 9.0:
        sev = 'critical'
    # Fallback only — `lib.get('name')` below is the canonical package name.
    # `filename` looks like `lodash-4.17.20.tgz`; strip `.tgz` and the trailing
    # `-<version>` so the fallback is `lodash`, not `lodash-4.17.20`.
    pkg = re.sub(r'-\d+(?:\.\d+)*(?:[-+][^-+]+)?$', '',
                 lib.get('filename', '').replace('.tgz', ''))
    rows.append({
        'cve':      v.get('name', ''),
        'severity': sev,
        'cvss':     cvss,
        'package':  lib.get('name', pkg),
        'version':  lib.get('version', ''),
        'fix':      v.get('fixResolutionText', ''),
        'direct':   a.get('directDependency', False),
    })

order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
rows.sort(key=lambda r: (order.get(r['severity'], 9), -r['cvss']))

for r in rows:
    dep_type = 'direct' if r['direct'] else 'transitive'
    print(f"{r['severity'].upper():8} | {r['package']:35} | {r['version']:12} | {dep_type:10} | {r['cve']} | {r['fix']}")
```

### Step 4 — Analyze dependency chains and determine fix order

For each vulnerability, run `npm ls <package>` to see the full dependency chain:

```bash
npm ls <package-name> 2>/dev/null
```

**Fix order logic:**

1. **Critical transitive** — fix first by upgrading the direct parent dep that pulls it in. Only fall back to `overrides` if no parent upgrade resolves it (see Step 6).
2. **Critical direct** — bump the version in `package.json`.
3. **High** — same approach, after criticals.
4. **Medium** — last, if in scope.

**Deduplication — check if fixing one resolves others before creating a PR:**

For transitive vulnerabilities, check if multiple CVEs affect the same underlying package. Upgrading a single direct parent (e.g. `axios`) often pulls in patched versions of several transitive deps (e.g. `follow-redirects`), resolving multiple CVEs in one PR without needing `overrides`.

Use `npm ls` to see what pulls in a transitive dep:

```bash
npm ls follow-redirects 2>/dev/null
# Example output:
# └─┬ axios@1.3.0
#   └── follow-redirects@1.14.0
```

If all paths to a vulnerable transitive dep go through one direct dep, upgrading that direct dep may fix the transitive automatically — no `overrides` needed. Verify with `npm ls <transitive>` after the upgrade.

### Step 5 — List fixable and non-fixable

Before making any changes, present a table:

```
FIXABLE:
| Severity | Package          | Current | Fix version | Type       | CVE            | Fix method                          |
|----------|-----------------|---------|-------------|------------|----------------|-------------------------------------|
| CRITICAL | follow-redirects | 1.14.0  | >=1.15.4    | transitive | CVE-2023-26159 | upgrade parent `axios` to >=1.6.0   |
| HIGH     | axios            | 1.3.0   | >=1.6.0     | direct     | CVE-2023-45857 | bump package.json                   |

NOT FIXABLE:
| Severity | Package | Reason                                           |
|----------|---------|--------------------------------------------------|
| HIGH     | foo     | No patch available yet; latest version still vulnerable |
| MEDIUM   | bar     | Requires major version bump (breaking API change) — needs dedicated effort |
```

Get the scope (see [Mode behavior](#mode-behavior-interactive-vs-auto)). The interactive prompt to the user is: "Fix all fixable ones, or only critical and high? Reply with: `all` OR `critical+high`."

Wait for the user's answer before touching any files.

### Step 6 — Apply fixes

**Keep the user informed throughout this step.** Fixes, `npm install`, and verification can take several minutes — long silences make users think the process is stuck. Print a short one-line status message (a single sentence, no tables or bullets) before every meaningful action, so the user always knows what you're doing and that you're still working. Examples:

- `Deleting package-lock.json before applying fixes...`
- `Bumping axios from ^1.3.0 to ^1.6.0 in package.json...`
- `Adding overrides entry for follow-redirects@^1.15.4...`
- `Running npm install — this may take 1–2 minutes...`
- `npm install finished. Verifying follow-redirects is now patched...`
- `Fix 3 of 7 applied. Moving on to the next CVE...`

Do this for every sub-step below (delete lock file, each package bump, each override, `npm install`, each `npm ls` verification). One line each — enough to confirm progress, not a full narration.

#### Before making any changes, delete package-lock.json

```bash
rm -f package-lock.json
```

`-f` keeps the step idempotent — re-running the skill after a partial run, or running it against a repo where the lockfile is already absent, won't fail here.

#### Direct vulnerabilities (`directDependency: true`)

Bump the version range under `dependencies` or `devDependencies` in the **root `package.json` first** — root drives `package-lock.json` and is what actually gets installed. Use `^` (caret) unless the fix requires an exact version.

```jsonc
// Before
"lodash": "^4.17.20"
// After
"lodash": "^4.17.21"
```

**If the package is not declared in root at all** (e.g. `express` lives only in `libs/auth`, `libs/otel`, `libs/logger`, `libs/nest-utils`), bump it in every lib that declares it *and* add it to root `dependencies` (or to root `overrides` if it should stay transitive) so the lock file actually resolves to the patched version. Otherwise the lib declaration changes but nothing installed changes.

#### Transitive vulnerabilities (`directDependency: false`)

**Prefer upgrading the direct parent in `dependencies` / `devDependencies` over editing `overrides`.** `overrides` pin a transitive version across the whole tree and can silently break sibling packages that expect the original version — they should be the last resort, not the default.

Workflow for each transitive CVE:

1. Run `npm ls <vulnerable-package>` to list every direct parent that pulls it in.
2. For each parent, check whether a newer version ships with the patched transitive (via `npm view <parent> versions --json`, release notes, or the parent's own `package.json`).
3. **If a parent upgrade resolves it** → bump the parent in root `dependencies` / `devDependencies` (same rules as direct vulns — root first, then libs if the parent isn't in root). Re-run `npm ls <vulnerable-package>` after `npm install` to confirm.
4. **If no parent upgrade resolves it** (parent hasn't released a fix, or the vulnerable dep is pulled in by an unmaintained package) → **add an `overrides` entry automatically** in both interactive and auto modes. Never ask the user; never leave the CVE unfixed. For each override applied, record the following in memory for the PR body (Step 8):
   - The CVE ID, package, and fix version forced.
   - The direct parent(s) that pulled the vulnerable transitive in, and why a parent upgrade was not possible (e.g. "axios@1.6.0 still pins follow-redirects@1.14.0", "parent `foo` is unmaintained, last release 2021").
   - The risk of **not** overriding: the CVE remains open, `npm audit` / Mend gates keep failing, and the vulnerable code stays in `node_modules` until an upstream parent ships a fix (which may take weeks or never come).
   - The risk of **adding** the override: it forces every consumer of `<package>` onto `<fix-version>`, even ones not tested against it — a sibling dep could break at runtime if it relies on older behavior. Reviewers must verify sibling consumers.

   Add the entry:

   ```jsonc
   "overrides": {
     "follow-redirects": "^1.15.4"
   }
   ```

   Use `"npm:empty-npm-package@1.0.0"` only when certain the package is not used at runtime (build-time dev tooling only).

#### Sync the patched version across every `package.json` (and template) in the monorepo

Root drives `package-lock.json`, but individual `libs/*/package.json`, `apps/**/package.json`, and **`package.json.ejs` templates** (which are rendered into real `package.json` files at script-generation time) declare their own runtime deps and will drift out of sync unless they are updated too. After every root bump (or lib bump, for the no-root-entry case above), align every other declaration of the same package to the **same range used in root**.

Find every declaration recursively — do not use a single-level glob like `apps/*/package.json`, since it will miss nested files such as `apps/script-generator/src/assets/templates/package.json.ejs`. Use `git ls-files` so `node_modules` is excluded automatically:

```bash
git ls-files '*package.json' '*package.json.ejs' | xargs grep -l '"<package-name>"' 2>/dev/null
```

For each match, edit the range to match root — including the `.ejs` template files (they are valid JSON with EJS expressions; only edit the `"<package>": "<range>"` line, leave EJS tags untouched). Skip `@perfectomobiledev/*` and `@perforce-perfecto/*` entries — those are workspace-internal pins (`0.0.1`) that track the monorepo's own versioning, not npm versions.

If you added an `overrides` entry in root, also add the same entry to any lib that declares the affected package, so the lib's local view matches the resolved tree.

There is only one `package-lock.json` (at root), so there is no lib-level lock file to regenerate.

#### Regenerate package-lock.json

```bash
npm install
```

Verify the patched versions are installed:

```bash
npm ls <package-name>
```

#### Adapt call sites to breaking API changes (major version bumps)

After any major version bump (`x.y.z` → `(x+1).0.0`), the new release often changes the package's public surface. Run through the [Major Version Bump Checklist](#major-version-bump-checklist) under Reference before Step 7 — proactive rewrites are cheaper than failure-driven diagnosis, and they keep tests honest (a test passing because nothing imports the bumped code is not a green light).

If the checklist resulted in any edit to `package.json` (root, libs, apps, or `.ejs` templates) — most commonly a revert/downgrade of a bump that turned out to need real logic rewrite, or adding a shim/polyfill dependency — the lock file is now stale. Regenerate it before Step 7:

```bash
git diff --name-only | grep -E '(^|/)package\.json(\.ejs)?$' && npm install
```

Skip this if no `package.json` changed during the checklist — re-running `npm install` against an unchanged tree is wasted CI time but otherwise harmless.

### Step 7 — Build and test

Both must pass before staging changes.

```bash
# Build all projects
npx nx run-many -t build

# Run all unit tests
npx nx run-many -t test
```

If a build or test fails, diagnose the root cause before proceeding. A failing test may indicate a breaking change in the upgraded package — revert that specific fix and mark it as "not fixable (breaking change)" in the summary.

If Jest fails with `SyntaxError: Cannot use import statement outside a module` or `SyntaxError: Unexpected token 'export'` originating in `node_modules/<pkg>/...`, this is an ESM-only release hitting Jest in CJS mode — see [ESM-only packages and Jest](#esm-only-packages-and-jest) under Reference. **Do not revert the bump.**

### Step 8 — Stage all changes

Stage every file that was modified as part of the fix. In a monorepo fix this typically includes root `package.json`, root `package-lock.json`, and any `libs/*/package.json` or `apps/*/package.json` that were touched during the sync sub-step, plus any follow-on code changes:

```bash
git add package.json package-lock.json
git add libs/*/package.json apps/*/package.json   # only modified files actually get staged
# Add any other files modified during fixes
```

Then show `git status` so the user (or the workflow log) can confirm what's staged:

```bash
git status
```

Build the **PR summary** — list every CVE fixed with severity, package, version bump, and fix type, plus any CVEs that were not fixable. Every CVE patched via an `overrides` entry must get its own dedicated subsection so reviewers can immediately see what was forced and why. Severity column uses the same labels as Step 3 (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) so reviewers can scan blast radius at a glance.

```
Fix Mend vulnerabilities:
- CRITICAL | CVE-2023-26159 | follow-redirects 1.14.0 → >=1.15.4 | transitive (via axios parent upgrade)
- HIGH     | CVE-2023-45857 | axios 1.3.0 → ^1.6.0 | direct

Overrides applied (no parent upgrade resolves the transitive — please verify sibling consumers):
- CRITICAL | CVE-2024-XXXXX | follow-redirects 1.14.0 → ^1.15.4
  - Pulled in via: request@2.88.2 (unmaintained, last release 2020 — no patched version exists)
  - Why required: without the override the vulnerable version stays in node_modules, Mend keeps flagging the CVE, and npm audit / security gates continue to fail
  - Risk of override: every consumer of follow-redirects is forced onto ^1.15.4; sibling deps that relied on older behavior may break at runtime — please smoke-test request-based call sites

Not fixed (included for visibility):
- MEDIUM   | CVE-XXXX-YYYY | foo | no patch available
```

The "Overrides applied" section must be present (even if just one entry) whenever any `overrides` entry was added during the run. If no overrides were needed, omit the section entirely.

Finish the run per [Mode behavior](#mode-behavior-interactive-vs-auto):

**Interactive** — stop here. Do NOT create a commit and do NOT create a PR. Print the summary above for the user to paste into their PR description.

**Auto** — commit, push, and open a draft PR:

```bash
git commit -m "$(cat <<'EOF'
fix(mend): patch security vulnerabilities

<paste the PR summary here>
EOF
)"

git push -u origin HEAD

gh pr create --draft \
  --base main \
  --title "fix(mend): patch security vulnerabilities" \
  --body "$(cat <<'EOF'
<paste the PR summary here, including any "Overrides applied" warnings>

---
Generated automatically by `.github/workflows/mend-agent.yaml`. Review the dependency bumps and the build/test output before marking ready for review.
EOF
)"
```

If the Jira flag was a real ticket (not `none`), include it in the PR title: `fix(mend): patch security vulnerabilities (MOB-XXXXX)`.

If `gh pr create` fails with a permissions error ("GitHub Actions is not permitted to create or approve pull requests"), the repo's "Allow Actions to create PRs" setting is off — the workflow needs a `PR_TOKEN` PAT secret. Print the error and exit non-zero so the workflow run fails visibly.

## Reference

### Major version bump checklist

For each package crossing a major boundary (`x.y.z` → `(x+1).0.0`), run these three checks before Step 7. Mechanical updates (renamed import, reordered args, awaited Promise) are part of the fix; they should be applied silently and noted in the PR body. Only escalate to "not fixable (breaking change)" if the new signature requires real logic rewrite — the function was split into two, the return type ripples through many call sites with different semantics, etc.

#### 1. Fetch migration notes via context7 (cheap upfront signal)

Before grepping imports or running `tsc`, fetch the package's docs via the context7 MCP (`mcp__context7__resolve-library-id` → `mcp__context7__query-docs` with a query like `"breaking changes v<old> to v<new>"`) so the greps in checks 2 and 3 are targeted. context7 is a heuristic — `*.d.ts` and `tsc --noEmit` below remain the source of truth for the actually-installed version. Skip if context7 has no entry, or if the bump is minor/patch.

#### 2. Import shape changes (default vs named export)

Major bumps frequently drop or reshape default exports. Examples:
- `uuid` v3 → v7+: `import uuid from 'uuid'` becomes `import { v4 } from 'uuid'`.
- `chalk` v4 → v5: default-exported function becomes a named-exports module.
- `node-fetch` v2 → v3: CJS default becomes ESM named exports.

For every major-bumped package, find every import in the codebase:

```bash
git grep -nE "(from|require\()[ ]*['\"]<pkg>['\"]" -- ':!node_modules' ':!package-lock.json'
```

Cross-check each match against the new release's exports — read `node_modules/<pkg>/package.json` (`exports` field) and the package's `*.d.ts` or migration guide (from context7 in check 1). **Do not guess the shape; read it.** Rewrite imports to match.

#### 3. API signature changes (arity, positional → named, sync → async)

A function may keep its name but change its parameter list — `func(a, b, c)` becomes `func(a, b)` or `func(a, { b, c })`. The TypeScript compiler is the cheapest way to find every mismatched call site at once:

```bash
npx tsc --noEmit
```

For each error, look at the new signature in `node_modules/<pkg>/**/*.d.ts` (or the migration guide from context7) and update the call site. Patterns to watch for:
- Positional args collapsed into an options bag: `fn(a, b, c)` → `fn(a, { b, c })`.
- Callback replaced by a Promise: `fn(arg, cb)` → `const result = await fn(arg)`.
- A required arg became optional, or vice versa.
- The return shape changed (e.g. an array became an object with `data`/`meta` fields).

### ESM-only packages and Jest

**Symptom:** Jest fails with `SyntaxError: Cannot use import statement outside a module` or `SyntaxError: Unexpected token 'export'` originating in `node_modules/<package>/...`.

Many major bumps in 2024+ ship ESM-only releases (e.g. `uuid` v14, `node-fetch` v3, `chalk` v5). Jest in CJS mode chokes on them. **This is not a breaking change — do not revert the bump.** Instead, add the package to `transformIgnorePatterns` in `jest.preset.js` so Jest transforms it through Babel:

```js
// jest.preset.js — before
module.exports = {
  ...nxPreset,
  roots: ['<rootDir>', path.resolve(__dirname, './__mocks__')]
};

// jest.preset.js — after (uuid added to the not-ignored list)
module.exports = {
  ...nxPreset,
  roots: ['<rootDir>', path.resolve(__dirname, './__mocks__')],
  transformIgnorePatterns: [
    ...(nxPreset.transformIgnorePatterns || []),
    'node_modules/(?!(uuid)/)'
  ]
};
```

If `transformIgnorePatterns` already exists with another package (e.g. `'node_modules/(?!(node-fetch)/)'`), extend the alternation rather than replacing it: `'node_modules/(?!(node-fetch|uuid)/)'`.

Re-run `npx nx run-many -t test` to confirm. Only revert the bump and mark "not fixable" if tests still fail after the Jest config fix — that would indicate a real API breaking change, not an ESM-loader issue.

### Pitfalls and lessons learned

Non-obvious gotchas the skill has hit before. Skim this list when something looks wrong mid-run — the fix is probably already documented in the referenced step.

- **Mend API returns `"high"` for both critical and high.** Derive critical from `cvss3_score >= 9.0` — see Step 3.
- **`productToken` leaks sibling-project alerts** (e.g. `*-old`, `*-staging`). Filter by exact project name `GH_scriptless-mobile-backend`, not substring — see Step 3.
- **Lib `package.json` drifts from root.** Root drives `package-lock.json`; if a package is only declared in `libs/*`, edits to the lib won't change what's installed. Bump in every lib *and* add to root — see Step 6 ("Direct vulnerabilities").
- **`.ejs` package templates are easy to miss.** `apps/*/package.json` globs skip nested files like `apps/script-generator/src/assets/templates/package.json.ejs`. Use `git ls-files '*package.json' '*package.json.ejs'` — see Step 6 ("Sync the patched version").
- **`overrides` can silently break sibling consumers.** Always try a parent upgrade first; only fall back to `overrides` when no parent release resolves the CVE — see Step 6 ("Transitive vulnerabilities").
- **Jest `SyntaxError: Cannot use import statement outside a module` is *not* a breaking change.** It's an ESM-only release hitting Jest in CJS mode. Add the package to `transformIgnorePatterns` in `jest.preset.js` — see [ESM-only packages and Jest](#esm-only-packages-and-jest). Do not revert the bump.
- **Call-site adapt can re-stale the lock file.** If the Major Version Bump Checklist edits any `package.json` (revert/downgrade, shim added), re-run `npm install` before Step 7 — see Step 6 ("Adapt call sites to breaking API changes").
- **Always list "not fixed" CVEs in the PR body.** Reviewers need the complete picture, including the ones blocked on upstream — see Step 5 / Step 8.

### Error handling

| Error                                | Action                                                                                     |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| Empty variable after credential read | `~/.mend/credentials` missing or malformed — show expected format to user                  |
| `{"errorCode":...}` in response      | Print `errorMessage`; wrong `product_token` is the most common cause                       |
| Empty `alerts` array                 | Product token may be for a different product — use `getAllProducts` to list available ones |
| `fixResolutionText` empty            | Use NVD entry for the CVE as fallback version                                              |
| Build fails after fix                | Likely breaking change — revert that specific package and mark as "not fixable (breaking)" |
| `npm ls` shows no path               | Package may have already been resolved by another fix applied earlier in the session       |
