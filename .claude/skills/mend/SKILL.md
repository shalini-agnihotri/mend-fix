---
name: mend
description: Fetch Mend vulnerability alerts for this repo, analyze direct vs transitive deps, list fixable/non-fixable, apply fixes, run build + tests, and stage all changes for the user to raise a PR
---

You are fixing Mend (WhiteSource) security vulnerabilities for the `scriptless-mobile-backend` Node.js repo.

## Execution rules

- **Do not ask permission to edit files or run commands.** Just do it and announce what you did in a short one-line status message. Edits to `package.json`, `libs/*/package.json`, `apps/*/package.json`, deleting `package-lock.json`, running `npm install`, running builds/tests, and `git add` all proceed without a confirmation prompt.
- **Only pause for the explicit user-input questions called out in the steps below.** Those are:
  1. Step 1 — the Jira ticket ID for the branch name.
  2. Step 5 — whether to fix `all` fixable CVEs or just `critical+high`.
  3. Step 6 — whether to add an `overrides` entry when no parent upgrade resolves a transitive CVE.
- Everything else runs end-to-end autonomously from Step 1 through Step 8.

## Auto mode (CI / scheduled runs)

When this skill is invoked with arguments of the form `--jira=<value> --scope=<value> --overrides=<value>` (for example, from the GitHub Actions workflow at `.github/workflows/mend-fix.yaml`), it must run **fully unattended** — all three prompts are answered by the flags and the skill must complete by opening a draft PR.

Flag values:

| Flag           | Allowed values                | Effect                                                                                                         |
| -------------- | ----------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `--jira`       | `MOB-12345` or `none`         | Used in the branch name. `none` means "no Jira", same as the `no jira` reply in interactive mode.              |
| `--scope`      | `all` or `critical+high`      | Step 5 — which severities to fix. Skip the user prompt entirely.                                               |
| `--overrides`  | `skip` or `auto`              | Step 6 — `skip` means never add `overrides` entries; mark those CVEs as "needs manual review" in the PR body. `auto` means add the override with the warning baked into the PR description. Skip the user prompt either way. |

In auto mode, **Step 8 changes**: instead of stopping after `git add`, the skill must commit the staged changes and run `gh pr create --draft` with the CVE summary as the PR body. See Step 8 for the auto-mode block.

If any of the three flags is missing while at least one is present, treat it as a malformed invocation: stop and print the expected flag set. Do not fall back to interactive prompts in CI — they will hang the workflow.

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
```

If any variable is empty, stop and tell the user to populate `~/.mend/credentials`. The file must have a `[saas-eu]` section with `org_token`, `user_key`, `api_url`, and `product_token`. These can be found in the Mend web UI at **Integrate → Organization → API Key** and **Profile → User Keys**.

## Step 1 — Create a branch from main

Before fetching alerts or making any changes, create a dedicated branch off the latest `main` by invoking the `/git create-branch` workflow (see [.claude/commands/git.md](../../commands/git.md)).

**Auto mode:** if `--jira=<value>` was passed, use it directly (no prompt). `--jira=none` means no Jira ticket.

**Interactive mode:** ask the user — "What is the Jira ticket ID for this Mend fix? (e.g. MOB-12345) — reply `no jira` if there isn't one."

Then invoke the git create-branch subcommand with a `mend-vulnerabilities` description:
- With Jira ticket: `/git create-branch MOB-XXXXX mend vulnerabilities` → branch like `<username>/mend-vulnerabilities/MOB-XXXXX`
- Without Jira: `/git create-branch mend vulnerabilities` → branch like `<username>/mend-vulnerabilities`

Confirm the branch is created, checked out, and pushed to origin before continuing to Step 2.

## Step 2 — Fetch all vulnerability alerts

Response can be 2 MB+. Save to a temp file and always open with `encoding="utf-8"`.

```bash
export TMPFILE=$(python3 -c "import tempfile, os; print(os.path.join(tempfile.gettempdir(), 'mend_alerts.json'))")

curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{\"requestType\": \"getProductAlertsByType\", \"userKey\": \"$USER_KEY\", \"orgToken\": \"$ORG_TOKEN\", \"productToken\": \"$PRODUCT_TOKEN\", \"alertType\": \"SECURITY_VULNERABILITY\"}" \
  -o "$TMPFILE"
```

`TMPFILE` is exported so Step 3 reads from the same path. If you run Step 3 in a new shell, re-run the `export` line first.

## Step 3 — Parse and triage

The API returns `"high"` for both critical and high. Derive critical from CVSS score >= 9.0.

```python
import json, os, sys

tmpfile = os.environ.get('TMPFILE')
if not tmpfile:
    sys.exit("TMPFILE is not set — re-run the export line from Step 2.")

with open(tmpfile, encoding='utf-8') as f:
    alerts = json.load(f).get('alerts', [])

# Filter to this repo's project only
alerts = [a for a in alerts if 'scriptless-mobile-backend' in a.get('project', '')]

rows = []
for a in alerts:
    v = a.get('vulnerability', {})
    lib = a.get('library', {})
    sev = v.get('severity', 'unknown')
    cvss = v.get('cvss3_score', 0)
    if sev == 'high' and cvss >= 9.0:
        sev = 'critical'
    pkg = lib.get('filename', '').replace('.tgz', '')
    # Strip version suffix from filename to get package name (e.g. lodash-4.17.20 → lodash)
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

## Step 4 — Analyze dependency chains and determine fix order

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

## Step 5 — List fixable and non-fixable

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

**Auto mode:** if `--scope=<value>` was passed (`all` or `critical+high`), use it directly and proceed to Step 6 without prompting.

**Interactive mode:** STOP — USER INPUT REQUIRED. Print the question as its own visually distinct block so it does not get buried under the tables above:

```
════════════════════════════════════════════════════════════
>>> ACTION REQUIRED — PLEASE RESPOND <<<

   Fix all fixable ones, or only critical and high?

   Reply with:  "all"   OR   "critical+high"
════════════════════════════════════════════════════════════
```

Wait for the user's answer before touching any files.

## Step 6 — Apply fixes

**Keep the user informed throughout this step.** Fixes, `npm install`, and verification can take several minutes — long silences make users think the process is stuck. Print a short one-line status message (a single sentence, no tables or bullets) before every meaningful action, so the user always knows what you're doing and that you're still working. Examples:

- `Deleting package-lock.json before applying fixes...`
- `Bumping axios from ^1.3.0 to ^1.6.0 in package.json...`
- `Adding overrides entry for follow-redirects@^1.15.4...`
- `Running npm install — this may take 1–2 minutes...`
- `npm install finished. Verifying follow-redirects is now patched...`
- `Fix 3 of 7 applied. Moving on to the next CVE...`

Do this for every sub-step below (delete lock file, each package bump, each override, `npm install`, each `npm ls` verification). One line each — enough to confirm progress, not a full narration.

### Before making any changes, delete package-lock.json

```bash
rm package-lock.json
```

### Direct vulnerabilities (`directDependency: true`)

Bump the version range under `dependencies` or `devDependencies` in the **root `package.json` first** — root drives `package-lock.json` and is what actually gets installed. Use `^` (caret) unless the fix requires an exact version.

```jsonc
// Before
"lodash": "^4.17.20"
// After
"lodash": "^4.17.21"
```

**If the package is not declared in root at all** (e.g. `express` lives only in `libs/auth`, `libs/otel`, `libs/logger`, `libs/nest-utils`), bump it in every lib that declares it *and* add it to root `dependencies` (or to root `overrides` if it should stay transitive) so the lock file actually resolves to the patched version. Otherwise the lib declaration changes but nothing installed changes.

### Transitive vulnerabilities (`directDependency: false`)

**Prefer upgrading the direct parent in `dependencies` / `devDependencies` over editing `overrides`.** `overrides` pin a transitive version across the whole tree and can silently break sibling packages that expect the original version — they should be the last resort, not the default.

Workflow for each transitive CVE:

1. Run `npm ls <vulnerable-package>` to list every direct parent that pulls it in.
2. For each parent, check whether a newer version ships with the patched transitive (via `npm view <parent> versions --json`, release notes, or the parent's own `package.json`).
3. **If a parent upgrade resolves it** → bump the parent in root `dependencies` / `devDependencies` (same rules as direct vulns — root first, then libs if the parent isn't in root). Re-run `npm ls <vulnerable-package>` after `npm install` to confirm.
4. **If no parent upgrade resolves it** (parent hasn't released a fix, or the vulnerable dep is pulled in by an unmaintained package) → handle based on mode:

   **Auto mode (`--overrides=<value>`):**
   - `--overrides=skip` → do **not** add an `overrides` entry. Leave the CVE unfixed and list it in the PR body under "Needs manual review — add `overrides` entry?" with the parent list and fix version, so a human can decide.
   - `--overrides=auto` → add the `overrides` entry without prompting. Include a clear warning in the PR body: "Override added for `<package>` — please verify sibling consumers still work, since this forces the whole tree onto `<fix-version>`."

   **Interactive mode:** stop and ask the user before touching `overrides`:

   > "I can't fix `<package>@<version>` (CVE-XXXX-YYYY) by upgrading its parent(s) `<parent-list>` — no released version of them pulls in a patched `<package>`. The only remaining option is an `overrides` entry in `package.json` that forces `<package>` to `<fix-version>` across the whole tree.
   >
   > **Why this is needed:** without it, the vulnerable version stays in `node_modules` and Mend keeps flagging the CVE; `npm audit` / security gates will continue to fail.
   >
   > **Risk of adding the override:** it forces every consumer of `<package>` onto `<fix-version>`, even ones that haven't been tested against it — a sibling dep could break at runtime if it relies on older behavior.
   >
   > **Risk of not adding it:** the CVE remains open until an upstream parent releases a fix, which may take weeks or never come.
   >
   > Do you want me to add the `overrides` entry?"

   Only add the entry after the user confirms (interactive) or `--overrides=auto` (auto):

   ```jsonc
   "overrides": {
     "follow-redirects": "^1.15.4"
   }
   ```

   Use `"npm:empty-npm-package@1.0.0"` only when certain the package is not used at runtime (build-time dev tooling only).

### Sync the patched version across every `package.json` (and template) in the monorepo

Root drives `package-lock.json`, but individual `libs/*/package.json`, `apps/**/package.json`, and **`package.json.ejs` templates** (which are rendered into real `package.json` files at script-generation time) declare their own runtime deps and will drift out of sync unless they are updated too. After every root bump (or lib bump, for the no-root-entry case above), align every other declaration of the same package to the **same range used in root**.

Find every declaration recursively — do not use a single-level glob like `apps/*/package.json`, since it will miss nested files such as `apps/script-generator/src/assets/templates/package.json.ejs`. Use `git ls-files` so `node_modules` is excluded automatically:

```bash
git ls-files '*package.json' '*package.json.ejs' | xargs grep -l '"<package-name>"' 2>/dev/null
```

For each match, edit the range to match root — including the `.ejs` template files (they are valid JSON with EJS expressions; only edit the `"<package>": "<range>"` line, leave EJS tags untouched). Skip `@perfectomobiledev/*` and `@perforce-perfecto/*` entries — those are workspace-internal pins (`0.0.1`) that track the monorepo's own versioning, not npm versions.

If you added an `overrides` entry in root, also add the same entry to any lib that declares the affected package, so the lib's local view matches the resolved tree.

There is only one `package-lock.json` (at root), so there is no lib-level lock file to regenerate.

### Regenerate package-lock.json

```bash
npm install
```

Verify the patched versions are installed:

```bash
npm ls <package-name>
```

## Step 7 — Build and test

Both must pass before staging changes.

```bash
# Build all projects
npx nx run-many -t build

# Run all unit tests
npx nx run-many -t test
```

If a build or test fails, diagnose the root cause before proceeding. A failing test may indicate a breaking change in the upgraded package — revert that specific fix and mark it as "not fixable (breaking change)" in the summary.

### ESM-only upgrades (Jest `SyntaxError: Cannot use import statement outside a module`)

Many major bumps in 2024+ ship ESM-only releases (e.g. `uuid` v14, `node-fetch` v3, `chalk` v5). Jest in CJS mode chokes on them with `SyntaxError: Cannot use import statement outside a module` or `SyntaxError: Unexpected token 'export'` originating in `node_modules/<package>/...`. **This is not a breaking change — do not revert the bump.** Instead, add the package to `transformIgnorePatterns` in `jest.preset.js` so Jest transforms it through Babel:

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

## Step 8 — Stage all changes (and, in auto mode, open a draft PR)

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

Build the **PR summary** — list every CVE fixed with package, version bump, and fix type, plus any CVEs that were not fixable:

```
Fix Mend vulnerabilities:
- CVE-2023-26159 | follow-redirects 1.14.0 → >=1.15.4 | transitive (via axios parent upgrade)
- CVE-2023-45857 | axios 1.3.0 → ^1.6.0 | direct

Not fixed (included for visibility):
- CVE-XXXX-YYYY | foo | no patch available
```

Call out explicitly any CVE that was fixed via `overrides` (with the reason the parent upgrade was not possible), so reviewers know to test sibling consumers. In auto mode with `--overrides=skip`, also include a "Needs manual review — add `overrides`?" section listing the CVEs that were left unfixed because no parent upgrade resolved them.

### Interactive mode

**Do NOT create a commit and do NOT create a PR.** Stop here — print the summary above for the user to paste into their PR description. The user will commit and raise the PR on their own.

### Auto mode

If invoked with `--jira / --scope / --overrides` flags, finish the run by committing and opening a draft PR:

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
<paste the PR summary here, including any "Needs manual review" / overrides warnings>

---
Generated automatically by `.github/workflows/mend-fix.yml`. Review the dependency bumps and the build/test output before marking ready for review.
EOF
)"
```

If the Jira flag was a real ticket (not `none`), include it in the PR title: `fix(mend): patch security vulnerabilities (MOB-XXXXX)`.

If `gh pr create` fails with a permissions error ("GitHub Actions is not permitted to create or approve pull requests"), the repo's "Allow Actions to create PRs" setting is off — the workflow needs a `PR_TOKEN` PAT secret. Print the error and exit non-zero so the workflow run fails visibly.

## Error handling

| Error                                | Action                                                                                     |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| Empty variable after credential read | `~/.mend/credentials` missing or malformed — show expected format to user                  |
| `{"errorCode":...}` in response      | Print `errorMessage`; wrong `product_token` is the most common cause                       |
| Empty `alerts` array                 | Product token may be for a different product — use `getAllProducts` to list available ones |
| `fixResolutionText` empty            | Use NVD entry for the CVE as fallback version                                              |
| Build fails after fix                | Likely breaking change — revert that specific package and mark as "not fixable (breaking)" |
| `npm ls` shows no path               | Package may have already been resolved by another fix applied earlier in the session       |
