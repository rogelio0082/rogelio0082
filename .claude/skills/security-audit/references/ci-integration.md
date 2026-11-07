# Wiring Scanning Into CI and Pre-Commit

Read this when the user wants scanning to run automatically rather than on demand.

The governing principle for an existing project: **freeze the past, block the future.**
Never start by failing the build on hundreds of pre-existing findings. That gets the
whole thing switched off within a week.

## Contents
- [Pre-commit hooks](#pre-commit-hooks)
- [Husky and lint-staged](#husky-and-lint-staged)
- [GitHub Actions](#github-actions)
- [SARIF: do not merge](#sarif-do-not-merge)
- [Baseline and ratchet](#baseline-and-ratchet)
- [Rollout order](#rollout-order)

## Pre-commit hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/semgrep/pre-commit
    rev: v1.172.0
    hooks:
      - id: semgrep
        args: [--config=p/default, --config=p/secrets, --error, --skip-unknown-extensions]
```

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files    # establishes the baseline, see below
```

The gitleaks hook runs `gitleaks git --pre-commit --redact --staged --verbose` with
`pass_filenames: false`. Three variants exist: `gitleaks` builds via Go,
`gitleaks-docker` uses the published image, and `gitleaks-system` expects the binary on
`PATH` — the last is fastest and the right choice inside a CI image.

Pin `rev` to a real tag; check with
`git ls-remote --tags https://github.com/gitleaks/gitleaks`. Re-run
`pre-commit autoupdate` quarterly.

## Husky and lint-staged

For JS projects that already have Husky:

```sh
# .husky/pre-commit
npx lint-staged
gitleaks git --pre-commit --redact --staged --verbose || {
  echo "gitleaks: staged secret detected. Remove it, or add a fingerprint to .gitleaksignore"; exit 1;
}
```

```json
{
  "lint-staged": {
    "*.{js,jsx,ts,tsx}": ["eslint --fix", "semgrep --config p/javascript --error --skip-unknown-extensions"]
  }
}
```

lint-staged appends filenames to each command, which is what Semgrep wants. Keep
gitleaks outside lint-staged: it reads the git index, not a file list.

## GitHub Actions

**The permissions block is where most setups fail.** SARIF upload needs all three:

```yaml
permissions:
  contents: read          # mandatory on private repos
  security-events: write  # the upload itself
  actions: read           # omitting this gives "Resource not accessible by integration"
```

Semgrep:

```yaml
jobs:
  semgrep:
    runs-on: ubuntu-latest
    container: { image: semgrep/semgrep }
    steps:
      - uses: actions/checkout@v5
        with: { fetch-depth: 0 }        # required for --baseline-commit
      - run: semgrep scan --config=p/default --config=p/secrets --sarif --output=semgrep.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with: { sarif_file: semgrep.sarif, category: semgrep }
```

Trivy — **pin by SHA**, given the March 2026 compromise of this exact action
(see `iac-cloud-config.md`):

```yaml
      - uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: fs
          ignore-unfixed: true
          format: sarif
          output: trivy.sarif
          severity: CRITICAL,HIGH
          limit-severities-for-sarif: true   # without this, ALL severities reach code scanning
      - uses: github/codeql-action/upload-sarif@v4
        if: always()                          # else findings vanish when the scan fails the job
        with: { sarif_file: trivy.sarif, category: trivy }
```

osv-scanner ships reusable workflows. They moved — the copies in `google/osv-scanner`
are deprecated:

```yaml
jobs:
  scan-pr:
    uses: "google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@v2.3.8"
```

Do not pass `--format` or `--output` in `scan-args`; the reusable workflow sets them and
they conflict. The PR variant is inherently diff-only, so it needs no baseline.

gitleaks: `gitleaks/gitleaks-action@v3` requires a `GITLEAKS_LICENSE` for
**organization-owned** repos, and the free tier covers exactly one repo. Personal repos
are unaffected. For a multi-repo org, run the MIT binary directly instead:

```yaml
      - run: |
          curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz \
            | tar -xz -C /usr/local/bin gitleaks
          gitleaks git . --redact --report-format sarif --report-path gitleaks.sarif \
                   --baseline-path .gitleaks-baseline.json --exit-code 1
```

## SARIF: do not merge

**Merging SARIF files for GitHub upload is now an anti-pattern.** Since 22 July 2025
code scanning no longer combines multiple runs sharing a tool and category, and affected
files are rejected outright.

Upload once per tool, each with a distinct `category`:

```yaml
      - uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: semgrep.sarif, category: semgrep }
      - uses: github/codeql-action/upload-sarif@v4
        with: { sarif_file: trivy.sarif, category: trivy }
```

Precedence for run identity is the explicit `category` input, then
`runs[].automationDetails.id`, then the tool name. Pointing `sarif_file` at a directory
works only if every file inside carries a unique `automationDetails.id`.

Merge only for local or human-facing reports, where the multi-run structure is fine:

```bash
pip install sarif-tools
sarif copy --output merged.sarif ./artifacts/
sarif summary merged.sarif
sarif html --output report.html merged.sarif
sarif diff baseline.sarif current.sarif
```

Cross-tool deduplication (the same CVE from Trivy and osv-scanner) is not solved by any
of these. Approximate it:

```bash
jq -s '[.[].runs[].results[]]
       | group_by(.ruleId + (.locations[0].physicalLocation.artifactLocation.uri // ""))
       | map(.[0]) | length' *.sarif
```

## Baseline and ratchet

Each tool has a first-class mechanism. Capture the baselines, commit them, then gate
only on what is new.

```bash
gitleaks git . --report-path .gitleaks-baseline.json    # commit this
git rev-parse HEAD > .semgrep-baseline-commit           # commit this
```

```bash
gitleaks git . --baseline-path .gitleaks-baseline.json --exit-code 1
semgrep scan --config=p/default --error --baseline-commit "$(cat .semgrep-baseline-commit)"
```

On pull requests prefer `semgrep ci`, which auto-detects the merge base. Both forms need
`fetch-depth: 0`. The environment-variable equivalents are `SEMGREP_BASELINE_COMMIT` and
`SEMGREP_BASELINE_REF` for CI providers other than GitHub and GitLab.

A baseline is debt, not an exemption. Make it decay:

```yaml
      - run: |
          age=$(( ($(date +%s) - $(git log -1 --format=%ct .gitleaks-baseline.json)) / 86400 ))
          [ "$age" -gt 90 ] && { echo "::error::baseline stale >90d"; exit 1; }; true
```

Regenerate the baseline only in a dedicated pull request, so the diff is reviewable.
Folded into a feature branch it becomes a place to bury findings.

## Rollout order

This sequence is what survives contact with a team:

1. **Measure first.** Every workflow runs with `continue-on-error: true` and uploads
   SARIF. Two weeks of data, zero pull-request friction.
2. **Secrets block from day one.** Small volume, unambiguous, high impact. Nobody
   argues with a blocked commit containing a live key.
3. **Critical dependency CVEs block after two weeks**, with `--ignore-unfixed` so a
   vulnerability with no available patch does not block anyone.
4. **SAST warns for a quarter**, then blocks new findings only.
5. **Everything pre-existing is a backlog ticket, never a pull-request blocker.**

The middle-ground gate that blocks serious new problems without touching the backlog:

```yaml
        with:
          severity: CRITICAL,HIGH
          exit-code: '1'
          ignore-unfixed: true
```
