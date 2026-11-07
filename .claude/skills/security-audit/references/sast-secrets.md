# SAST and Secret Scanning

Verified tool syntax. Flags changed recently in gitleaks and Semgrep; most blog posts
online are stale. Use what is here.

## Contents
- [Install](#install)
- [Secret scanning — gitleaks](#secret-scanning--gitleaks)
- [Secret scanning — TruffleHog](#secret-scanning--trufflehog)
- [Secret triage](#secret-triage)
- [Remediation: rotate then scrub](#remediation-rotate-then-scrub)
- [SAST — Semgrep](#sast--semgrep)
- [SAST — Bandit (Python)](#sast--bandit-python)
- [SAST — gosec (Go)](#sast--gosec-go)
- [Degraded path: no tools installed](#degraded-path-no-tools-installed)

## Never trust an exit code alone

All three scanners here ship documented silent-failure modes that exit 0 while having
scanned nothing:

- Semgrep exits 0 on Python parse errors and reports "no findings" (#11443), on an
  invalid rule where the docs promise 7 (#10319), on a space in `--config` (#7630), and
  when multicore parallelism silently produces zero findings on high-vCPU hosts with
  constrained memory (#11606).
- Bandit ignores `exclude` config entirely when filenames are passed on the command
  line (#499, #657, #693), so it scans what you told it to skip.
- Checkov silently ignores unknown check IDs passed to `--check` (#7614), skips
  Kustomize and Helm charts whose build emits warnings (#7599, #7605), and passes when
  an external module fails to load (#7314).

**Parse the JSON or SARIF output and assert on the finding count yourself.** An exit
code of 0 from any of these means "nothing went wrong that I noticed", not "the code is
clean". In the audit report, a scanner that produced no output at all is a coverage gap,
not a pass — say so.

## What Semgrep Community Edition actually does

Worth knowing before you present its output as authoritative. Semgrep's own README
describes CE as *"suitable for ad-hoc use cases with a high tolerance for false
positives"* and warns it *"will miss many true positives as it can only analyze code
within the boundaries of a single function or file."*

Cross-file and cross-function taint analysis is a paid feature. So CE will not follow
user input from a route handler into a helper module — which is precisely the shape of
most real injection bugs. Treat its findings as leads for your own tracing, and when the
audit reports "Semgrep found nothing", note the single-file limitation as part of the
coverage section rather than implying the code is clean.

Note also that the `semgrep-rules` repository is licensed `NOASSERTION` for internal use
only, separately from the LGPL-2.1 engine. That matters if anyone plans to redistribute
rules. Opengrep is an LGPL-2.1 fork created in response.

## Install

Windows first, since that is where this usually runs.

```powershell
winget install Gitleaks.Gitleaks      # or: scoop install gitleaks
pip install semgrep                    # runs natively on Windows now; no WSL needed
pip install "bandit[sarif,toml]"       # sarif extra is required for -f sarif
scoop install trufflehog               # no winget package; or grab the release binary
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

macOS/Linux: `brew install gitleaks semgrep trufflehog gosec`.

**pip installs land in a `Scripts\` directory that is frequently not on PATH** on
Windows — `pip install semgrep` succeeds, then `semgrep` is "not found" in the same
shell. Do not conclude the install failed or reinstall: `pip show -f semgrep` prints
the real location, `python -m semgrep --version` runs it regardless, and a new shell
picks up PATH edits an installer made.

Everything here is free and account-free. Two network caveats: `semgrep --config p/…`
fetches rules over the network and sends metrics unless you pass `--metrics=off`, and
TruffleHog's verification feature calls the credential's live API by design.

## Secret scanning — gitleaks

The CLI changed in v8.19. Use `git` / `dir` / `stdin`. The `detect` and `protect`
subcommands still work but are deprecated and hidden from `--help` — if you see them
in a tutorial, that tutorial is old.

```bash
# Full git history — the important one. Scans every commit by default.
gitleaks git -v .

# Machine-readable
gitleaks git -f json -r gitleaks-report.json .
gitleaks git -f sarif -r gitleaks.sarif .

# All branches, or a commit range
gitleaks git --log-opts="--all" .
gitleaks git --log-opts="--all commitA..commitB" .

# Working tree only, no history (fast, and works outside a git repo)
gitleaks dir -v .

# Staged changes, for a pre-commit hook
gitleaks git --pre-commit --staged --redact -v
```

Exit codes: `0` clean, `1` leaks found or error, `126` unknown flag. Override the
findings exit code with `--exit-code N`.

**`dir` walks the raw filesystem and does not consult `.gitignore`**, so on a built
project most of its hits sit in `.next/`, `dist/` or `node_modules/` — hundreds of
artifact matches that drown the question that matters, "is anything committed?".
Answer that with `gitleaks git`, then point `dir` at specific build-output directories
as a separate, separately-labelled pass.

**A custom `.gitleaks.toml` replaces the entire default ruleset** unless it begins with:

```toml
[extend]
useDefault = true
```

Without that line, adding one custom rule silently deletes every built-in detector, and
the scan comes back clean because it is looking for almost nothing. Check for this
before trusting a quiet gitleaks result on a repo that has its own config.

Suppression: `.gitleaksignore` at the repo root holding report `Fingerprint` values,
or a `.gitleaks.toml` with regex/path/stopword allowlists. Write ignore entries
**without the commit SHA** (`path/to/file.txt:generic-api-key:5`) — fingerprints
containing a SHA are invalidated by squash-merge, so suppressed findings resurrect on
the main branch. Baseline workflow for an existing repo drowning in findings:

```bash
gitleaks git --report-path baseline.json .
gitleaks git --baseline-path baseline.json --report-path new.json .   # only new leaks
```

Gotcha: fingerprints include the commit SHA, so rewriting history invalidates every
entry in `.gitleaksignore`.

## Secret scanning — TruffleHog

The differentiator is verification: it calls the credential's API to check whether it
is still live. That takes findings from "looks like a key" to "this key works right now".

```bash
# Full history, verified and unknown results, JSON out
trufflehog git file://. --results=verified,unknown --json

# Gate a pipeline on it
trufflehog git file://. --results=verified --fail

# Filesystem, no history
trufflehog filesystem ./dist --results=verified

# Incremental
trufflehog git file://. --since-commit HEAD~50
```

Exit code with `--fail` is **183**, not 1. Gate on that specific code. Without
`--fail` it exits 0 even with findings.

`--results=verified|unknown|unverified|filtered_unverified` replaces the deprecated
`--only-verified`. Use `--no-verification` for air-gapped runs, which reduces it to a
pattern scanner. `-x/--exclude-paths FILE` takes newline-separated path regexes.

Two gotchas: it clones local repos to a temp directory before scanning unless you pass
`--trust-local-git-config` (trusted repos only), and it exits 0 on an invalid
`--since-commit` rather than erroring.

Do not scan with `--results=verified` alone during an audit. A revoked-but-real
historical secret still tells you a credential leaked and was never rotated properly.
Use `verified,unknown`.

## What the secret scanners actually score

Measured on SecretBench (818 public repos, 97,479 labelled candidates, 15,084 real
secrets). These numbers should shape how you present findings:

| Tool | Precision | Recall |
|---|---|---|
| gitleaks | 46% | 88% |
| TruffleHog (unverified mode) | 6% | 52% |
| GitHub secret scanning | 75% | 6% |

So roughly **half of gitleaks findings are false**, and in unverified mode about
**94% of TruffleHog findings are**. That is not a reason to skip them — gitleaks has the
best recall of any tool tested, which is exactly what you want for an audit. It is a
reason never to paste raw scanner output into a report as though each line were a
finding. Triage every hit.

The paper's own conclusion is that no single tool suffices, which is why both are here:
gitleaks for recall, TruffleHog verification for precision.

Trivy's secret scanner is neither. Its ruleset is markedly narrower than gitleaks',
and its coverage moves between versions: in field canary testing one install missed a
bare AWS access-key ID (`AKIA…`) outright and fired only on the GitHub PAT in the same
file, while v0.73.0 catches both. Treat a Trivy secret hit as corroboration, never as
coverage: gitleaks is the gate for AWS-style keys, and Trivy's secret scanner exits 0
whatever it finds (see `sca-supply-chain.md`).

Three operational traps:

- **In GitHub Actions, `fetch-depth: 0` is mandatory.** The default shallow clone means
  history-scanning tools scan exactly one commit while appearing to succeed.
- **`.gitleaksignore` fingerprints are not portable.** They embed the OS path separator,
  so an ignore file written on Windows silently fails in Linux CI. They are also
  invalidated by squash-merges. Prefer path and rule allowlists in `.gitleaks.toml`,
  which survive both.
- **TruffleHog verification makes outbound authentication attempts** to third-party APIs
  using the credentials it finds. That is what makes it accurate, and it is also real
  egress that may need sign-off in a regulated environment. Say so before enabling it.

## Secret triage

For each hit, in order:

1. **Is the value real?** `placeholder`, `your-key-here`, `xxx`, and obvious test
   fixtures are not findings. Check the shape against the provider's format.
2. **Is it committed at all?** A hit from a filesystem scan of a gitignored
   working-tree file is not a leak. Confirm with
   `git log --oneline --all -- <path>` — empty output means never committed
   (`--diff-filter=A` shows when it arrived, if not). Committed, in a deployed bundle,
   or otherwise published → continue as a leak. Never committed and never shipped →
   note it as local hygiene and stop; rotation is not required.
3. **Is it reachable?** A key in `dist/`, `.next/`, or any client bundle is public
   the moment the app is deployed. That is automatically more severe than the same
   key in a server-only file.
4. **What is the blast radius?** These are critical no matter where they appear:
   - `service_role` (Supabase) — bypasses row-level security entirely
   - `AKIA…` (AWS access key) — exposed AWS keys have produced six-figure bills in hours
   - `sk_live_…` (Stripe secret) — live payment operations
   - `sk-…` / `sk-ant-…` (LLM provider keys) — billable, and AI-credential leaks rose
     81% year over year
   - Any private key block (`-----BEGIN … PRIVATE KEY-----`)
5. **Is it in history only?** Still live. `git rm` does not remove anything; git is
   append-only and every clone has the full history.

Never paste the full value into the report. Location, type, first 4 characters.

## Remediation: rotate then scrub

Users get this backwards constantly. State the order explicitly. This procedure is for
secrets that are actually exposed — committed to history, shipped in a bundle, or
otherwise published. A never-committed working-tree hit (triage step 2) gets a
`.gitignore` note, not this.

1. **Rotate the credential at the provider.** Until this happens the secret is
   compromised, and nothing else you do matters.
2. **Then** scrub history if you still want it gone:
   `git filter-repo --path .env --invert-paths` (or BFG), force-push, and have every
   collaborator re-clone. Stale clones and forks keep the old objects.
3. Add `.env*` to `.gitignore` and enable push protection on the host.

Scrubbing without rotating is the single most common mistake in this area.

## SAST — Semgrep

The polyglot baseline: JS/TS, Python, Go, Java, C#, and more in the free engine.

```bash
semgrep scan --config p/security-audit --config p/owasp-top-ten .

# CI-ready: fail on findings, SARIF to a file, no telemetry
semgrep scan --config p/security-audit --error --metrics=off --sarif-output=semgrep.sarif .

# Only what this branch introduced
semgrep scan --config p/security-audit --baseline-commit=main .
```

Useful rulesets: `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/secrets`,
`p/jwt`, `p/sql-injection`, plus language packs `p/javascript`, `p/typescript`,
`p/python`, `p/golang`, `p/java`, `p/csharp`.

**Semgrep exits 0 even with findings unless you pass `--error`.** This silently
no-ops many CI setups. Other codes: 2 internal failure, 5 invalid YAML, 7 invalid
rule, 13 invalid API key.

Suppression: `.semgrepignore` (gitignore syntax), inline `// nosemgrep: rule-id`,
or `--baseline-commit`. Known bug: `nosemgrep` comments are ignored when writing with
`--sarif-output`; redirect `--sarif > file` instead if that bites.

Fully offline: download the ruleset YAML once, then `--config ./rules.yaml`.
`--config auto` and the Pro engine require `semgrep login`; nothing else does.

## SAST — Bandit (Python)

```bash
bandit -r . -f sarif -o bandit.sarif
bandit -r . -ll -ii              # medium+ severity and confidence only, much less noise
bandit -r . -x ./tests,./venv
```

Exit 1 when issues at or above the threshold are found; `--exit-zero` forces 0.

Suppression: inline `# nosec B608`, `-s B101,B601` to skip test IDs, `-x` for paths.
Baseline (JSON only): `bandit -r . -f json -o baseline.json`, then
`bandit -r . -b baseline.json`.

`-ll -ii` is almost always the right default. Bandit at full sensitivity flags every
`assert` in a test suite and buries the real findings.

## SAST — gosec (Go)

```bash
gosec -fmt sarif -out gosec.sarif -stdout ./...
gosec -severity medium -confidence medium ./...
gosec -exclude-dir=vendor ./...
```

Exit 0 when clean, 1 on findings or a processing error; `-no-fail` always exits 0.

Suppression: inline `// #nosec G402 -- reason`. Keep suppressions honest with
`-nosec-require-rules -nosec-require-justification`, and keep them visible in the
report with `-track-suppressions`. Per-path rules:
`--exclude-rules="cmd/.*:G204,G304"`.

## Degraded path: no tools installed

Grep still finds the high-frequency classes. Label these as pattern-matched, not
scanner-verified, and verify each by reading the code.

**Use the Grep tool with `output_mode: "files_with_matches"` for the secret patterns
below.** Content mode prints the whole matching line, which puts the complete
credential into context and the transcript — exactly what rule 1 forbids. Get the file
list first, then read only enough to classify the key type.

```bash
# Client-exposed secrets — the most common critical finding in AI-generated apps
NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|SERVICE)
(sk_live_|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|service_role|-----BEGIN [A-Z ]*PRIVATE KEY)

# Run the same patterns against dist/, .next/ and build/ — this is where they become public

# SQL built by string interpolation
grep -rEn "(execute|query|raw)\(.*(f\"|f'|\$\{|\+\s*req\.|%\s*\(|\.format\()" .

# Unsafe deserialization and eval-family sinks
grep -rEn "\b(eval|exec)\(|new Function\(|pickle\.loads|yaml\.load\(" .

# JWT verification disabled
grep -rEn "verify_signature\"?\s*:\s*(false|False)|verify\s*=\s*False|algorithms\s*=\s*\[?\s*['\"]?none" .

# Tokens in localStorage (readable by any XSS)
grep -rn "localStorage.setItem.*[Tt]oken\|localStorage.*jwt" .

# .env tracked by git
git ls-files | grep -E "\.env($|\.)"
```

Prefer the Grep tool over shelling out — it handles permissions and paths correctly
on Windows and returns clickable results.
