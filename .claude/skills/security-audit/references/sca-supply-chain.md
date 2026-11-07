# Dependencies and Supply Chain

## Contents
- [Which tool for which ecosystem](#which-tool-for-which-ecosystem)
- [osv-scanner](#osv-scanner)
- [Trivy](#trivy)
- [npm / pnpm](#npm--pnpm)
- [pip-audit (Python)](#pip-audit-python)
- [govulncheck (Go)](#govulncheck-go)
- [Grype and Syft](#grype-and-syft)
- [Hallucinated packages (slopsquatting)](#hallucinated-packages-slopsquatting)
- [Lockfile and registry integrity](#lockfile-and-registry-integrity)
- [Licences](#licences)
- [Ranking findings](#ranking-findings)

## Which tool for which ecosystem

| Situation | Run |
|---|---|
| Any repo, first pass | `osv-scanner` |
| Second opinion, or containers/IaC/licences too | `trivy` |
| Go | `govulncheck` — authoritative, proves reachability |
| Node | `npm audit` + `npm audit signatures` |
| Python | `pip-audit` |
| Need an SBOM artifact | `syft`, then scan the SBOM |
| Java or .NET with fat JARs / DLLs | OWASP dependency-check, otherwise skip it |

Do not run every tool. Two overlapping scanners plus the language-native one is
enough; more just multiplies duplicate findings you then have to merge.

## osv-scanner

```powershell
winget install Google.OSVScanner    # or: scoop install osv-scanner
```

```bash
osv-scanner scan source -r .
osv-scanner scan source -r . --format sarif --output osv.sarif
osv-scanner scan source -L package-lock.json
osv-scanner scan source -r . --licenses="MIT,Apache-2.0,BSD-3-Clause"
```

Note the v2 syntax: `scan source`, not the bare v1 form. Formats: `table`, `json`,
`sarif`, `markdown`, `html`, `cyclonedx-1-5`.

Exit codes: `0` clean, `1` findings, `127` error, **`128` no packages found** — that
last one means the scan found nothing to scan, which in CI reads as neither pass nor
fail. Handle it explicitly.

No severity gating flag exists. Filter the JSON yourself. Suppression lives in
`osv-scanner.toml` beside the scanned artifact (it does **not** apply to
subdirectories) or via `--config`:

```toml
[[IgnoredVulns]]
id = "GO-2022-0968"
ignoreUntil = 2026-12-31
reason = "not reachable from our entry points"
```

Offline: `--offline-vulnerabilities --download-offline-databases`.

**Windows C/C++ caveat.** With git's `core.autocrlf` enabled — the Windows default —
osv-scanner's C/C++ detection matches on content hashes that CRLF conversion has
changed, so it **misses vulnerabilities silently**. The same repo scans differently on
Windows and Linux. Set `* text=auto eol=lf` in `.gitattributes` before scanning C/C++ on
Windows, or treat the result as unreliable and say so in the coverage section.

## Trivy

**Version check first.** The Trivy ecosystem was compromised in March 2026
(CVE-2026-33634, CVSS 9.4, actively exploited): a malicious binary shipped as v0.69.4,
malicious images as v0.69.5 and v0.69.6, and 76 of 77 tags in `aquasecurity/trivy-action`
were force-pushed to credential-stealing malware. Require **v0.70 or newer**, and in CI
pin `trivy-action` to v0.35.0+ by commit SHA. Full detail and indicators of compromise
are in `iac-cloud-config.md`.

```bash
trivy --version    # must be >= 0.70
```

```bash
trivy fs --scanners vuln .
trivy fs --scanners vuln,misconfig,secret,license .
trivy fs --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed .
trivy fs --format sarif --output trivy.sarif .
trivy image myapp:latest
trivy repo https://github.com/org/repo
```

**Trivy exits 0 by default even with findings.** Pass `--exit-code 1` to gate. Note that
the **secret scanner's exit code is 0 regardless**, so never gate on Trivy alone for
secrets — that is gitleaks' job (its secret ruleset also varies by version: one field
canary run missed a bare `AKIA…` key ID outright — `sast-secrets.md` has the comparison). `--exit-code` has also historically been sensitive to
flag order; confirm it actually fails on a known-bad input rather than assuming.

Scanning is slower than expected mostly because `fs` and `image` run the secret and
misconfiguration scanners by default. `--scanners vuln` restricts it to dependencies.

`--ignore-unfixed` is usually right for triage: a vulnerability with no available fix
is a risk decision, not an action item, and mixing the two buries the actionable ones.

Suppression: `.trivyignore` (one ID per line, supports `CVE-2019-14697 exp:2026-01-01`),
`.trivyignore.yaml` for per-path scoping, or a VEX document via `--vex`.

Three gotchas. SARIF output ignores `--severity` by design and emits everything. The
vulnerability DB is pulled from GHCR, which rate-limits busy CI.

And **if the project contains JARs, pass `--offline-scan`.** Trivy otherwise makes a
network call to Maven Central per JAR, and when that rate-limits it surfaces as a
generic `context deadline exceeded`. People spent three years tuning `--timeout` against
what was actually a 429; the error message was only corrected in 2026. A Java scan that
mysteriously times out is this, essentially every time.

## npm / pnpm

```bash
npm audit --omit=dev --audit-level=high
npm audit --json
npm audit signatures          # verifies registry signatures and provenance
npm audit fix --dry-run
```

```bash
pnpm audit --audit-level high --prod --json
```

`--omit=dev --audit-level=high` is the sane default; unfiltered `npm audit` is
notoriously noisy on dev-only advisories and trains people to ignore it.

**Advisory severities drift after publication.** The audit database re-rates
advisories, so an `--audit-level=high` gate that passed at merge time can start
failing on an untouched branch when a moderate advisory is re-rated high. A CI audit
job that "broke on its own" is usually this, not a new dependency. It also means a
green gate today is not durable evidence — during an audit, run the check fresh
rather than citing CI, and pin decisions with `overrides` (or a recorded suppression)
instead of trusting the threshold to stay stable.

`npm audit signatures` is cheap and catches tampering that a CVE scan cannot. Run it.

npm has no native ignore list — force patched versions through `overrides` in
`package.json`. pnpm's suppression key has moved between major versions; check
`pnpm audit --help` and the current docs before writing one rather than copying a
snippet, since a misplaced key is silently ignored and you will believe findings are
suppressed when they are not.

## pip-audit (Python)

```bash
pip install pip-audit
pip-audit                                    # current environment
pip-audit --no-deps -r requirements.txt      # pinned file, fast path
pip-audit -f json
pip-audit --ignore-vuln GHSA-xxxx-yyyy-zzzz
pip-audit --fix --dry-run
```

Exit 0 clean, 1 on findings. No SARIF, no severity filter — ID-based suppression only.

**Use `--no-deps` on pinned requirements files.** Without it, pip-audit resolves and
builds dependencies, which can execute `setup.py` from source distributions. That is
arbitrary code execution during a security scan.

## govulncheck (Go)

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
govulncheck -show traces ./...
govulncheck -mode binary ./app.exe
```

This does symbol-level reachability analysis, so it reports only vulnerabilities your
code can actually reach. When Trivy or osv-scanner flags a Go module and govulncheck
does not, govulncheck is right and the finding is noise. Say that in the report rather
than passing along a CVE nobody can trigger.

Divergence from osv-scanner is the norm: osv-scanner reports every advisory in the
lockfile, govulncheck only the vulnerable symbols your binaries call, so a double-digit
advisory list collapsing to two or three reachable findings is both tools working. When
a trace looks surprising — a module you never import directly, like grpc arriving via
pgx — confirm the path with `go mod why -m <module>` and `govulncheck -show traces`
before reporting it. And when the audit is scoped to one deployable, scope the run
(`govulncheck ./cmd/<target>/...`) or the report inherits a sibling binary's call graph.

Exit 3 on findings, 0 clean — **but `-format json|sarif|openvex` always exits 0.**
Parse the output or run it twice if you need both a gate and a report.

## Grype and Syft

```bash
syft dir:. -o cyclonedx-json=sbom.cdx.json
grype sbom:./sbom.cdx.json --fail-on high
grype dir:. -o sarif
```

`--fail-on high` exits **2**, not 1. Suppression lives in `.grype.yaml`.

Generating the SBOM once per build and scanning the SBOM afterwards is faster and
reproducible compared with re-cataloguing the tree each time. It is also the artifact
auditors ask for.

## Hallucinated packages (slopsquatting)

The supply-chain risk specific to AI-generated code. A USENIX Security 2025 study over
2.23M samples found **19.7% referenced at least one package that does not exist**, and
critically, 43% of the hallucinated names recurred across all re-runs. That
consistency is what makes them worth registering for an attacker: the same fake name
gets suggested to many developers, so squatting it is reliable.

Check every dependency that looks unfamiliar:

```bash
npm view <package> time.created maintainers
curl -s https://api.npmjs.org/downloads/point/last-month/<package>
pip index versions <package>
```

Download counts are not in the registry packument, so `npm view <pkg> downloads`
returns nothing. Use the downloads API endpoint above — a package with near-zero
monthly downloads that your code imports is the signal.

Flag any dependency that: does not resolve upstream, was first published within days
of appearing in this repo, has negligible download history, or is a near-miss of a
popular package (`python-dateutil` vs `dateutil`, `crypto-js` vs `cryptojs`). The three
observed patterns are outright fabrication (51%), conflation of two real packages
(38%), and typos (13%).

`guarddog` automates the heuristic side:

```bash
pip install guarddog
guarddog npm verify package-lock.json --output-format sarif
guarddog pypi verify requirements.txt
```

## Lockfile and registry integrity

```bash
npx lockfile-lint --path package-lock.json --type npm \
  --allowed-hosts npm --validate-https --validate-integrity --validate-package-names
```

Catches lockfile injection — a dependency whose resolved URL points somewhere other
than the registry. Runs offline, exits nonzero on violation.

Baseline hygiene to recommend when absent:
- Commit the lockfile; install with `npm ci` / `pnpm install --frozen-lockfile` /
  `pip install --require-hashes`.
- Pin the registry in `.npmrc`; use scoped names for internal packages so a public
  package cannot shadow them.
- Set a minimum release age (pnpm `minimumReleaseAge`, or Renovate's equivalent) so a
  freshly compromised version is not pulled within hours of publication. This became
  the consensus baseline after the 2025 npm worm incidents.

## Licences

```bash
trivy fs --scanners license --license-full .
osv-scanner scan source -r . --licenses="MIT,Apache-2.0,BSD-3-Clause,ISC"
npx license-checker-rseidelsohn --onlyAllow "MIT;Apache-2.0;ISC;BSD-2-Clause;BSD-3-Clause" --production
```

Relevant to an audit only when the user asks or when a copyleft licence appears in a
proprietary product. Do not editorialise about licences otherwise.

## Ranking findings

Rank by exploitability, not CVSS:

1. Reachable from untrusted input, fix available, production dependency.
2. Reachable, no fix available — this is a risk-acceptance decision, present it as one.
3. Production dependency, reachability unproven.
4. Dev-only dependency — build tooling, not runtime attack surface.
5. Unreachable (govulncheck says so, or the code path does not exist).

A "247 vulnerabilities" headline is useless. Three exploitable ones with a fix are
what the user can act on today.
