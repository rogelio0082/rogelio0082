# IaC, Containers, CI Workflows, and Web Config

## Contents
- [Read first: the scanners are themselves a supply chain](#read-first-the-scanners-are-themselves-a-supply-chain)
- [Deprecated, do not adopt](#deprecated-do-not-adopt)
- [IaC scanning](#iac-scanning)
- [Containers and Dockerfiles](#containers-and-dockerfiles)
- [CI/CD workflow security](#cicd-workflow-security)
- [GitHub Actions hardening practices](#github-actions-hardening-practices)
- [Kubernetes and cloud posture](#kubernetes-and-cloud-posture)
- [Security headers, cookies, TLS](#security-headers-cookies-tls)
- [Minimum viable stack](#minimum-viable-stack)

## Read first: the scanners are themselves a supply chain

Three 2026 incidents that change what you should recommend:

**CVE-2026-33634 (CVSS 9.4, actively exploited).** The Trivy ecosystem was compromised
between 19 and 22 March 2026. A malicious `trivy` binary shipped as v0.69.4 through
GitHub, deb and rpm, malicious Docker Hub images as v0.69.5 and v0.69.6, and **76 of 77
tags in `aquasecurity/trivy-action` were force-pushed to credential-stealing malware**.
All seven tags of `setup-trivy` were replaced.

Trivy is still the right tool. Install **v0.70 or newer** (current is v0.73.0), pin
`trivy-action` to **v0.35.0 or newer by commit SHA**, and `setup-trivy` to v0.2.6+.
Indicators of compromise to check for if the user ran Trivy in CI during that window:
`scan.aquasecurtiy.org` (note the typo), `45.148.10.212`, and `tpcp-docs-*`
repositories appearing in their GitHub org. Any CI secret exposed on 19-20 March needs
rotation.

**Checkmarx, 23 March to 22 April 2026.** KICS Docker Hub tags were compromised,
including `latest`, `debian` and `alpine`. Use KICS 2.1.20 or newer, pinned by digest,
never by a mutable tag.

The practical takeaway is worth stating in the report when CI runs scanners: pin every
scanner by digest or commit SHA. These incidents are precisely the tag-force-push
scenario that SHA pinning defeats, and they are the strongest available argument for
the pinning practice described below.

## Deprecated, do not adopt

- **tfsec** — merged into Trivy, no new checks. Terraform features added since the
  merge are uncovered.
- **Terrascan** — repository archived by Tenable in November 2025, read-only.
- **ScoutSuite** — last release May 2024. Use Prowler.
- **observatory-cli** (npm) — dead; the v1 API shut down in October 2024. Use
  `npx @mdn/mdn-http-observatory` instead.

## IaC scanning

**Trivy** is the right default for a small app: one binary covers IaC, Dockerfiles,
images, secrets and SBOM, and severity filtering is free.

```bash
trivy config .
trivy config --severity HIGH,CRITICAL --format sarif --output trivy.sarif --exit-code 1 .
```

Windows install is the ZIP from GitHub Releases — there is no winget, choco or scoop
package for Trivy itself despite what some guides claim.

**Trivy exits 0 by default even with findings.** `--exit-code 1` is mandatory to gate.
This is the single most common mistake.

Inline suppression works in Terraform, CloudFormation, Helm and Dockerfiles only:

```hcl
#trivy:ignore:AVD-AWS-0089:exp:2026-12-31
#trivy:ignore:AVD-AWS-0089[bucket_name=logs]
```

Inline ignores **cannot suppress absence-triggered checks** such as a missing `USER`
directive in a Dockerfile. Those need `.trivyignore.yaml`. Migrate any legacy
`tfsec:ignore:` comments to `trivy:ignore:`.

**Checkov** has deeper policy coverage and better skip ergonomics, and it uniquely
covers GitHub Actions, GitLab CI, Bicep, ARM, Ansible and OpenAPI:

```bash
pipx install checkov
checkov -d . --compact --quiet --framework terraform,dockerfile,github_actions
checkov -d . -o sarif --output-file-path .,results
```

Inline: `#checkov:skip=CKV_AWS_20:reason`. Baselines via `--create-baseline` and
`--baseline`. Exit 0 pass, 1 fail, `--soft-fail` forces 0.

**The Checkov catch:** severity metadata is paywalled. Open-source Checkov ships no
severities, so `--hard-fail-on HIGH` and `--check HIGH` are unusable without a Prisma
Cloud API key. If the user wants severity gating for free, that is Trivy's job.

**KICS** is worth it only when you need Rego-authored custom policies. Note its exit
codes are severity values, not 0/1: 20 info, 30 low, 40 medium, 50 high, 60 critical.
CI logic written for 0/1 silently mis-gates.

## Containers and Dockerfiles

```bash
hadolint --failure-threshold error Dockerfile
hadolint --format sarif Dockerfile
```

Hadolint's `--failure-threshold` defaults to `info`, so noisy style rules will fail a
build unless you raise it to `error` or `warning`. Suppression is
`# hadolint ignore=DL3008` immediately above the offending line, or
`# hadolint global ignore=DL3003` at the top of the file. Set
`--disable-ignore-pragma` in CI so developers cannot silently ignore their way past the
gate while keeping pragmas working locally.

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 myapp:latest
```

`--ignore-unfixed` removes most of the noise from distro base images, which otherwise
report dozens of CVEs with no available patch.

Dockle adds built-image CIS checks that Dockerfile linting cannot see — root user, no
healthcheck, credentials left in ENV, apt cache retained. Useful but not essential;
skip it if Trivy image and Hadolint are already running. It also defaults to exit 0,
so pass `--exit-code 1`.

## CI/CD workflow security

**zizmor** is the tool to reach for here, and it is actively developed:

```bash
uv tool install zizmor        # or pipx install zizmor
zizmor .
zizmor --min-severity=medium --format=sarif . > zizmor.sarif
zizmor --fix .                # safe autofixes, including SHA pinning
```

Its audits map directly to how CI gets compromised: `unpinned-uses`,
`template-injection`, `artipacked` (checkout credential persistence),
`excessive-permissions`, `dangerous-triggers` (`pull_request_target`, `workflow_run`),
`cache-poisoning`, `secrets-inherit`, and `bot-conditions` (spoofable `github.actor`).

Exit codes are non-standard: 0 no findings, 1 audit error, 2 bad args, 3 no inputs
collected, and **11/12/13/14 for findings at info/low/medium/high**. SARIF format
returns 0. Write CI gates accordingly.

Suppression is `# zizmor: ignore[template-injection] reason` inline, or a `zizmor.yml`
that can also enforce policy repo-wide:

```yaml
rules:
  unpinned-uses:
    config:
      policies:
        - hash-pin
```

**actionlint** is complementary, not a substitute — it catches syntax errors,
expression type errors, bad runner labels and invalid cron, and runs shellcheck over
`run:` blocks. Exit 0 clean, 1 problems found.

## GitHub Actions hardening practices

**Pin every third-party action to a full commit SHA.** GitHub's own documentation
states this is the only way to use an action immutably. Immutable releases prevent
retagging but do not stop a compromised maintainer account from publishing a fresh
malicious version, and the Trivy incident above was exactly a tag force-push.

```yaml
uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
```

Automate it with `pinact run`, and enforce with `pinact run --check` in CI or
`zizmor --fix`. Since August 2025 GitHub Actions policy can enforce 40-character SHA
pinning across an org.

**`pull_request_target` and `workflow_run`** execute in the base repository context
with secrets and a write token. Never check out the PR head ref under them. Avoid both
unless commenting on forked PRs is genuinely required.

**Script injection.** Never interpolate `${{ github.event.* }}` directly into a `run:`
block. Route through an intermediate environment variable and quote it:

```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
run: echo "$TITLE"
```

**Token permissions.** Set the org default to read-only, then declare least privilege
per job. Add `id-token: write` only where OIDC is used.

**Prefer OIDC over long-lived cloud secrets.** Both 2026 incidents were credential
exfiltration attacks, and long-lived secrets sitting in CI are exactly what gets
stolen.

## Kubernetes and cloud posture

Relevant only when the deployment shape justifies it:

- **kube-bench** — CIS benchmark against a live cluster; needs host access. Irrelevant
  on Vercel, Netlify, Railway or Fly.io, which expose no control plane.
- **Prowler** — multi-cloud posture for AWS, Azure, GCP, Kubernetes and others. Worth
  running only when a real cloud account sits behind the app. Note exit code 3 means
  FAIL findings. It cannot audit Vercel or Netlify configuration.

## Security headers, cookies, TLS

**Windows gotcha that breaks the obvious command:** in Windows PowerShell 5.1, `curl`
is an alias for `Invoke-WebRequest`, so `curl -sSI` errors out. Call `curl.exe`
explicitly.

```bash
curl -sS -D - -o /dev/null -L https://example.com | grep -iE \
 '^(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy)'
```

```powershell
curl.exe -sS -D - -o NUL -L https://example.com | Select-String 'content-security-policy|strict-transport-security|x-frame-options|referrer-policy'
```

Use `-D -` with `-L` rather than `-I`: some origins return 405 for HEAD, and CSP is
frequently set only on GET.

**Cookies** — check `Secure`, `HttpOnly` and `SameSite` on every session cookie by
reading the raw header. The `-c cookies.txt` jar format does not surface `HttpOnly` or
`SameSite`:

```bash
curl -sS -D - -o /dev/null -L https://example.com/login | grep -i '^set-cookie'
```

**TLS.** `testssl.sh` is a bash script, so on Windows use Docker or WSL:

```bash
docker run --rm -it ghcr.io/testssl/testssl.sh https://example.com
```

The Windows-native alternative is sslyze, which is pure pip and needs no WSL:

```powershell
pip install --upgrade sslyze
python -m sslyze --json_out=scan.json example.com:443
```

**What the platform gives you free versus what is yours.** On Vercel and Netlify, TLS,
the HTTPS redirect and HSTS are automatic. **CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy and every cookie flag are
the application's responsibility.** Configure them in `vercel.json` or `netlify.toml`.

Netlify gotcha: custom headers do not apply to proxied content, Functions, Edge
Functions, or server-rendered pages. Those must emit headers in code, so verify against
a live response rather than reading the config file.

## Minimum viable stack

```bash
trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --exit-code 1 .
hadolint --failure-threshold error Dockerfile
zizmor --min-severity=medium .
curl.exe -sS -D - -o NUL -L https://yourapp.com | Select-String 'content-security-policy|strict-transport-security|x-frame-options'
```

Add Checkov when real Terraform exists and deeper policy matters. Add Dockle for
built-image CIS checks. Add Prowler when a cloud account sits behind the app. Skip
kube-bench and ScoutSuite for this deployment shape entirely.
