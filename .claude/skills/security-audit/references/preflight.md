# Preflight: canary verification and Docker fallback

Read during Phase 1. Availability is not health — a semgrep that `command -v` finds
can fatally error on every current rule and still look installed. Verify each present
tool against a known-vulnerable canary before reporting the inventory, and prefer the
official Docker image when a host install is broken.

## The canary set

Write these to `$TMP/security-audit/canary/` (PowerShell
`$env:TEMP\security-audit\canary\`). Everything in them is fabricated — never put a
real credential in a canary. Deleted with the artifact directory at the end of Phase 9.

`canary.py` — SAST sinks and secret formats in one file:

```python
import subprocess
aws_key = "AKIAQYLPMN5G3XVRWTZK"                  # fake, format-valid AWS key ID
github_token = "ghp_<36 random [0-9A-Za-z]>"      # assemble a fresh fake PAT, see below
subprocess.call("ls " + input(), shell=True)      # shell injection
```

Replace the PAT placeholder with 36 random alphanumerics you generate at write time,
as one assembled literal (`"ghp_Xw3…"` — scanners regex the source text, so a string
concatenation does not fire). No literal example appears here because a format-valid
PAT in a committed file trips GitHub push protection — the same property that makes
it a working canary. And do not "sanitise" either value into `AKIA…EXAMPLE` or
`ghp_000…`: scanners allowlist documentation keys and entropy-filter repeated
characters, so a polite canary tests nothing — it must exercise the same rules a
real leak would.

`requirements.txt` — one pinned, known-vulnerable release:

```
requests==2.19.1
```

(CVE-2018-18074, fixed in 2.20.0 — any working dependency scanner reports at least
one advisory against it.)

`go/go.mod` and `go/main.go` — only when Phase 0 detected Go:

```go
// go/main.go
package main

import (
	"os"
	"os/exec"
)

func main() { exec.Command(os.Args[1]).Run() } // G204, and G104 for the dropped error
```

```
// go/go.mod
module canary

go 1.22
```

## Per-tool canary runs

`$CANARY` is the canary directory. Canary only the tools this audit will actually run,
with the same config the real scan will use. Expected signal is what a healthy tool
must produce; anything else — error, empty output, exit 0 with zero findings — is
BROKEN. Record the exact error. Parse the JSON and count findings yourself; exit codes
lie (see "Never trust an exit code alone" in `sast-secrets.md`).

| Tool | Canary command | Expected signal |
|---|---|---|
| semgrep | `semgrep scan --config p/security-audit --json $CANARY` | ≥1 result (subprocess/shell) |
| bandit | `bandit -r $CANARY -f json` | ≥1 issue (B602/B604) |
| gitleaks | `gitleaks dir -v $CANARY` | ≥2 leaks (AWS key, GitHub PAT) |
| trufflehog | `trufflehog filesystem $CANARY --no-verification --json` | ≥1 result (GitHub detector) |
| trivy secrets | `trivy fs --scanners secret $CANARY` | GitHub PAT flagged (AWS key is version-dependent — see below) |
| trivy vuln | `trivy fs --scanners vuln $CANARY` | ≥1 CVE on requests 2.19.1 |
| osv-scanner | `osv-scanner scan source -L $CANARY/requirements.txt` | ≥1 advisory, exit 1 |
| gosec | `gosec ./...` from inside `$CANARY/go/` | ≥1 issue (G204) |

Two deliberate deviations, verified against the current tools:

- **trufflehog is the one canary that must not use the real scan's config.** Its
  verifier correctly rejects the fake credentials, and `--results=verified,unknown`
  then filters them out as "unverified" — a healthy install reports zero. Canary with
  `--no-verification`: the pattern engine is what is being tested. (Its AWS detector
  also needs a paired secret key, so only the GitHub PAT fires — expected.)
- **Trivy's bare-AWS-key detection is version-dependent.** A field run missed the
  `AKIA…` key ID entirely and fired only on the GitHub PAT; v0.73.0 catches both.
  Gate trivy's canary on the PAT alone — AWS-key silence is a known ruleset gap in
  some versions, not breakage — and never rely on trivy for secret coverage either
  way (`sast-secrets.md` has the measured comparison; gitleaks is the gate).

Not canaried here:

- **govulncheck** needs a module whose code calls a vulnerable symbol, which is too
  heavy for preflight. Inventory it as `present — verified at first use`: it fails
  loudly on package-load errors, so its exit codes are trustworthy, and a clean result
  is a reachability verdict, not silence (`sca-supply-chain.md`).
- Phase 5/7 tools (checkov, hadolint, zizmor, nuclei, ZAP) — their silent-failure
  checks live in their own references.

## Run via Docker — first choice for a BROKEN or MISS tool

Host installs rot — an ancient distro package, a Python packaging conflict — and the
official image sidesteps the toolchain entirely. Ask before the first pull, then re-run
the canary through the container: an image can be broken too.

| Tool | One-liner |
|---|---|
| semgrep | `docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan --config p/security-audit /src` |
| gitleaks | `docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest git /repo` |
| trufflehog | `docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest git file:///repo --results=verified,unknown` |
| bandit | `docker run --rm -v "$PWD:/src" ghcr.io/pycqa/bandit/bandit -r /src` |
| trivy | `docker run --rm -v "$PWD:/repo" ghcr.io/aquasecurity/trivy:0.73.0 fs --scanners vuln /repo` |
| osv-scanner | `docker run --rm -v "$PWD:/src" ghcr.io/google/osv-scanner:latest scan source -r /src` |
| gosec | `docker run --rm -v "$PWD:/app" -w /app securego/gosec ./...` |

**Trivy: pin an explicit tag >= 0.70, pull from GHCR, and check `--version` after the
pull.** Malicious images shipped as v0.69.5/v0.69.6 in the March 2026 compromise
(CVE-2026-33634) and the Docker Hub account was locked down afterwards — never
`latest` for trivy. Detail in `sca-supply-chain.md`.

Mount caveats: history scans (gitleaks `git`, trufflehog `git`) need `.git` inside the
mount — mount the repo root, not a subdirectory. On Windows pass an absolute path
(`-v "C:\repo:/repo"`); `$PWD` under Git Bash mangles the drive prefix.

Host install one-liners, if the user prefers them: `sast-secrets.md` → Install.
