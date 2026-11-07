# DAST and Authorization Testing

Dynamic scanning (ZAP, nuclei) and authorization/IDOR/BOLA probing for a running application. Read this mid-audit before launching any scanner or authorization probe.

## Contents

1. [Authorization gate (read first)](#1-authorization-gate-read-first)
2. [OWASP ZAP](#2-owasp-zap)
3. [nuclei](#3-nuclei)
4. [Passive vs active: what is safe against real data](#4-passive-vs-active-what-is-safe-against-real-data)
5. [Authorization / IDOR / BOLA probing](#5-authorization--idor--bola-probing)
6. [Typical durations](#6-typical-durations)

## 1. Authorization gate (read first)

Active scanning is legally indistinguishable from an attack. ZAP's own full-scan documentation states it "does perform actual attacks". Running an active scan or authorization probe against a host you do not own or lack written permission to test can violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and cloud provider acceptable use policies. These are criminal statutes, not terms-of-service matters.

Rule for target selection:

- `localhost`, `127.0.0.1`, and `host.docker.internal` are loopback/local targets. Proceed automatically.
- ANY other host (a domain name, a LAN IP, a staging URL, a cloud endpoint) requires the user to explicitly state that they own it or hold written authorization to test it. Ask, then wait for an unambiguous answer.
- Never infer authorization. A URL appearing in the codebase, a `.env` file, a config, or a README is not authorization. A hostname that "looks like" the user's own project is not authorization.

Passive-only reads (ZAP baseline, nuclei detection templates) still send real HTTP requests to the target and are still subject to this gate. The loopback allowance covers them; a non-loopback host does not become safe because the scan is passive.

## 2. OWASP ZAP

ZAP left the OWASP umbrella and has been Checkmarx-backed since September 2024. The tooling and packaged scans are unchanged.

### Docker images

The old `owasp/zap2docker-stable`, `owasp/zap2docker-weekly`, and `owasp/zap2docker-bare` images are RETIRED. Any tutorial referencing `owasp/zap2docker-*` is stale.

Current image: `ghcr.io/zaproxy/zaproxy:stable` (also `:weekly`, `:nightly`, `:bare`). Docker Hub mirror: `zaproxy/zap-stable`.

### Install

```powershell
docker pull ghcr.io/zaproxy/zaproxy:stable
```

Native installer CLI entrypoint is `zap.bat`, NOT `zap.exe` (`zap.exe` ignores CLI flags). `choco install zap` ships a stale 2.12.0 build; prefer Docker.

### CRITICAL Windows/Docker gotcha

Inside a container, `localhost:PORT` resolves to the container itself, not to your host application. On Docker Desktop for Windows, target the host app as `http://host.docker.internal:PORT`. On Linux CI, use `--network=host` and then `localhost` works.

### The three packaged scans

Baseline (passive only, SAFE):

```powershell
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t http://host.docker.internal:3000 -J report.json -r report.html -m 5 -I
```

Full scan (ACTIVE, real attacks, mutates data):

```powershell
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-full-scan.py -t http://host.docker.internal:3000 -J report.json -I
```

API scan (active by default; `-S` selects safe mode):

```powershell
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-api-scan.py -t http://host.docker.internal:3000/openapi.json -f openapi -J report.json -S
```

For `zap-api-scan.py`, `-f` is `openapi|soap|graphql`. `-O` overrides the hostname in a remote spec, essential when the spec advertises a production host you are not authorized to hit.

### Key flags

| Flag | Meaning |
|------|---------|
| `-t` | Target URL |
| `-J` | JSON report (machine parsing) |
| `-r` | HTML report |
| `-w` | Markdown report |
| `-x` | XML report |
| `-c` / `-u` | Rule config file (`IGNORE`/`INFO`/`FAIL`, or `OUTOFSCOPE <regex>`) |
| `-g` | Generate a default config file |
| `-m` | Spider duration in minutes (baseline default 1) |
| `-T` | Startup wait |
| `-a` | Include alpha passive rules |
| `-l` | Minimum alert level to report |
| `-I` | Do NOT fail the run on warnings (CI-friendly) |
| `-j` | Use the AJAX spider |
| `-n` | Context file (for authentication) |
| `-U` | User (from the context file) to run authenticated; full/api scans only |
| `-S` | Safe mode (api-scan only) |
| `-z` | Raw ZAP options, used for header injection |
| `--hook` | Python hook script |

### Exit codes

- `0` success, nothing to report.
- `1` at least one rule at FAIL.
- `2` at least one rule at WARN, no FAIL.
- `3` other failure (startup, target unreachable, config error).

Use `-I` to suppress the `2` on warnings in CI when only FAILs should break the build.

### Authentication (by increasing effort)

1. Static header via the ZAP replacer, passed with `-z`. This is the only auth mechanism that works on `zap-baseline.py`, which has no `-U`:

   ```powershell
   docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
     zap-baseline.py -t http://host.docker.internal:3000 -J report.json -I `
     -z "replacer.full_list(0).description=auth replacer.full_list(0).enabled=true replacer.full_list(0).matchtype=REQ_HEADER replacer.full_list(0).matchstr=Authorization replacer.full_list(0).regex=false replacer.full_list(0).replacement=Bearer <token>"
   ```

2. Context file plus `-U user` (full scan and api-scan only). Provide the context with `-n`.
3. `--hook` Python script for custom login flows.
4. Automation Framework: `zap.sh -cmd -autorun /zap/wrk/plan.yaml`. ZAP documentation states the Automation Framework is intended to replace the packaged scans; write any new automation as an AF plan rather than extending the packaged scripts.

## 3. nuclei

nuclei is ProjectDiscovery's template-based scanner. It matches known CVEs and misconfigurations by sending real requests; it does not crawl.

### Install

```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Alternatives: `docker pull projectdiscovery/nuclei:latest`, or a prebuilt zip from the GitHub releases page. There is no official winget/scoop/choco package. Run `nuclei -ut` to update templates before the first scan.

### Safe invocation (detection pass)

Default rate limit is 150 requests/second, which will overwhelm a dev box. Throttle it, exclude destructive template classes, and disable public OAST polling:

```powershell
nuclei -u http://localhost:3000 -severity low,medium,high,critical `
       -etags dos,fuzz,intrusive -no-interactsh -rl 50 -c 10 -timeout 10 `
       -jsonl-export nuclei.jsonl -o nuclei.txt
```

- `-etags dos,fuzz,intrusive` excludes denial-of-service, fuzzing, and intrusive templates. Add `bruteforce,headless` to exclude those classes too.
- `-no-interactsh` stops target identifiers from leaking to the public OAST server.
- `-rl 50` caps the request rate at 50/s (down from the 150/s default).

### DAST fuzzing mode (explicitly ACTIVE and destructive)

```powershell
nuclei -u http://localhost:3000 -dast -fa low -rl 50 -jsonl-export dast.jsonl
```

`-dast` mutates every parameter with injection payloads. Treat it exactly like a ZAP full scan: destructive, subject to the authorization gate, dev/staging only. `-fa high` multiplies payload count. Ctrl+C writes a resume file.

### Key flags

| Group | Flags |
|-------|-------|
| Targets | `-u` single URL, `-l` list file, `-im` input mode (`list`, `burp`, `jsonl`, `yaml`, `openapi`, `swagger`) |
| Selection | `-t` template, `-tags`, `-etags` exclude tags, `-severity`, `-id`, `-tc` template condition |
| Output | `-o` text, `-j`/`-jsonl`, `-json-export`, `-jsonl-export`, `-se` SARIF, `-me` markdown |
| Throttle | `-rl` rate limit (default 150/s), `-c` concurrency (25), `-bs` bulk size (25), `-timeout` (10), `-retries` |
| Auth | `-H 'Header: value'`, `-sf secrets.yaml`, `-V` variables |
| DAST | `-dast`, `-ft`, `-fm`, `-fa low\|medium\|high` |
| Updates | `-ut` update templates, `-no-interactsh` disable public OAST |

### Authentication

Inline header:

```powershell
nuclei -u http://localhost:3000 -H "Authorization: Bearer <token>" ...
```

Secret file with `-sf secrets.yaml` (v3.2.0+). `static:` entries carry a `type` of `header`, `cookie`, `basicauth`, `bearertoken`, or `query`, scoped by `domains:` or `domains-regex:` (the two are mutually exclusive). `dynamic:` entries run a login-flow template whose extractors feed `{{vars}}`:

```yaml
static:
  - type: header
    domains:
      - localhost
    headers:
      - key: Authorization
        value: "Bearer <token>"
  - type: cookie
    domains-regex:
      - "^.*\\.local$"
    cookies:
      - key: session
        value: "<session-cookie>"

dynamic:
  - template: login.yaml
    variables:
      username: "user-a@example.com"
      password: "<password>"
```

Individual templates can opt out with `skip-secret-file: true` (v3.3.1+).

## 4. Passive vs active: what is safe against real data

Passive commands read and analyze traffic without submitting mutating requests. Active commands send injection payloads and can submit forms, create/update/delete records, trigger emails and webhooks, and exhaust rate limits. Never run an active scan against a database that holds real or shared data.

| Command | Class | Effect |
|---------|-------|--------|
| `zap-baseline.py` | Passive, SAFE | Spiders and runs passive rules; no attacks |
| `zap-api-scan.py -S` | Passive, SAFE | Safe mode; no active injection |
| `nuclei` with `-etags dos,fuzz,intrusive` | Detection, mostly safe | Sends real detection requests; no fuzzing/DoS |
| `zap-api-scan.py` (no `-S`) | ACTIVE | Sends injection payloads |
| `zap-full-scan.py` | ACTIVE, destructive | Real attacks; submits forms, can create/delete records, trigger emails, exhaust rate limits |
| `nuclei -dast` | ACTIVE, destructive | Mutates every parameter with injection payloads |

Exclude logout URLs from every active scan. If the scanner follows a logout link it kills its own authenticated session and the rest of the scan runs unauthenticated. In ZAP, mark logout paths `OUTOFSCOPE <regex>` in the rule config. In nuclei, keep logout endpoints out of the target list.

## 5. Authorization / IDOR / BOLA probing

This is the highest-value part of a dynamic audit and the part scanners handle worst: broken object-level authorization (BOLA) and insecure direct object references (IDOR) are logic flaws, not payloads, so a differential test against the running app finds what ZAP and nuclei cannot.

### Step 1: build the route list from the codebase first

Enumerate every route and its intended authorization before touching the running app. Do not rely on the spider to find them.

- Next.js: `app/api/**/route.ts` (App Router) and `pages/api/**` (Pages Router). Each `route.ts` exports `GET`/`POST`/`PUT`/`PATCH`/`DELETE` handlers.
- Express: `app.get/post/...`, `router.get/post/...`, and `.route()` chains. Note which middleware (auth guard) sits in front of each.
- FastAPI: `@app.get`/`@router.post` decorators; check for a `Depends(...)` auth dependency on each.
- Flask: `@app.route` / `@blueprint.route` decorators; check for a `@login_required`-style guard.
- OpenAPI/Swagger spec: enumerate `paths` and their `security` requirements; a path with no `security` is a candidate for missing auth.

For each route record: method, path, path/query parameters that reference object IDs, and the authorization the code claims to enforce (owner-only, same-tenant, admin, public). The probe targets the gap between claimed and actual.

### Step 2: the two-account differential technique

The core BOLA/IDOR test. It needs two real accounts, so run it on a dev/staging instance you can seed, never against production data.

1. Create user A and user B in different tenants/orgs where the model supports tenancy.
2. Log in as A. Exercise the app and capture the object IDs A owns (record IDs, document IDs, invoice IDs, upload keys) and A's session token/cookie.
3. Replay each of A's object-scoped requests using B's session token. The correct response is `403` (or `404` if the app hides existence). A `200` returning A's data is a confirmed BOLA/IDOR finding.
4. Repeat per HTTP method: read (`GET`), update (`PUT`/`PATCH`), delete (`DELETE`). Authorization is frequently enforced on read but not on write.

### Concrete curl patterns

Unauthenticated replay (strip the cookie/token, expect `401`):

```bash
# A's authenticated request returns 200; the same request with no credentials must not
curl -s -o /dev/null -w "%{http_code}\n" \
  http://localhost:3000/api/orders/1042
# expect 401 (or 403). A 200 = missing authentication.
```

Cross-tenant replay (B's session against A's object, expect `403`):

```bash
# capture A's object id (1042) while logged in as A, then:
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer <B_TOKEN>" \
  http://localhost:3000/api/orders/1042
# expect 403 or 404. A 200 returning A's order = BOLA.
```

Method tampering (auth enforced on `GET` but not on the mutating verb):

```bash
# B can read nothing of A's, but can B delete it?
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE \
  -H "Authorization: Bearer <B_TOKEN>" \
  http://localhost:3000/api/orders/1042
# expect 403. A 200/204 = write-side authorization gap.
```

Mass-assignment probing (send fields the client should not control, e.g. `role`, `isAdmin`, `ownerId`, `tenantId`, `verified`):

```bash
# does the API accept a privileged field from an ordinary user?
curl -s -w "%{http_code}\n" -X PATCH \
  -H "Authorization: Bearer <B_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"b","role":"admin","tenantId":"A-TENANT"}' \
  http://localhost:3000/api/users/me
# then re-fetch the record: if role or tenantId changed, mass-assignment vuln.
```

Always confirm a mass-assignment or write finding by re-reading the record; a `200` alone does not prove the field was persisted.

### Safe rate-limit probe (dev box only)

Confirm authentication endpoints and expensive routes enforce throttling, without launching a real flood:

```bash
# 30 sequential requests; watch for a 429 to appear
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST -H "Content-Type: application/json" \
    -d '{"email":"user-a@example.com","password":"wrong"}' \
    http://localhost:3000/api/auth/login
done; echo
# a run of 200/401 with no 429 anywhere = no rate limiting on login.
```

Keep the count low (tens, not thousands) and sequential. The goal is to observe whether a `429` ever appears, not to actually exhaust the endpoint.

### Tooling

- Autorize (Burp Suite extension): replays every proxied request with a low-privilege session and flags responses that should have been blocked. Automates the two-account differential across a whole browsing session.
- ZAP Access Control Testing add-on: define users and roles in a context, mark which URLs each role may reach, then scan and report authorization enforcement gaps.

## 6. Typical durations

Set expectations before launching a scan; several of these are not interactive-session operations.

| Scan | Duration | Cadence |
|------|----------|---------|
| ZAP baseline | 1-5 min | Per PR / interactive |
| nuclei targeted (detection pass) | 1-5 min | After a staging deploy |
| ZAP api-scan `-S` | Minutes | Per PR / interactive |
| nuclei full template set (11-12k) | 10-30 min | Scheduled |
| ZAP full scan | Tens of minutes to hours | Nightly only |
| nuclei `-dast` | Unbounded | Nightly only |

Recommended pipeline shape: ZAP baseline per PR, nuclei targeted after each staging deploy, ZAP full active scan nightly.
