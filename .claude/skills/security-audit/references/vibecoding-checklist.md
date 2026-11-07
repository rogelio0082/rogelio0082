# Failure Classes in AI-Generated Code

Ranked by measured frequency across three independent 2025 audits: a 50-app manual
audit, an autonomous-pentest study covering 434 issues, and GitGuardian's secrets
telemetry. Every incident cited here is documented, not hypothetical.

The pattern that matters: **almost every item is a configuration or context failure,
not a code-logic bug.** AI generators optimise for "the feature runs", and nothing
about a missing authorization check stops the feature from running. This is exactly
why SAST alone misses most of them, and why this checklist is worked manually.

## Contents
1. [Missing row-level security](#1-missing-row-level-security--critical)
2. [Secrets in client bundles](#2-secrets-in-client-bundles--critical)
3. [Missing authorization / IDOR](#3-missing-authorization--idor--high)
4. [No rate limiting](#4-no-rate-limiting-on-auth-otp-reset--high)
5. [Secrets in git history](#5-secrets-committed-to-git--high)
6. [Permissive CORS](#6-permissive-cors--mediumhigh)
7. [Weak JWT handling](#7-weak-or-insecurely-stored-jwt--mediumhigh)
8. [Debug and admin exposure](#8-debug-mode-and-exposed-admin-routes--high-when-present)
9. [SQL injection](#9-sql-injection-via-string-interpolation--medium)
10. [Prompt injection](#10-prompt-injection--high-in-any-llm-app)
11. [Hallucinated dependencies](#11-hallucinated-dependencies--medium)

---

## 1. Missing row-level security — CRITICAL

**Frequency: 88% of audited apps. 70% had it completely off.**

Why it happens: Lovable, Bolt and v0 templates shipped with RLS disabled by default
until mid-2025 patches. The model generates working CRUD against the public `anon`
key and never emits `ALTER TABLE … ENABLE ROW LEVEL SECURITY`, because the app works
fine without it. Firebase equivalent: default-open rules.

Documented: the **Tea app** breach (July 2025) exposed 72,000 images including 13,000
government-ID selfies plus roughly 1.1M private messages, from an unsecured Firebase
Storage bucket. **CVE-2025-48757** (CVSS 9.3) covered RLS misconfiguration across 170+
Lovable apps; one exposed 18,697 student records to anyone holding the public key.

Phase 5 already routes this to the BaaS reference when Supabase or Firebase is present.
Do not open it from here; confirm Phase 5 ran it, because this single check outweighs
most of the rest of an audit.

## 2. Secrets in client bundles — CRITICAL

**Frequency: 78% of audited apps.**

Why it happens: the model cannot tell a publishable key from a server-only one, so it
prefixes everything with `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` to make it work in the
browser. That compiles the value into shipped JavaScript. Pasting a real key into a
prompt for context also gets it echoed back as a string literal.

Documented: **Moltbook** leaked 1.5M API tokens and 47GB of conversation history this
way. Combined with item 1, an exposed anon key plus absent RLS returns every row of
every table to anyone who opens devtools.

```bash
grep -rE "NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|SERVICE)" .
```

Only `NEXT_PUBLIC_SUPABASE_ANON_KEY` and `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (and
their framework equivalents) are legitimately public. Everything else is a finding.

Scan the **built** output, not just source — that is where it becomes public:

```bash
grep -rE "(sk_live_|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|service_role|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9)" dist/ .next/ build/
```

A `service_role` key anywhere client-side is automatically critical: it bypasses RLS
by design, so it voids every policy the database has.

Fix: move to server-only environment variables, proxy privileged calls through a
backend route, and rotate every exposed key — they are already public.

## 3. Missing authorization / IDOR — HIGH

**Frequency: 88 findings in the pentest study, second most common class. Rises from
11% of issues in small apps to 28% in larger ones.**

Why it happens: prompts specify *what* an endpoint returns, never *who* may call it.
Generated queries key on the request parameter alone (`WHERE id = :id`) with no owner
or tenant filter. Authentication gets checked; authorization does not. The distinction
is "is someone logged in" versus "does this particular user own this particular row".

Worse, the check is sometimes inverted — `if (session) { deny }` instead of
`if (!session) { deny }`. That appeared in 24% of audited apps; one such app blocked
real users while granting anonymous access and exposed 4,538 university records.

Documented: **Base44** (Wiz, July 2025) — undocumented registration and
email-verification endpoints required only a non-secret `app_id` that was visible in
the app URL and `manifest.json`. Anyone could create a verified account on any private
app and bypass SSO entirely.

**This is OWASP A01:2025 and no scanner in this skill will find it.** Work it manually:

1. Enumerate every route. Next.js `app/api/**/route.ts`, Express `router.<verb>`,
   FastAPI/Flask decorators, an OpenAPI spec — build the complete list first.
2. For each route, find the authorization check and confirm it constrains the query to
   the caller, not just that a session exists.
3. Flag any data access filtered only by a client-supplied identifier.

```bash
grep -rEn "\.(get|post|put|patch|delete)\(|@(app|router)\.(get|post|put|delete)|@(login_required|requires_auth)" .
grep -rEn "findUnique|findFirst|\.objects\.get\(|SELECT .* WHERE id" .
```

Phase 7 covers dynamic confirmation, which is the fastest way to turn a suspicion here
into a proven finding. Note the candidate routes now and carry them into that phase.

Fix: default-deny at a middleware choke point, assert a specific permission, and scope
every object lookup to the authenticated principal at the data-access layer.

## 4. No rate limiting on auth, OTP, reset — HIGH

**Frequency: the single largest class in the pentest study, 93 findings. Most
AI-generated apps have none at all.**

Why it happens: rate limiting is cross-cutting infrastructure. It never appears in a
feature prompt, so it never appears in the code.

Impact: credential stuffing, brute force, OTP guessing, and SMS-pumping abuse where
every request costs the operator real money.

```bash
grep -rEn "express-rate-limit|@upstash/ratelimit|slowapi|Flask-Limiter|rate.?limit" .
```

Absence of any limiter on `/login`, `/signup`, `/otp`, `/verify`, `/reset` is the
finding. Confirm dynamically by firing ~100 requests in 10 seconds at a dev instance
and checking whether any are rejected.

Fix: per-IP **and** per-account limits on every auth, OTP, reset and email-sending
route, exponential backoff, a challenge after repeated failures, and a hard per-account
cap on OTP sends. Note honestly that IP rate limiting alone does not stop
residential-proxy-distributed abuse — the per-account cap is what does.

## 5. Secrets committed to git — HIGH

**Frequency: 12.8M new secrets in public GitHub commits in one year, up 28%.
AI-service credential leaks up 81%.**

Why it happens: agents write `.env` files containing real values and do not reliably
add them to `.gitignore`; `git add .` sweeps them in. Because git is append-only,
deleting the file later changes nothing.

Phase 2 covers detection, triage and the rotate-then-scrub order.

## 6. Permissive CORS — MEDIUM-HIGH

Configuration and header issues were roughly 40% of findings in one 15-app breakdown.

Why it happens: the model hits a CORS error while making the feature work and reaches
for the fastest fix — `Access-Control-Allow-Origin: *`, bare `cors()`, or reflecting
the request `Origin` header back unconditionally. Often combined with
`Allow-Credentials: true`, which is spec-invalid but still partially honoured.

```bash
grep -rEn "Access-Control-Allow-Origin.*\*|origin:\s*true|cors\(\)" .
```

Flag any code that echoes `req.headers.origin` into the response without an allowlist
check. Confirm live:

```bash
curl -H "Origin: https://evil.example" -I https://target/api/endpoint
```

Reflected origin plus `Allow-Credentials: true` is critical — any site the victim
visits can read authenticated responses.

Fix: explicit origin allowlist, never reflect arbitrary origins, and set
`Allow-Credentials: true` only alongside a specific non-wildcard origin.

## 7. Weak or insecurely stored JWT — MEDIUM-HIGH

Why it happens: generated auth code decodes tokens without verifying the signature,
omits an algorithm allowlist, skips `exp`/`aud` validation, uses a hardcoded secret,
and stores the token in `localStorage` where any XSS can read it.

```bash
grep -rEn "verify_signature\"?\s*:\s*(false|False)|verify\s*=\s*False|algorithms\s*=\s*\[?\s*['\"]?none" .
grep -rn "localStorage.setItem.*[Tt]oken\|localStorage.*jwt" .
grep -rEn "jwt\.(decode|verify)\(" .
```

A `decode`/`verify` call with no explicit `algorithms=` allowlist lets the token's own
header choose the algorithm. That enables both `alg: none` and RS256-to-HS256
confusion, where the public key is used as an HMAC secret. Also flag signing secrets
that are short, literal, or obviously placeholder (`secret`, `changeme`).

Fix: always verify, pin an explicit algorithm allowlist, validate `exp`/`nbf`/`iss`/
`aud`, use a 256-bit random secret from the environment, and store session tokens in
`httpOnly` `Secure` `SameSite` cookies rather than `localStorage`.

## 8. Debug mode and exposed admin routes — HIGH when present

Six critical debug-mode-to-RCE findings appeared in the pentest study.

Why it happens: scaffolds ship with `DEBUG=True`, verbose error pages, and `/admin`,
`/debug`, `/seed` or test routes left mounted. In several frameworks debug mode
exposes an interactive console, which is remote code execution.

```bash
grep -rniE "debug\s*=\s*true|FLASK_DEBUG|app\.run\(.*debug\s*=\s*True|NODE_ENV.*development" .
grep -rEn "/(admin|debug|__debug__|actuator|seed|test)" --include="*.ts" --include="*.py" --include="*.js" .
```

Also check GraphQL introspection, which should be off in production.

Fix: enforce `DEBUG=False` through the environment rather than a code default, remove
or authenticate admin and seed routes, and return generic error pages.

## 9. SQL injection via string interpolation — MEDIUM

Declining, because newer frameworks default to parameterised queries, but hand-rolled
raw SQL still appears whenever the model steps outside the ORM.

```bash
grep -rEn "(execute|query|raw)\(.*(f\"|f'|\$\{|\+\s*req\.|%\s*\(|\.format\()" .
```

Semgrep's taint rules cover this better — use `p/sql-injection` when available.

Related sinks worth the same treatment when they touch user input: `eval()`, `exec()`,
`new Function()`, `pickle.loads`, and `yaml.load` without `SafeLoader`.

Fix: parameterised statements or ORM query builders, with no exceptions.

## 10. Prompt injection — HIGH in any LLM app

OWASP LLM01:2025, the top LLM risk. Vibe-coded apps are usually AI apps, which makes
this near-universal in this population. Phase 6b gives it full treatment.

Documented: GitHub Copilot **CVE-2025-53773** (CVSS 9.6), indirect prompt injection
leading to remote code execution. **PocketOS** — an over-privileged agent dropped the
production database, causing a 30-hour outage. Agents holding destructive permissions
with no confirmation gate appeared in 16% of audited apps.

## 11. Hallucinated dependencies — MEDIUM

19.7% of AI-generated samples reference a package that does not exist, and the same
fake names recur consistently enough for attackers to pre-register them. Phase 4
covers detection.

---

## Working this checklist

Do not paste the whole list into the report. Check each item, then report only what
you confirmed, with the file and line. Items 1-4 are where the real risk concentrates;
if time is short, do those four properly rather than all eleven superficially.

State which items you checked and found clean. "Verified: RLS enabled on all 14 tables"
is worth as much to the user as a finding, and it is what makes the report trustworthy.
