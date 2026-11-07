# Supabase and Firebase Security Verification

The highest-value check in this skill. Row-level security missing or disabled appeared
in 88% of audited AI-built apps, and it is what turned a public key into a full data
breach in every documented incident.

Verify enforcement. Never accept "RLS is enabled" as an answer — enabled with a
permissive policy, or enabled without `FORCE`, is the same as off.

## Contents
- [The two commands that catch most of it](#the-two-commands-that-catch-most-of-it)
- [Supabase: tooling that actually exists](#supabase-tooling-that-actually-exists)
- [Supabase: SQL audit queries](#supabase-sql-audit-queries)
- [Supabase: anon vs service_role, and the 2025 key migration](#supabase-anon-vs-service_role-and-the-2025-key-migration)
- [Supabase: black-box enforcement tests](#supabase-black-box-enforcement-tests)
- [Supabase: auth config, the multiplier](#supabase-auth-config-the-multiplier)
- [Firebase: audit what is deployed](#firebase-audit-what-is-deployed)
- [Firebase: default-open rule patterns](#firebase-default-open-rule-patterns)
- [Firebase: black-box testing](#firebase-black-box-testing)
- [What client keys actually protect](#what-client-keys-actually-protect)
- [Corrections to widely repeated advice](#corrections-to-widely-repeated-advice)

## The two commands that catch most of it

```bash
supabase db advisors --linked --level error
```

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/releases" | jq
```

Everything below is the detail behind those, plus the black-box probes that prove
enforcement rather than assume it.

## Supabase: tooling that actually exists

| Command | What it does | Security use |
|---|---|---|
| `supabase db lint` | `plpgsql_check` — PL/pgSQL runtime and schema errors | **Not a security linter.** Widely mistaken for one. |
| `supabase db advisors` | Runs the embedded `splinter` lint SQL | **This is the security check.** Needs CLI 2.81.3 or newer. |
| `supabase inspect db <sub>` | bloat, locks, index-stats, outliers, vacuum-stats | **No security subcommand.** Performance and ops only. |
| `supabase test db [path]` | pgTAP | RLS regression tests in CI |
| Dashboard Security Advisor | Same splinter lints, in the UI | Manual check |

Run splinter directly against any Postgres, with no CLI version dependency:

```bash
curl -sO https://raw.githubusercontent.com/supabase/splinter/main/splinter.sql
psql "$DB_URL" -f splinter.sql
```

Known bug: `supabase db advisors --db-url` fails on local databases with custom ports
(`SQLSTATE 42601`) because the embedded SQL prepends `set local search_path = ''`.
Running `psql -f splinter.sql` sidesteps it.

Splinter's ERROR-level security lints: `rls_disabled_in_public`,
`policy_exists_rls_disabled`, `auth_users_exposed`, `security_definer_view`,
`rls_references_user_metadata`, `insecure_queue_exposed_in_api`, `fkey_to_auth_unique`,
`sensitive_columns_exposed`. WARN level adds `rls_policy_always_true`,
`public_bucket_allows_listing`, `function_search_path_mutable`, `extension_in_public`,
`materialized_view_in_api`, and the `*_security_definer_function_executable` pair.

## Supabase: SQL audit queries

**Tables with RLS off** — the headline vulnerability:

```sql
select n.nspname as schema, c.relname as table,
       c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p')
  and n.nspname not in ('pg_catalog','information_schema','pg_toast')
  and not c.relrowsecurity
order by 1,2;
```

`relforcerowsecurity` matters independently: without `FORCE`, the **table owner
bypasses RLS**. If migrations or a `SECURITY DEFINER` function run as the owner,
policies do not apply. AI-generated projects effectively never set it.

**RLS enabled with zero policies** — fails closed, so it is safe but usually a bug.
Worth flagging because the fix a coding agent applies next is often `using (true)`:

```sql
select n.nspname, c.relname
from pg_class c join pg_namespace n on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where c.relkind in ('r','p') and c.relrowsecurity
  and n.nspname not in ('pg_catalog','information_schema')
group by 1,2 having count(p.oid) = 0;
```

**Overly permissive policies:**

```sql
select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname not in ('pg_catalog','information_schema')
  and ( (cmd in ('SELECT','UPDATE','DELETE','ALL') and qual in ('true','(true)'))
     or (cmd in ('INSERT','UPDATE','ALL') and with_check in ('true','(true)'))
     or qual ilike '%auth.role()%authenticated%'
     or qual ilike '%auth.uid() is not null%' )
order by 1,2;
```

Check the `roles` column as an amplifier. `{public}` or `{anon}` means the
unauthenticated internet. `{authenticated}` means anyone who can sign up, which is
everyone while signup is open.

**Policies reading user-editable metadata** — a complete auth bypass:

```sql
select schemaname, tablename, policyname, cmd, qual, with_check
from pg_policies
where qual ilike any (array['%user_metadata%','%raw_user_meta_data%'])
   or with_check ilike any (array['%user_metadata%','%raw_user_meta_data%']);
```

`auth.jwt() -> 'user_metadata' ->> 'role' = 'admin'` is extremely common in
AI-generated policies and is trivially bypassed, because `user_metadata` is writable
by the user themselves. The probe that proves it is in the auth-config section below.

**What `anon` and `authenticated` were actually granted.** RLS is irrelevant on a
table `anon` cannot select from, and fatal on one it can:

```sql
select table_schema, table_name, grantee,
       string_agg(privilege_type, ',' order by privilege_type) as privs
from information_schema.role_table_grants
where grantee in ('anon','authenticated','PUBLIC')
  and table_schema not in ('pg_catalog','information_schema')
group by 1,2,3 order by 1,2,3;

select * from pg_default_acl;   -- silently grants on FUTURE tables
```

**SECURITY DEFINER functions callable by anon:**

```sql
select n.nspname, p.proname, pg_get_userbyid(p.proowner) as owner,
       coalesce(array_to_string(p.proconfig,','), 'MUTABLE search_path!') as config,
       has_function_privilege('anon', p.oid, 'execute') as anon_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog','information_schema');
```

Two distinct risks. The function runs as its owner and therefore bypasses RLS on
everything it touches, which is a hole punched straight through your policies. And a
null `proconfig` means a mutable `search_path`, so a caller who can create objects can
shadow a name and get owner-privileged execution. Fix both:

```sql
alter function public.my_fn() set search_path = '';
revoke execute on function public.my_fn() from anon, public;
```

**SECURITY DEFINER views.** Views run with the definer's rights unless PG15+
`security_invoker` is set, so a view over an RLS-protected table leaks the whole table:

```sql
select n.nspname, c.relname, c.reloptions
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v','m') and n.nspname not in ('pg_catalog','information_schema');
```

Anything without `{security_invoker=on}` in `reloptions` is definer semantics. Fix with
`alter view public.my_view set (security_invoker = on);`. Materialized views cannot
have RLS at all — revoke access instead.

**Extensions, and `pg_net` as an SSRF primitive:**

```sql
select p.proname, has_function_privilege('anon', p.oid, 'execute') as anon_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('net','http','vault','pgsodium','extensions');
```

Any `true` there combined with a `SECURITY DEFINER` wrapper is exfiltration as a
service. `net.http_post` makes outbound requests from Supabase infrastructure.

**Storage buckets:**

```sql
select id, name, public, file_size_limit, allowed_mime_types from storage.buckets
order by public desc, name;
select * from pg_policies where schemaname = 'storage';
```

`public = true` bypasses all access control for reads.

## Supabase: anon vs service_role, and the 2025 key migration

| | `anon` / `sb_publishable_…` | `service_role` / `sb_secret_…` |
|---|---|---|
| RLS | Enforced | **`BYPASSRLS` — skips every policy** |
| Safe in a client bundle | Yes, by design | **Never** |

New opaque key formats shipped June 2025 and are mandatory on new projects; legacy
JWT-style keys are being removed in late 2026. `sb_secret_` keys are blocked on a
browser `User-Agent` match, which raises the bar but is **not a control** — curl and
Postman work fine.

Why `service_role` in client code is critical, precisely: the role carries the Postgres
`BYPASSRLS` attribute, so RLS evaluation is skipped at the engine level. Every policy
you wrote becomes decoration. It is equivalent to publishing your database password.

```bash
rg -n --hidden --glob '!node_modules' \
   -e 'service_role' -e 'sb_secret_' -e 'SUPABASE_SERVICE' \
   . dist build .next out .vercel .env* 2>/dev/null

# decode a legacy JWT-style key and read its role claim
echo "$KEY" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '.role, .ref'
```

New opaque keys cannot be decoded. Classify them behaviourally instead: query a table
you know RLS protects. If rows come back, it is a secret key.

## Supabase: black-box enforcement tests

```bash
BASE="https://$REF.supabase.co"
H=(-H "apikey: $ANON" -H "Authorization: Bearer $ANON")
```

Enumerate the entire exposed surface, then test reads and writes:

```bash
curl -s "$BASE/rest/v1/" "${H[@]}" | jq -r '.paths | keys[]'
curl -s "$BASE/rest/v1/profiles?select=*&limit=5" "${H[@]}"
```

Interpreting the read result: rows belonging to other users is a confirmed failure.
`{"code":"42501"}` (permission denied) or a missing relation is safe. An empty array is
**ambiguous** — disambiguate with an exact count, which leaks totals even when rows are
hidden:

```bash
curl -sD - -o /dev/null "$BASE/rest/v1/profiles?select=id" \
  "${H[@]}" -H "Prefer: count=exact" -H "Range: 0-0" | grep -i content-range
# 0-0/1482  -> rows exist and the policy is filtering them (good)
# */0       -> table is genuinely empty (proves nothing)
```

**Always test writes.** Read policies are the ones an agent bothers to write; missing
`with_check` is routine:

```bash
curl -s -X POST "$BASE/rest/v1/profiles" "${H[@]}" \
  -H "Content-Type: application/json" -d '{"email":"pwn@example.com","role":"admin"}'
curl -s -X PATCH "$BASE/rest/v1/profiles?id=eq.<someone-elses-id>" "${H[@]}" \
  -H "Content-Type: application/json" -d '{"role":"admin"}'
```

Do not forget the second surface:

```bash
curl -s -X POST "$BASE/graphql/v1" "${H[@]}" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'
curl -s "$BASE/storage/v1/bucket" "${H[@]}" | jq '.[] | {name, public}'
```

**The only sound test is a two-tenant positive control.** An empty result for anon
proves nothing about tenant isolation:

```sql
begin;
select plan(2);
set local role authenticated;
set local request.jwt.claims = '{"sub":"<uuid-A>","role":"authenticated"}';
select results_eq('select count(*)::int from profiles', array[1], 'A sees only own row');
set local request.jwt.claims = '{"sub":"<uuid-B>","role":"authenticated"}';
select results_eq('select count(*)::int from profiles where id = ''<uuid-A>''',
                  array[0], 'B cannot see A');
select * from finish();
rollback;
```

## Supabase: auth config, the multiplier

```bash
curl -s "$BASE/auth/v1/settings" -H "apikey: $ANON" | jq
```

If `disable_signup` is false (the default), an attacker mints a legitimate
`authenticated` JWT in one request, which makes **every `auth.role() = 'authenticated'`
policy public**:

```bash
curl -s -X POST "$BASE/auth/v1/signup" -H "apikey: $ANON" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1!"}'
```

Then confirm the metadata escalation is live:

```bash
curl -s -X PUT "$BASE/auth/v1/user" -H "apikey: $ANON" \
  -H "Authorization: Bearer $USER_JWT" -H "Content-Type: application/json" \
  -d '{"data":{"role":"admin","is_admin":true}}'
```

Success means any policy reading `user_metadata` is fully bypassable.

## Firebase: audit what is deployed

Console edits silently diverge from the `firestore.rules` file in git. Always pull the
live ruleset rather than reading the repo copy:

```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/releases" \
  | jq -r '.releases[] | "\(.name)\t\(.rulesetName)"'

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/rulesets/<id>" \
  | jq -r '.source.files[] | "// === \(.name)\n\(.content)"'
```

Realtime Database rules are a separate system with a separate endpoint:

```bash
curl -s "https://$DB_INSTANCE.firebaseio.com/.settings/rules.json?access_token=$TOKEN"
```

Rule propagation takes minutes, so never assert immediately after a deploy in CI.

## Firebase: default-open rule patterns

```bash
rg -n -e 'if\s+true' -e 'if\s+request\.auth\s*!=\s*null\s*;' -e 'timestamp\.date\(' \
   firestore.rules storage.rules
rg -n -e '"\.read"\s*:\s*true' -e '"\.write"\s*:\s*true' database.rules.json
rg -rn '"type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN' --glob '!node_modules' . dist build
```

The four failing patterns, and why each fails:

```javascript
// 1. Fully open. The project ID is in your JS bundle, so anyone owns the data.
match /{document=**} { allow read, write: if true; }

// 2. Test-mode default. Silently open until the date, then silently breaks the app,
//    at which point the usual "fix" is to bump the date.
match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 9, 1); }

// 3. Open in practice: signup is enabled by default, so "authenticated" means anyone.
match /{document=**} { allow read, write: if request.auth != null; }

// 4. Unverified email. Sign-in does not verify the address.
allow read: if request.auth.token.email.endsWith('@corp.com');
//   needs: && request.auth.token.email_verified
```

Two structural traps worth grepping for. Rules are **OR'd**, so one permissive
`match /{document=**}` anywhere grants access regardless of a later `if false`. And
`allow read` on a document does not authorize the `list` query that returns it — split
`read` into `get` and `list` when they differ.

The **Rules Playground evaluates the ruleset in the editor, not the deployed one.** An
unsaved console edit makes it pass while production is wide open. Only the live-ruleset
fetch above and black-box testing prove what is deployed.

For regression coverage, `@firebase/rules-unit-testing` with
`firebase emulators:exec "npm test"` gives `assertFails` / `assertSucceeds` against
`authenticatedContext(uid)` and `unauthenticatedContext()`. Use a `demo-` prefixed
project ID so it can never touch production.

## Firebase: black-box testing

The project ID and API key are in the client bundle by design, and that is all these
need:

```bash
curl -s "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents"
curl -s "https://$P-default-rtdb.firebaseio.com/.json?shallow=true"
curl -sX PUT -d '{"pwn":1}' "https://$P-default-rtdb.firebaseio.com/pwn.json"
curl -s "https://firebasestorage.googleapis.com/v0/b/$P.appspot.com/o?maxResults=1000"
```

**Then escalate: mint a real identity and re-run everything.** This is what turns
`if request.auth != null` from "looks fine" into a finding:

```bash
TOKEN=$(curl -s -X POST \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/users"
```

Run from a clean profile or a different IP. A cached session or an allowlisted browser
origin makes an open project look locked.

## What client keys actually protect

**Client-side keys are identifiers, not authorization.** They answer "which project",
never "may this caller read this row". Data protection lives entirely in server-side
policy evaluation.

| Platform | Public by design | The real control | Never in a client |
|---|---|---|---|
| Firebase | `apiKey`, `projectId`, `appId` | Security Rules, plus App Check for abuse | Service-account JSON |
| Supabase | `sb_publishable_…` / `anon` | RLS, grants, exposed-schema config | `sb_secret_…` / `service_role` |

Firebase documents this explicitly: the API key is public and rules are what protect
the data. The asymmetry that catches people is that Supabase ships a *second* key that
grants `BYPASSRLS`, and both keys look like similar opaque blobs sitting adjacent in
the dashboard, so coding agents paste the wrong one routinely.

Consequence for the report: "we rotated the leaked key" is not a fix. For a public key
there was nothing to leak; for a `service_role` key rotation stops the bleeding but the
underlying missing-RLS misconfiguration remains.

App Check attests that a request comes from your app binary, not that a user may read a
row. It blocks scripted abuse and quota exhaustion. It is not access control, and App
Check in front of `allow read, write: if true` is still an open database. Fix rules
first, add App Check second.

## Corrections to widely repeated advice

1. `supabase db lint` is not a security scanner. It is `plpgsql_check`. Use
   `supabase db advisors`.
2. `supabase inspect db` has no security subcommand.
3. An empty array from a Supabase REST query is not proof of working RLS. Confirm with
   `Prefer: count=exact` and a two-tenant positive control.
4. `request.auth != null` and `auth.role() = 'authenticated'` are public while
   self-signup is enabled, which is the default on both platforms.
5. Enabling RLS is not sufficient without `FORCE` if any owner-privileged code path
   touches the table.
6. The Firebase Rules Playground tests the editor's ruleset, not the deployed one.
