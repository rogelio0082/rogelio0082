# Credential Rotation

Read this when the audit found a live credential. Hand the user the specific procedure
for their provider rather than generic advice.

**Rotate first, scrub second.** Users routinely get this backwards: they rewrite git
history, feel finished, and leave a working credential in an attacker's hands. Removing
a secret from history changes nothing about whether it still authenticates. Until the
credential is revoked at the provider, it is compromised, and every minute counts —
exposed AWS keys have produced six-figure bills within hours of publication.

Assume compromise. A key that sat in a public repository, a CI log, or a client bundle
must be treated as known to an attacker even if no abuse is visible yet.

## Contents
- [Order of operations](#order-of-operations)
- [Supabase](#supabase)
- [Firebase and Google Cloud](#firebase-and-google-cloud)
- [AWS](#aws)
- [Stripe](#stripe)
- [OpenAI and Anthropic](#openai-and-anthropic)
- [GitHub](#github)
- [Database connection strings](#database-connection-strings)
- [Scrubbing git history](#scrubbing-git-history)

## Order of operations

1. Revoke or rotate at the provider.
2. Check the provider's audit log for use you did not authorize, and record the window
   between exposure and revocation.
3. Deploy the new credential.
4. Only then consider scrubbing history.
5. Add the file to `.gitignore` and enable push protection so it cannot recur.

Steps 1 and 2 are the ones that matter. Step 4 is hygiene.

## Supabase

Which key leaked determines the severity.

**`anon` / `sb_publishable_…`** — public by design. This is not a leak. If it grants
access to data, the finding is missing row-level security, not an exposed key, and
rotating it fixes nothing. See `baas-supabase-firebase.md`.

**`service_role` / `sb_secret_…`** — critical. The role carries `BYPASSRLS`, so it
ignores every policy in the database. Treat it as a leaked database password.

Rotate in the dashboard under Project Settings, API. The newer `sb_secret_` format
supports multiple concurrent keys that can be revoked individually, which allows a
zero-downtime rollover: create a new secret key, deploy it, then revoke the old one.

Legacy JWT-format keys are derived from the project's JWT secret, so rotating that
secret invalidates `anon` and `service_role` together **and signs out every logged-in
user**, because existing user JWTs were signed with it. Plan for the session loss, or
migrate to the new key format first.

After rotating, audit what the key touched. Postgres logs and the dashboard's
API/Logs section are the places to look. Assume every table readable by that role was
read.

## Firebase and Google Cloud

**Web API key (`AIza…`)** — public by design and present in every client bundle.
Google's own documentation says so. Do not treat it as a leak, and do not let a scanner
finding here distract from the real question, which is whether Security Rules allow
what that key can reach. Restrict it by HTTP referrer or app in the Cloud Console to
limit abuse of billable APIs, but that is quota protection, not access control.

**Service account JSON** — critical, and this is the real Firebase leak. It contains a
`private_key` and typically has broad project permissions.

In the Cloud Console under IAM and Admin, Service Accounts, Keys: create a new key,
deploy it, then delete the exposed one. Deletion is effective immediately. Then check
Cloud Audit Logs for activity attributed to that service account during the exposure
window, and review whether the account's roles were wider than necessary — a leaked
key with `Editor` is a different incident from one scoped to a single bucket.

Prefer workload identity federation or attached service accounts over downloaded key
files, which removes this failure mode entirely.

## AWS

An exposed `AKIA…` key is an emergency. Automated scrapers find keys in public repos
within minutes and start expensive compute.

Use the two-key rotation so nothing breaks:

```bash
aws iam create-access-key --user-name <user>
# deploy the new key everywhere, verify the application works
aws iam update-access-key --user-name <user> --access-key-id <OLD> --status Inactive
# confirm nothing broke, then
aws iam delete-access-key --user-name <user> --access-key-id <OLD>
```

Deactivating before deleting gives you a reversible step: if something still used the
old key, reactivate briefly rather than scrambling.

Check for abuse in CloudTrail, filtering on the access key ID:

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
```

Look for `RunInstances` in regions you do not use, `CreateUser`, `AttachUserPolicy`, and
`CreateAccessKey` — an attacker's first move is usually persistence. If you find any,
this is an incident, not a rotation: involve whoever owns the account, and check Billing
for unexpected charges.

AWS may quarantine a detected-exposed key by attaching `AWSCompromisedKeyQuarantine`.
That limits damage; it does not revoke the key. Still delete it.

Long term, replace static keys with IAM roles or OIDC federation from CI.

## Stripe

Under Developers, API keys, use **Roll key**. Stripe's roll flow lets you set an expiry
on the old key so both work briefly, which avoids downtime during deploy. Choosing
immediate expiry revokes it at once.

Restricted keys should be rolled the same way. Check Developers, Logs and Events for
requests you did not make during the exposure window, paying attention to refunds,
payouts, and customer data reads.

A leaked publishable key (`pk_live_…`) is not a finding; it is meant to be public.

## OpenAI and Anthropic

Revoke in the provider console under API keys. Revocation is immediate and there is no
grace period, so create and deploy the replacement first if downtime matters.

Then check usage. Both providers expose per-key usage in the console, and a spike
against a key you did not use is the abuse signal. These keys are attractive precisely
because they are directly billable, and AI-service credential leaks rose 81% year over
year.

Where the organization supports it, scope keys per service and set spend limits so the
next leak has a ceiling.

## GitHub

**Fine-grained personal access token** — revoke under Settings, Developer settings.
Effective immediately. Prefer these: they are repository- and permission-scoped.

**Classic PAT** — revoke the same way, and treat it as higher severity, because classic
tokens carry broad scopes such as `repo` across every repository the user can reach.

**Deploy keys** — remove under the repository's Settings, Deploy keys. Check whether the
key was write-enabled.

**GitHub App / OAuth tokens** — revoke the installation or rotate the app's client
secret in the app settings.

After revoking, review the account's Security log and the repository's audit log for
pushes, workflow runs, or new keys added during the exposure window. Then enable secret
scanning and push protection on the repository so the next one is blocked before it
lands.

## Database connection strings

Rotate the password, not the whole cluster, and avoid downtime by using a second user:

1. Create a new user with identical grants.
2. Deploy the new connection string.
3. Confirm connections have moved (`pg_stat_activity` on Postgres shows the connecting
   user).
4. Drop or disable the old user.

For managed platforms, do the equivalent through the console: Atlas under Database
Access, RDS via `modify-db-instance --master-user-password`, Supabase under Database
Settings.

Then check whether the database was reachable from the internet at all. A leaked
connection string for a database bound to a private network is a lower-severity finding
than one for a publicly reachable host, and that distinction belongs in the report.

## Scrubbing git history

Only after rotation. This rewrites every commit hash from the touched point forward.

`git filter-repo` is the current recommendation; `git filter-branch` is deprecated and
its own documentation says not to use it. BFG Repo-Cleaner remains a reasonable
alternative for the simple "delete this file everywhere" case.

```bash
pip install git-filter-repo
git filter-repo --path .env --invert-paths
git push --force --all
git push --force --tags
```

BFG equivalent:

```bash
bfg --delete-files .env
git reflog expire --expire=now --all && git gc --prune=now --aggressive
```

**Be explicit with the user about what this does not fix:**

- Every collaborator must re-clone. Merging from a stale clone reintroduces the old
  history.
- Existing forks keep the original objects, and you cannot rewrite someone else's fork.
- Pull request refs on GitHub can retain the old commits, and cached commit views may
  persist. Removing those requires contacting GitHub Support to purge the cache.
- Anything already cloned, mirrored, or archived by a third party is beyond reach.
- The force push rewrites shared history, so coordinate it. On a busy branch this is
  disruptive enough to schedule.

Because none of that is fully controllable, scrubbing is defence in depth. The rotation
in the earlier sections is the actual fix, and the report should say so plainly.
