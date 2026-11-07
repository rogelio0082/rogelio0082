# LLM and Agent Application Security

Read this when the app calls an LLM API. Most AI-built apps are themselves AI apps, so
this applies more often than not.

Two current OWASP lists apply. The **LLM Top 10 2026** (released 3 August 2026) keeps
the 2025 identifiers and titles, LLM01 Prompt Injection through LLM10 Unbounded
Consumption, with updated rankings. The **Top 10 for Agentic Applications 2026**
(ASI01-ASI10) is the one that matters once the app gives a model tools: ASI01 Agent
Goal Hijack, ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04 Agentic
Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning,
ASI07 Insecure Inter-Agent Comms, ASI08 Cascading Failures, ASI09 Human-Agent Trust
Exploitation, ASI10 Rogue Agents.

## Contents
- [Static detection](#static-detection)
- [LLM01: untrusted input in the system prompt](#llm01-untrusted-input-in-the-system-prompt)
- [LLM05: unsanitized model output](#llm05-unsanitized-model-output)
- [LLM06: over-permissive tools](#llm06-over-permissive-tools)
- [LLM10: no token or cost caps](#llm10-no-token-or-cost-caps)
- [LLM07/LLM02: prompt or key in client code](#llm07llm02-prompt-or-key-in-client-code)
- [Agent and tool-calling checklist](#agent-and-tool-calling-checklist)
- [MCP server security](#mcp-server-security)
- [Dynamic red-teaming tools](#dynamic-red-teaming-tools)
- [What needs authorization](#what-needs-authorization)

## Static detection

Start with Semgrep rather than hand-rolling rules. It runs natively on Windows now and
ships relevant packs:

```bash
semgrep --config p/ai-best-practices --config p/shadow-ai-pro --metrics=off .
```

`p/ai-best-practices` covers prompt injection, unrestricted tool use and unsafe
integrations. `p/shadow-ai-pro` covers hardcoded keys, missing guardrails and insecure
agent configuration across the OpenAI, Anthropic, Gemini and Cohere SDKs.

The patterns below are the offline triage path and the basis for manual verification.

## LLM01: untrusted input in the system prompt

```bash
rg -n --pcre2 '"role"\s*:\s*"system".{0,200}(f["'\'']|\+\s*\w|\.format\(|%\s)' -g '*.py'
rg -n --pcre2 'system\s*=\s*(f["'\'']|["'\''][^"'\'']*["'\'']\s*\+|\w+\s*\+)' -g '*.py'
rg -n --pcre2 'role:\s*["'\'']system["'\''][\s\S]{0,200}\$\{' -g '*.{js,ts,jsx,tsx}'
rg -n --pcre2 'system:\s*`[^`]*\$\{' -g '*.{js,ts,jsx,tsx}'
```

The triage rule: any variable in the *system* slot that is not a compile-time constant
is a finding. Retrieved documents, tool results, web pages and file contents all count
as untrusted, because indirect injection is the same vulnerability with a longer path.

Fix: keep untrusted content in a clearly delimited user turn, never the system role.
Length-cap and strip control characters. Treat the model's output as untrusted too.

## LLM05: unsanitized model output

The finding is a renderer present with no sanitizer in the same module.

```bash
rg -n 'dangerouslySetInnerHTML' -g '*.{jsx,tsx,js,ts}'
rg -n 'v-html|\[innerHTML\]|@html' -g '*.{vue,html,svelte,ts}'
rg -n 'marked\(|markdown-it|react-markdown|showdown' -g '*.{js,ts,jsx,tsx}'
rg -n 'DOMPurify|sanitize-html|rehype-sanitize|bleach|nh3'   # absence is the finding
```

Also check for model output reaching an interpreter, which is the escalation from XSS
to code execution:

```bash
rg -n --pcre2 '\b(eval|exec|Function|child_process|execSync)\s*\(' -g '*.{js,ts}'
rg -n 'os\.system|subprocess\.(run|call|Popen).*shell\s*=\s*True' -g '*.py'
rg -n 'render_template_string|Markup\(|\|\s*safe' -g '*.{py,html}'
```

## LLM06: over-permissive tools

LangChain flags the dangerous options in the keyword name itself, which makes them easy
to find:

```bash
rg -n 'allow_dangerous_(requests|tools|deserialization)\s*=\s*True' -g '*.py'
rg -n 'PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess' -g '*.py'
rg -n 'create_sql_agent|SQLDatabaseChain|SQLDatabase\.from_uri' -g '*.py'
```

Then inspect the tool schemas. A free-text parameter is the antipattern:

```bash
rg -n --pcre2 '"(query|sql|command|cmd|code|path|url|script)"\s*:\s*\{\s*"type"\s*:\s*"string"' -g '*.{py,js,ts,json}'
rg -n 'additionalProperties'            # absence in a tool schema is the finding
rg -n 'autoApprove|auto_approve|tool_choice.*required'
```

Also flag any tool implementation that fetches a model-supplied URL, which is both an
SSRF primitive and an exfiltration channel, or writes to a model-supplied path.

## LLM10: no token or cost caps

```bash
rg -n 'messages\.create\(|chat\.completions\.create\(|generate_content\(' -g '*.{py,js,ts}'
rg -n 'max_tokens|max_output_tokens|maxTokens'      # absence at a call site is the finding
rg -n 'max_iterations|max_execution_time|maxSteps|recursion_limit'
rg -n 'rate.?limit|slowapi|express-rate-limit|Upstash'
```

Three distinct findings live here: a call site with no output cap, an agent executor
with no iteration bound, and an unauthenticated API route that calls a paid model with
no rate limit. The last one is someone else's bill.

## LLM07/LLM02: prompt or key in client code

```bash
rg -n 'dangerouslyAllowBrowser\s*:\s*true' -g '*.{js,ts,jsx,tsx}'
rg -n --pcre2 '(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)\w*(API_KEY|SECRET|ANTHROPIC|OPENAI)'
rg -n --pcre2 '\b(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})'
rg -n --pcre2 '(SYSTEM_PROMPT|systemPrompt|system\s*:\s*`)' -g 'src/**' -g 'app/**' -g '*.{jsx,tsx,vue,svelte}'
```

`dangerouslyAllowBrowser: true` is unambiguous: the SDK has been explicitly told to run
in a browser, which ships the API key to every visitor.

A system prompt in any file that reaches the bundle is LLM07 by construction. It is not
a leak risk, it is already leaked. Report it as disclosed, not as at-risk.

## Agent and tool-calling checklist

Work this when the app gives a model database, shell, HTTP or filesystem access.

**Identity and credentials (ASI03).** The agent should hold its own identity, not the
app's service account or the user's session token, so it is independently auditable and
revocable. Database access should be a read-only role constrained by row-level security
or an explicit view, not the migration user. Prefer short-lived tokens over long-lived
tokens in `.env`. Scope credentials per tool so one leak does not grant the rest.

**Blast radius (ASI02, ASI05).** Tools should be an explicit allowlist, not every method
on a class. Reject generic escape hatches: `run_sql`, `execute`, `shell`,
`http_request(url)` and `read_file(path)` with free-text parameters. Replace them with
narrow typed verbs such as `get_order(order_id)`, with `additionalProperties: false`.
Separate write, delete, spend and send operations from reads and gate them individually.

**Human in the loop (ASI09).** Destructive, financial and outbound-communication
operations need confirmation showing the **fully resolved parameters**, not the model's
summary of them. The confirmation surface must not be renderable by model output, and
approval should be per call rather than a session-wide "always allow".

**Sandboxing (ASI05).** Code execution belongs in a container or microVM with no host
filesystem, egress denied by default, CPU, memory and wall-clock caps, non-root, and
ephemeral. Never `shell=True` with a model-derived string; pass an argv array.

**Bounds and observability (LLM10, ASI08).** Cap iterations, tool calls, wall-clock and
spend per session and per user. Add a circuit breaker on repeated failures. Log every
tool call with inputs, outputs, principal and triggering message, because that log is
the only way to reconstruct a goal hijack afterwards. Use idempotency keys on mutating
tools so a retry loop cannot double-charge.

**Injection surface (ASI01, ASI06).** Tool results, retrieved chunks, web pages and file
contents are untrusted and must never reach the system role or alter tool permissions.
If the agent has persistent memory, check what can write to it and whether memory is
re-read as instructions — that is the poisoning path.

## MCP server security

Risks: tool poisoning, where malicious instructions hide in a tool *description* that
the model reads as context; rug pulls, where a server changes its tool definitions after
approval; tool shadowing, where one server's description overrides a trusted tool's
behaviour; credential theft from environment variables; and typosquatting. The first
malicious MCP package was observed in September 2025.

The scanner was renamed after Snyk acquired Invariant Labs:

```bash
uvx snyk-agent-scan@latest
uvx snyk-agent-scan@latest inspect     # print tool descriptions without verification
```

Two caveats that matter: **scanning MCP configs executes the commands defined in them**,
so it requires consent and is itself code execution, and tool names and descriptions are
sent to Snyk's API with no documented offline mode. Never pass
`--dangerously-run-mcp-servers`.

Before connecting any MCP server: read the source and full tool schemas, treating
description, parameter names and return schema as injection surface; pin the version and
verify the checksum; hash the tool definitions and re-verify before execution to catch
rug pulls; enforce strict schemas with `additionalProperties: false`; use scoped
per-server credentials; bind local HTTP servers to `127.0.0.1`, never `0.0.0.0`; and
never auto-approve tool calls, which is where shadowing lands.

## Dynamic red-teaming tools

**garak** is the best default for pointing at an endpoint. Detector-based judging means
no second API key:

```bash
py -m pip install -U garak
python -m garak --target_type rest -G rest.json --probes promptinject,xss,leakreplay
```

The `rest.json` generator config maps `$INPUT` into your request body and names the
response field to read. Flag names differ across releases (`--target_type` on current
main, `--model_type` on older ones), so check `garak --help` before scripting.

**promptfoo** has the best OWASP preset coverage and JUnit output for CI:

```bash
npx promptfoo@latest redteam init --no-gui
npx promptfoo@latest redteam run
```

Plugins include `owasp:llm`, `owasp:agentic`, `excessive-agency`, `prompt-extraction`,
`indirect-prompt-injection` and `bola`; strategies include `jailbreak`, `crescendo`
(multi-turn) and encoding variants. Note that attack generation defaults to promptfoo's
hosted service, so your `purpose` string and prompts leave the machine unless you set
`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`, which the docs admit produces
noticeably weaker attacks.

PyRIT is a framework rather than a scanner, worth reaching for only when the two above
find nothing and you need bespoke multi-turn campaigns. Skip Giskard; its scan docs have
moved to a legacy domain.

## What needs authorization

Safe to run automatically: every ripgrep pattern above, Semgrep against a local rule
file, and reading MCP configs to hash tool descriptions yourself.

Announce before running, because data leaves the machine: Semgrep with a registry
config, promptfoo generation with the default remote service, and `snyk-agent-scan`.

**Requires explicit user authorization**: any garak, promptfoo `redteam run`, or PyRIT
execution. These spend real tokens on the user's key, send hundreds to thousands of
requests, and log deliberately harmful jailbreak content against the user's provider
account, which carries terms-of-service exposure. Most importantly, **if the target is
an agent with tools, the attacks will execute those tools** against whatever database,
mailbox or API they are wired to.

Before running, confirm four things: the target is non-production with non-production
credentials, there is a spend ceiling, which provider key is being charged, and that
tools point at a scratch dataset.
