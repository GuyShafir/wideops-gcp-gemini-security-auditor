# GCP Gemini Security Auditor & Financial Circuit Breaker

A read-only security auditor that detects a "silent" privilege escalation vector affecting GCP projects with the Generative Language API (Gemini) enabled. It also audits API quotas — your only real-time defense against runaway inference costs.

> **Read-only.** This tool only calls `list` and `get` endpoints on Cloud Resource Manager, Service Usage, and API Keys. It does not modify keys, quotas, or any other configuration.

---

## The Vulnerability: "Silent" Privilege Inheritance

Legacy API keys for services like Firebase or Google Maps were historically considered identifiers rather than secrets, and were often deployed "Unrestricted" — meaning they could call any enabled API in the project. If the Generative Language API gets enabled in such a project (often by a different team, often years later), those existing public keys silently gain the ability to call Gemini endpoints.

The result: an API key embedded in a public web page or mobile app, originally scoped to a benign service, can now invoke a paid LLM.

### What a "financial circuit breaker" means here

GCP billing alerts are **not** circuit breakers — they notify, they don't stop. Quotas are. A quota set on `generativelanguage.googleapis.com` is enforced by GCP in real time and will reject requests once exceeded. Billing dashboards, by contrast, can lag substantially behind actual usage. Quotas are the only mechanism that can hard-stop an attack while it's happening.

A circuit breaker only counts if you've explicitly set it. The auditor distinguishes **consumer overrides** (limits you've configured) from **defaults** (Google's published baseline) — only the former gives you protection tuned to your workload.

### Risks paired with mitigations

| Risk | Mitigation |
|------|-----------|
| **Financial catastrophe** — attackers run massive high-token inference jobs on your account before billing alerts fire. | **Cap quotas** on `generativelanguage.googleapis.com` to the minimum your workload needs. This is the circuit breaker. |
| **Data exfiltration** — keys with Gemini access can potentially read content via the Files API. | **Restrict every API key** with explicit `apiTargets` in the GCP Console. No key should be unrestricted. |
| **Latent exposure** — keys shipped in old client-side code remain valid indefinitely. | **Rotate** any key that was ever deployed unrestricted, then re-deploy with proper restrictions. |
| **Direct client exposure** — keys in browsers or mobile apps are extractable by definition. | **Backend proxy** — never call Gemini from a client. Route through Cloud Functions or equivalent with server-side auth. |

---

## What the auditor does

For every active project the caller can see, it:

1. Checks whether `generativelanguage.googleapis.com` is enabled. If not, the project is skipped.
2. Lists all API keys in the project (paginated).
3. Flags any key that is either fully unrestricted, partially restricted but unrestricted at the API level, or explicitly scoped to allow Gemini.
4. Fetches the project's *effective* Gemini quota configuration (consumer overrides where set, defaults otherwise) so you can see, per finding, whether a circuit breaker is in place.
5. Writes everything to a CSV report.

Projects the caller lacks permissions on are logged as warnings and skipped — they will not appear in the report. Check the log output if the finding count seems lower than expected.

### Risk levels

| Level | Meaning |
|-------|---------|
| `CRITICAL (Fully Unrestricted)` | No API restrictions and no referrer/IP restrictions. Anyone with the key string can call Gemini. |
| `CRITICAL (Unrestricted APIs, partial referrer/IP restriction)` | No API restrictions, but the key has browser/Android/iOS/server restrictions. Still critical — the key can call any enabled API including Gemini, but the attack surface is narrower. |
| `HIGH (Gemini Scoped)` | API restrictions exist, and Gemini is explicitly in the allowlist. Intended access — verify it's necessary and that quotas are capped. |

Keys with API restrictions that *don't* include Gemini are not reported.

### Sample output

Terminal:

```
2026-01-15 09:42:11 [INFO] Initializing Gemini security audit...
2026-01-15 09:42:13 [INFO] Discovered 47 active project(s).
2026-01-15 09:42:18 [WARNING] Cannot list API keys for legacy-sandbox-2019: Permission denied
2026-01-15 09:42:24 [INFO] Found 3 finding(s): 2 CRITICAL, 1 HIGH. Report saved to gemini_security_report.csv
```

`gemini_security_report.csv`:

```csv
project_id,key_name,risk_level,quotas
acme-marketing-prod,Maps JS Key (legacy),CRITICAL (Fully Unrestricted),DEFAULTS ONLY (no circuit breaker) | Generate requests per minute: 60 (default)
acme-mobile-app,Firebase Web Key,CRITICAL (Unrestricted APIs, partial referrer/IP restriction),Generate requests per minute: 30 (override)
acme-internal-tools,Gemini Eval Key,HIGH (Gemini Scoped),Generate requests per minute: 1000 (override)
```

Column reference:

- **`project_id`** — GCP project containing the finding.
- **`key_name`** — display name of the API key.
- **`risk_level`** — see the table above.
- **`quotas`** — pipe-separated effective quota limits for the Generative Language API. Each entry is tagged `(override)` (a limit you configured) or `(default)` (Google's baseline). A `DEFAULTS ONLY (no circuit breaker)` prefix on the field means *zero* overrides exist for this project — the project has no real circuit breaker against runaway usage.

### Exit codes

The script is designed to be wired into CI pipelines:

| Exit code | Meaning |
|-----------|---------|
| `0` | Ran successfully, no CRITICAL findings. |
| `1` | Ran successfully, CRITICAL findings present. |
| `2` | Tool error (auth failure, project list failure, invalid args). |

A CI job that should fail on critical findings can simply run `python audit_gemini.py` and check the exit code — no parsing required.

---

## Getting started

### Prerequisites

- Python 3.8+
- Google Cloud SDK (`gcloud`)

### Required permissions

The calling identity needs three roles. For a full org-wide audit, grant them at the **organization** level; for a single-project audit, grant at the project level.

| Role | Purpose |
|------|---------|
| `roles/browser` (Project Viewer) | Enumerate projects via Cloud Resource Manager |
| `roles/serviceusage.serviceUsageConsumer` | Read enabled-API status and quota metrics |
| `roles/serviceusage.apiKeysViewer` | List and inspect API key restrictions |

Grant org-wide (replace `ORG_ID` and `USER`):

```bash
for ROLE in roles/browser roles/serviceusage.serviceUsageConsumer roles/serviceusage.apiKeysViewer; do
  gcloud organizations add-iam-policy-binding ORG_ID \
    --member="user:USER@example.com" \
    --role="$ROLE"
done
```

### Installation

```bash
pip install google-api-python-client google-auth
```

### Usage

```bash
gcloud auth application-default login
python audit_gemini.py
```

#### Command-line options

| Flag | Default | Description |
|------|---------|-------------|
| `--output PATH` | `gemini_security_report.csv` | Output CSV path |
| `--workers N` | `15` | Parallel project audits |
| `--project PROJECT_ID` | (all accessible) | Audit a single project instead of every project the caller can see |
| `--log-level LEVEL` | `INFO` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR` |

Examples:

```bash
# Audit a single project, verbose logging
python audit_gemini.py --project my-prod-project --log-level DEBUG

# Org-wide audit, custom output path, more parallelism
python audit_gemini.py --workers 30 --output reports/audit-$(date +%F).csv
```

---

## What this tool does *not* do

- It does not modify keys, quotas, IAM, or any other GCP resource.
- It does not detect keys leaked outside GCP (e.g., committed to a public repo). Use a secret-scanning tool for that.
- It does not analyze actual API usage or billing data — only configuration posture.
- It does not check service account keys, OAuth clients, or Workload Identity bindings. Scope is strictly API keys (the `apikeys.googleapis.com` resource type).

---

## Contributing

Issues and pull requests welcome. For security-sensitive findings, please email `security@wideops.com` rather than opening a public issue.

## License

MIT — see `LICENSE`.

---

*Maintained by the WideOps Engineering Team.*
