# Censys Platform Enum (v3)

Quick OSINT/Red Team helper for the Censys Platform API v3. Supports direct CenQL queries, preset enumeration, strict AND/OR target scoping, lazy matching on host/web/cert name fields, and JSON/CSV reporting with lightweight summaries.

Path: `src/OSINT/censys-enum/censys-enump.py`

## Features
- Direct query mode via `-q/--query` (CenQL).
- Preset enumeration via `-e/--enum` with curated queries:
 - `remote_access`, `databases`, `vpn`, `web_logins`, `ics`.
- Target scoping with clear logic:
 - Commas mean OR inside one `-t` group; multiple `-t` flags are ANDed.
- Lazy matching across common name fields with substring or wildcardregex.
- Deterministic JSON and CSV outputs with timestamped prefix.
- Optional raw page dumps per query (`--save-raw`).
- Simple retries and paging controls.

## Requirements
- Python 3.8+
- `requests` (`pip install requests`)
- Censys Personal Access Token (PAT)
 - Optional: Censys Organization ID

Environment variables (or flags) accepted:
- `CENSYS_PAT` (or `--pat`)
- `CENSYS_ORG_ID` (or `--org-id`)

## Quick Start
```bash
# from repo root
python3 src/OSINT/censys-enum/censys-enump.py -e -t example.com
```
Writes `censys_report_YYYYMMDD_HHMMSS.json` and `.csv` in the current directory.

## Usage
```
python3 censys-enump.py [options]
```

Key options:
- `-e`, `--enum` — Run preset OSINT enumeration.
- `-q`, `--query` — Direct CenQL query string.
- `-t`, `--target` — Target group. Commas = OR within the group; multiple `-t` = AND across groups. Repeatable.
- `--pat` — Censys Personal Access Token (or set `CENSYS_PAT`).
- `--org-id` — Optional Organization ID (or set `CENSYS_ORG_ID`).
- `-o`, `--out-prefix` — Output file prefix (default `censys_report`). You can include directories, e.g., `reports/acme`.
- `--json-only` / `--csv-only` — Write only the selected format.
- `--page-size` — Results per page (default 100).
- `--max-pages` — Max pages per query (default 100).
- `--fields` — Comma‑separated fields to request; overrides sensible defaults.
- `--save-raw` — Dump raw page JSON for each query for troubleshooting.

Exit codes:
- `0` on success; `2` on usage/auth errors.

## Target Logic and Matching
- Each `-t` creates an AND group; within a group, comma‑separated terms are ORed.
- Term handling:
 - IP or CIDR `host.ip`
 - `ASNNNN` `host.autonomous_system.asn`
 - Contains `*` or `?` converted to regex and matched against `web.hostname`, `host.dns.names`, `cert.names`.
 - Otherwise a case‑insensitive substring match on those same fields.

Examples:
```bash
# OR within group, AND across groups
python3 censys-enump.py -e -t "acme.com,acme.co" -t "prod,admin"

# Combine a direct query with additional target scoping
python3 censys-enump.py -q 'web.hostname:"vpn" or host.services.protocol: RDP' -t acme.com

# Override fields entirely (comma-separated)
python3 censys-enump.py -e -t acme.com \
 --fields 'host.ip,web.hostname,host.services.port,host.services.protocol'

# Save raw API pages and write only JSON
python3 censys-enump.py -e -t acme.com --save-raw --json-only -o reports/acme
```

## Preset Enum Queries
- `remote_access` — Common remote access ports/protocols (SSH, RDP, VNC, WinRM, etc.).
- `databases` — Popular DB protocols (MongoDB, Elasticsearch, Redis, Postgres, MySQL, MSSQL, CouchDB).
- `vpn` — Common VPN products and `web.hostname:"vpn"` hints.
- `web_logins` — `web.labels.value:"LOGIN_PAGE"` web UIs.
- `ics` — ICS/OT protocols (MODBUS, DNP3, BACNET, S7, IEC‑104, OPC‑UA).

These presets are combined with your `-t/--target` clause, if provided.

## Output
- Filenames: `<out-prefix>_YYYYMMDD_HHMMSS.json` and `.csv`.
- JSON structure:
 - `run_meta` — settings, targets, fields, paging, task count, timestamps.
 - `queries[]` — one per executed query with `label`, `query`, `count`, `last_meta`, `top_ports`, `top_protocols`, and a small `preview` sample.
 - `summary` — totals and overall finish timestamp.
- CSV rows are normalized for quick triage. Common columns include:
 - `asset_type`
 - `host.ip`, `host.dns.names`, `host.asn`, `host.asn_name`
 - `host.services.ports`, `host.services.protocols`, `host.services.products`
 - `web.hostname`, `web.port`, `web.http.status_code`, `web.http.title`
 - `cert.names`, `cert.subject_dn`, `cert.issuer_dn`

Tip: Use `-o reports/acme` to write outputs under `reports/` (directories are auto‑created).

## Authentication
Set `CENSYS_PAT` or pass `--pat`. If you belong to an organization, set `CENSYS_ORG_ID` or pass `--org-id` to attribute queries accordingly.

PATs can be created in your Censys account settings. Keep tokens secure; avoid committing them.

## Notes & Limits
- Defaults request a conservative field set to keep payloads small; override with `--fields` if needed.
- API quotas and server caps apply; the script retries briefly on 5xx responses.
- `--max-pages` acts as a safety cap to avoid unbounded pulls.
- Be mindful of legal/acceptable‑use constraints. Only query assets you are authorized to assess.

## Troubleshooting
- `auth/init error` — Ensure `CENSYS_PAT` is set or `--pat` provided; verify token validity and organization ID (if used).
- `Censys API error ...` — Use `--save-raw` to capture responses; reduce `--page-size`, increase `--max-pages` if needed.
- Empty CSV — No matching assets for your query/targets; broaden presets or adjust `--fields`.

