#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

# ------------------------- hard-coded settings (tweak here) -------------------------
API_BASE = "https://api.platform.censys.io/v3"
SEARCH_PATH = "/global/search/query"  # POST
REQUEST_TIMEOUT = (10, 120)           # (connect, read) seconds
DEFAULT_PAGE_SIZE = 100               # Censys may cap; I usually keep it near 100
MAX_PAGES = 100                       # safety cap so I don't pull forever by accident
RETRY_MAX = 3                         # simple retry loop on 5xx
RETRY_BACKOFF = 1.6                   # backoff factor in seconds

# Preferred fields to get back (keep conservative so results don't explode)
DEFAULT_FIELDS = [
    # Host-focused
    "host.ip",
    "host.dns.names",
    "host.autonomous_system.asn",
    "host.autonomous_system.name",
    "host.services.port",
    "host.services.protocol",
    "host.services.software.product",
    "host.labels.value",
    # Web property-focused
    "web.hostname",
    "web.port",
    "web.endpoints.endpoint_type",
    "web.endpoints.http.status_code",
    "web.endpoints.http.title",
    "web.labels.value",
    # Certificate-focused
    "cert.names",
    "cert.parsed.subject_dn",
    "cert.parsed.issuer_dn",
    "cert.parsed.validity.not_before",
    "cert.parsed.validity.not_after",
]

# Default enum presets. These are CenQL snippets I tend to start with.
# NOTE: In CenQL, list-membership with braces {..} is valid, and substring `:` operator is case-insensitive.
ENUM_PRESETS = {
    # exposed remote access
    "remote_access": 'host.services.port: {22, 23, 5900, 3389, 5985, 5986} or host.services.protocol: {SSH, TELNET, VNC, RDP}',
    # common dbs likely to be exposed if misconfigured
    "databases": 'host.services.protocol: {MONGODB, ELASTICSEARCH, REDIS, POSTGRES, MYSQL, MSSQL, COUCHDB}',
    # vpn gateways (mix of product fingerprints + easy hostname hint)
    "vpn": 'host.services.software.product: {"OpenVPN", "Pulse Secure", "GlobalProtect", "FortiGate", "Fortinet", "Cisco ASA", "AnyConnect", "SonicWALL", "Check Point"} or web.hostname: "vpn"',
    # common admin/login UIs visible on the web property layer
    "web_logins": 'web.labels.value: "LOGIN_PAGE"',
    # ICS/OT protocols (useful for surface mapping; keep it careful)
    "ics": 'host.services.protocol: {MODBUS, DNP3, BACNET, S7, IEC_104, OPC_UA}',
}

# Output knobs
DEFAULT_OUTPUT_PREFIX = "censys_report"
WRITE_RAW_PER_QUERY = False  # if True, saves raw page payloads per query for troubleshooting
# ------------------------------------------------------------------------------------

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if (v is not None and v.strip() != "") else default


def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class CensysClient:

    def __init__(
        self,
        pat: str,
        org_id: Optional[str] = None,
        api_base: str = API_BASE,
        timeout: Tuple[int, int] = REQUEST_TIMEOUT,
        retry_max: int = RETRY_MAX,
        backoff: float = RETRY_BACKOFF,
    ) -> None:
        if not pat:
            raise ValueError("Missing Censys Personal Access Token (env CENSYS_PAT or --pat).")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.retry_max = retry_max
        self.backoff = backoff
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {pat}",
            "Content-Type": "application/json",
            # Accept header is optional; platform returns latest schema if omitted. Keeping simple.
            # If you want to pin: "Accept": "application/vnd.censys.api.v3.host.v1+json",
        })
        if org_id:
            # org header is optional; Censys recommends including if you have it
            self.session.headers["X-Organization-ID"] = org_id

    def search_pages(
        self,
        query: str,
        fields: Optional[List[str]] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = MAX_PAGES,
    ) -> Iterable[Dict[str, Any]]:
        url = f"{self.api_base}{SEARCH_PATH}"
        page_token = None
        pages = 0

        while True:
            payload: Dict[str, Any] = {
                "query": query,
                "page_size": page_size,
            }
            if fields:
                payload["fields"] = fields
            if page_token:
                payload["page_token"] = page_token

            # dumb retry, just in case API is moody
            for attempt in range(1, self.retry_max + 1):
                r = self.session.post(url, json=payload, timeout=self.timeout)
                if r.status_code >= 500:
                    # tiny backoff
                    time.sleep(self.backoff * attempt)
                    continue
                break

            if r.status_code >= 400:
                # keep it readable for troubleshooting
                try:
                    body = r.json()
                except Exception:
                    body = r.text
                raise RuntimeError(f"Censys API error {r.status_code}: {body}")

            data = r.json()
            result = data.get("result", data)

            # Censys Platform SDK shows page_size/query fields; result shape uses next_page_token
            # I'll normalize here.
            assets = (
                result.get("assets")
                or result.get("results")
                or result.get("hits")
                or result.get("records")
                or result.get("items")
                or result.get("data")
                or []
            )
            next_token = (
                result.get("next_page_token")
                or result.get("next_page")
                or result.get("next")
                or result.get("page_token")  # being cautious
            )

            yield {
                "assets": assets,
                "result_meta": {k: v for k, v in result.items() if k != "assets"},
                "raw": data,
            }

            pages += 1
            if not next_token:
                break
            if pages >= max_pages:
                break
            page_token = next_token

    def search_all(
        self,
        query: str,
        fields: Optional[List[str]] = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = MAX_PAGES,
        save_raw_prefix: Optional[Path] = None,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        all_assets: List[Dict[str, Any]] = []
        last_meta: Dict[str, Any] = {}
        for idx, page in enumerate(self.search_pages(query, fields, page_size, max_pages)):
            assets = page["assets"]
            all_assets.extend(assets)
            last_meta = page.get("result_meta", {})
            if save_raw_prefix:
                raw_file = save_raw_prefix.parent / f"{save_raw_prefix.name}_page{idx+1}.json"
                raw_file.write_text(json.dumps(page["raw"], indent=2))
        return all_assets, last_meta


# --- Query building helpers (jr style: keep this practical) -------------------------

_IP_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_ASN_RE = re.compile(r"^AS(\d+)$", re.IGNORECASE)

def esc_regex(s: str) -> str:
    # CenQL wants double-escaped in some spots, but here we keep it simple for =~
    # https://docs.censys.com/docs/censys-platform-syntax-differences (regex is unanchored)
    s = s.replace("\\", "\\\\")
    return re.sub(r"([.^$|(){}\[\]+])", r"\\\1", s)

def wildcard_to_regex(glob: str) -> str:
    # convert *, ? to a regex (unanchored; platform matches anywhere)
    rx = "".join(".*" if c == "*" else "." if c == "?" else esc_regex(c) for c in glob)
    return rx

def build_target_condition(term: str) -> str:
    term = term.strip()
    if not term:
        return ""

    if _IP_CIDR_RE.match(term):
        # bare IP or CIDR
        return f'(host.ip: {term} or web.hostname: "{term}")'

    m = _ASN_RE.match(term)
    if m:
        asn = m.group(1)
        return f"host.autonomous_system.asn: {asn}"

    # If they put * or ? I'll switch to regex; otherwise use substring operator :
    if "*" in term or "?" in term:
        rx = wildcard_to_regex(term)
        return f'(web.hostname=~`{rx}` or host.dns.names=~`{rx}` or cert.names=~`{rx}`)'
    else:
        # lazy contains (case-insensitive) across relevant name fields
        return f'(web.hostname: "{term}" or host.dns.names: "{term}" or cert.names: "{term}")'

def build_targets_clause(target_args: List[str]) -> Optional[str]:
    if not target_args:
        return None

    and_groups: List[str] = []
    for group in target_args:
        terms = [t for t in (group.split(",")) if t.strip() != ""]
        ors = [build_target_condition(t) for t in terms]
        ors = [o for o in ors if o]
        if not ors:
            continue
        and_groups.append("(" + " or ".join(ors) + ")")

    if not and_groups:
        return None
    return " and ".join(and_groups)

def combine_query(base: str, targets_clause: Optional[str]) -> str:
    if targets_clause:
        return f"({base}) and ({targets_clause})"
    return f"({base})"


# ----------------------------- reporting helpers -----------------------------------

def normalize_asset(row: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    # try to guess asset type
    if "host" in row:
        host = row.get("host", {})
        out["asset_type"] = "host"
        out["host.ip"] = host.get("ip")
        out["host.dns.names"] = ";".join(host.get("dns", {}).get("names", [])) if isinstance(host.get("dns", {}), dict) else None
        asn = host.get("autonomous_system", {})
        out["host.asn"] = asn.get("asn")
        out["host.asn_name"] = asn.get("name")
        # services could be many; lift common items if we have them
        services = host.get("services") or []
        if services:
            # try to summarize first few services
            ports = []
            protos = []
            prods = []
            for s in services[:5]:  # avoid blowing up the row
                p = s.get("port")
                if p is not None:
                    ports.append(str(p))
                proto = s.get("protocol")
                if proto:
                    protos.append(str(proto))
                sw = (s.get("software") or {})
                prod = sw.get("product") if isinstance(sw, dict) else None
                if prod:
                    prods.append(str(prod))
            out["host.services.ports"] = ",".join(ports) if ports else None
            out["host.services.protocols"] = ",".join(protos) if protos else None
            out["host.services.products"] = ",".join(prods) if prods else None

    if "web" in row:
        web = row.get("web", {})
        out["asset_type"] = out.get("asset_type") or "web"
        out["web.hostname"] = web.get("hostname")
        out["web.port"] = web.get("port")
        endpoints = web.get("endpoints") or {}
        http = endpoints.get("http") if isinstance(endpoints, dict) else None
        if isinstance(http, dict):
            out["web.http.status_code"] = http.get("status_code")
            out["web.http.title"] = http.get("title")

    if "cert" in row:
        cert = row.get("cert", {})
        out["asset_type"] = out.get("asset_type") or "cert"
        # Platform cert ID is SHA-256; name here varies by response; keep names/DNs handy
        out["cert.names"] = ";".join(cert.get("names", [])) if isinstance(cert.get("names", []), list) else None
        parsed = cert.get("parsed") if isinstance(cert.get("parsed"), dict) else {}
        out["cert.subject_dn"] = parsed.get("subject_dn")
        out["cert.issuer_dn"] = parsed.get("issuer_dn")

    # fallback: copy a couple common top-levels if they show up (SDKs may return flattened fields)
    for k in ["host.ip", "web.hostname", "web.port"]:
        if k in row and k not in out:
            out[k] = row.get(k)

    return out


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2))


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        path.write_text("")  # nothing to write
        return
    # pick headers from union of keys
    headers: List[str] = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({h: r.get(h) for h in headers})


# ---------------------------------- CLI --------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Censys Platform v3 OSINT helper (query + enum).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # modes
    p.add_argument("-e", "--enum", action="store_true",
                   help="Run preset OSINT enumeration (comprehensive).")
    p.add_argument("-q", "--query", type=str, default=None,
                   help="Direct CenQL query string.")
    # target scoping
    p.add_argument("-t", "--target", action="append", default=[],
                   help="Targets. Comma means OR inside one -t. Multiple -t's are ANDed. Examples: -t acme.com,corp.com -t prod")
    # auth
    p.add_argument("--pat", type=str, default=env("CENSYS_PAT"),
                   help="Censys Personal Access Token (or set CENSYS_PAT).")
    p.add_argument("--org-id", type=str, default=env("CENSYS_ORG_ID"),
                   help="Optional Censys Organization ID (or set CENSYS_ORG_ID).")
    # output
    p.add_argument("-o", "--out-prefix", type=str, default=DEFAULT_OUTPUT_PREFIX,
                   help="Output file prefix (JSON and CSV will be created).")
    p.add_argument("--json-only", action="store_true", help="Only write JSON.")
    p.add_argument("--csv-only", action="store_true", help="Only write CSV.")
    # paging/fields
    p.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE, help="Results per page.")
    p.add_argument("--max-pages", type=int, default=MAX_PAGES, help="Max pages per query.")
    p.add_argument("--fields", type=str, default=None,
                   help="Comma-separated fields to request (overrides defaults).")
    # misc
    p.add_argument("--save-raw", action="store_true",
                   help="Dump raw page responses per query for debugging.")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.enum and not args.query:
        print("error: need either --enum or --query (or both).", file=sys.stderr)
        return 2

    fields = [f.strip() for f in (args.fields.split(",") if args.fields else DEFAULT_FIELDS) if f.strip()]
    targets_clause = build_targets_clause(args.target)

    # Build the list of (label, final_query) we will execute
    tasks: List[Tuple[str, str]] = []

    if args.query:
        tasks.append(("direct", combine_query(args.query, targets_clause)))

    if args.enum:
        for name, base_q in ENUM_PRESETS.items():
            tasks.append((f"enum::{name}", combine_query(base_q, targets_clause)))

    # auth + client
    try:
        client = CensysClient(pat=args.pat, org_id=args.org_id)
    except Exception as e:
        print(f"auth/init error: {e}", file=sys.stderr)
        return 2

    # output prefix with timestamp
    timestamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_prefix = Path(f"{args.out_prefix}_{timestamp}")
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    run_meta: Dict[str, Any] = {
        "started_at": now_iso(),
        "modes": {
            "enum": bool(args.enum),
            "query": bool(args.query),
        },
        "page_size": args.page_size,
        "max_pages": args.max_pages,
        "targets": args.target,
        "targets_clause": targets_clause,
        "fields": fields,
        "tasks_count": len(tasks),
    }

    json_report: Dict[str, Any] = {
        "run_meta": run_meta,
        "queries": [],
        "summary": {},
    }

    csv_rows: List[Dict[str, Any]] = []

    # loop tasks
    for label, q in tasks:
        print(f"[+] running {label}: {q}")
        save_raw_prefix = (out_prefix.with_suffix("")) if args.save_raw or WRITE_RAW_PER_QUERY else None
        try:
            assets, last_meta = client.search_all(
                q, fields=fields, page_size=args.page_size, max_pages=args.max_pages,
                save_raw_prefix=(save_raw_prefix and (out_prefix.parent / (out_prefix.name + f"_{label.replace(':','_')}")))
            )
        except Exception as e:
            print(f"[-] query failed for {label}: {e}", file=sys.stderr)
            json_report["queries"].append({
                "label": label,
                "query": q,
                "error": str(e),
            })
            continue

        # normalize a copy for CSV
        norm_rows = [normalize_asset(a) for a in assets]
        csv_rows.extend(norm_rows)

        # build simple rollups (ports/protocols)
        port_counts: Dict[str, int] = {}
        proto_counts: Dict[str, int] = {}

        for r in norm_rows:
            if r.get("host.services.ports"):
                for p in str(r["host.services.ports"]).split(","):
                    p = p.strip()
                    if p:
                        port_counts[p] = port_counts.get(p, 0) + 1
            if r.get("host.services.protocols"):
                for pr in str(r["host.services.protocols"]).split(","):
                    pr = pr.strip()
                    if pr:
                        proto_counts[pr] = proto_counts.get(pr, 0) + 1

        json_report["queries"].append({
            "label": label,
            "query": q,
            "count": len(assets),
            "last_meta": last_meta,
            "top_ports": sorted([{"port": k, "count": v} for k, v in port_counts.items()],
                                key=lambda x: (-x["count"], int(x["port"]) if x["port"].isdigit() else 99999))[:20],
            "top_protocols": sorted([{"protocol": k, "count": v} for k, v in proto_counts.items()],
                                    key=lambda x: -x["count"])[:20],
            # keep a small preview (first 10) to make the JSON comfortable
            "preview": assets[:10],
        })

    # overall summary
    json_report["summary"] = {
        "finished_at": now_iso(),
        "total_rows": len(csv_rows),
        "queries_ran": len([q for q in json_report["queries"] if "error" not in q]),
        "queries_failed": len([q for q in json_report["queries"] if "error" in q]),
    }

    # write outputs
    if not args.csv_only:
        write_json(out_prefix.with_suffix(".json"), json_report)
        print(f"[+] wrote JSON: {out_prefix.with_suffix('.json')}")
    if not args.json_only:
        write_csv(out_prefix.with_suffix(".csv"), csv_rows)
        print(f"[+] wrote CSV:  {out_prefix.with_suffix('.csv')}")

    print("[+] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
