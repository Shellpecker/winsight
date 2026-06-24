#!/usr/bin/env python3
"""
winsight build script
======================
Pulls Microsoft security-update data from the MSRC CVRF API for a rolling
window of months and writes a flat data/index.json for the static frontend
to fetch and filter client-side.

No database, no other backend. Source is MSRC only (no Winbindex, no
binary-level data) - see the project README for why.

Data source (confirmed via the published OpenAPI spec at
https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json):

  GET /cvrf/{id}      Full CVRF document for one month. id format: yyyy-Mon
                       (e.g. "2026-Jun"). This is where CVE, CVSS, KB,
                       exploited-status, and affected-product data live.
  GET /updates        All security-update summaries, OData-filterable.
                       Used here only to discover which months actually
                       have a published document, with a safe fallback to
                       a fixed month walk if that call fails or its OData
                       filter syntax doesn't behave as expected - the
                       month-by-month /cvrf/{id} walk is independently
                       confirmed and doesn't depend on /updates at all.

No API key / auth required for either endpoint as of this writing.
Always send `Accept: application/json`, or you get an XML/HTML rendering
instead of the JSON shown in the swagger doc.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
USER_AGENT = "winsight/1.0 (+https://github.com/) build_index.py"

BACKFILL_MONTHS = int(os.environ.get("WINSIGHT_BACKFILL_MONTHS", "24"))
OUTPUT_PATH = os.environ.get("WINSIGHT_OUTPUT", "data/index.json")
REQUEST_DELAY_SEC = 0.3
MAX_RETRIES = 3


def http_get_json(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # expected: month doesn't exist (too old / too new)
            last_err = e
        except json.JSONDecodeError as e:
            last_err = e
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(REQUEST_DELAY_SEC * attempt)
    print(f"  ! giving up on {url}: {last_err}", file=sys.stderr)
    return None


def month_ids(n_months):
    """CVRF document IDs like '2026-Jun' for the last n_months, newest first."""
    today = date.today()
    y, m = today.year, today.month
    out = []
    for _ in range(n_months):
        out.append(date(y, m, 1).strftime("%Y-%b"))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return out


# ---------------------------------------------------------------------------
# Product tree -> version labels
# ---------------------------------------------------------------------------

def parse_product_tree(doc):
    """
    CVRF's ProductTree.Branch is a nested structure ending in <FullProductName
    ProductID="...">label</FullProductName> leaves. We just need a flat
    {product_id: label} map per document; nesting doesn't matter for our
    purposes since each CVE's affected products are already a flat ID list.
    """
    products = {}

    def walk(node):
        if not isinstance(node, dict):
            return
        branches = node.get("Branch")
        if isinstance(branches, dict):
            branches = [branches]
        for b in (branches or []):
            walk(b)
        names = node.get("FullProductName")
        if isinstance(names, dict):
            names = [names]
        for n in (names or []):
            pid = n.get("ProductID")
            val = n.get("Value")
            if pid and val:
                products[pid] = val

    walk(doc.get("ProductTree") or {})
    return products


def normalize_version_label(label):
    """
    Collapse a verbose MSRC product string down to a stable, filterable
    family label, e.g.:
      "Windows 11 Version 23H2 for x64-based Systems" -> "Windows 11 23H2"
      "Windows Server 2022 (Server Core installation)" -> "Windows Server 2022"
    Keeps the full original string too, for display.
    """
    s = label
    s = re.sub(r"\s*\(.*?\)\s*", " ", s)               # drop parenthetical installation type
    s = re.sub(r"\s+for\s+(x64|x86|ARM64|32-bit|64-bit)[\w-]*\s+Systems\b", "", s, flags=re.I)
    s = re.sub(r"\s+for\s+(x64|x86|ARM64|32-bit|64-bit)[\w-]*", "", s, flags=re.I)
    s = re.sub(r"\s*Version\s+", " ", s)
    s = re.sub(r"\s{2,}", " ", s).strip()
    return s


# ---------------------------------------------------------------------------
# Vulnerability parsing
# ---------------------------------------------------------------------------

def kb_ids_from_remediations(vuln):
    """
    CVRF v3 dropped the KBArticle element present in v2.  The KB number is now
    encoded in two places within each remediation:
      - Description.Value: a bare 7–8 digit number, e.g. "5060531"
      - URL: catalog.update.microsoft.com link with ?q=KB5060531

    We extract from both and deduplicate.
    """
    kbs = set()
    for rem in vuln.get("Remediations", []) or []:
        desc_val = ((rem.get("Description") or {}).get("Value") or "").strip()
        if re.match(r"^\d{6,8}$", desc_val):
            kbs.add(f"KB{desc_val}")
        url = rem.get("URL") or ""
        m = re.search(r"[?&]q=KB(\d+)", url, re.I)
        if m:
            kbs.add(f"KB{m.group(1)}")
    return kbs


def extract_cwe(vuln):
    cwe = vuln.get("CWE") or {}
    cwe_id = cwe.get("ID", "").strip()
    cwe_name = cwe.get("Value", "").strip()
    if cwe_id:
        return {"id": cwe_id, "name": cwe_name}
    return None


def product_ids_from_vuln(vuln):
    pids = set()
    for rem in vuln.get("Remediations", []) or []:
        for pid in rem.get("ProductID", []) or []:
            pids.add(pid)
    # some CVRF docs also carry an explicit per-vuln ProductStatuses block
    for status in vuln.get("ProductStatuses", []) or []:
        for pid in status.get("ProductID", []) or []:
            pids.add(pid)
    return pids


def extract_score(vuln):
    sets = vuln.get("CVSSScoreSets") or []
    if sets:
        try:
            return float(sets[0].get("BaseScore"))
        except (TypeError, ValueError):
            return None
    return None


def extract_exploited(vuln):
    """
    MSRC encodes exploit status in Type=1 Threat entries.  The Description.Value
    is a semicolon-separated string, e.g.:
        "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"
        "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"
    We only look at Type=1 entries (ExploitStatus).  Other types (0=Severity,
    3=Impact) share the same Threats array but never carry exploitation data.
    Returns (exploited, disclosed, assessment):
        exploited   bool   — "Exploited:Yes" found in any Type=1 entry
        disclosed   bool   — "Publicly Disclosed:Yes" found in any Type=1 entry
        assessment  str    — highest-priority exploitability index label, or None
    """
    exploited = False
    disclosed = False
    # Priority order for assessment: Detected > More Likely > Less Likely > Unlikely > N/A
    _ASSESS_PRIORITY = [
        "exploitation detected",
        "exploitation more likely",
        "exploitation less likely",
        "exploitation unlikely",
        "not applicable",
    ]
    _ASSESS_LABEL = {
        "exploitation detected":    "Exploitation Detected",
        "exploitation more likely": "Exploitation More Likely",
        "exploitation less likely": "Exploitation Less Likely",
        "exploitation unlikely":    "Exploitation Unlikely",
        "not applicable":           "Not Applicable",
    }
    assessment_rank = len(_ASSESS_PRIORITY)  # sentinel = none found
    assessment = None

    for threat in vuln.get("Threats", []) or []:
        if threat.get("Type") != 1:
            continue  # only ExploitStatus threats carry exploitation data
        desc = (threat.get("Description") or {}).get("Value", "")
        if not isinstance(desc, str):
            continue
        low = desc.lower()

        # Explicit "Exploited:Yes/No" field — authoritative for the exploited boolean.
        if "exploited:yes" in low:
            exploited = True
        # Don't bother checking "exploited:no" — it's the default.

        # Explicit "Publicly Disclosed:Yes/No" field.
        if "publicly disclosed:yes" in low:
            disclosed = True

        # Exploitability Assessment index — keep highest-priority match seen.
        # MSRC may emit per-product entries, so iterate all and keep the worst.
        for rank, key in enumerate(_ASSESS_PRIORITY):
            if key in low and rank < assessment_rank:
                assessment_rank = rank
                assessment = _ASSESS_LABEL[key]
                break

    return exploited, disclosed, assessment


def classify_impact(title, vuln):
    text = (title or "").lower()
    if "remote code execution" in text:
        return "rce"
    if "elevation of privilege" in text:
        return "eop"
    if "denial of service" in text:
        return "dos"
    if "spoofing" in text:
        return "spoofing"
    if "information disclosure" in text:
        return "info"
    if "security feature bypass" in text:
        return "bypass"
    if "tampering" in text:
        return "tamper"
    return "other"


def is_windows_cve(versions, full_products):
    """
    Return True only if the CVE affects a Windows OS product.
    We check the normalized version labels (e.g. "Windows 10 22H2",
    "Windows Server 2022") rather than raw product strings, because
    normalize_version_label already strips the arch/edition noise.
    Products like Office, Azure, Exchange, .NET, SQL Server, Edge, or
    Visual Studio are excluded — they appear in the same monthly CVRF
    documents but are out of scope for winsight.
    """
    WINDOWS_OS_PREFIXES = (
        "Windows 10",
        "Windows 11",
        "Windows Server",
        "Windows RT",
    )
    return any(
        v.startswith(WINDOWS_OS_PREFIXES)
        for v in versions
    )


def parse_cvrf(doc, month_id):
    """Turn one CVRF JSON document into a list of normalized CVE records."""
    out = []
    if not doc:
        return out

    product_labels = parse_product_tree(doc)
    release_date = (doc.get("DocumentTracking") or {}).get("CurrentReleaseDate", "")

    for vuln in doc.get("Vulnerability", []) or []:
        cve = vuln.get("CVE")
        if not cve:
            continue

        title = (vuln.get("Title") or {}).get("Value", "") or cve
        kbs = kb_ids_from_remediations(vuln)
        pids = product_ids_from_vuln(vuln)

        all_versions = sorted({
            normalize_version_label(product_labels[pid])
            for pid in pids if pid in product_labels
        })
        full_products = sorted({product_labels[pid] for pid in pids if pid in product_labels})

        # Keep only Windows OS version labels — strips .NET/ASP.NET/Linux/Mac entries
        # that appear when a CVE affects both Windows and cross-platform runtimes.
        versions = [v for v in all_versions if v.startswith((
            "Windows 10", "Windows 11", "Windows Server", "Windows RT",
        ))]

        if not versions:
            continue

        exploited, disclosed, exploitability = extract_exploited(vuln)

        out.append({
            "id": cve,
            "month": month_id,
            "date": release_date[:10] if release_date else "",
            "title": title,
            "cvss": extract_score(vuln),
            "exploited": exploited,
            "disclosed": disclosed,
            "exploitability": exploitability,
            "impact": classify_impact(title, vuln),
            "cwe": extract_cwe(vuln),
            "kbs": sorted(kbs),
            "versions": versions,
            "products": full_products,
        })
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    months = month_ids(BACKFILL_MONTHS)
    print(f"Fetching {len(months)} months of MSRC CVRF data: {months[-1]} .. {months[0]}")

    all_cves = []
    months_with_data = []
    for month_id in months:
        url = f"{MSRC_BASE}/cvrf/{month_id}"
        doc = http_get_json(url)
        records = parse_cvrf(doc, month_id)
        status = f"{len(records)} CVEs" if doc else "no document (skipped)"
        print(f"-> {month_id}: {status}")
        if doc:
            months_with_data.append(month_id)
        all_cves.extend(records)
        time.sleep(REQUEST_DELAY_SEC)

    all_cves.sort(key=lambda c: c.get("date", ""), reverse=True)

    all_versions = sorted({v for c in all_cves for v in c["versions"]})
    all_impacts = sorted({c["impact"] for c in all_cves})

    out = {
        "generated_at": date.today().isoformat(),
        "source": {
            "msrc_cvrf": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/",
            "msrc_updates": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        },
        "months_requested": months,
        "months_with_data": months_with_data,
        "count": len(all_cves),
        "filters": {
            "versions": all_versions,
            "impacts": all_impacts,
        },
        "cves": all_cves,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH) or ".", exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(f"Wrote {OUTPUT_PATH}: {len(all_cves)} CVEs across {len(months_with_data)} months")


if __name__ == "__main__":
    main()
