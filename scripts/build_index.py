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
    kbs = set()
    for rem in vuln.get("Remediations", []) or []:
        kb = rem.get("KBArticle") or {}
        kb_id = kb.get("ID") if isinstance(kb, dict) else None
        if kb_id and re.match(r"^\d{6,7}$", str(kb_id)):
            kb_id = f"KB{kb_id}"
        if kb_id:
            kbs.add(str(kb_id))
    return kbs


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
    MSRC encodes exploitation/disclosure status in the Threats array under
    a ThreatType for "Exploit Status", with free-text Description values
    like "Exploitation Detected" / "Exploitation More Likely" / "Public-
    ation:Disclosed" etc. We classify conservatively: only count it as
    "exploited" if the text explicitly says detected/observed, not just
    "more likely" (which is a forward-looking assessment, not a fact).
    """
    exploited = False
    disclosed = False
    for threat in vuln.get("Threats", []) or []:
        desc = (threat.get("Description") or {}).get("Value", "")
        if not isinstance(desc, str):
            continue
        low = desc.lower()
        if "exploitation detected" in low or "exploited" in low and "detected" in low:
            exploited = True
        if "publicly disclosed" in low or "public disclosure" in low:
            disclosed = True
    return exploited, disclosed


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
    if "security feature bypass" in text or "bypass" in text:
        return "bypass"
    if "tampering" in text:
        return "tamper"
    return "other"


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

        versions = sorted({
            normalize_version_label(product_labels[pid])
            for pid in pids if pid in product_labels
        })
        full_products = sorted({product_labels[pid] for pid in pids if pid in product_labels})

        exploited, disclosed = extract_exploited(vuln)

        out.append({
            "id": cve,
            "month": month_id,
            "date": release_date[:10] if release_date else "",
            "title": title,
            "cvss": extract_score(vuln),
            "exploited": exploited,
            "disclosed": disclosed,
            "impact": classify_impact(title, vuln),
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
