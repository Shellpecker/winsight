#!/usr/bin/env python3
"""
winsight ZDI advisory ingestion
===============================
Optional third stage. Cross-references Microsoft CVEs against Trend Micro's
Zero Day Initiative (ZDI) published advisories. ZDI is (frequently) the party
that *found and root-caused* the bug, so its advisory titles name the specific
affected binary — where MSRC often gives a vague component ("Windows Kernel
Elevation of Privilege Vulnerability") that hides which of dozens of kernel-
adjacent drivers actually changed.

Why this matters
----------------
build_modules.py guesses a binary from the MSRC title and then lets Winbindex
gate the guess: a wrong filename simply yields no download. That safety net
structurally *cannot* catch the worst case — a vague "Windows Kernel" title
guessed as ntoskrnl.exe. ntoskrnl.exe changes in every cumulative update, so a
wrong guess still resolves to a real (but wrong) download. ZDI naming the real
binary (e.g. ndis.sys, netvsc.sys, splwow64.exe) is the authoritative fix for
exactly that class.

What this produces
------------------
data/zdi_map.json:
    {
      "generated_at": "2026-07-21",
      "count": <int>,
      "map": {
        "CVE-2026-26179": {
          "id": "ZDI-26-276",
          "url": "https://www.zerodayinitiative.com/advisories/ZDI-26-276/",
          "component": "Secure Kernel",   # phrase ZDI used, for display
          "files": ["securekernel.exe"]   # resolved binaries (may be empty)
        },
        ...
      }
    }

The file is PERSISTENT and grows over time. ZDI's RSS feed only carries the ~200
most-recent advisories (a few months), so each run MERGES freshly-parsed items
into whatever data/zdi_map.json already holds. Historical entries are retained,
and an entry marked "source": "manual" is preserved verbatim (same hand-
correction convention as cve_modules.json).

build_modules.py consumes this file: when a CVE has a ZDI entry with files, those
files REPLACE the title-based guess and the advisory link is attached. This step
is best-effort — if ZDI is unreachable, the existing map is left untouched and
the pipeline continues on the heuristic alone.
"""

import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date

ZDI_RSS_URL = os.environ.get(
    "WINSIGHT_ZDI_RSS", "https://www.zerodayinitiative.com/rss/published/"
)
ZDI_LISTING_URL = "https://www.zerodayinitiative.com/advisories/published/{}/"
ZDI_MAP_PATH = os.environ.get("WINSIGHT_ZDI_OUTPUT", "data/zdi_map.json")
ZDI_ADVISORY_URL = "https://www.zerodayinitiative.com/advisories/{}/"
USER_AGENT = "winsight/1.0 (+https://github.com/) zdi.py"

# Years of published-advisory listings to backfill. The RSS feed only carries the
# ~200 most-recent advisories across ALL vendors (a few months, ~10 of them
# Windows), so RSS alone can never cover winsight's 24-month CVE window. The
# per-year listing pages are static HTML with the full title + CVE inline, so we
# parse them for complete historical coverage. Defaults to the current year and
# the two prior; override with WINSIGHT_ZDI_YEARS="2026,2025".
def _default_years():
    y = date.today().year
    return [y, y - 1, y - 2]


ZDI_YEARS = [
    int(s) for s in os.environ.get("WINSIGHT_ZDI_YEARS", "").split(",") if s.strip()
] or _default_years()

# Impact phrases that terminate the component region of a ZDI title. ZDI titles
# read "Microsoft Windows <component> <bug-class> <impact> Vulnerability", so the
# component is everything between the product prefix and the earliest impact word.
IMPACT_PHRASES = (
    "Remote Code Execution",
    "Elevation of Privilege",
    "Local Privilege Escalation",
    "Privilege Escalation",
    "Information Disclosure",
    "Denial of Service",
    "Denial-of-Service",
    "Security Feature Bypass",
    "Spoofing",
    "Tampering",
)

# Bug-class phrases that sit between the component and the impact. Stripped from
# the tail of the component region so "splwow64 Race Condition" -> "splwow64".
# Longest-first so multi-word phrases win over their sub-phrases.
BUGCLASS_PHRASES = sorted((
    "Exposed Dangerous Method",
    "Exposed Dangerous Function",
    "Out-Of-Bounds Read",
    "Out-Of-Bounds Write",
    "Out-of-Bounds Read",
    "Out-of-Bounds Write",
    "Heap-based Buffer Overflow",
    "Stack-based Buffer Overflow",
    "Integer Overflow",
    "Buffer Overflow",
    "Race Condition",
    "Double Free",
    "Use-After-Free",
    "Use After Free",
    "Improper Locking",
    "Improper Input Validation",
    "Improper Access Control",
    "Improper Authentication",
    "Improper Authorization",
    "Incorrect Authorization",
    "Incorrect Permission Assignment",
    "Incorrect Default Permissions",
    "Type Confusion",
    "Untrusted Pointer Dereference",
    "NULL Pointer Dereference",
    "Uninitialized Variable",
    "Uninitialized Pointer",
    "Link Following",
    "Path Traversal",
    "Directory Traversal",
    "Memory Corruption",
    "Time-Of-Check Time-Of-Use",
    "Deserialization of Untrusted Data",
    "External Control of File Name or Path",
    "Missing Authorization",
    "Insufficient Verification of Data Authenticity",
    "Improper Validation of Array Index",
    "Improper Release of Memory",
    "Uncontrolled Search Path Element",
    "Access of Resource Using Incompatible Type",
    "Incorrect Conversion",
    "Out-Of-Bounds",
), key=len, reverse=True)

# Distinctive ZDI component phrase -> Winbindex filename(s). Keys are matched as
# lowercased substrings of the extracted component, so they must be specific
# enough not to collide with bug-class words. Many ZDI components are already the
# bare binary basename (win32kfull, splwow64, netvsc); those are handled here so
# the extension is correct. Literal "foo.sys/.dll/.exe" tokens in the title are
# picked up separately and need no entry. Grow this as new components appear.
ZDI_COMPONENT_MAP = (
    ("win32kfull", ["win32kfull.sys"]),
    ("win32kbase", ["win32kbase.sys"]),
    ("win32k", ["win32kfull.sys", "win32kbase.sys"]),
    ("splwow64", ["splwow64.exe"]),
    ("netvsc", ["netvsc.sys"]),
    ("secure kernel", ["securekernel.exe"]),
    ("wmi providers", ["wmiprvse.exe", "wbemcomn.dll"]),
    ("message queu", ["mqqm.dll", "mqsvc.exe"]),       # Queueing / Queuing
    ("ndis", ["ndis.sys"]),
    ("clfs", ["clfs.sys"]),
    ("ancillary function", ["afd.sys"]),
    ("tcp/ip", ["tcpip.sys"]),
    ("tcpip", ["tcpip.sys"]),
    ("dwm core", ["dwmcore.dll"]),
    ("kernel streaming", ["ks.sys"]),
    ("cloud files", ["cldflt.sys"]),
    ("common log file system", ["clfs.sys"]),
    ("bluetooth", ["bthport.sys"]),
    ("kerberos", ["kerberos.dll"]),
    ("netlogon", ["netlogon.dll"]),
    ("print spooler", ["spoolsv.exe", "localspl.dll"]),
    ("mup", ["mup.sys"]),
    # bare basenames / abbreviations ZDI uses that need an extension appended
    ("vhdmp", ["vhdmp.sys"]),
    ("mskssrv", ["mskssrv.sys"]),
    ("dxgkrnl", ["dxgkrnl.sys"]),
    ("dxkrnl", ["dxgkrnl.sys"]),           # ZDI abbreviation of dxgkrnl
    ("cldflt", ["cldflt.sys"]),
    ("installer service", ["msiexec.exe", "msi.dll"]),
    ("desktop window manager", ["dwmcore.dll"]),
    ("ntfs", ["ntfs.sys"]),
)

FILENAME_RE = re.compile(r"\b([a-z0-9][a-z0-9_\-]*\.(?:sys|dll|exe|efi))\b", re.I)
ZDI_ID_RE = re.compile(r"ZDI-\d\d-\d+")
CVE_RE = re.compile(r"CVE-20\d{2}-\d+")


# ---------------------------------------------------------------------------
# Title parsing (pure, unit-tested)
# ---------------------------------------------------------------------------

def parse_component(title):
    """Extract the component phrase from a ZDI advisory title, or '' if none.

    'ZDI-26-276: Microsoft Windows Secure Kernel Double Free Local Privilege
    Escalation Vulnerability' -> 'Secure Kernel'.
    """
    s = re.sub(r"^\s*ZDI-\d\d-\d+:\s*", "", title).strip()
    # Drop a leading event tag, e.g. "(Pwn2Own) " or "(0Day) ".
    s = re.sub(r"^\((?:Pwn2Own[^)]*|0Day)\)\s*", "", s, flags=re.I)
    # Drop the vendor/product prefix. Order matters: strip the longer
    # "Windows Server" before "Windows".
    s = re.sub(
        r"^Microsoft\s+(Windows Server|Windows|Hyper-V|Edge|Office|SharePoint|\.NET|Visual Studio)\s+",
        "", s, flags=re.I,
    )
    # Drop a leading OS-version remnant left by the prefix strip ("11 ", "10 ",
    # "Server 2019 ") so the component starts at the real component name.
    s = re.sub(r"^(?:Server\s+)?(?:10|11|20\d\d)\b\s*", "", s)
    # Cut at the earliest impact phrase.
    cut = len(s)
    for imp in IMPACT_PHRASES:
        i = s.find(imp)
        if 0 <= i < cut:
            cut = i
    comp = s[:cut].strip()
    # Strip a trailing bug-class phrase (longest-first).
    for bc in BUGCLASS_PHRASES:
        m = re.search(re.escape(bc) + r"\s*$", comp, flags=re.I)
        if m:
            comp = comp[: m.start()].strip()
            break
    return comp.strip(" -:")


def component_files(title, component):
    """Resolve a ZDI title + component phrase to Winbindex filename(s).

    Combines literal filename tokens anywhere in the title with the curated
    ZDI_COMPONENT_MAP. The map is FIRST-MATCH-WINS (ordered specific -> generic,
    so "win32kfull" resolves to just win32kfull.sys and never also drags in the
    broader win32k set). Returns a de-duplicated, order-preserving list (possibly
    empty when ZDI names a component with no diffable binary, e.g. ServerManager).
    """
    files = []

    def _add(f):
        f = f.lower()
        if f not in files:
            files.append(f)

    for m in FILENAME_RE.finditer(title):
        _add(m.group(1))

    low = f" {component.lower()} "
    for token, mapped in ZDI_COMPONENT_MAP:
        if token in low:
            for f in mapped:
                _add(f)
            break  # first (most specific) component match wins
    return files


# ---------------------------------------------------------------------------
# RSS fetch + item parsing
# ---------------------------------------------------------------------------

def fetch_rss(url=ZDI_RSS_URL):
    """Return the raw RSS XML, or None on failure (best-effort)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            print(f"  ! zdi rss: HTTP {e.code}", file=sys.stderr)
            if e.code < 500:
                break
        except Exception as e:  # noqa: BLE001
            print(f"  ! zdi rss (attempt {attempt}): {e}", file=sys.stderr)
        time.sleep(0.5 * attempt)
    return None


def _strip_cdata(s):
    return re.sub(r"<!\[CDATA\[|\]\]>", "", s).strip()


def parse_rss(xml):
    """Yield {cve, id, url, component, files} for each Windows/Hyper-V item.

    Items without an assigned CVE (unpatched 0-days) are skipped: winsight keys
    everything on the MSRC CVE, so an advisory we can't join is not useful yet.
    """
    out = {}
    for block in re.findall(r"(?s)<item>(.*?)</item>", xml):
        tm = re.search(r"(?s)<title>(.*?)</title>", block)
        if not tm:
            continue
        title = _strip_cdata(tm.group(1))
        # Only Microsoft OS advisories — the affected-binary story only applies to
        # things Winbindex indexes (Windows / Hyper-V), not Office/Edge/Azure.
        if not re.search(r"Microsoft\s+(Windows|Hyper-V)", title, re.I):
            continue
        cve_m = CVE_RE.search(block) or CVE_RE.search(title)
        if not cve_m:
            continue
        cve = cve_m.group(0)
        id_m = ZDI_ID_RE.search(title) or ZDI_ID_RE.search(block)
        zdi_id = id_m.group(0) if id_m else ""
        lm = re.search(r"(?s)<link>(.*?)</link>", block)
        url = _strip_cdata(lm.group(1)) if lm else ""
        if not url and zdi_id:
            url = ZDI_ADVISORY_URL.format(zdi_id)
        component = parse_component(title)
        files = component_files(title, component)
        # Last write wins; RSS is newest-first so this keeps the newest advisory
        # if the same CVE somehow appears twice.
        out.setdefault(cve, {
            "id": zdi_id,
            "url": url,
            "component": component,
            "files": files,
        })
    return out


# ---------------------------------------------------------------------------
# Published-listing backfill (per-year static HTML pages)
# ---------------------------------------------------------------------------

def fetch_listing(year, url_tmpl=ZDI_LISTING_URL):
    """Return the raw listing HTML for a year, or None on failure (best-effort)."""
    url = url_tmpl.format(year)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            print(f"  ! zdi listing {year}: HTTP {e.code}", file=sys.stderr)
            if e.code < 500:
                break
        except Exception as e:  # noqa: BLE001
            print(f"  ! zdi listing {year} (attempt {attempt}): {e}", file=sys.stderr)
        time.sleep(0.5 * attempt)
    return None


_TITLE_CELL_RE = re.compile(
    r"advisory-title-cell[^>]*>.*?<span>(.*?)</span>", re.S)
_LINK_ID_RE = re.compile(r"/advisories/(ZDI-\d\d-\d+)/")


def parse_listing(html_text):
    """Yield {cve: {id, url, component, files}} from a published-listing page.

    Each advisory is one <tr> carrying a ZDI-id link, a CVE cell, and an
    advisory-title-cell with the full descriptive title. We split on <tr so a
    single row's ZDI id / CVE / title stay together regardless of other markup.
    """
    out = {}
    for row in re.split(r"<tr\b", html_text):
        idm = _LINK_ID_RE.search(row)
        if not idm:
            continue
        cvem = CVE_RE.search(row)
        if not cvem:
            continue  # 0-day with no assigned CVE
        tm = _TITLE_CELL_RE.search(row)
        if not tm:
            continue
        title = html.unescape(re.sub(r"<[^>]+>", "", tm.group(1))).strip()
        if not re.search(r"Microsoft\s+(Windows|Hyper-V)", title, re.I):
            continue
        zdi_id = idm.group(1)
        component = parse_component(title)
        out.setdefault(cvem.group(0), {
            "id": zdi_id,
            "url": ZDI_ADVISORY_URL.format(zdi_id),
            "component": component,
            "files": component_files(title, component),
        })
    return out


# ---------------------------------------------------------------------------
# Merge + persist
# ---------------------------------------------------------------------------

def load_existing(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return (json.load(f) or {}).get("map", {})
    except (json.JSONDecodeError, OSError) as e:
        print(f"  ! could not read existing {path}: {e}", file=sys.stderr)
        return {}


def merge(existing, fresh):
    """Merge freshly-parsed items into the persistent map.

    Manual entries are never overwritten. Otherwise the fresh parse wins (so a
    grown ZDI_COMPONENT_MAP re-resolves files on the next run), but entries for
    CVEs not in the current RSS window are retained untouched.
    """
    merged = dict(existing)
    for cve, item in fresh.items():
        if (existing.get(cve) or {}).get("source") == "manual":
            continue
        merged[cve] = item
    return merged


def main():
    merged = load_existing(ZDI_MAP_PATH)
    any_source = False

    # Backfill from per-year published-advisory listings (complete historical
    # coverage of the CVE window). Oldest first so newer pages win on overlap.
    for year in sorted(ZDI_YEARS):
        html_text = fetch_listing(year)
        if html_text is None:
            continue
        any_source = True
        items = parse_listing(html_text)
        merged = merge(merged, items)
        print(f"  listing {year}: {len(items)} Windows/Hyper-V advisories with a CVE")

    # Freshest layer last: the RSS is published same-day and may lead the listing
    # by a few hours around Patch Tuesday.
    xml = fetch_rss()
    if xml is not None:
        any_source = True
        items = parse_rss(xml)
        merged = merge(merged, items)
        print(f"  rss: {len(items)} Windows/Hyper-V advisories with a CVE")

    if not any_source:
        # Best-effort: keep whatever we already had rather than wiping the map.
        print("  ! all ZDI sources unavailable; leaving existing map unchanged", file=sys.stderr)

    with_files = sum(1 for v in merged.values() if v.get("files"))
    out = {
        "generated_at": date.today().isoformat(),
        "source": "Zero Day Initiative (published advisories)",
        "count": len(merged),
        "count_with_files": with_files,
        "map": merged,
    }
    os.makedirs(os.path.dirname(ZDI_MAP_PATH) or ".", exist_ok=True)
    with open(ZDI_MAP_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=False)

    print(
        f"Wrote {ZDI_MAP_PATH}: {len(merged)} ZDI-mapped Windows CVEs "
        f"({with_files} with a resolved binary)"
    )


if __name__ == "__main__":
    main()
