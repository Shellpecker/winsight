#!/usr/bin/env python3
"""
winsight module / patch-diff builder
====================================
Second-stage build step. Reads data/index.json (produced by build_index.py,
which carries a per-CVE `fixes` list of {kb, version, winver, arch}) and derives,
for each CVE, the affected Windows binaries plus direct download links for the
patched and immediately-preceding (unpatched) build of each — so a researcher
can start patch-diffing in two clicks.

How it works
------------
1. COMPONENT_MAP turns the CVE title into a small set of candidate binaries.
   MSRC titles name the component ("Win32k", "Common Log File System Driver",
   ...) but not the file, so this map is the one piece of human judgement. We
   recommend a *set* per component (e.g. win32kfull.sys + win32kbase.sys +
   win32k.sys) because the most-diffable file isn't always obvious and the thin
   win32k.sys stub is not individually downloadable (see below).

2. For each candidate file we pull Winbindex's by-filename index. It maps each
   physical build (sha256) to its PE fileInfo (version, timestamp, virtualSize,
   machineType) and the windowsVersions -> KB it shipped in. This is authoritative,
   not a guess.

3. For each CVE fix (kb, winver, arch) we find the build that shipped in that KB
   (= patched) and the highest build strictly before it (= unpatched).

4. Download URLs use the Microsoft Symbol Server PE addressing scheme:
       https://msdl.microsoft.com/download/symbols/{name}/{TimeDateStamp:08X}{SizeOfImage:x}/{name}
   BUT that id is only unique when TimeDateStamp + SizeOfImage are unique. Some
   files (notably win32k.sys) reuse a constant reproducible-build timestamp and a
   page-identical SizeOfImage across many builds, so several builds collide to the
   same URL and the symbol server can only serve one of them. We therefore only
   emit a download link when the build's id is unique across the file's entire
   history; otherwise the build is reported (version + sha256) but flagged
   downloadable=false, with a Winbindex fallback link in the UI.

Advisory cross-reference (ZDI)
------------------------------
MSRC sometimes ships a deliberately vague title ("Windows Kernel Elevation of
Privilege Vulnerability") that maps to many different drivers. scripts/zdi.py
cross-references those CVEs against Zero Day Initiative advisories, which name
the actual affected binary. When data/zdi_map.json has a resolved binary for a
CVE, it REPLACES the title-based guess (source="zdi", confidence="advisory") and
the advisory link is attached. This is the authoritative fix for the one
false-positive class the Winbindex gate can't catch (see HIGH_CHURN_FILES).

Confidence
----------
Every entry carries a "confidence":
  - "advisory"  — a ZDI advisory named the binary. Trust it.
  - "heuristic" — title keyword match, gated by Winbindex. Solid but a guess.
  - "low"       — the guess is only a high-churn binary (ntoskrnl.exe) with no
                  advisory corroboration; Winbindex can't disprove it, so the UI
                  presents it as "verify" rather than a confident download.

Persistence
-----------
data/cve_modules.json is intended to outlive the rolling MSRC window and to be
hand-correctable: any entry whose "source" is "manual" is preserved verbatim
across runs. Everything else is regenerated from the heuristic (plus the ZDI
cross-reference) each build.
"""

import gzip
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date

INDEX_PATH = os.environ.get("WINSIGHT_OUTPUT", "data/index.json")
MODULES_PATH = os.environ.get("WINSIGHT_MODULES_OUTPUT", "data/cve_modules.json")
# Optional CVE -> ZDI advisory map (produced by scripts/zdi.py). When a CVE is
# present here with resolved files, the ZDI-named binary REPLACES the title-based
# guess and the advisory link is attached. Best-effort: a missing file just means
# the pipeline runs on the heuristic alone.
ZDI_MAP_PATH = os.environ.get("WINSIGHT_ZDI_OUTPUT", "data/zdi_map.json")
# build_index.py splits the CVE list across two files; modules must cover both.
ARCHIVE_PATH = os.environ.get("WINSIGHT_ARCHIVE_OUTPUT", "data/index-archive.json")
USER_AGENT = "winsight/1.0 (+https://github.com/) build_modules.py"
WINBINDEX_URL = "https://winbindex.m417z.com/data/by_filename_compressed/{}.json.gz"
SYMBOL_BASE = "https://msdl.microsoft.com/download/symbols"

# Optional on-disk cache for Winbindex responses, keyed by filename. Enabled in CI
# (via actions/cache) by setting WINSIGHT_WINBINDEX_CACHE. Files older than the TTL
# are re-downloaded so weekly refreshes still pick up newly-shipped builds; the
# cache mainly spares repeated same-week runs (reruns, workflow_dispatch) from
# re-fetching ~40 files.
WINBINDEX_CACHE_DIR = os.environ.get("WINSIGHT_WINBINDEX_CACHE", "")
CACHE_TTL_SECONDS = int(os.environ.get("WINSIGHT_WINBINDEX_TTL_DAYS", "6")) * 86400

# Only x64 is resolved for v1: it's the build essentially every researcher diffs,
# and it keeps cve_modules.json lean. arm64/x86 fixes are ignored for now.
ARCHS = ("x64",)
MACHINE_TYPE = {0x8664: "x64", 0xAA64: "arm64", 0x14C: "x86"}

# Ubiquitous binaries that change in essentially every cumulative update. A guess
# landing on one of these is NOT confirmed by the fact that Winbindex resolves it
# (it always will), so the usual "wrong filename -> no download" safety net can't
# fire. When a heuristic guess consists ONLY of these and nothing corroborates it
# (no ZDI advisory), the entry is marked confidence="low" so the UI can present it
# as a guess to verify rather than a confident download. This is exactly the
# vague "Windows Kernel ... Vulnerability" -> ntoskrnl.exe false-positive class.
HIGH_CHURN_FILES = {"ntoskrnl.exe"}


# ---------------------------------------------------------------------------
# Component -> candidate binary set
# ---------------------------------------------------------------------------
# Ordered: the FIRST entry whose any-substring matches the lowercased title wins,
# so put specific components before generic ones (win32k/graphics before kernel).
# Substrings are matched case-insensitively against the title.
COMPONENT_MAP = [
    ("Win32k", ("win32k", "win32 kernel subsystem", "kernel-mode driver"),
        ["win32kfull.sys", "win32kbase.sys", "win32k.sys"]),
    ("DirectX Graphics Kernel", ("directx graphics kernel",),
        ["dxgkrnl.sys", "dxgmms2.sys"]),
    ("Graphics Component", ("graphics component", "gdi"),
        ["gdi32full.dll", "win32kfull.sys"]),
    ("Common Log File System Driver", ("common log file system", "clfs"),
        ["clfs.sys"]),
    ("Ancillary Function Driver for WinSock", ("ancillary function driver", "winsock", " afd "),
        ["afd.sys"]),
    ("TCP/IP", ("tcp/ip", "tcpip"),
        ["tcpip.sys"]),
    ("DWM Core Library", ("dwm core", "desktop window manager"),
        ["dwmcore.dll", "udwm.dll"]),
    ("Cloud Files Mini Filter Driver", ("cloud files mini filter", "cldflt"),
        ["cldflt.sys"]),
    ("Resilient File System (ReFS)", ("resilient file system", "refs"),
        ["refs.sys", "refsv1.sys"]),
    ("NTFS", ("ntfs",),
        ["ntfs.sys"]),
    ("SMB Server", ("smb server",),
        ["srv2.sys", "srvnet.sys"]),
    ("SMB Client", ("smb client",),
        ["mrxsmb.sys", "mrxsmb20.sys", "mup.sys"]),
    ("SMB", ("smb", "server message block"),
        ["srv2.sys", "mrxsmb.sys"]),
    ("LDAP", ("lightweight directory access", "ldap"),
        ["wldap32.dll"]),
    ("Kerberos", ("kerberos",),
        ["kerberos.dll", "kdcsvc.dll"]),
    ("NTLM", ("ntlm",),
        ["msv1_0.dll"]),
    ("LSASS", ("local security authority", "lsass", " lsa "),
        ["lsasrv.dll"]),
    ("Routing and Remote Access (RRAS)", ("routing and remote access", "rras"),
        ["rasmans.dll", "mprddm.dll", "rasapi32.dll"]),
    ("Remote Access Connection Manager", ("remote access connection manager",),
        ["rasman.dll"]),
    ("Telephony Service", ("telephony",),
        ["tapisrv.dll"]),
    ("Message Queuing (MSMQ)", ("message queuing", "msmq"),
        ["mqqm.dll", "mqsvc.exe"]),
    ("Print Spooler", ("print spooler",),
        ["spoolsv.exe", "localspl.dll"]),
    ("HTTP.sys", ("http.sys", "http protocol stack"),
        ["http.sys"]),
    ("Hyper-V", ("hyper-v", "storage vsp"),
        ["vmswitch.sys", "vid.sys", "storvsp.sys"]),
    ("Kernel Streaming", ("kernel streaming",),
        ["ks.sys"]),
    ("USB Video Class Driver", ("usb video",),
        ["usbvideo.sys"]),
    ("Mobile Broadband Driver", ("mobile broadband",),
        ["wwanmm.dll"]),
    ("Secure Kernel Mode", ("secure kernel", "virtualization-based security", "vbs enclave"),
        ["securekernel.exe"]),
    ("Secure Channel", ("secure channel", "schannel"),
        ["schannel.dll"]),
    ("Remote Desktop Client", ("remote desktop client",),
        ["mstscax.dll"]),
    ("Remote Desktop Services", ("remote desktop",),
        ["rdpcorets.dll"]),
    ("Netlogon", ("netlogon",),
        ["netlogon.dll"]),
    ("MSHTML Platform", ("mshtml",),
        ["mshtml.dll"]),
    ("OLE / COM", ("windows ole", " ole ", "object linking", "com objects", "inbox com"),
        ["combase.dll", "ole32.dll"]),
    ("Windows Kernel", ("windows kernel", "nt os kernel", "kernel memory"),
        ["ntoskrnl.exe"]),
    ("Storage Spaces", ("storage spaces",),
        ["spaceport.sys"]),
    ("Bluetooth Service", ("bluetooth",),
        ["bthport.sys", "bthserv.dll"]),

    # ---- expanded coverage (2026-07). High-confidence component -> binary maps,
    # every filename verified present in Winbindex. These sit after the more
    # specific entries above and before the generic USB catch-all; Winbindex still
    # gates each guess, so a wrong file yields no download rather than a bad link.
    ("DNS", (" dns ",),
        ["dnsapi.dll", "dns.exe"]),
    ("BitLocker", ("bitlocker",),
        ["fvevol.sys"]),
    ("Brokering File System", ("brokering file system",),
        ["bfs.sys"]),
    ("Projected File System", ("projected file system",),
        ["prjflt.sys"]),
    ("Universal Plug and Play (UPnP)", ("universal plug and play", "upnp device host"),
        ["upnphost.dll"]),
    ("Defender Firewall", ("defender firewall",),
        ["mpssvc.dll"]),
    ("SSDP Service", ("simple search and discovery", "ssdp"),
        ["ssdpsrv.dll"]),
    ("Virtual Hard Disk", ("virtual hard disk",),
        ["vhdmp.sys"]),
    ("Windows Installer", ("windows installer",),
        ["msi.dll", "msiexec.exe"]),
    ("MapUrlToZone", ("mapurltozone",),
        ["urlmon.dll"]),
    ("Windows Shell", ("windows shell",),
        ["windows.storage.dll", "shell32.dll"]),
    ("Mark of the Web", ("mark of the web",),
        ["windows.storage.dll"]),
    ("File Explorer", ("file explorer",),
        ["explorer.exe", "windows.storage.dll"]),
    ("Connected Devices Platform Service", ("connected devices platform",),
        ["cdpsvc.dll"]),
    ("Push Notifications", ("push notification",),
        ["wpncore.dll", "wpnservice.dll"]),
    ("Windows Media", ("windows media", "windows digital media"),
        ["mf.dll", "mfcore.dll", "mfplat.dll", "wmvcore.dll"]),
    ("Remote Procedure Call (RPC)", ("remote procedure call",),
        ["rpcrt4.dll"]),
    ("Cryptographic Services", ("cryptographic services",),
        ["cryptsvc.dll", "ncrypt.dll"]),
    ("Task Scheduler", ("task scheduler",),
        ["schedsvc.dll"]),
    ("Error Reporting Service", ("error reporting",),
        ["wersvc.dll", "faultrep.dll"]),
    ("Storage Management Provider", ("storage management", "standards-based storage"),
        ["smphost.dll"]),
    ("WLAN AutoConfig", ("wlan",),
        ["wlansvc.dll"]),

    # ---- expanded coverage (2026-07-17). Derived from an unmapped-CVE audit
    # after a Patch Tuesday refresh; same rule as above — Winbindex gates every
    # guess, and every filename here was verified present before being added.
    ("Windows Runtime", ("windows runtime",),
        ["windows.staterepository.dll", "twinapi.appcore.dll"]),
    ("Windows Management Services", ("windows management services",),
        ["wmiprvse.exe", "wbemcomn.dll"]),
    ("Secure Boot", ("secure boot",),
        ["bootmgfw.efi", "bootmgr.efi"]),
    ("Windows Search Service", ("windows search service",),
        ["tquery.dll"]),
    ("Windows Hello", ("windows hello",),
        ["winbio.dll"]),
    ("DHCP Server Service", ("dhcp server",),
        ["dhcpssvc.dll"]),
    ("DHCP Client", ("dhcp client",),
        ["dhcpcore.dll", "dhcpcore6.dll"]),
    ("Universal Disk Format (UDFS)", ("universal disk format",),
        ["udfs.sys"]),
    ("Active Directory Domain Services", ("active directory domain services",),
        ["ntdsai.dll"]),
    ("Function Discovery Service", ("function discovery",),
        ["fdwsd.dll"]),
    ("Local Session Manager (LSM)", ("local session manager",),
        ["lsm.dll"]),
    ("Windows User Interface Core", ("windows user interface core",),
        ["win32u.dll"]),
    ("Windows Speech Runtime", ("windows speech runtime",),
        ["sapi.dll"]),
    ("PowerShell", ("powershell",),
        ["powershell.exe"]),
    ("Core Messaging", ("core messaging",),
        ["coreuicomponents.dll"]),
    ("Windows Update Stack", ("windows update stack",),
        ["wuaueng.dll"]),
    ("Microsoft Management Console", ("microsoft management console",),
        ["mmc.exe"]),
    ("Client-Side Caching", ("client-side caching",),
        ["csc.sys"]),
    ("OpenSSH", ("openssh",),
        ["sshd.exe"]),
    ("Internet Connection Sharing / NAT", ("internet connection sharing", "network address translation"),
        ["ipnathlp.dll"]),
    ("Wireless WAN Service (WwanSvc)", ("wireless wide area network",),
        ["wwansvc.dll", "wwanmm.dll"]),
    ("App Package Installer", ("app package installer",),
        ["appxdeploymentclient.dll"]),
    ("Reliable Multicast Transport (RMCAST)", ("reliable multicast transport",),
        ["rmcast.sys"]),
    ("IP Routing Management", ("ip routing management",),
        ["iprtrmgr.dll", "iprtprio.dll"]),

    ("Win32 USB", ("usb",),
        ["usbhub3.sys", "ucx01000.sys"]),
]


def guess_module(title):
    """Return (component_label, [files]) for a CVE title, or (None, [])."""
    low = f" {title.lower()} "  # pad so ' afd '/' lsa ' word-boundary tricks work
    for label, subs, files in COMPONENT_MAP:
        if any(s in low for s in subs):
            return label, list(files)
    return None, []


# ---------------------------------------------------------------------------
# Winbindex fetch + indexing
# ---------------------------------------------------------------------------
_wb_cache = {}  # filename -> indexed dict or None (negative cache)


def _disk_cache_path(name):
    if not WINBINDEX_CACHE_DIR:
        return None
    return os.path.join(WINBINDEX_CACHE_DIR, f"{name}.json.gz")


def fetch_winbindex(name):
    if name in _wb_cache:
        return _wb_cache[name]

    raw = None  # decompressed JSON bytes
    cpath = _disk_cache_path(name)

    # 1. Fresh on-disk cache hit?
    if cpath and os.path.exists(cpath) and (time.time() - os.path.getmtime(cpath)) < CACHE_TTL_SECONDS:
        try:
            with open(cpath, "rb") as f:
                raw = gzip.decompress(f.read())
        except Exception as e:  # noqa: BLE001 — corrupt cache entry, fall back to network
            print(f"  ! winbindex cache read {name}: {e}", file=sys.stderr)
            raw = None

    # 2. Otherwise download (and refresh the cache).
    if raw is None:
        url = WINBINDEX_URL.format(name)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        for attempt in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    compressed = resp.read()
                raw = gzip.decompress(compressed)
                if cpath:
                    os.makedirs(WINBINDEX_CACHE_DIR, exist_ok=True)
                    with open(cpath, "wb") as f:
                        f.write(compressed)
                break
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    break  # file simply isn't tracked by Winbindex
                print(f"  ! winbindex {name}: HTTP {e.code}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"  ! winbindex {name} (attempt {attempt}): {e}", file=sys.stderr)
            time.sleep(0.5 * attempt)

    data = json.loads(raw) if raw else None
    indexed = _index_winbindex(data) if data else None
    _wb_cache[name] = indexed
    return indexed


def _sym_id(ts, vsize):
    return f"{int(ts) & 0xFFFFFFFF:08X}{int(vsize):x}"


def _index_winbindex(data):
    """
    Collapse Winbindex's by-hash document into:
      by_target: {(winver, arch): [build, ...]}  sorted ascending by (bld, rev)
      id_count:  {sym_id: count}                  across the whole file history
    A build = {bld, rev, version, sym_id, sha256, kbs(set)}.
    id_count spans every physical build of the filename because the symbol-server
    URL is keyed only by name + sym_id, so any collision anywhere makes the link
    ambiguous.
    """
    by_target = {}
    id_count = {}
    for entry in data.values():
        fi = entry.get("fileInfo") or {}
        ts = fi.get("timestamp")
        vsize = fi.get("virtualSize")
        if ts is None or vsize is None:
            continue
        sym_id = _sym_id(ts, vsize)
        id_count[sym_id] = id_count.get(sym_id, 0) + 1

        arch = MACHINE_TYPE.get(fi.get("machineType"))
        if arch is None:
            continue
        m = re.match(r"^10\.0\.(\d+)\.(\d+)", fi.get("version") or "")
        if not m:
            continue
        wv = entry.get("windowsVersions") or {}
        if not isinstance(wv, dict):
            continue
        build_base = {
            "bld": int(m.group(1)),
            "rev": int(m.group(2)),
            "version": (fi.get("version") or "").split(" ")[0],
            "sym_id": sym_id,
            "sha256": fi.get("sha256", ""),
        }
        for winver, kbnode in wv.items():
            kbs = set(kbnode.keys()) if isinstance(kbnode, dict) else set()
            by_target.setdefault((winver, arch), []).append({**build_base, "kbs": kbs})

    for lst in by_target.values():
        lst.sort(key=lambda b: (b["bld"], b["rev"]))
    return {"by_target": by_target, "id_count": id_count}


# ---------------------------------------------------------------------------
# Patched / unpatched resolution
# ---------------------------------------------------------------------------

def resolve_pair(wb, winver, arch, kb):
    """Return (patched_build, unpatched_build|None) or None if KB not found."""
    chain = wb["by_target"].get((winver, arch))
    if not chain:
        return None
    patched = None
    for b in chain:
        if kb in b["kbs"]:
            patched = b  # if a KB appears at multiple revs, keep the highest
    if patched is None:
        return None
    pkey = (patched["bld"], patched["rev"])
    unpatched = None
    for b in chain:
        if (b["bld"], b["rev"]) < pkey:
            unpatched = b  # chain is ascending -> last one below pkey wins
        elif (b["bld"], b["rev"]) >= pkey:
            break
    return patched, unpatched


def build_dl(name, build, wb):
    if build is None:
        return None
    unique = wb["id_count"].get(build["sym_id"], 0) == 1
    info = {
        "build": build["version"],
        "sha256": build["sha256"],
        "downloadable": unique,
    }
    if unique:
        info["url"] = f"{SYMBOL_BASE}/{name}/{build['sym_id']}/{name}"
    return info


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _advisory_ref(zdi):
    """Shape a ZDI map entry into the `advisory` block stored on a module."""
    if not zdi:
        return None
    return {
        "source": "ZDI",
        "id": zdi.get("id", ""),
        "url": zdi.get("url", ""),
        "component": zdi.get("component", ""),
    }


def resolve_component(cve, zdi=None):
    """Decide the (component, files, source, confidence) for a CVE.

    Precedence:
      1. ZDI advisory that resolved to file(s) -> those files win (source=zdi,
         confidence=advisory). This is the authoritative correction for MSRC's
         vague titles.
      2. Title heuristic -> its files (source=heuristic). Confidence is "low" when
         the guess is only high-churn binaries with no advisory to back it,
         otherwise "heuristic".
      3. ZDI named a component but no diffable binary -> keep the advisory link so
         the real component is still surfaced, with no files (source=zdi).
    Returns (component, files, source, confidence) or None when nothing applies.
    """
    h_component, h_files = guess_module(cve.get("title", ""))
    zdi_files = (zdi or {}).get("files") or []

    if zdi_files:
        return (zdi.get("component") or h_component, list(zdi_files), "zdi", "advisory")
    if h_files:
        confidence = "low" if all(f in HIGH_CHURN_FILES for f in h_files) else "heuristic"
        return (h_component, h_files, "heuristic", confidence)
    if zdi:
        return (zdi.get("component") or None, [], "zdi", "advisory")
    return None


def build_entry_for_cve(cve, zdi=None):
    """Return a module entry dict, or None if neither heuristic nor ZDI matched."""
    resolved = resolve_component(cve, zdi)
    if resolved is None:
        return None
    component, files, source, confidence = resolved

    fixes = [f for f in (cve.get("fixes") or []) if f.get("winver") and f.get("arch") in ARCHS]
    targets = []
    seen = set()
    for name in files:
        wb = fetch_winbindex(name)
        if not wb:
            continue
        for fx in fixes:
            key = (name, fx["winver"], fx["arch"])
            if key in seen:
                continue
            res = resolve_pair(wb, fx["winver"], fx["arch"], fx["kb"])
            if not res:
                continue
            seen.add(key)
            patched, unpatched = res
            targets.append({
                "file": name,
                "version": fx["version"],
                "winver": fx["winver"],
                "arch": fx["arch"],
                "kb": fx["kb"],
                "patched": build_dl(name, patched, wb),
                "unpatched": build_dl(name, unpatched, wb),
            })

    # Sort targets for stable output: by file, then version label.
    targets.sort(key=lambda t: (files.index(t["file"]), t["version"]))
    entry = {
        "source": source,
        "confidence": confidence,
        "component": component,
        "files": files,
        "targets": targets,
    }
    advisory = _advisory_ref(zdi)
    if advisory:
        entry["advisory"] = advisory
    return entry


def main():
    with open(INDEX_PATH, encoding="utf-8") as f:
        index = json.load(f)

    existing = {}
    if os.path.exists(MODULES_PATH):
        try:
            with open(MODULES_PATH, encoding="utf-8") as f:
                existing = (json.load(f) or {}).get("modules", {})
        except (json.JSONDecodeError, OSError) as e:
            print(f"  ! could not read existing {MODULES_PATH}: {e}", file=sys.stderr)

    zdi_map = {}
    if os.path.exists(ZDI_MAP_PATH):
        try:
            with open(ZDI_MAP_PATH, encoding="utf-8") as f:
                zdi_map = (json.load(f) or {}).get("map", {})
        except (json.JSONDecodeError, OSError) as e:
            print(f"  ! could not read {ZDI_MAP_PATH}: {e}", file=sys.stderr)
    print(f"Loaded {len(zdi_map)} ZDI advisory cross-references from {ZDI_MAP_PATH}")

    # index.json holds only the recent slice; the older CVEs live in the archive
    # file. Resolve modules for both so every CVE gets a patch-diff entry.
    cves = list(index.get("cves", []))
    if os.path.exists(ARCHIVE_PATH):
        try:
            with open(ARCHIVE_PATH, encoding="utf-8") as f:
                cves.extend((json.load(f) or {}).get("cves", []))
        except (json.JSONDecodeError, OSError) as e:
            print(f"  ! could not read {ARCHIVE_PATH}: {e}", file=sys.stderr)
    print(f"Resolving affected modules for {len(cves)} CVEs ...")

    modules = {}
    # Preserve hand-curated entries verbatim, even for CVEs no longer in window.
    for cve_id, entry in existing.items():
        if entry.get("source") == "manual":
            modules[cve_id] = entry

    for cve in cves:
        cve_id = cve.get("id")
        if not cve_id or cve_id in modules:  # manual entry already kept
            continue
        try:
            entry = build_entry_for_cve(cve, zdi_map.get(cve_id))
        except Exception as e:  # noqa: BLE001 — never let one CVE break the build
            print(f"  ! {cve_id}: {e}", file=sys.stderr)
            entry = None
        if not entry:
            continue
        modules[cve_id] = entry

    # Metrics computed over the FINAL set (heuristic + preserved manual entries).
    # count_with_modules counts every CVE we could name a binary for; many of those
    # have no downloadable build (Server-only, unmapped winver, symbol-id collision),
    # so count_downloadable_cves is the honest "can actually start diffing" number.
    n_modules = n_targets = n_downloads = n_downloadable_cves = 0
    n_zdi = n_low = 0
    for entry in modules.values():
        if entry.get("files"):
            n_modules += 1
        if entry.get("advisory"):
            n_zdi += 1
        if entry.get("confidence") == "low":
            n_low += 1
        targets = entry.get("targets") or []
        n_targets += len(targets)
        cve_has_download = False
        for t in targets:
            for side in ("patched", "unpatched"):
                if (t.get(side) or {}).get("downloadable"):
                    n_downloads += 1
                    cve_has_download = True
        if cve_has_download:
            n_downloadable_cves += 1

    out = {
        "generated_at": date.today().isoformat(),
        "symbol_server": SYMBOL_BASE,
        "winbindex": "https://winbindex.m417z.com/",
        "count_with_modules": n_modules,
        "count_downloadable_cves": n_downloadable_cves,
        "count_targets": n_targets,
        "count_downloadable_builds": n_downloads,
        "count_zdi_advisories": n_zdi,
        "count_low_confidence": n_low,
        "modules": modules,
    }
    os.makedirs(os.path.dirname(MODULES_PATH) or ".", exist_ok=True)
    with open(MODULES_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    print(
        f"Wrote {MODULES_PATH}: {n_modules} CVEs with modules "
        f"({n_downloadable_cves} with a downloadable build), "
        f"{n_targets} version targets, {n_downloads} downloadable builds, "
        f"{n_zdi} ZDI-corroborated, {n_low} low-confidence, "
        f"{len(_wb_cache)} winbindex files fetched"
    )


if __name__ == "__main__":
    main()
