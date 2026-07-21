# winsight

A patch-diffing research tool for Windows CVEs. Browse Microsoft's monthly
security advisories, see which binary each one actually patched, and download
the **unpatched** and **patched** build directly — so you can start diffing
in two clicks instead of an afternoon of digging through Winbindex by hand.

Static site on GitHub Pages. No database, no server, no backend to keep
running — a scheduled GitHub Action rebuilds two JSON files and the page
fetches and filters them entirely client-side.

**Live:** https://shellpecker.github.io/winsight/

## What it does

- **Browse & filter** ~2,000+ Windows CVEs from the last 24 months: severity,
  vulnerability type, CWE, affected Windows version, exploited / publicly
  disclosed / listed in CISA's KEV catalog / covered by a ZDI advisory, EPSS
  score, and whether a downloadable patch-diff build exists. A **CVSS vector** filter adds a dropdown
  per base metric (AV, AC, PR, UI, S, C, I, A) so any combination is
  filterable — e.g. AV=Network + PR=None + UI=None for the wormable-RCE hunt. Free-text search covers CVE ID,
  title, KB numbers, version labels, *and* affected binary filenames (try
  `clfs.sys` or `win32kfull.sys`).
- **Patch-diff panel** — for ~1,400 of those CVEs (and counting), one click
  downloads the exact unpatched and patched build of the affected binary,
  sourced live from Microsoft's own symbol server. IDA, Ghidra, and BinDiff
  resolve symbols for these automatically, no extra setup. Each guess shows a
  confidence: `advisory-confirmed` when a **ZDI advisory** named the binary
  (with a link to it), or `best guess — verify` when it rests only on a
  high-churn binary MSRC's vague title couldn't pin down.
- **Binary biography** — click any binary's name to see its *entire* history:
  every CVE that ever touched it, its full build chain per Windows version,
  and pick any two builds (not just one CVE's pair) to diff.
- **Overview** — severity/type/component/release-month breakdowns over
  the current filtered view.
- **Shareable URLs** — filters, search, sort, and an open CVE all live in
  the URL hash, so any view can be linked directly.
- **RSS feed** (`data/feed.xml`) of the most recent CVEs, plus a "Last Patch
  Tuesday" quick filter.
- Dark/light themes styled after Windows 11's own Fluent design language —
  deliberately, since this is a tool about Windows.

## How it works

```
MSRC CVRF API   ──┐
FIRST EPSS      ──┼──>  scripts/build_index.py   ──>  data/index.json
CISA KEV        ──┘                                    data/feed.xml
                                                              │
ZDI advisories  ────>  scripts/zdi.py  ──>  data/zdi_map.json │
                                                       │      │
                                                       ▼      ▼
Winbindex       ─────────────────>  scripts/build_modules.py  ──>  data/cve_modules.json
                                                              │
                                                              ▼
                                                        index.html
                                                   (GitHub Pages, static fetch,
                                                    all filtering/rendering
                                                    happens in the browser)
```

A single GitHub Actions workflow (`.github/workflows/pages.yml`) handles both
the data refresh and the deploy:

1. **`build_index.py`** walks the last 24 months of MSRC's `/cvrf/{yyyy-Mon}`
   documents and normalizes them into flat CVE records (severity, CVSS, CWE,
   affected products/versions, KBs, exploited/disclosed status, per-KB
   `fixes` mapping). It also enriches every record with **EPSS** (exploit
   probability, from FIRST.org) and **CISA KEV** (confirmed exploited in the
   wild) — both best-effort, null on fetch failure — and emits an RSS feed of
   the most recent entries.
2. **`zdi.py`** cross-references those CVEs against
   [Zero Day Initiative](https://www.zerodayinitiative.com/) advisories. ZDI
   is often the party that found the bug, so its advisory title names the
   *actual* affected binary — where MSRC frequently gives a vague component
   ("Windows Kernel Elevation of Privilege Vulnerability") that maps to any of
   dozens of drivers. It parses ZDI's published RSS + per-year listing pages
   into `data/zdi_map.json` (`CVE → {advisory, binary}`), a persistent,
   hand-correctable file that grows over time.
3. **`build_modules.py`** takes each CVE's title, maps it to a small set of
   candidate binaries (`COMPONENT_MAP`), and confirms each against
   [Winbindex](https://winbindex.m417z.com/)'s build index. For every
   Windows-version fix it resolves the exact patched build and its
   predecessor, then constructs a Microsoft Symbol Server download URL for
   each — but **only when that build's symbol-server id is unique** across
   the file's whole history. Some files (notably `win32k.sys`) reuse a
   constant timestamp+size across many builds, so the server can only serve
   one of them; those are shown as version + sha256 with a Winbindex
   fallback link instead of a broken download. Each mapping carries a
   **confidence**: a ZDI advisory that named the binary *replaces* the title
   guess and shows as `advisory-confirmed` (with a link to the advisory); a
   guess resting only on a high-churn binary like `ntoskrnl.exe` with nothing
   to corroborate it is flagged `best guess — verify`, because Winbindex can't
   disprove it (that file changes in every update). `cve_modules.json` is
   persistent across refreshes: entries with `"source": "manual"` are never
   overwritten, so a hand-corrected mapping sticks.
4. The workflow **only re-runs the data build** on its weekly cron, manual
   dispatch, or a push touching `scripts/**`. A push that only touches
   `index.html` / `data/**` / the SVG assets skips straight to deploy —
   fast iteration on the frontend without waiting on MSRC + Winbindex.

Everything else — filtering, sorting, the patch-diff panel, the binary
biography view, the Overview modal — is plain JS reading the two committed
JSON files. There is no runtime backend.

## Data sources

- [MSRC CVRF v3 API](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json) —
  CVE records, CVSS, CWE, KBs, exploited/disclosed status, affected products.
  No API key required.
- [Winbindex](https://winbindex.m417z.com/) — per-file build history
  (version, sha256, timestamp/size, which KB shipped it) used to resolve
  patch-diff targets. Not affiliated with this project.
- [Zero Day Initiative](https://www.zerodayinitiative.com/) — published
  advisories, cross-referenced to pin the specific affected binary when
  MSRC's title is vague. Public advisories only, no API key. Not affiliated
  with this project.
- [FIRST EPSS](https://www.first.org/epss/) — daily exploit-probability
  scores.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) —
  confirmed-exploited-in-the-wild catalog.

## Honest limitations

- **Patch-diff coverage is real but partial.** ~1,400 of ~2,000 CVEs
  (roughly three-quarters) currently resolve to a downloadable build. Gaps:
  CVE titles that don't map to a known component, Windows Server 2022+
  (Winbindex has no key for it — only 2016/2019 are reachable, since they
  share build numbers with client Windows), and components with no binary at
  all (Secure Boot firmware, VBS enclaves).
- **x64 only**, for now. arm64/x86 targets aren't resolved.
- **The affected-module mapping is a heuristic**, not ground truth — MSRC's
  advisories name a *component* ("Windows Common Log File System Driver"),
  not a filename. `COMPONENT_MAP` in `build_modules.py` maps titles to
  binaries by keyword match, then Winbindex gates the guess (a wrong
  filename simply produces no download, never a broken one). **One case
  slips that gate**: a vague "Windows Kernel" title guessed as `ntoskrnl.exe`,
  which changes in every cumulative update and so always resolves — the guess
  can be wrong yet still serve a (wrong) download. Two mitigations: where a
  **ZDI advisory** names the real binary it overrides the guess and is marked
  `advisory-confirmed`; otherwise an uncorroborated high-churn guess is marked
  `best guess — verify` rather than presented as fact. ZDI coverage is a
  minority of CVEs, so this corrects the worst false positives, not all of
  them. Corrections are welcome — see below.
- **Not affiliated with Microsoft, Winbindex, FIRST, or CISA.** Independent,
  unofficial, best-effort.

## Correcting a wrong affected-module mapping

If a CVE's binary guess is wrong, hand-edit its entry in
`data/cve_modules.json` and set `"source": "manual"` — the refresh workflow
preserves manual entries and never overwrites them.

To supply or fix an advisory cross-reference (e.g. add a binary for a CVE ZDI
named but `zdi.py` couldn't map), edit its entry in `data/zdi_map.json` and set
`"source": "manual"` there; `zdi.py` preserves manual entries the same way, and
`build_modules.py` will pick up the corrected binary on the next build. New
`ZDI_COMPONENT_MAP` keywords in `scripts/zdi.py` fix it for every CVE at once.

## Local development

There's no build step for the frontend — `index.html` is a single static
file. To run the data scripts you need Python 3.12+ and network access to
MSRC/Winbindex/FIRST/CISA:

```bash
WINSIGHT_BACKFILL_MONTHS=2 WINSIGHT_FEED_OUTPUT=data/feed.xml python scripts/build_index.py
python scripts/zdi.py                                          # -> data/zdi_map.json
WINSIGHT_MODULES_OUTPUT=data/cve_modules.json python scripts/build_modules.py
python -m http.server 8000   # then open localhost:8000
```

`build_modules.py` accepts `WINSIGHT_WINBINDEX_CACHE=<dir>` to cache
Winbindex responses on disk (the CI workflow uses this via
`actions/cache` so same-week reruns skip re-downloading ~40 files).

## Setup (deploying your own copy)

1. Push this repo to GitHub (public, for free Pages + Actions minutes).
2. **Settings → Pages → Source → GitHub Actions**.
3. **Settings → Actions → General → Workflow permissions → Read and write
   permissions** (the workflow commits the refreshed data files back to the
   repo).
4. **Actions tab → "Build & deploy" → Run workflow** to trigger the first
   build manually rather than waiting for the weekly cron.
5. Once it succeeds, the site is live at `https://<you>.github.io/<repo>/`.

## Extending

- **More history**: raise `WINSIGHT_BACKFILL_MONTHS` in
  `.github/workflows/pages.yml`. MSRC's archive doesn't go back forever —
  very old months 404 and are skipped gracefully.
- **More binaries**: add entries to `COMPONENT_MAP` in
  `scripts/build_modules.py`. Winbindex gates every guess, so it's safe to
  be aggressive.
- **Different refresh cadence**: edit the `cron:` line in
  `.github/workflows/pages.yml`.

## Credits

Data: Microsoft Security Response Center, Winbindex, FIRST, CISA.
Not affiliated with any of them.

## License

[MIT](LICENSE) — free to use, modify, and redistribute.
