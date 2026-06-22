# winsight

A searchable table of Microsoft security advisories (CVEs) — filter by date
range, affected Windows version, vulnerability type, CVSS score, exploited /
disclosed status, and KB number. Static site on GitHub Pages, no database,
no server. Data comes entirely from the official MSRC Security Update API.

## How it works

```
MSRC CVRF API  ──>  scripts/build_index.py  ──>  data/index.json  ──>  index.html (fetch)
                       (GitHub Action,                                  (GitHub Pages,
                        weekly cron)                                     static fetch)
```

A scheduled GitHub Action runs `build_index.py`, which walks the last 24
months of MSRC's `/cvrf/{yyyy-Mon}` documents, normalizes them into a flat
list of CVE records, and commits the result to `data/index.json`. The page
itself is static HTML/JS that fetches that file and does all filtering and
sorting in the browser — nothing is queried live, and there's no backend to
keep running.

## Data source

Everything comes from the [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json),
confirmed via its published OpenAPI spec. No API key or login required.

- `GET /cvrf/{id}` — full advisory document for one month (`id` is
  `yyyy-Mon`, e.g. `2026-Jun`). This is where CVE IDs, titles, CVSS scores,
  KB numbers, exploited/disclosed status, and the affected-product list all
  come from.
- `GET /updates` — an OData-filterable summary list across all months.
  Not required by the current build script (which walks months directly,
  since that's independently confirmed to work), but available if you want
  to extend the discovery logic later.

**Scope note:** this tool is intentionally MSRC-only. MSRC's data maps a
CVE to an affected *product* (e.g. "Windows 11 Version 23H2 for x64-based
Systems"), not to specific binary filenames or exact build numbers — that
finer-grained mapping only exists in third-party indexes like Winbindex,
which this project deliberately does not use. The "Windows version" filter
is therefore MSRC's own product name, normalized (e.g. "Windows 11 23H2"),
not a raw build number like `10.0.22631`.

## Filters

- **Search** — free text across CVE ID, title, KB numbers, and version labels
- **Date range** — by the advisory's release date
- **Windows version** — MSRC's product name, normalized
- **Vulnerability type** — derived from the advisory title (RCE, EoP, DoS,
  Information Disclosure, Spoofing, Security Feature Bypass, Tampering)
- **CVSS range** — min/max base score
- **Exploited in the wild** / **Publicly disclosed** — from MSRC's threat
  description text. "Exploited" only counts confirmed/detected exploitation,
  not a forward-looking "more likely to be exploited" assessment.

## ⚠️ Honest limitations

- **Built without live network access**, so it hasn't been run end-to-end
  against the real API yet. The parsing logic was tested against a mock
  CVRF document shaped exactly like the real schema (confirmed via MSRC's
  own GitHub issue threads and the published swagger spec), and a real bug
  in the version-label cleanup regex was caught and fixed during that test
  — but the **first true end-to-end run is the GitHub Action itself**.
  Check its log and step summary after the first run before trusting the
  output.
- **Exploited-status classification is conservative by design.** MSRC's
  `Threats` array uses free-text descriptions without a clean enum, so this
  only flags a CVE as "exploited" on an explicit "detected" signal, not on
  a softer "exploitation more likely" forward assessment. If MSRC changes
  its phrasing, this logic may need a small update — check a sample of
  flagged CVEs against the live MSRC page after the first run.
- **No binary-level or build-number data**, by design (see Scope note
  above). If you want that, the previous iteration of this project added a
  Winbindex cross-reference for exact pre/post binary versions — ask if
  you want that layered back in as a separate, optional view.

## Setup

1. Push this repo to GitHub (public, for free Pages + Actions minutes).
2. **Settings → Pages → Source → GitHub Actions**.
3. **Settings → Actions → General → Workflow permissions → Read and write
   permissions** (the Action needs this to commit the refreshed
   `data/index.json` back to the repo).
4. **Actions tab → "Refresh index" → Run workflow** — trigger the first
   build manually rather than waiting for Wednesday's cron.
5. Once it succeeds, the site is live at `https://<you>.github.io/<repo>/`.

## Local testing

```bash
WINSIGHT_BACKFILL_MONTHS=2 python scripts/build_index.py   # quick 2-month test run
python -m http.server 8000                                   # then open localhost:8000
```

## Extending

- **More history**: raise `WINSIGHT_BACKFILL_MONTHS` in
  `.github/workflows/refresh.yml` (each extra month is one more API call;
  cheap, but MSRC's CVRF archive doesn't go back forever — very old months
  may 404 and are skipped gracefully).
- **Different cadence**: edit the `cron:` line in the workflow.

## Credits / data source

Microsoft Security Response Center — https://msrc.microsoft.com

Not affiliated with Microsoft.
