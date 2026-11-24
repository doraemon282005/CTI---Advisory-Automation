# Infrastructure Security Advisory & Vulnerability Automated Surveillance

An automated end-to-end vulnerability surveillance system for infrastructure and enterprise applications. It ingests advisory feeds from **Inoreader**, first screens them against the configured **Application Inventory (.xlsx)**, evaluates **Security Impact & Severity** using AI, and routes inventory-matched advisories into formatted morning review workbooks. After human review and report generation, it updates the corresponding cumulative archives.

---

## Output Architecture (Four Daily Workbooks)

Filtering has two levels. First, an advisory must match an application in the configured Application Inventory. Related-story and footer text is excluded from that match and from company routing. Only those inventory-matched advisories are then routed to exactly one category: **Telecom** if the advisory also contains a telecom-list company name; otherwise **Vendor** if it contains a vendor-list name; otherwise **Miscellaneous**. The order prevents an advisory from being duplicated across category workbooks and prevents telecom/vendor names alone from admitting unrelated advisories. Ambiguous common one-word company names are matched only when written in their listed all-caps form; short names require nearby telecom context.

The daily run creates or rebuilds three category workbooks and one separate informational workbook. Information advisories are excluded from the Telecom, Vendor, and Miscellaneous workbooks. Each workbook is created with Summary headers even when it has no records. If a same-day workbook exists, its unreviewed rows and decisions are retained while the full scan window is refreshed.

1. **Telecom**: `reports/daily/YYYY-MM-DD/Daily_Telecom_Advisories_YYYY-MM-DD.xlsx`; archive: `reports/Master_Telecom_Advisories.xlsx`. Names come from `Global Telecom List.xlsx`.
2. **Vendor**: `reports/daily/YYYY-MM-DD/Daily_Vendor_Advisories_YYYY-MM-DD.xlsx`; archive: `reports/Master_Vendor_Advisories.xlsx`. Names come from `Vendor List.xlsx`.
3. **Miscellaneous**: `reports/daily/YYYY-MM-DD/Daily_Miscellaneous_Advisories_YYYY-MM-DD.xlsx`; archive: `reports/Master_Miscellaneous_Advisories.xlsx`. This contains application-inventory matches not already routed to Telecom or Vendor.
4. **Informational**: `reports/daily/YYYY-MM-DD/Daily_Informational_Advisories_YYYY-MM-DD.xlsx`. This contains all advisories classified as `Information`, regardless of their Telecom/Vendor/Miscellaneous route. It is a standalone daily workbook and is not included in category master archives.

All four daily workbooks are grouped in one `reports/daily/YYYY-MM-DD/` folder for the report date.
Running `--process-reviewed` also creates eligible Word reports in that date folder's `Detailed Advisory Reports/` subfolder. The daily and category master Summary sheets contain a **View Detailed Report** link beside **View Report**. Reports use `Detailed Advisory Report Format.docx`; incomplete or unstructured fields are left blank rather than presented as facts.

Each daily Summary stages candidates as `Selected` by default; review each category workbook before running `--process-reviewed`. Unreviewed category advisories from the last seven days remain eligible for cross-source matching and are carried forward when a same-day workbook is rebuilt. The original `Master_Advisories.xlsx` is retained unchanged as a legacy backup. Its historical Summary records are copied into the three category archives.

The default Inoreader window is the previous local calendar day, from midnight inclusive to today's midnight exclusive, regardless of report-generation time. Window eligibility uses Inoreader's crawl timestamp so newly discovered articles are not dropped because a publisher's original publication date is older; the publisher date remains the date shown in reports. The feed is paginated through all available articles in the window; there is no per-run article-count cap. `--hours N` scans the N-hour window ending at today's local midnight.

### Cross-source duplicate handling

The pipeline compares each candidate with other articles in the scan, recent unreviewed daily workbooks, and records in all category archives. It checks CVEs, product identity, versions, vulnerability class, shared named entities (such as actors, malware, and victims), and title/summary similarity. Candidate pairs that are uncertain are adjudicated by the configured Gemini/OpenAI evaluator; if neither API is available, they remain separate and flagged for human review. Different lifecycle stages of one CVE—disclosure, active exploitation, or patch release—are kept separate and cross-referenced.

Gemini requests are paced by `gemini.requests_per_minute` (default `12`) so parallel advisory evaluation and merge checks stay below the Free Tier's 15-requests-per-minute limit. This makes runs slower rather than requiring billing. On an HTTP 429, 404, or network failure, Gemini is disabled for the rest of that run and the pipeline continues with rule-based results and human review; if another process used the free quota, wait for its window to reset before rerunning. `openai.enabled` defaults to `false`, so the pipeline will not make billable OpenAI fallback calls even if an OpenAI key is present. Set it to `true` only if you explicitly want to allow paid OpenAI requests.

Confirmed same-event reports become one advisory. A single merged summary is generated from all source records when an AI API is available; otherwise the existing rule-based summary merge is used. Unique remediation, affected products/versions, CVEs, and IOCs are retained. Source conflicts (including affected versions or severity) are preserved and called out in the summary. Every source URL is shown on its own line in **Link of Advisory**; the first URL is clickable. **Other Sources** lists each additional source and link. Possible matches remain separate and are described in **Duplicate Check**.

For a human duplicate decision, select **Same Event** or **Keep Separate** from the **Duplicate Check** cell. Decisions are stored by article-ID pair so a resolved pair is not repeatedly flagged. Choosing **Keep Separate** on an already merged row splits its stored source records back into separate review items on the next pipeline run. These controls are separate from `Review Decision`, which continues to control advisory relevance.

The cache database keeps a pair-decision table and a send ledger keyed by stable `advisory_id`, recipient team, and content hash. No mail is sent by this stage. If new unique source facts join an advisory that already has a send-ledger entry, the record is marked `UPDATE` and its `Update Summary` contains only the newly added facts. Repeated content hashes are idempotent in the ledger.

Transient Inoreader connection failures are retried up to two times with a short backoff. If the feed still cannot be reached, the run stops with an error rather than substituting sample data; check the network connection and Inoreader availability before retrying.

### Human-reviewed relevance workflow

1. Run the normal daily command. Candidates appear in the applicable category workbook with `Review Decision` set to `Selected` by default. Change unwanted items to `☒ Rejected` (or `☐ Pending` if they still need review). The master archives are not updated during this step. Candidates flagged by initial AI triage remain visible and are marked `UNASSESSED` instead of being silently dropped.
2. Review the Summary sheet in each daily workbook and confirm or change `Review Decision`: `☑ Selected`, `☐ Pending`, or `☒ Rejected`. Use `Duplicate Check` only to resolve a possible/merged duplicate. `Model Suggestion` is advisory only.
3. Run `.\.venv\Scripts\python.exe -u "src\pipeline.py" --process-reviewed`. This processes available category workbooks within the configured pending window. Detailed report sheets are generated for items left `Selected` with non-LOW severity; separate Word reports are generated for selected, non-LOW `Actionable` and `Patching` items. After each daily report is saved successfully, its records are appended to the corresponding category archive. Pending, rejected, previously-reported, and LOW advisories never get detailed reports.
4. Open the **Learning Tracker** sheet in each category master workbook for its status view. Only human Selected/Rejected decisions count as training labels.

If the daily pipeline is rerun on the same date, that date's existing master rows are ignored during duplicate matching so the fresh scan can rebuild the review workbooks. Pending rows and their review decisions are retained. When `--process-reviewed` saves a reviewed batch, it replaces that workbook date's rows and report tabs in the master archive while preserving records from earlier dates.

The `deduplication` section in `config.json` controls `pending_days` (default `7`), `same_event_confidence_threshold` (default `0.85`), and `candidate_similarity_threshold` (default `0.18`). The database stores stable advisory IDs, member article IDs, pair decisions, and delivery status fields in hidden workbook columns without changing the existing Summary layout.

The first local learner is an explainable, weighted Naive Bayes baseline using advisory text, matched applications, severity, and advisory type. It retrains from human `Selected` and `Rejected` decisions in the Master Summary on later runs. Suggestions begin only after at least five labels in each class. The Learning Tracker reports cross-validated metrics and recurring terms; these are early indicators, not a guarantee of production accuracy. The model never selects or publishes advisories. Corrected decisions are used on the next run. Advisory format examples are templates, not relevance labels. Detailed report sheets are created only for items left `Selected` after human review. Threat details, summaries, and recommendations are rendered as concise bullet points; the source link remains available for context.

Matched advisories in languages other than English are translated to English by the configured AI evaluator before they are added to the review workbook. The original source remains available through the advisory link.

Detailed reports list affected products and only the versions explicitly stated in the advisory, include the technical impact detail under Threat Classification, and provide a separate concise Summary focused on the security issue. IOC values are defanged in report content (for example, `192[.]168[.]34[.]5` and `hxxps://example[.]com`).

### CVE enrichment credentials

- NVD API key (optional, increases lookup rate limits): set the `NVD_API_KEY` environment variable. The exporter uses NVD CVSS v4.0 metrics when available, falling back to v3.1, v3.0, and v2.
- Tenable Vulnerability Management credentials: set `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`; `TENABLE_BASE_URL` defaults to `https://cloud.tenable.com`.
- Keep API keys in environment variables rather than committing them to `config.json`. NVD does not publish IOCs; IOC extraction remains sourced from the advisory content.
- CVE table values are sourced from NVD when available; missing ratings/vectors are labeled `Not available`. If neither the advisory nor Tenable provides remediation text, the report directs the reader to the vendor advisory rather than leaving the recommendation cell empty.
- NVD CVEs are queried in batches and cached locally under `data/nvd_cve_cache.json`. Routine runs only enrich newly processed advisories; `--refresh-reports` explicitly rechecks existing report entries.
- Recovered report text and fetched web pages are checked against the advisory CVEs/title before they can populate recommendations. Mismatched text is discarded, and refreshed matching advisories can update stale links in the master archive.

In PowerShell, save credentials for your Windows user (replace the placeholders locally; do not paste keys into chat):
```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "<your-nvd-api-key>", "User")
[Environment]::SetEnvironmentVariable("TENABLE_ACCESS_KEY", "<your-tenable-access-key>", "User")
[Environment]::SetEnvironmentVariable("TENABLE_SECRET_KEY", "<your-tenable-secret-key>", "User")
```
Open a new terminal or restart the scheduled task process after setting them. NVD can be used without a key at a lower rate; Tenable enrichment requires both Tenable keys.

Each summary row includes a **View Report** button after the vendor link. It opens that advisory's generated report sheet. Report tabs use a concise heading derived from the advisory title.

### Excel Column Specification
| Col # | Field Name | Description |
| :--- | :--- | :--- |
| **1** | **Source Name** | E.g., Cisco PSIRT, CISA KEV, Palo Alto, Oracle CPU, NVD, GBHackers, The Hacker News |
| **2** | **Advisory Type** | `Actionable`, `Patching`, or `Information` |
| **3** | **Advisory Heading** | Clean technical title including CVE identifiers |
| **4** | **Link of Advisory** | One source URL per line; the first URL is the clickable hyperlink |
| **5** | **View Report** | Button linking directly to the generated report sheet; displays `Not generated` until a report exists |
| **6** | **Other Sources** | Additional source names and links consolidated for the same issue |
| **7** | **Duplicate Check** | Possible duplicate details or the human Same Event / Keep Separate control |
| **8** | **Severity** | Color-coded badge (`CRITICAL` [Red], `HIGH` [Orange], `MEDIUM` [Yellow], `LOW` [Green]) |
| **9** | **CVSS** | Extracted CVSS Base Score (e.g., 9.8, 8.6) |
| **10** | **Published Date & Time** | Original publication timestamp (`YYYY-MM-DD HH:MM`) |
| **11** | **Security Impact / Summary** | Technical summary describing the vulnerability mechanics, exploit vectors (RCE, Auth Bypass, DoS, Info Disclosure), and affected software components |
| **12** | **Matched Application / Component** | Which specific asset from your inventory triggered the alert |
| **13** | **CVE Details** | CVE identifiers and descriptions |
| **14** | **CVE Risk Score** | CVSS risk score when available |
| **15** | **Attack Vector** | Source-reported or enriched attack vector |
| **16** | **AV Type** | Attack-vector category |
| **17** | **IOCs** | Defanged indicators of compromise |

---

## Project Structure

Required input workbooks, local credentials, caches, and generated reports are
intentionally excluded from Git. Keep the workbooks named below in the project
root on each installation.

```text
C:\Users\PwC\Desktop\Advisory API\
└── Codebase/
    ├── .gitignore
    ├── config.example.json         # Safe template; copy to local config.json
    ├── run_daily.bat               # One-click execution batch script
    ├── run_full_scan.bat           # Force re-processing of feed advisories
    ├── schedule_task.ps1           # 5:00 AM Windows Scheduled Task configurator
    ├── commands.txt                # Setup, run, schedule, pause, and removal commands
    └── src/
        ├── config.py               # Configuration & path loader
        ├── inventory_manager.py    # Reads .xlsx with Win32 shared lock & fast regex index
        ├── inoreader_client.py     # Inoreader API client with ClientLogin & corporate SSL
        ├── ai_evaluator.py         # AI Security Impact & Severity Evaluator
        ├── excel_exporter.py       # Formatted openpyxl Excel generator with safe saving
        ├── cache_db.py             # Deduplication database tracker
        └── pipeline.py             # Main execution orchestrator
```

Place `Advisory Formats.xlsx`, `Global Telecom List.xlsx`, `Vendor List.xlsx`, and
your application inventory (default: `inventory.xlsx`) in the project root. They
are required at runtime but should remain local and untracked.

---

## How to Run in VS Code

### 1. Prepare local configuration and workbooks

Copy the safe configuration template and add your local credentials:
```powershell
Copy-Item .\config.example.json .\config.json
```

Keep credentials in environment variables where possible. The local `config.json`,
all Excel workbooks, generated reports, caches, and logs are ignored by Git because
they may contain credentials or private inventory/advisory data. Place these required
workbooks in the project root: `Advisory Formats.xlsx`, `Global Telecom List.xlsx`,
`Vendor List.xlsx`, and your configured application inventory (default:
`inventory.xlsx`). Do not commit populated local copies.

### 2. Open the Folder in VS Code
Open `C:\Users\PwC\Desktop\Advisory API\Codebase` in VS Code.

### 3. Run the Pipeline
Open the terminal in VS Code (``Ctrl + ` ``) and execute:
```powershell
.\run_daily.bat
```
or run with Python directly:
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py"
```

To scan a different number of hours ending at local midnight:
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py" --hours 48
```

To force re-processing of already cached items:
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py" --force
```

To evaluate and print duplicate decisions without writing workbooks or cache entries:
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py" --dry-run-merges
```

To rebuild existing daily and master workbooks with the latest CVE metrics and remediation extraction (without fetching the feed):
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py" --refresh-reports
```

After marking decisions in today's Daily Advisories Summary, generate the selected reports and then update the master archive:
```powershell
.\.venv\Scripts\python.exe -u "src\pipeline.py" --process-reviewed
```

### 4. Schedule the Daily 5:00 AM Automated Run
```powershell
powershell -ExecutionPolicy Bypass -File .\schedule_task.ps1
```

For dependency setup, one-time/full scans, reviewed reports, schedule pause/resume, and task removal, see [commands.txt](./commands.txt).
