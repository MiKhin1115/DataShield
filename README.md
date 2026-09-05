# Intelligent USB DLP Prototype

This is the first implementation slice for the USB Data Loss Prevention project.
It covers:

- USB storage insertion and removal detection on Windows
- Automatic ejection of explicitly unauthorized or blocked USB storage
- File copy monitoring on detected USB drives
- Sensitive data scanning for copied files
- File classification as Public, Internal, Confidential, or Restricted
- Risk scoring from 0 to 100
- Policy decisions to Allow, Alert, or Block
- SOC alerts in the console and through an optional webhook
- Durable JSONL incident records and JSON/CSV reports
- Local incident dashboard with charts, filters, summaries, and CSV export
- Synthetic test files covering common DLP scenarios
- Administrator-managed policies with priorities, conditions, risk overrides, and actions
- Role-based access for administrators, SOC analysts, auditors, and read-only users
- SHA-256, SHA-1, and MD5 file fingerprints with duplicate correlation
- Incident assignment, status, investigation notes, USB authorization, and audit history
- Encrypted high-risk evidence packages with integrity hashes and retention dates
- Incident search across users, computers, USB serials, files, risk, actions, status, and time
- Chronological incident timelines covering detection, scanning, decisions, evidence, and alerts
- OpenRouter-powered incident summaries, risk explanations, recommendations, and investigation questions

The prototype is intentionally lightweight and uses Python standard-library
polling, so it can run in a Windows VM before Wazuh, Sysmon, Elasticsearch, or a
dashboard are added.

## Run

```powershell
python -m dlp_agent monitor --interval 0.5
```

Sensitive PowerShell transfers using commands such as `Invoke-WebRequest -InFile`
are suspended pending an SOC decision. Selecting **Block** in the dashboard terminates
only the verified originating process tree; selecting **Allow** resumes it.

High-risk and blocked events preserve evidence metadata and, by default, an encrypted
copy of files up to 25 MB in `data/evidence`. Windows Data Protection API (DPAPI)
encryption binds protected copies to the Windows account running the agent. The
default retention period is 90 days and expired packages are removed when the agent
starts. Configure these settings with:

```powershell
python -m dlp_agent run --evidence-retention-days 30
python -m dlp_agent run --no-evidence-copy
python -m dlp_agent run --evidence-directory D:\ProtectedEvidence
```

Incidents are saved to `data/incidents.jsonl`. Alert and Block decisions display
an immediate `[SOC ALERT]` message. To also send alerts to a SOC webhook:

```powershell
python -m dlp_agent run --alert-webhook https://your-alert-receiver.example/webhook
```

For a quick scanner test against one file:

```powershell
python -m dlp_agent scan path\to\file.txt
```

Create the synthetic test dataset:

```powershell
python -m dlp_agent generate-test-data
```

Populate the dashboard with matching demonstration incidents:

```powershell
python -m dlp_agent generate-test-data --seed-incidents
```

Start the dashboard:

```powershell
python -m dlp_agent dashboard --port 8080
```

To enable AI incident analysis, create a local `.env` file from the included example
and add your OpenRouter API key:

```powershell
Copy-Item .env.example .env
notepad .env
python -m dlp_agent dashboard --port 8080
```

The default model is `openai/gpt-oss-20b`. Change `OPENROUTER_MODEL` in `.env` to
use another OpenRouter model. Restart the dashboard after changing `.env`. Never
commit or share the `.env` file.

Then open `http://127.0.0.1:8080`. The agent and dashboard use the same incident
file, so the page refreshes as new USB activity is recorded.

### USB authorization behavior

USB authorization is matched by hardware serial number when Windows reports one,
with the PnP identifier and drive letter retained as compatibility fallbacks.

- **Authorized** devices remain available and are monitored for file-copy events.
- **Unknown** devices are not in the authorization list. They remain monitored and
  immediately create an Alert incident for administrator review.
- **Unauthorized** and **Blocked** devices immediately create a Block incident and
  the agent asks Windows to safely eject the drive. The incident timeline records
  whether enforcement succeeded. If Windows refuses the eject request, the result
  is recorded as a block failure and file monitoring continues as a fallback.

Start the agent before inserting the USB device. Register the serial shown in the
insertion incident from **Access control > USB authorization**, then remove and
reinsert the device to test its new authorization state.

## Dashboard Accounts

The first dashboard start creates local demonstration accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin123!` |
| SOC Analyst | `soc` | `Soc123!` |
| Auditor | `auditor` | `Audit123!` |
| Read-Only User | `viewer` | `View123!` |

These are test credentials. Change their passwords in Access Control before using
the platform outside a local demonstration.

Administrators and SOC analysts can view evidence metadata and download a verified,
decrypted evidence copy. Auditors can view metadata but cannot download protected
files. Read-only users cannot access evidence. The operating-system folder ACL also
restricts `data/evidence` to the agent account and `SYSTEM`.

Administrators and SOC analysts can generate and view AI incident analyses. Auditors
can review saved analyses but cannot generate them. Read-only users do not have AI
analysis access.

## AI Incident Analysis

Open an incident and select **Generate analysis**. The dashboard asks OpenRouter for:

- A concise incident summary
- An explanation of the existing deterministic risk score
- Prioritized investigation recommendations
- Questions for the assigned analyst

The first request is saved in `data/ai_analyses.jsonl`. Reopening or requesting the
same analysis uses the saved result; **Regenerate analysis** explicitly creates a new
version. Requests, failures, cache hits, and completions are recorded in the audit
log. Successful generations are also added to the incident timeline.

AI is advisory only. It cannot change the official classification, risk score,
policy decision, enforcement action, status, or assignment. The first release sends
only sanitized category-level metadata such as department, USB authorization state,
file type and size bucket, sensitive-data type counts, and the existing official
decision. It excludes raw file contents, file names, paths, hashes, usernames,
computer names, USB serials, detected values, evidence, and case notes.

OpenRouter requests require structured JSON output, request Zero Data Retention, and
deny provider data collection. The API key remains on the dashboard server and is
never sent to the browser or stored in an incident record.

## Incident Investigation

The Incidents workspace supports quick filters for risk level, action, status, and
the last 24 hours, 7 days, or 30 days. Advanced filters cover incident ID, username,
computer, USB name and serial number, file name and type, classification, risk-score
range, and an exact date/time range. Filters can be combined.

Open an incident to see its evidence summary and chronological timeline. New events
include USB insertion and authorization, file detection, sensitive-data scanning,
classification, risk calculation, policy action, evidence collection, SOC alerting,
and later analyst workflow changes. Older records without timeline data display a
short compatibility timeline.

## Investigation Workflow

New incidents start as **Open**. Administrators and SOC analysts can move an incident
through Open, Investigating, Resolved, False Positive, Escalated, Pending User
Confirmation, Pending Manager Approval, and Closed. A reason is required whenever
the status or assigned analyst changes. Every change records the actor, previous and
new value, timestamp, reason, audit event, and timeline event.

Incidents can be assigned or reassigned only to enabled SOC Analyst accounts. The
Incidents workspace shows the responsible analyst and can filter by a specific
analyst, assigned incidents, or unassigned incidents.

Case notes are append-only and receive a permanent note ID, analyst identity, role,
timestamp, and related incident ID. A note may include one attachment up to 2 MB.
Attachments are stored under `data/case_attachments`, include a SHA-256 integrity
hash, and can only be downloaded by administrators and SOC analysts. Notes and
attachments cannot be edited or deleted through the platform.

## Policy Management

Administrators can create, edit, enable, disable, delete, and prioritize policies
from the Policies workspace. Conditions can use classification, sensitive-data
type or count, file size or extension, USB authorization, user, department, risk
score, and transfer time. Policy changes are loaded for each transfer, so the
monitoring agent does not need to be restarted.

The Access Control workspace manages dashboard accounts, roles, departments, and
USB authorization. For department policies, the monitoring agent matches the
current Windows username to a managed account. If there is no matching account,
the `USB_DLP_DEPARTMENT` environment variable can provide the department.

Every new incident records SHA-256, SHA-1, and MD5 hashes. SHA-256 is used to
count previous incidents containing identical file content even when the file was
renamed.

Print the latest incidents as JSON or CSV:

```powershell
python -m dlp_agent report --limit 100 --format json
python -m dlp_agent report --limit 100 --format csv
```

## What It Detects

The scanner currently looks for:

- Email addresses
- Phone numbers
- Passport-like values
- Myanmar NRC-like values
- Bank account-like numbers
- Password assignments
- API keys and tokens
- Salary/payroll terms
- Confidential, restricted, secret, and internal keywords

## Output

When a new or modified file appears on a USB drive, the agent scans the file and
prints one JSON incident record. Each record includes the detected sensitive
data, file classification, risk score, policy decision, and reasons for the
decision.

The default policy is:

- **Public**: Allow
- **Internal**: Alert
- **Confidential**: Alert
- **Restricted**: Block

Critical credentials such as passwords, API keys, tokens, and private keys are
classified as Restricted. High-severity data such as bank accounts, passport
numbers, NRC values, and salary information is classified as Confidential.

USB device-level `Block` decisions are enforced by safely ejecting explicitly
unauthorized storage. File-level `Block` decisions are still recorded policy
decisions; a Windows filesystem filter driver would be required to cancel an
individual copy operation before Windows writes the file.
