# AI Security Alert Triage

A beginner-friendly security operations (SOC) project that automatically reviews security alerts, assigns a risk score, recommends a priority, and suggests next steps.

> **Important:** This starter project uses an explainable, rule-based triage engine. It does not call an external AI service or make production security decisions. The scoring logic is designed so you can later connect an LLM or machine-learning model.

## Features

- Reads security alerts from a JSON file.
- Calculates a risk score from 0–100.
- Assigns **Critical**, **High**, **Medium**, or **Low** priority.
- Explains why an alert received its score.
- Recommends investigation and containment steps.
- Adds a suggested MITRE ATT&CK technique when a matching pattern is recognized.
- Exports results to JSON.
- Includes sample alerts and unit tests.

## Project structure

```text
ai-security-alert-triage/
├── data/
│   └── sample_alerts.json
├── src/
│   ├── __init__.py
│   ├── triage.py
│   └── main.py
├── tests/
│   └── test_triage.py
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.9 or newer
- No third-party Python packages are required.

## Run the project

Open a terminal in this project folder.

```bash
python src/main.py
```

Use a different input file:

```bash
python src/main.py --input data/sample_alerts.json
```

Save the results to a JSON report:

```bash
python src/main.py --input data/sample_alerts.json --output triage_report.json
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Input format

The input file must contain a JSON array. Each alert can contain:

```json
{
  "id": "ALERT-001",
  "timestamp": "2026-10-30T08:00:00Z",
  "title": "Multiple failed login attempts",
  "description": "Many failed logins followed by a successful login",
  "source_ip": "203.0.113.10",
  "event_type": "brute_force",
  "severity": "medium",
  "asset_criticality": "high",
  "failed_logins": 18,
  "successful_login_after_failures": true,
  "known_malicious_ip": false
}
```

Supported `event_type` values include `brute_force`, `malware`, `phishing`, `data_exfiltration`, `privilege_escalation`, and `suspicious_process`. Unknown event types are still triaged using the other available fields.

## How the score works

The engine starts with a base score and adds risk signals such as:

- Alert severity
- Asset criticality
- Known malicious source indicator
- Failed login volume
- Successful login after repeated failures
- Sensitive activity such as data exfiltration or privilege escalation

The final score is capped at 100.

| Score | Priority |
|---:|---|
| 80–100 | Critical |
| 60–79 | High |
| 30–59 | Medium |
| 0–29 | Low |

The output includes the score factors so an analyst can understand the result. Tune the weights in `src/triage.py` to fit your lab or organization.

## Example output

```text
AI SECURITY ALERT TRIAGE
============================================================
ALERT-001 | Critical | Risk: 92/100
Title: Multiple failed login attempts
Reasons:
  - High alert severity (+25)
  - High asset criticality (+20)
  - Successful login after repeated failures (+25)
Recommended actions:
  - Validate the login with the account owner.
  - Review authentication logs and source IP reputation.
  - Consider disabling or resetting the affected account.
```

Scores depend on the exact sample input and scoring rules.

## GitHub upload

1. Create a new repository on GitHub, for example `ai-security-alert-triage`.
2. Extract this ZIP file.
3. Open a terminal inside the extracted project folder.
4. Run:

```bash
git init
git add .
git commit -m "Initial AI security alert triage project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/ai-security-alert-triage.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.

You can also create a repository on GitHub and use **Add file → Upload files** to upload the extracted project files.

## Safety and limitations

- This is a learning/demo project, not a production SOC platform.
- A high score is a recommendation for human review, not proof of compromise.
- Do not upload real credentials, personal data, private logs, or confidential incident details to a public repository.
- Validate all alerts with trusted telemetry before taking containment actions.
- The sample IP addresses are documentation/test ranges and are not intended to identify real attackers.

## Possible improvements

- Add a Streamlit dashboard.
- Connect a SIEM such as Splunk, Microsoft Sentinel, or Elastic.
- Add a carefully controlled LLM explanation layer.
- Store analyst feedback and measure false-positive rates.
- Add role-based access, audit logs, and integration tests.
