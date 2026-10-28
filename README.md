# Simple Phishing Analyzer

A Python-based phishing email analyzer that performs automated triage of `.eml` files.

Simple Phishing Analyzer analyzes email headers, extracts security observables, identifies suspicious email characteristics, hashes attachments, calculates a risk score, and optionally enriches URLs and attachment hashes using external threat intelligence sources.

The analyzer can run entirely without API credentials. External threat intelligence enrichment is opt-in using the `--enrich` flag.

![Sample Output](assets/screenshot.png)

## Skills Demonstrated

- Phishing email triage and analysis
- Email authentication analysis (SPF, DKIM, DMARC)
- Observable extraction and safe defanging
- Threat intelligence enrichment
- Python CLI development
- Risk-based detection logic
- MITRE ATT&CK mapping

## Features

- `.eml` email parsing
- Email header analysis
- SPF, DKIM, and DMARC analysis
- Display-name spoofing detection
- Reply-To mismatch detection
- Received-chain analysis
- URL extraction
- Domain extraction
- IP address identification
- Attachment hashing
- Unified observable reporting
- Risk scoring and analyst verdict
- Optional VirusTotal URL enrichment
- Optional MalwareBazaar attachment enrichment
- MITRE ATT&CK mapping
  - T1566 - Phishing
  - T1566.001 - Spearphishing Attachment
  - T1566.002 - Spearphishing Link

## Analysis Workflow

Simple Phishing Analyzer separates local email analysis from external threat intelligence enrichment.

```text
                  .eml Email
                      |
                      v
                Email Parsing
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Headers       Body     Attachments
          |           |           |
          +-----------+-----------+
                      |
                      v
                 Observables
               /      |       \
            URLs    Domains   IPs
                      |
                  Attachments
                    / Hashes
                      |
              +-------+-------+
              |               |
              v               v
        Local Analysis    --enrich
              |               |
              |        +------+------+
              |        |             |
              |    VirusTotal   MalwareBazaar
              |        |             |
              +--------+------+------+
                              |
                              v
                       Risk Assessment
```

## Installation

Clone the repository and install the required dependencies:

```bash
pip install -r requirements.txt
```

Tested using Python 3.10.9.

## Usage

### Local Analysis

External API access is not required for standard analysis.

Windows:

```powershell
python phishing_analyzer.py <path-to-file.eml>
```

Linux/macOS:

```bash
python3 phishing_analyzer.py <path-to-file.eml>
```

The report includes header analysis, findings, extracted observables, attachment hashes, and risk scoring.

### Threat Intelligence Enrichment

External threat intelligence enrichment is disabled by default.

To enable enrichment:

Windows:

```powershell
python phishing_analyzer.py <path-to-file.eml> --enrich
```

Linux/macOS:

```bash
python3 phishing_analyzer.py <path-to-file.eml> --enrich
```

When enabled, the analyzer attempts to enrich supported observables using:

- VirusTotal for URL reputation
- MalwareBazaar for attachment hash lookup

## API Keys

API credentials are only required when using the `--enrich` option.

Create a `.env` file in the project directory:

```text
VT_API_KEY=your_key_here
MB_API_KEY=your_key_here
```

Having a `.env` file does not automatically enable external enrichment. The `--enrich` option must be explicitly specified.

Without `--enrich`, analysis remains local and no threat intelligence lookups are requested.

## Observables

The analyzer consolidates artifacts discovered during email analysis into a unified Observables section. Observables are artifacts identified within the email and are not necessarily malicious.

Example:

```text
=== Observables ===

URLs (1)
  [1] hxxp://example[.]test/account

Domains (3)
  [1] example[].test
  [2] sender[.]example
  [3] reply[.]example

IP Addresses (0)
  None

Attachments (0)
  None
```
  
For safer analyst handling, URLs, domains, and IP addresses are defanged when displayed. Raw values are retained internally for analysis and optional threat intelligence enrichment.

Example:
```
http://example.test/login → hxxp://example[.]test/login
```

## Threat Intelligence

When enrichment is disabled:

```text
=== Threat Intelligence ===
Enrichment: DISABLED
Run with --enrich to enable external threat intelligence lookups.
```

When `--enrich` is specified, supported observables are submitted to the configured threat intelligence services for additional analysis.

## MITRE ATT&CK Mapping

Simple Phishing Analyzer maps relevant findings to:

- T1566 - Phishing
- T1566.001 - Spearphishing Attachment
- T1566.002 - Spearphishing Link

## Sample Data

Test emails are sourced from:

https://github.com/rf-peixoto/phishing_pot/

## Code Quality

- Type checked with mypy
- Unit tested with unittest

## Version

1.1.0

## Author

Philip Zangara

## License

MIT
