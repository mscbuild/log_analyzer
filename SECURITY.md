# Security Policy for log_analyzer

## Supported Versions


| Version | Supported          |
| ------- | ------------------ |
| >= 1.0  | :white_check_mark: |
| < 1.0   | :x:                |

## Security Focus: Data Parsing & Privacy

Because this tool processes sensitive server logs (Apache/Nginx) using `pandas`, `regex`, and `ipaddress`, we focus on:

*   **Regular Expression Denial of Service (ReDoS)**: We use the `regex` library to mitigate some risks, but complex patterns in `log_parser.py` must be audited for catastrophic backtracking.
*   **IP Address Validation**: Using the `ipaddress` module to prevent injection attacks or SSRF-related vulnerabilities when resolving or filtering log sources.
*   **Data Leakage in Visualizations**: Ensuring `visualizer.py` (via `seaborn`/`matplotlib`) does not inadvertently expose sensitive PII (Personally Identifiable Information) like full IP addresses in public reports if not intended.
*   **Large File Vulnerability**: Protecting `traffic_analyzer.py` from memory exhaustion (OOM) when loading massive `.log` files into `pandas` DataFrames.

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

1. **Private Report**: Please use the [GitHub Private Vulnerability Reporting](https://github.com) feature.
2. **Email**: Alternatively, contact **[security@mscbuild.dev]**.
3. **Response**: We aim to acknowledge all reports within **48 hours** and provide a fix or mitigation within **14 days**.

## Security Recommendations
- **Environment**: Always use a virtual environment (`python -m venv venv`).
- **Audit**: Run `pip-audit` regularly to check `pandas` and `numpy` for known CVEs.
- **Privacy**: If sharing `output/` files, ensure you have anonymized sensitive log data.
