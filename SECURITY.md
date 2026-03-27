# Security Policy for log_analyzer

## Supported Versions

We provide security updates for the following versions:


| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Considerations for Log Analysis

As a tool that processes raw server data, we prioritize the following risks:

*   **Log Injection**: Maliciously crafted log entries designed to exploit the parser or visualizer.
*   **ReDoS (Regular Expression DoS)**: Complex strings in `log_parser.py` that could cause CPU exhaustion when processing large files.
*   **Path Traversal**: Vulnerabilities where a user could manipulate file paths to read logs outside of the intended directory.
*   **Sensitive Data Exposure**: Ensuring that IP addresses or user agents in `output/` are handled according to privacy standards (GDPR/CCPA).

## How to Report a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability, please report it privately:

1.  **Email**: Send a detailed report to **[security@mscbuild.dev]**.
2.  **GitHub Advisory**: Use the [Private Vulnerability Reporting](https://github.com) feature on GitHub.
3.  **Details**: Please include a sample log file (if applicable) that triggers the issue and the version of Python used.

### Response Timeline
*   **Acknowledgment**: Within 48 hours.
*   **Patch Goal**: Critical vulnerabilities aim to be patched within 10–14 days.

## Best Practices for Users
*   **Sanitize Inputs**: Only run this tool on logs from trusted sources.
*   **Output Security**: Be cautious when sharing files from the `output/` directory, as they may contain sensitive infrastructure data.
*   **Environment**: We recommend running the analyzer in a virtual environment (`venv`) to isolate dependencies.
