# Log analysis mechanism

A project for analyzing server logs (Apache/Nginx) using Pandas to detect hacking attempts and traffic anomalies.

## Possibilities

### Security analysis
- **SQL Injection**: Detecting SQL injection attempts
- **XSS attacks**: identifying cross-site scripting
- **Path Traversal**: detecting file system access attempts
- **Command Injection**: command injection detection
- **Brute Force**: detection of password guessing attacks
- **Scan**: Vulnerability Scan Detection
- **Access to Admin Panels**: Monitoring attempts to access administrative resources

### Traffic analysis
- **Traffic Bursts**: Detecting Abnormal Request Peak
- **DDoS Attacks**: Identifying Potential Denial of Service Attacks
- **Bot Traffic**: Definition of Automated Traffic
- **Pattern Analysis**: Hourly and Daily Traffic Patterns
- **Status Codes**: Distribution of HTTP response codes

### Visualization
- Traffic timeline graph
- HTTP status code distribution
- Hourly traffic patterns
- Top IP addresses
- Detected attacks graph
- Comprehensive dashboard

## Installation

1. Clone the repository:
```bash
git clone https://github.com/mscbuild/log_analyzer 
cd log_analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic analysis
```bash
python main.py -f /path/to/access.log
```

### Nginx log analysis
```bash
python main.py -f /path/to/nginx.log --format nginx
```

### Analysis with saving to the specified directory
```bash
python main.py -f /path/to/access.log -o results
```

### Just a quick summary
```bash
python main.py -f /path/to/access.log --summary-only
```

## Project structure

```
log_analyzer/
├── src/
│   ├── log_parser.py          # Apache/Nginx Log Parser
│   ├── security_analyzer.py   # Security analysis
│   ├── traffic_analyzer.py    # Traffic analysis
│   └── visualizer.py          # Visualization of results
├── examples/
│   ├── sample_apache.log      # Example Apache logs
│   └── sample_nginx.log       # Example of Nginx logs
├── output/                    # Directory for results
├── main.py                    # Main script
└── requirements.txt           # Dependencies
```

## Example of use

### Analysis of test data
```bash
# Apache log analysis
python main.py -f examples/sample_apache.log

# Nginx log analysis
python main.py -f examples/sample_nginx.log --format nginx
```

### Results of the analysis

After the analysis is completed, the following are created:
- **JSON Report**: A detailed report with analysis results
- **Charts**: Visualization of patterns and anomalies
- **Summary**: Brief information in the console

## Log formats

### Apache Common Log Format
```
192.168.1.100 - - [25/Jan/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

### Nginx Log Format
```
192.168.1.100 - - [25/Jan/2026:15:30:01 +0300] "GET / HTTP/1.1" 200 1234 "https://google.com" "Mozilla/5.0"
```

## Security metrics

The system calculates the following metrics:
- **Risk Score**: Risk score for IP addresses (0-100)
- **Error Rate**: Error rate for each IP
- **Attack Severity**: Severity of detected attacks
- **Traffic Anomalies**: Traffic anomalies

## Requirements

- Python 3.7+
- Pandas >= 1.5.0
- NumPy >= 1.21.0
- Matplotlib >= 3.5.0
- Seaborn >= 0.11.0
- Scipy >= 1.9.0

## Output example

```
[*] Parsing log file: examples/sample_apache.log
[+] Successfully parsed 25 log entries
[+] Time range: 2026-01-25 10:00:01 to 2026-01-25 10:00:26
[+] Unique IPs: 12

[*] Analyzing security threats...
[*] Analyzing traffic patterns...
[+] Report saved to: output/analysis_report_1643123456.json

==================================================
ANALYSIS SUMMARY
==================================================

Security Threats Detected:
  SQL Injection attempts: 2
  XSS attempts: 2
  Path traversal attempts: 2
  Command injection attempts: 2
  Brute force attacks: 1
  Scanning activities: 0
  Admin access attempts: 2

Traffic Anomalies:
  Traffic spikes: 0
  Potential DDoS patterns: 0

Traffic Statistics:
  Total requests: 25
  Unique IPs: 12
  Bot IPs detected: 3
```

## License

MIT License
