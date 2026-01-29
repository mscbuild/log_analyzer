#!/usr/bin/env python3

import argparse
import json
import sys
import os
from pathlib import Path

from src.log_parser import LogParser
from src.security_analyzer import SecurityAnalyzer
from src.traffic_analyzer import TrafficAnalyzer


class LogAnalyzer:
    def __init__(self, log_format: str = 'apache'):
        self.parser = LogParser(log_format)
        self.security_analyzer = SecurityAnalyzer()
        self.traffic_analyzer = TrafficAnalyzer()
    
    def analyze_logs(self, log_file: str, output_dir: str = 'output') -> dict:
        print(f"[*] Parsing log file: {log_file}")
        
        try:
            df = self.parser.parse_to_dataframe(log_file)
            
            if df.empty:
                print("[-] No valid log entries found")
                return {}
            
            print(f"[+] Successfully parsed {len(df)} log entries")
            print(f"[+] Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
            print(f"[+] Unique IPs: {df['ip'].nunique()}")
            
            print("\n[*] Analyzing security threats...")
            security_report = self.security_analyzer.generate_security_report(df)
            
            print("\n[*] Analyzing traffic patterns...")
            traffic_report = self.traffic_analyzer.generate_traffic_report(df)
            
            full_report = {
                'metadata': {
                    'log_file': log_file,
                    'analysis_timestamp': str(pd.Timestamp.now()),
                    'total_entries': len(df),
                    'unique_ips': df['ip'].nunique(),
                    'time_range': {
                        'start': str(df['timestamp'].min()),
                        'end': str(df['timestamp'].max())
                    }
                },
                'security_analysis': security_report,
                'traffic_analysis': traffic_report
            }
            
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f'analysis_report_{int(pd.Timestamp.now().timestamp())}.json')
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(full_report, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"[+] Report saved to: {output_file}")
            
            self.print_summary(full_report)
            
            return full_report
            
        except FileNotFoundError:
            print(f"[-] Error: Log file '{log_file}' not found")
            return {}
        except Exception as e:
            print(f"[-] Error during analysis: {str(e)}")
            return {}
    
    def print_summary(self, report: dict):
        print("\n" + "="*50)
        print("ANALYSIS SUMMARY")
        print("="*50)
        
        security = report.get('security_analysis', {}).get('attacks', {})
        print(f"\nSecurity Threats Detected:")
        print(f"  SQL Injection attempts: {security.get('sql_injection', 0)}")
        print(f"  XSS attempts: {security.get('xss_attempts', 0)}")
        print(f"  Path traversal attempts: {security.get('path_traversal', 0)}")
        print(f"  Command injection attempts: {security.get('command_injection', 0)}")
        print(f"  Brute force attacks: {security.get('brute_force', 0)}")
        print(f"  Scanning activities: {security.get('scanning', 0)}")
        print(f"  Admin access attempts: {security.get('admin_access', 0)}")
        
        traffic = report.get('traffic_analysis', {}).get('anomalies', {})
        print(f"\nTraffic Anomalies:")
        print(f"  Traffic spikes: {len(traffic.get('traffic_spikes', []))}")
        print(f"  Potential DDoS patterns: {len(traffic.get('ddos_patterns', []))}")
        
        summary = report.get('traffic_analysis', {}).get('summary', {})
        print(f"\nTraffic Statistics:")
        print(f"  Total requests: {summary.get('total_requests', 0):,}")
        print(f"  Unique IPs: {summary.get('unique_ips', 0):,}")
        print(f"  Bot IPs detected: {summary.get('bot_ips_detected', 0)}")
        
        top_suspicious = report.get('security_analysis', {}).get('top_suspicious_ips', [])
        if top_suspicious:
            print(f"\nTop Suspicious IPs:")
            for i, ip_data in enumerate(top_suspicious[:3], 1):
                print(f"  {i}. {ip_data['ip']} (Risk Score: {ip_data['risk_score']:.1f})")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze server logs for security threats and traffic anomalies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py -f /var/log/apache2/access.log
  python main.py -f access.log --format nginx -o results
  python main.py -f access.log --summary-only
        '''
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Path to the log file to analyze'
    )
    
    parser.add_argument(
        '--format',
        choices=['apache', 'nginx'],
        default='apache',
        help='Log format (default: apache)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='output',
        help='Output directory for reports (default: output)'
    )
    
    parser.add_argument(
        '--summary-only',
        action='store_true',
        help='Only print summary, don\'t save full report'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: Log file '{args.file}' not found")
        sys.exit(1)
    
    analyzer = LogAnalyzer(args.format)
    
    if args.summary_only:
        print("[*] Running analysis in summary-only mode...")
    
    report = analyzer.analyze_logs(args.file, args.output)
    
    if args.summary_only and report:
        analyzer.print_summary(report)


if __name__ == '__main__':
    import pandas as pd
    main()