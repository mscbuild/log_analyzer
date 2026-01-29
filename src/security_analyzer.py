import pandas as pd
import re
import numpy as np
from typing import Dict, List, Tuple, Set
from collections import defaultdict, Counter


class SecurityAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'\.\./.*',  # Path traversal
            r'<script.*?>',  # XSS attempts
            r'union.*select',  # SQL injection
            r'drop.*table',  # SQL injection
            r'cmd\.exe',  # Command injection
            r'/etc/passwd',  # File access attempts
            r'admin/',  # Admin panel access
            r'wp-admin/',  # WordPress admin
            r'phpmyadmin',  # Database admin
            r'\.php\?cmd=',  # PHP command injection
        ]
        
        self.error_status_codes = [400, 401, 403, 404, 500, 501, 502, 503]
        self.critical_status_codes = [401, 403, 500, 501, 502, 503]
    
    def detect_sql_injection(self, df: pd.DataFrame) -> pd.DataFrame:
        sql_patterns = [
            r'(?i)union.*select',
            r'(?i)select.*from',
            r'(?i)insert.*into',
            r'(?i)update.*set',
            r'(?i)delete.*from',
            r'(?i)drop.*table',
            r'(?i)create.*table',
            r'(?i)alter.*table',
            r"(?i)'.*or.*'.*='",
            r'(?i)".*or.*".*="',
            r'(?i)1.*=.*1',
            r'(?i)true.*or.*true',
        ]
        
        suspicious_rows = []
        for pattern in sql_patterns:
            mask = df['url'].str.contains(pattern, regex=True, na=False)
            suspicious_rows.extend(df[mask].to_dict('records'))
        
        return pd.DataFrame(suspicious_rows).drop_duplicates() if suspicious_rows else pd.DataFrame()
    
    def detect_xss_attempts(self, df: pd.DataFrame) -> pd.DataFrame:
        xss_patterns = [
            r'(?i)<script',
            r'(?i)javascript:',
            r'(?i)onload=',
            r'(?i)onerror=',
            r'(?i)onclick=',
            r'(?i)onmouseover=',
            r'(?i)alert\(',
            r'(?i)document\.cookie',
            r'(?i)window\.location',
        ]
        
        suspicious_rows = []
        for pattern in xss_patterns:
            mask = df['url'].str.contains(pattern, regex=True, na=False)
            suspicious_rows.extend(df[mask].to_dict('records'))
        
        return pd.DataFrame(suspicious_rows).drop_duplicates() if suspicious_rows else pd.DataFrame()
    
    def detect_path_traversal(self, df: pd.DataFrame) -> pd.DataFrame:
        path_traversal_patterns = [
            r'\.\./.*',
            r'\.\.\\.*',
            r'%2e%2e%2f',
            r'%2e%2e\\',
            r'\.\.%2f',
            r'\.\.%5c',
        ]
        
        suspicious_rows = []
        for pattern in path_traversal_patterns:
            mask = df['url'].str.contains(pattern, regex=True, na=False)
            suspicious_rows.extend(df[mask].to_dict('records'))
        
        return pd.DataFrame(suspicious_rows).drop_duplicates() if suspicious_rows else pd.DataFrame()
    
    def detect_command_injection(self, df: pd.DataFrame) -> pd.DataFrame:
        command_patterns = [
            r'(?i)cmd\.exe',
            r'(?i)/bin/sh',
            r'(?i)/bin/bash',
            r'(?i)powershell',
            r'(?i);.*cat',
            r'(?i);.*ls',
            r'(?i);.*dir',
            r'(?i)`.*`',
            r'(?i)\$\(.*\)',
            r'(?i)&&.*',
            r'(?i)\|.*',
        ]
        
        suspicious_rows = []
        for pattern in command_patterns:
            mask = df['url'].str.contains(pattern, regex=True, na=False)
            suspicious_rows.extend(df[mask].to_dict('records'))
        
        return pd.DataFrame(suspicious_rows).drop_duplicates() if suspicious_rows else pd.DataFrame()
    
    def detect_brute_force(self, df: pd.DataFrame, time_window: int = 300, threshold: int = 20) -> pd.DataFrame:
        auth_failures = df[df['status'].isin([401, 403])].copy()
        auth_failures = auth_failures.sort_values('timestamp')
        
        attacks = []
        
        for ip, group in auth_failures.groupby('ip'):
            if len(group) < threshold:
                continue
            
            group['time_diff'] = group['timestamp'].diff().dt.total_seconds()
            group['session'] = (group['time_diff'] > time_window).cumsum()
            
            for session_id, session_group in group.groupby('session'):
                if len(session_group) >= threshold:
                    attack_duration = (
                        session_group['timestamp'].max() - session_group['timestamp'].min()
                    ).total_seconds()
                    
                    attacks.append({
                        'ip': ip,
                        'attack_type': 'brute_force',
                        'start_time': session_group['timestamp'].min(),
                        'end_time': session_group['timestamp'].max(),
                        'duration_seconds': attack_duration,
                        'attempts': len(session_group),
                        'unique_urls': session_group['url'].nunique(),
                        'user_agents': list(session_group['user_agent'].unique())
                    })
        
        return pd.DataFrame(attacks) if attacks else pd.DataFrame()
    
    def detect_scan_attempts(self, df: pd.DataFrame, url_threshold: int = 50, error_threshold: float = 0.7) -> pd.DataFrame:
        scans = []
        
        for ip, group in df.groupby('ip'):
            unique_urls = group['url'].nunique()
            total_requests = len(group)
            error_rate = len(group[group['status'].isin(self.error_status_codes)]) / total_requests
            
            if unique_urls >= url_threshold and error_rate >= error_threshold:
                scan_duration = (
                    group['timestamp'].max() - group['timestamp'].min()
                ).total_seconds()
                
                scans.append({
                    'ip': ip,
                    'attack_type': 'scan',
                    'start_time': group['timestamp'].min(),
                    'end_time': group['timestamp'].max(),
                    'duration_seconds': scan_duration,
                    'total_requests': total_requests,
                    'unique_urls': unique_urls,
                    'error_rate': error_rate,
                    'user_agents': list(group['user_agent'].unique())
                })
        
        return pd.DataFrame(scans) if scans else pd.DataFrame()
    
    def detect_admin_access_attempts(self, df: pd.DataFrame) -> pd.DataFrame:
        admin_patterns = [
            r'(?i)/admin',
            r'(?i)/administrator',
            r'(?i)/wp-admin',
            r'(?i)/phpmyadmin',
            r'(?i)/manager',
            r'(?i)/cpanel',
            r'(?i)/webmail',
        ]
        
        admin_attempts = []
        for pattern in admin_patterns:
            mask = df['url'].str.contains(pattern, regex=True, na=False)
            admin_attempts.extend(df[mask].to_dict('records'))
        
        admin_df = pd.DataFrame(admin_attempts).drop_duplicates() if admin_attempts else pd.DataFrame()
        
        if not admin_df.empty:
            failed_admin = admin_df[admin_df['status'].isin([401, 403])]
            return failed_admin
        
        return pd.DataFrame()
    
    def get_suspicious_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        ip_stats = []
        
        for ip, group in df.groupby('ip'):
            total_requests = len(group)
            error_requests = len(group[group['status'].isin(self.error_status_codes)])
            critical_errors = len(group[group['status'].isin(self.critical_status_codes)])
            unique_urls = group['url'].nunique()
            unique_user_agents = group['user_agent'].nunique()
            error_rate = error_requests / total_requests if total_requests > 0 else 0
            
            ip_stats.append({
                'ip': ip,
                'total_requests': total_requests,
                'error_requests': error_requests,
                'critical_errors': critical_errors,
                'error_rate': error_rate,
                'unique_urls': unique_urls,
                'unique_user_agents': unique_user_agents,
                'first_seen': group['timestamp'].min(),
                'last_seen': group['timestamp'].max(),
                'risk_score': self._calculate_risk_score(total_requests, error_rate, unique_urls, unique_user_agents)
            })
        
        return pd.DataFrame(ip_stats).sort_values('risk_score', ascending=False)
    
    def _calculate_risk_score(self, requests: int, error_rate: float, unique_urls: int, unique_agents: int) -> float:
        score = 0.0
        
        if requests > 1000:
            score += 20
        elif requests > 500:
            score += 10
        elif requests > 100:
            score += 5
        
        score += error_rate * 30
        
        if unique_urls > 100:
            score += 20
        elif unique_urls > 50:
            score += 10
        
        if unique_agents == 1 and requests > 50:
            score += 15
        
        return min(100, score)
    
    def generate_security_report(self, df: pd.DataFrame) -> Dict:
        report = {
            'summary': {
                'total_requests': len(df),
                'unique_ips': df['ip'].nunique(),
                'error_rate': len(df[df['status'].isin(self.error_status_codes)]) / len(df),
                'time_range': {
                    'start': df['timestamp'].min(),
                    'end': df['timestamp'].max()
                }
            },
            'attacks': {
                'sql_injection': len(self.detect_sql_injection(df)),
                'xss_attempts': len(self.detect_xss_attempts(df)),
                'path_traversal': len(self.detect_path_traversal(df)),
                'command_injection': len(self.detect_command_injection(df)),
                'brute_force': len(self.detect_brute_force(df)),
                'scanning': len(self.detect_scan_attempts(df)),
                'admin_access': len(self.detect_admin_access_attempts(df))
            },
            'top_suspicious_ips': self.get_suspicious_ips(df).head(10).to_dict('records')
        }
        
        return report