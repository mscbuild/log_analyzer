import pandas as pd
import numpy as np
from scipy import stats
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import matplotlib.pyplot as plt
import seaborn as sns


class TrafficAnalyzer:
    def __init__(self):
        self.anomaly_methods = ['zscore', 'iqr', 'isolation_forest']
    
    def detect_traffic_spikes(self, df: pd.DataFrame, time_window: str = '5T', threshold: float = 2.0) -> pd.DataFrame:
        df_copy = df.copy()
        df_copy = df_copy.set_index('timestamp')
        
        traffic_counts = df_copy.groupby(pd.Grouper(freq=time_window)).size().reset_index()
        traffic_counts.columns = ['timestamp', 'request_count']
        
        traffic_counts['zscore'] = np.abs(stats.zscore(traffic_counts['request_count']))
        
        spikes = traffic_counts[traffic_counts['zscore'] > threshold].copy()
        spikes['anomaly_type'] = 'traffic_spike'
        spikes['severity'] = spikes['zscore']
        
        return spikes
    
    def detect_ddos_patterns(self, df: pd.DataFrame, time_window: str = '1T', request_threshold: int = 1000) -> pd.DataFrame:
        df_copy = df.copy()
        df_copy = df_copy.set_index('timestamp')
        
        high_traffic = df_copy.groupby(pd.Grouper(freq=time_window)).size()
        ddos_periods = high_traffic[high_traffic > request_threshold]
        
        ddos_attacks = []
        for timestamp, request_count in ddos_periods.items():
            window_data = df_copy.loc[timestamp:timestamp + pd.Timedelta(time_window)]
            
            unique_ips = window_data['ip'].nunique()
            total_requests = len(window_data)
            requests_per_ip = total_requests / unique_ips if unique_ips > 0 else 0
            
            ddos_attacks.append({
                'timestamp': timestamp,
                'request_count': request_count,
                'unique_ips': unique_ips,
                'requests_per_ip': requests_per_ip,
                'anomaly_type': 'potential_ddos',
                'severity': min(10, request_count / 100)
            })
        
        return pd.DataFrame(ddos_attacks) if ddos_attacks else pd.DataFrame()
    
    def analyze_traffic_patterns(self, df: pd.DataFrame) -> Dict:
        df_copy = df.copy()
        df_copy['hour'] = df_copy['timestamp'].dt.hour
        df_copy['day_of_week'] = df_copy['timestamp'].dt.dayofweek
        df_copy['day_name'] = df_copy['timestamp'].dt.day_name()
        
        hourly_traffic = df_copy.groupby('hour').size().reset_index()
        hourly_traffic.columns = ['hour', 'request_count']
        
        daily_traffic = df_copy.groupby('day_name').size().reset_index()
        daily_traffic.columns = ['day', 'request_count']
        
        hourly_stats = {
            'peak_hour': hourly_traffic.loc[hourly_traffic['request_count'].idxmax(), 'hour'],
            'lowest_hour': hourly_traffic.loc[hourly_traffic['request_count'].idxmin(), 'hour'],
            'peak_requests': hourly_traffic['request_count'].max(),
            'lowest_requests': hourly_traffic['request_count'].min(),
            'average_requests_per_hour': hourly_traffic['request_count'].mean()
        }
        
        daily_stats = {
            'peak_day': daily_traffic.loc[daily_traffic['request_count'].idxmax(), 'day'],
            'lowest_day': daily_traffic.loc[daily_traffic['request_count'].idxmin(), 'day'],
            'peak_requests': daily_traffic['request_count'].max(),
            'lowest_requests': daily_traffic['request_count'].min(),
            'average_requests_per_day': daily_traffic['request_count'].mean()
        }
        
        return {
            'hourly_pattern': hourly_stats,
            'daily_pattern': daily_stats,
            'hourly_data': hourly_traffic.to_dict('records'),
            'daily_data': daily_traffic.to_dict('records')
        }
    
    def detect_bot_traffic(self, df: pd.DataFrame) -> pd.DataFrame:
        bot_patterns = [
            r'(?i)bot',
            r'(?i)crawler',
            r'(?i)spider',
            r'(?i)scraper',
            r'(?i)wget',
            r'(?i)curl',
            r'(?i)python-requests',
            r'(?i)httpclient',
            r'(?i)java',
            r'(?i)go-http-client'
        ]
        
        bot_ips = []
        
        for pattern in bot_patterns:
            mask = df['user_agent'].str.contains(pattern, regex=True, na=False)
            bot_ips.extend(df[mask]['ip'].unique())
        
        bot_ips = list(set(bot_ips))
        
        bot_traffic = df[df['ip'].isin(bot_ips)].copy()
        
        if not bot_traffic.empty:
            bot_stats = bot_traffic.groupby('ip').agg({
                'timestamp': ['min', 'max', 'count'],
                'url': 'nunique',
                'user_agent': 'first'
            }).round(2)
            
            bot_stats.columns = ['first_seen', 'last_seen', 'request_count', 'unique_urls', 'user_agent']
            bot_stats = bot_stats.reset_index()
            
            bot_stats['duration_hours'] = (
                bot_stats['last_seen'] - bot_stats['first_seen']
            ).dt.total_seconds() / 3600
            
            bot_stats['requests_per_hour'] = bot_stats.apply(
                lambda row: row['request_count'] / row['duration_hours'] if row['duration_hours'] > 0 else row['request_count'],
                axis=1
            )
            
            return bot_stats.sort_values('request_count', ascending=False)
        
        return pd.DataFrame()
    
    def analyze_status_codes(self, df: pd.DataFrame) -> Dict:
        status_distribution = df['status'].value_counts().reset_index()
        status_distribution.columns = ['status_code', 'count']
        
        error_rates = {}
        for ip, group in df.groupby('ip'):
            total_requests = len(group)
            error_requests = len(group[group['status'].isin([400, 401, 403, 404, 500, 502, 503])])
            error_rates[ip] = error_requests / total_requests if total_requests > 0 else 0
        
        high_error_ips = {ip: rate for ip, rate in error_rates.items() if rate > 0.5}
        
        return {
            'status_distribution': status_distribution.to_dict('records'),
            'high_error_ips': high_error_ips,
            'overall_error_rate': sum(error_rates.values()) / len(error_rates) if error_rates else 0
        }
    
    def detect_anomalies_iqr(self, df: pd.DataFrame, time_window: str = '5T') -> pd.DataFrame:
        df_copy = df.copy()
        df_copy = df_copy.set_index('timestamp')
        
        traffic_counts = df_copy.groupby(pd.Grouper(freq=time_window)).size().reset_index()
        traffic_counts.columns = ['timestamp', 'request_count']
        
        Q1 = traffic_counts['request_count'].quantile(0.25)
        Q3 = traffic_counts['request_count'].quantile(0.75)
        IQR = Q3 - Q1
        
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        
        anomalies = traffic_counts[
            (traffic_counts['request_count'] < lower_bound) | 
            (traffic_counts['request_count'] > upper_bound)
        ].copy()
        
        anomalies['anomaly_type'] = 'iqr_anomaly'
        anomalies['lower_bound'] = lower_bound
        anomalies['upper_bound'] = upper_bound
        anomalies['severity'] = np.abs(anomalies['request_count'] - np.mean([lower_bound, upper_bound]))
        
        return anomalies
    
    def get_top_urls(self, df: pd.DataFrame, top_n: int = 20) -> pd.DataFrame:
        url_stats = df.groupby('url').agg({
            'timestamp': 'count',
            'ip': 'nunique',
            'status': lambda x: (x == 200).sum()
        }).reset_index()
        
        url_stats.columns = ['url', 'total_requests', 'unique_ips', 'successful_requests']
        url_stats['success_rate'] = url_stats['successful_requests'] / url_stats['total_requests']
        
        return url_stats.sort_values('total_requests', ascending=False).head(top_n)
    
    def get_top_ips(self, df: pd.DataFrame, top_n: int = 20) -> pd.DataFrame:
        ip_stats = df.groupby('ip').agg({
            'timestamp': ['count', 'min', 'max'],
            'url': 'nunique',
            'status': lambda x: (x == 200).sum(),
            'size': 'sum'
        }).round(2)
        
        ip_stats.columns = ['total_requests', 'first_seen', 'last_seen', 'unique_urls', 'successful_requests', 'total_bytes']
        ip_stats = ip_stats.reset_index()
        
        ip_stats['success_rate'] = ip_stats['successful_requests'] / ip_stats['total_requests']
        ip_stats['duration_hours'] = (ip_stats['last_seen'] - ip_stats['first_seen']).dt.total_seconds() / 3600
        ip_stats['requests_per_hour'] = ip_stats.apply(
            lambda row: row['total_requests'] / row['duration_hours'] if row['duration_hours'] > 0 else row['total_requests'],
            axis=1
        )
        
        return ip_stats.sort_values('total_requests', ascending=False).head(top_n)
    
    def generate_traffic_report(self, df: pd.DataFrame) -> Dict:
        traffic_spikes = self.detect_traffic_spikes(df)
        ddos_patterns = self.detect_ddos_patterns(df)
        bot_traffic = self.detect_bot_traffic(df)
        traffic_patterns = self.analyze_traffic_patterns(df)
        status_analysis = self.analyze_status_codes(df)
        top_urls = self.get_top_urls(df)
        top_ips = self.get_top_ips(df)
        
        return {
            'summary': {
                'total_requests': len(df),
                'unique_ips': df['ip'].nunique(),
                'unique_urls': df['url'].nunique(),
                'time_range': {
                    'start': df['timestamp'].min(),
                    'end': df['timestamp'].max()
                },
                'traffic_spikes_detected': len(traffic_spikes),
                'ddos_patterns_detected': len(ddos_patterns),
                'bot_ips_detected': len(bot_traffic)
            },
            'anomalies': {
                'traffic_spikes': traffic_spikes.to_dict('records') if not traffic_spikes.empty else [],
                'ddos_patterns': ddos_patterns.to_dict('records') if not ddos_patterns.empty else []
            },
            'patterns': traffic_patterns,
            'status_analysis': status_analysis,
            'top_entities': {
                'urls': top_urls.to_dict('records') if not top_urls.empty else [],
                'ips': top_ips.to_dict('records') if not top_ips.empty else [],
                'bots': bot_traffic.to_dict('records') if not bot_traffic.empty else []
            }
        }