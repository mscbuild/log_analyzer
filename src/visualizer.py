import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import os


class LogVisualizer:
    def __init__(self, output_dir: str = 'output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def plot_traffic_timeline(self, df: pd.DataFrame, time_window: str = '5T'):
        plt.figure(figsize=(15, 8))
        
        df_copy = df.copy()
        df_copy = df_copy.set_index('timestamp')
        
        traffic_counts = df_copy.groupby(pd.Grouper(freq=time_window)).size().reset_index()
        traffic_counts.columns = ['timestamp', 'request_count']
        
        plt.plot(traffic_counts['timestamp'], traffic_counts['request_count'], 
                linewidth=2, color='#2E86AB', alpha=0.8)
        
        mean_traffic = traffic_counts['request_count'].mean()
        plt.axhline(y=mean_traffic, color='red', linestyle='--', alpha=0.7, 
                   label=f'Average: {mean_traffic:.1f}')
        
        plt.fill_between(traffic_counts['timestamp'], traffic_counts['request_count'], 
                         alpha=0.3, color='#2E86AB')
        
        plt.title('Traffic Timeline', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Requests per Time Window', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        output_path = os.path.join(self.output_dir, 'traffic_timeline.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def plot_status_code_distribution(self, df: pd.DataFrame):
        plt.figure(figsize=(12, 8))
        
        status_counts = df['status'].value_counts().sort_index()
        
        colors = []
        for status in status_counts.index:
            if 200 <= status < 300:
                colors.append('#2ECC71')  # Green for success
            elif 300 <= status < 400:
                colors.append('#3498DB')  # Blue for redirect
            elif 400 <= status < 500:
                colors.append('#F39C12')  # Orange for client error
            else:
                colors.append('#E74C3C')  # Red for server error
        
        bars = plt.bar(range(len(status_counts)), status_counts.values, color=colors)
        
        plt.title('HTTP Status Code Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Status Code', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.xticks(range(len(status_counts)), status_counts.index)
        plt.grid(True, alpha=0.3, axis='y')
        
        for bar, count in zip(bars, status_counts.values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(status_counts)*0.01,
                    str(count), ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        
        output_path = os.path.join(self.output_dir, 'status_code_distribution.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def plot_hourly_pattern(self, df: pd.DataFrame):
        plt.figure(figsize=(14, 7))
        
        df_copy = df.copy()
        df_copy['hour'] = df_copy['timestamp'].dt.hour
        df_copy['day_name'] = df_copy['timestamp'].dt.day_name()
        
        hourly_avg = df_copy.groupby('hour').size().reset_index()
        hourly_avg.columns = ['hour', 'avg_requests']
        
        plt.plot(hourly_avg['hour'], hourly_avg['avg_requests'], 
                marker='o', linewidth=3, markersize=8, color='#9B59B6')
        plt.fill_between(hourly_avg['hour'], hourly_avg['avg_requests'], 
                         alpha=0.3, color='#9B59B6')
        
        plt.title('Average Traffic by Hour of Day', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Hour of Day', fontsize=12)
        plt.ylabel('Average Requests', fontsize=12)
        plt.grid(True, alpha=0.3)
        plt.xticks(range(0, 24))
        
        peak_hour = hourly_avg.loc[hourly_avg['avg_requests'].idxmax()]
        plt.annotate(f'Peak: {peak_hour["hour"]}:00\n{peak_hour["avg_requests"]:.0f} requests',
                    xy=(peak_hour['hour'], peak_hour['avg_requests']),
                    xytext=(peak_hour['hour']+2, peak_hour['avg_requests']*1.1),
                    arrowprops=dict(arrowstyle='->', color='red'),
                    fontsize=10, fontweight='bold')
        
        plt.tight_layout()
        
        output_path = os.path.join(self.output_dir, 'hourly_pattern.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def plot_top_ips(self, df: pd.DataFrame, top_n: int = 15):
        plt.figure(figsize=(14, 10))
        
        ip_counts = df['ip'].value_counts().head(top_n)
        
        colors = plt.cm.Reds(np.linspace(0.3, 0.9, len(ip_counts)))
        
        bars = plt.barh(range(len(ip_counts)), ip_counts.values, color=colors)
        
        plt.title(f'Top {top_n} IP Addresses by Request Count', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Number of Requests', fontsize=12)
        plt.ylabel('IP Address', fontsize=12)
        plt.yticks(range(len(ip_counts)), ip_counts.index)
        plt.grid(True, alpha=0.3, axis='x')
        
        for i, (bar, count) in enumerate(zip(bars, ip_counts.values)):
            plt.text(bar.get_width() + max(ip_counts)*0.01, bar.get_y() + bar.get_height()/2,
                    str(count), ha='left', va='center', fontweight='bold')
        
        plt.tight_layout()
        
        output_path = os.path.join(self.output_dir, 'top_ips.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def plot_security_attacks(self, security_report: dict):
        attacks = security_report.get('attacks', {})
        
        if not any(attacks.values()):
            return None
        
        plt.figure(figsize=(12, 8))
        
        attack_types = []
        attack_counts = []
        
        for attack_type, count in attacks.items():
            if count > 0:
                attack_types.append(attack_type.replace('_', ' ').title())
                attack_counts.append(count)
        
        colors = plt.cm.Set3(np.linspace(0, 1, len(attack_types)))
        
        wedges, texts, autotexts = plt.pie(attack_counts, labels=attack_types, colors=colors,
                                           autopct='%1.1f%%', startangle=90, textprops={'fontsize': 10})
        
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        plt.title('Security Attacks Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.axis('equal')
        
        output_path = os.path.join(self.output_dir, 'security_attacks.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def plot_traffic_anomalies(self, traffic_report: dict):
        anomalies = traffic_report.get('anomalies', {})
        spikes = anomalies.get('traffic_spikes', [])
        
        if not spikes:
            return None
        
        plt.figure(figsize=(14, 8))
        
        spike_times = [datetime.fromisoformat(spike['timestamp'].replace('Z', '+00:00')) for spike in spikes]
        spike_severities = [spike.get('severity', 1) for spike in spikes]
        
        plt.scatter(range(len(spike_times)), spike_severities, 
                   s=[severity*50 for severity in spike_severities], 
                   alpha=0.7, c=spike_severities, cmap='Reds', 
                   edgecolors='black', linewidth=2)
        
        plt.colorbar(label='Severity')
        plt.title('Traffic Anomalies Over Time', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Anomaly Index', fontsize=12)
        plt.ylabel('Severity', fontsize=12)
        plt.grid(True, alpha=0.3)
        
        for i, (time, severity) in enumerate(zip(spike_times, spike_severities)):
            if severity > 3:
                plt.annotate(f'{time.strftime("%H:%M")}',
                           xy=(i, severity), xytext=(i, severity+0.5),
                           ha='center', fontsize=8)
        
        plt.tight_layout()
        
        output_path = os.path.join(self.output_dir, 'traffic_anomalies.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def create_dashboard(self, df: pd.DataFrame, security_report: dict, traffic_report: dict):
        fig = plt.figure(figsize=(20, 16))
        
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        ax1 = fig.add_subplot(gs[0, :])
        
        df_copy = df.copy()
        df_copy = df_copy.set_index('timestamp')
        traffic_counts = df_copy.groupby(pd.Grouper(freq='10T')).size()
        
        ax1.plot(traffic_counts.index, traffic_counts.values, linewidth=2, color='#2E86AB')
        ax1.set_title('Traffic Overview', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Requests')
        ax1.grid(True, alpha=0.3)
        
        ax2 = fig.add_subplot(gs[1, 0])
        status_counts = df['status'].value_counts().head(10)
        ax2.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%')
        ax2.set_title('Status Codes', fontsize=12, fontweight='bold')
        
        ax3 = fig.add_subplot(gs[1, 1])
        df_copy['hour'] = df_copy.index.hour
        hourly_counts = df_copy.groupby('hour').size()
        ax3.bar(hourly_counts.index, hourly_counts.values, color='#3498DB')
        ax3.set_title('Hourly Distribution', fontsize=12, fontweight='bold')
        ax3.set_xlabel('Hour')
        ax3.set_ylabel('Requests')
        
        ax4 = fig.add_subplot(gs[1, 2])
        top_ips = df['ip'].value_counts().head(5)
        ax4.barh(range(len(top_ips)), top_ips.values, color='#E74C3C')
        ax4.set_yticks(range(len(top_ips)))
        ax4.set_yticklabels(top_ips.index)
        ax4.set_title('Top IPs', fontsize=12, fontweight='bold')
        ax4.set_xlabel('Requests')
        
        ax5 = fig.add_subplot(gs[2, :])
        attacks = security_report.get('attacks', {})
        attack_types = [k.replace('_', ' ').title() for k, v in attacks.items() if v > 0]
        attack_counts = [v for k, v in attacks.items() if v > 0]
        
        if attack_types:
            ax5.bar(attack_types, attack_counts, color='#9B59B6')
            ax5.set_title('Security Attacks Detected', fontsize=12, fontweight='bold')
            ax5.set_xlabel('Attack Type')
            ax5.set_ylabel('Count')
            ax5.tick_params(axis='x', rotation=45)
        else:
            ax5.text(0.5, 0.5, 'No Security Attacks Detected', 
                    ha='center', va='center', transform=ax5.transAxes,
                    fontsize=14, fontweight='bold')
            ax5.set_title('Security Analysis', fontsize=12, fontweight='bold')
        
        plt.suptitle('Log Analysis Dashboard', fontsize=18, fontweight='bold', y=0.98)
        
        output_path = os.path.join(self.output_dir, 'dashboard.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def generate_all_visualizations(self, df: pd.DataFrame, security_report: dict, traffic_report: dict):
        visualizations = {}
        
        print("[*] Generating visualizations...")
        
        try:
            visualizations['traffic_timeline'] = self.plot_traffic_timeline(df)
            print("[+] Traffic timeline plot created")
        except Exception as e:
            print(f"[-] Error creating traffic timeline: {e}")
        
        try:
            visualizations['status_distribution'] = self.plot_status_code_distribution(df)
            print("[+] Status code distribution plot created")
        except Exception as e:
            print(f"[-] Error creating status distribution: {e}")
        
        try:
            visualizations['hourly_pattern'] = self.plot_hourly_pattern(df)
            print("[+] Hourly pattern plot created")
        except Exception as e:
            print(f"[-] Error creating hourly pattern: {e}")
        
        try:
            visualizations['top_ips'] = self.plot_top_ips(df)
            print("[+] Top IPs plot created")
        except Exception as e:
            print(f"[-] Error creating top IPs plot: {e}")
        
        try:
            visualizations['security_attacks'] = self.plot_security_attacks(security_report)
            if visualizations['security_attacks']:
                print("[+] Security attacks plot created")
        except Exception as e:
            print(f"[-] Error creating security attacks plot: {e}")
        
        try:
            visualizations['traffic_anomalies'] = self.plot_traffic_anomalies(traffic_report)
            if visualizations['traffic_anomalies']:
                print("[+] Traffic anomalies plot created")
        except Exception as e:
            print(f"[-] Error creating traffic anomalies plot: {e}")
        
        try:
            visualizations['dashboard'] = self.create_dashboard(df, security_report, traffic_report)
            print("[+] Dashboard created")
        except Exception as e:
            print(f"[-] Error creating dashboard: {e}")
        
        valid_visualizations = {k: v for k, v in visualizations.items() if v is not None}
        
        print(f"[+] Generated {len(valid_visualizations)} visualization files")
        
        return valid_visualizations