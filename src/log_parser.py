import pandas as pd
import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Union


class LogParser:
    def __init__(self, log_format: str = 'apache'):
        self.log_format = log_format
        self.patterns = {
            'apache': self._get_apache_pattern(),
            'nginx': self._get_nginx_pattern()
        }
        self.columns = self._get_columns()
    
    def _get_apache_pattern(self) -> re.Pattern:
        return re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^"]*)" (?P<status>\d+) '
            r'(?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def _get_nginx_pattern(self) -> re.Pattern:
        return re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^"]*) HTTP/[\d.]+" (?P<status>\d+) '
            r'(?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def _get_columns(self) -> List[str]:
        return ['ip', 'timestamp', 'method', 'url', 'status', 'size', 'referer', 'user_agent']
    
    def parse_line(self, line: str) -> Optional[Dict[str, Union[str, int]]]:
        try:
            pattern = self.patterns[self.log_format]
            match = pattern.match(line.strip())
            if not match:
                return None
            
            data = match.groupdict()
            
            data['timestamp'] = datetime.strptime(
                data['timestamp'], '%d/%b/%Y:%H:%M:%S %z'
            )
            data['status'] = int(data['status'])
            data['size'] = int(data['size']) if data['size'] != '-' else 0
            
            return data
        except Exception:
            return None
    
    def parse_file(self, file_path: str, chunk_size: int = 10000) -> pd.DataFrame:
        rows = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                parsed_line = self.parse_line(line)
                if parsed_line:
                    rows.append(parsed_line)
                
                if len(rows) >= chunk_size:
                    df_chunk = pd.DataFrame(rows)
                    rows = []
                    yield df_chunk
            
            if rows:
                yield pd.DataFrame(rows)
    
    def parse_to_dataframe(self, file_path: str) -> pd.DataFrame:
        chunks = []
        for chunk in self.parse_file(file_path):
            chunks.append(chunk)
        
        if chunks:
            df = pd.concat(chunks, ignore_index=True)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            return df
        else:
            return pd.DataFrame(columns=self.columns)
    
    def validate_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def filter_valid_ips(self, df: pd.DataFrame) -> pd.DataFrame:
        return df[df['ip'].apply(self.validate_ip)].copy()