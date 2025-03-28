#!/usr/bin/env python3

import re
from datetime import datetime
from typing import Dict, List, Tuple
from pathlib import Path
import json

class DashboardDataParser:
    def __init__(self, log_file_path: str):
        self.log_file_path = Path(log_file_path)
        self.stats = {
            'total_attempts': 0,
            'failed_attempts': 0,
            'blocked_ips': 0,
            'unique_attackers': set()
        }
        self.recent_logs = []
        
    def parse_logs(self) -> None:
        """Parse the log file and update statistics."""
        if not self.log_file_path.exists():
            return
            
        with open(self.log_file_path, 'r') as f:
            for line in f:
                self._process_log_line(line)
                
        # Convert unique_attackers set to count
        self.stats['unique_attackers'] = len(self.stats['unique_attackers'])
        
    def _process_log_line(self, line: str) -> None:
        """Process a single log line and update statistics."""
        try:
            # Parse timestamp
            timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if not timestamp_match:
                return
                
            timestamp = timestamp_match.group(1)
            
            # Parse IP address
            ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if not ip_match:
                return
                
            ip = ip_match.group(1)
            
            # Parse username
            username_match = re.search(r'Username: ([^,]+)', line)
            username = username_match.group(1) if username_match else 'Unknown'
            
            # Parse success status
            success_match = re.search(r'Success: (true|false)', line)
            success = success_match.group(1).lower() == 'true' if success_match else False
            
            # Parse blocked status
            blocked_match = re.search(r'blocked for', line)
            is_blocked = bool(blocked_match)
            
            # Update statistics
            self.stats['total_attempts'] += 1
            if not success:
                self.stats['failed_attempts'] += 1
            if is_blocked:
                self.stats['blocked_ips'] += 1
            self.stats['unique_attackers'].add(ip)
            
            # Add to recent logs
            log_entry = {
                'timestamp': timestamp,
                'ip': ip,
                'username': username,
                'status': 'Blocked' if is_blocked else ('Success' if success else 'Failure'),
                'details': line.strip()
            }
            self.recent_logs.append(log_entry)
            
        except Exception as e:
            print(f"Error processing log line: {e}")
            
    def get_stats(self) -> Dict:
        """Get the current statistics."""
        return self.stats
        
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Get the most recent logs."""
        # Sort logs by timestamp in descending order
        sorted_logs = sorted(self.recent_logs, 
                           key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S'),
                           reverse=True)
        return sorted_logs[:limit]
        
    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get the top attackers by number of attempts."""
        attacker_counts = {}
        for log in self.recent_logs:
            ip = log['ip']
            attacker_counts[ip] = attacker_counts.get(ip, 0) + 1
            
        # Sort by count in descending order
        sorted_attackers = sorted(attacker_counts.items(), 
                                key=lambda x: x[1], 
                                reverse=True)
        return sorted_attackers[:limit]
        
    def get_attack_patterns(self) -> Dict:
        """Analyze attack patterns in the logs."""
        patterns = {
            'common_usernames': {},
            'common_passwords': {},
            'time_distribution': {},
            'attack_duration': {}
        }
        
        for log in self.recent_logs:
            # Count common usernames
            username = log['username']
            patterns['common_usernames'][username] = patterns['common_usernames'].get(username, 0) + 1
            
            # Parse password from details if available
            password_match = re.search(r'Password: ([^,]+)', log['details'])
            if password_match:
                password = password_match.group(1)
                patterns['common_passwords'][password] = patterns['common_passwords'].get(password, 0) + 1
                
            # Analyze time distribution
            hour = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S').hour
            patterns['time_distribution'][hour] = patterns['time_distribution'].get(hour, 0) + 1
            
        return patterns
        
    def export_stats(self, output_file: str) -> None:
        """Export statistics to a JSON file."""
        export_data = {
            'stats': self.stats,
            'recent_logs': self.recent_logs,
            'top_attackers': self.get_top_attackers(),
            'attack_patterns': self.get_attack_patterns()
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
            
def create_dashboard_data(log_file_path: str) -> DashboardDataParser:
    """Create and initialize a dashboard data parser."""
    parser = DashboardDataParser(log_file_path)
    parser.parse_logs()
    return parser

def parse_logs(log_file):
    """Parse log files and return statistics"""
    stats = {
        'total_attempts': 0,
        'failed_attempts': 0,
        'blocked_ips': 0,
        'unique_attackers': set()
    }
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                stats['total_attempts'] += 1
                if 'Failed login' in line:
                    stats['failed_attempts'] += 1
                if 'Blocked IP' in line:
                    stats['blocked_ips'] += 1
                # Extract IP address and add to unique attackers
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    stats['unique_attackers'].add(ip_match.group())
    except FileNotFoundError:
        pass
    
    # Convert set to length for JSON serialization
    stats['unique_attackers'] = len(stats['unique_attackers'])
    return stats

def get_recent_logs(log_file, limit=10):
    """Get most recent log entries"""
    logs = []
    try:
        with open(log_file, 'r') as f:
            logs = f.readlines()[-limit:]
    except FileNotFoundError:
        pass
    return logs

def analyze_attack_patterns(log_file):
    """Analyze attack patterns from logs"""
    patterns = {
        'common_usernames': {},
        'common_passwords': {},
        'attack_times': {},
        'ip_frequency': {}
    }
    return patterns