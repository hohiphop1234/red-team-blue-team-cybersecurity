#!/usr/bin/env python3
"""
Blue Team Tool: Log Analyzer
Analyzes security logs for suspicious activities and patterns.
"""

import re
import argparse
from collections import defaultdict, Counter
from datetime import datetime
from colorama import init, Fore, Style
from pathlib import Path

init(autoreset=True)

class LogAnalyzer:
    def __init__(self, logfile):
        self.logfile = logfile
        self.events = []
        self.suspicious_activities = []
        
    def parse_auth_log(self, line):
        """Parse authentication log entries"""
        # Common patterns for auth logs
        patterns = {
            'failed_login': r'Failed password|authentication failure|Invalid user',
            'successful_login': r'Accepted password|Successful login',
            'invalid_user': r'Invalid user (\w+)',
            'ssh_connection': r'ssh.*from (\d+\.\d+\.\d+\.\d+)',
            'sudo_access': r'sudo.*COMMAND=.*USER=(\w+)',
        }
        
        event = {
            'line': line,
            'timestamp': self.extract_timestamp(line),
            'type': 'unknown'
        }
        
        for event_type, pattern in patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                event['type'] = event_type
                if 'invalid_user' in event_type:
                    match = re.search(patterns['invalid_user'], line)
                    if match:
                        event['user'] = match.group(1)
                if 'ssh_connection' in event_type:
                    match = re.search(patterns['ssh_connection'], line)
                    if match:
                        event['source_ip'] = match.group(1)
                break
        
        return event
    
    def extract_timestamp(self, line):
        """Extract timestamp from log line"""
        # Try common timestamp formats
        patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',  # Jan 1 12:00:00
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # 2024-01-01 12:00:00
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        return None
    
    def analyze_failed_logins(self):
        """Analyze failed login attempts"""
        print(f"{Fore.CYAN}[*] Analyzing failed login attempts...{Style.RESET_ALL}")
        
        failed_logins = [e for e in self.events if e['type'] == 'failed_login']
        ip_attempts = Counter()
        user_attempts = Counter()
        
        for event in failed_logins:
            # Extract IP if present
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', event['line'])
            if ip_match:
                ip_attempts[ip_match.group(1)] += 1
            
            # Extract username if present
            user_match = re.search(r'for (\w+)', event['line'])
            if user_match:
                user_attempts[user_match.group(1)] += 1
        
        if ip_attempts:
            print(f"\n{Fore.YELLOW}Top IPs with failed login attempts:{Style.RESET_ALL}")
            for ip, count in ip_attempts.most_common(10):
                if count > 5:  # Threshold
                    print(f"  {Fore.RED}{ip:15s} - {count} attempts{Style.RESET_ALL}")
                    self.suspicious_activities.append({
                        'type': 'Multiple Failed Logins',
                        'ip': ip,
                        'count': count,
                        'severity': 'HIGH' if count > 20 else 'MEDIUM'
                    })
        
        if user_attempts:
            print(f"\n{Fore.YELLOW}Users with failed login attempts:{Style.RESET_ALL}")
            for user, count in user_attempts.most_common(10):
                if count > 3:
                    print(f"  {Fore.YELLOW}{user:15s} - {count} attempts{Style.RESET_ALL}")
    
    def analyze_invalid_users(self):
        """Analyze invalid user attempts"""
        print(f"\n{Fore.CYAN}[*] Analyzing invalid user attempts...{Style.RESET_ALL}")
        
        invalid_users = [e for e in self.events if e['type'] == 'invalid_user']
        user_counter = Counter()
        
        for event in invalid_users:
            if 'user' in event:
                user_counter[event['user']] += 1
        
        if user_counter:
            print(f"\n{Fore.YELLOW}Invalid user attempts:{Style.RESET_ALL}")
            for user, count in user_counter.most_common(10):
                print(f"  {Fore.RED}{user:15s} - {count} attempts{Style.RESET_ALL}")
                if count > 5:
                    self.suspicious_activities.append({
                        'type': 'Brute Force Attempt',
                        'user': user,
                        'count': count,
                        'severity': 'HIGH'
                    })
    
    def analyze_sudo_access(self):
        """Analyze sudo access patterns"""
        print(f"\n{Fore.CYAN}[*] Analyzing sudo access...{Style.RESET_ALL}")
        
        sudo_events = [e for e in self.events if e['type'] == 'sudo_access']
        user_commands = defaultdict(list)
        
        for event in sudo_events:
            if 'user' in event:
                cmd_match = re.search(r'COMMAND=(.+)', event['line'])
                if cmd_match:
                    user_commands[event['user']].append(cmd_match.group(1))
        
        if user_commands:
            print(f"\n{Fore.YELLOW}Sudo command usage:{Style.RESET_ALL}")
            for user, commands in list(user_commands.items())[:10]:
                unique_commands = len(set(commands))
                print(f"  {Fore.CYAN}{user:15s} - {unique_commands} unique commands{Style.RESET_ALL}")
    
    def load_logs(self):
        """Load and parse log file"""
        print(f"{Fore.CYAN}[*] Loading log file: {self.logfile}{Style.RESET_ALL}")
        
        try:
            with open(self.logfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    event = self.parse_auth_log(line.strip())
                    if event['type'] != 'unknown':
                        self.events.append(event)
            
            print(f"{Fore.GREEN}[+] Loaded {len(self.events)} security events{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Log file not found{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading log file: {e}{Style.RESET_ALL}")
            return False
        
        return True
    
    def generate_report(self):
        """Generate security report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Security Log Analysis Report{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.suspicious_activities:
            print(f"{Fore.GREEN}[+] No suspicious activities detected{Style.RESET_ALL}")
        else:
            high_severity = [a for a in self.suspicious_activities if a['severity'] == 'HIGH']
            medium_severity = [a for a in self.suspicious_activities if a['severity'] == 'MEDIUM']
            
            print(f"{Fore.RED}HIGH Severity: {len(high_severity)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}MEDIUM Severity: {len(medium_severity)}{Style.RESET_ALL}\n")
            
            if high_severity:
                print(f"{Fore.RED}High Severity Alerts:{Style.RESET_ALL}")
                for activity in high_severity:
                    print(f"  - {activity['type']}: {activity.get('ip', activity.get('user', 'Unknown'))} "
                          f"({activity['count']} occurrences)")
    
    def analyze(self):
        """Run complete analysis"""
        if not self.load_logs():
            return
        
        self.analyze_failed_logins()
        self.analyze_invalid_users()
        self.analyze_sudo_access()
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='Blue Team Log Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python log_analyzer.py --logfile /var/log/auth.log
  python log_analyzer.py --logfile /var/log/secure
        '''
    )
    parser.add_argument('--logfile', required=True, help='Path to log file')
    parser.add_argument('--type', default='auth', choices=['auth', 'syslog'], 
                       help='Log type (default: auth)')
    
    args = parser.parse_args()
    
    try:
        analyzer = LogAnalyzer(args.logfile)
        analyzer.analyze()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Analysis interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

