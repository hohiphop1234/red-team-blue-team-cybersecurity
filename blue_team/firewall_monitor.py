#!/usr/bin/env python3
"""
Blue Team Tool: Firewall Monitor
Monitors firewall logs and analyzes blocked connections.
"""

import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class FirewallMonitor:
    def __init__(self, logfile):
        self.logfile = logfile
        self.blocked_connections = []
        self.allowed_connections = []
        self.stats = defaultdict(int)
        
    def parse_firewall_log(self, line):
        """Parse firewall log entry"""
        # Common firewall log formats
        # Example: DROP IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP SPT=12345 DPT=22
        
        entry = {
            'line': line,
            'action': None,
            'source_ip': None,
            'dest_ip': None,
            'protocol': None,
            'source_port': None,
            'dest_port': None,
            'timestamp': None
        }
        
        # Extract action
        if 'DROP' in line or 'REJECT' in line or 'BLOCK' in line:
            entry['action'] = 'BLOCKED'
        elif 'ACCEPT' in line or 'ALLOW' in line:
            entry['action'] = 'ALLOWED'
        
        # Extract IP addresses
        src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
        if src_match:
            entry['source_ip'] = src_match.group(1)
        
        dst_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', line)
        if dst_match:
            entry['dest_ip'] = dst_match.group(1)
        
        # Extract protocol
        proto_match = re.search(r'PROTO=(\w+)', line)
        if proto_match:
            entry['protocol'] = proto_match.group(1)
        
        # Extract ports
        spt_match = re.search(r'SPT=(\d+)', line)
        if spt_match:
            entry['source_port'] = int(spt_match.group(1))
        
        dpt_match = re.search(r'DPT=(\d+)', line)
        if dpt_match:
            entry['dest_port'] = int(dpt_match.group(1))
        
        # Extract timestamp
        timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            entry['timestamp'] = timestamp_match.group(1)
        
        return entry
    
    def load_logs(self):
        """Load firewall logs"""
        print(f"{Fore.CYAN}[*] Loading firewall logs: {self.logfile}{Style.RESET_ALL}")
        
        try:
            with open(self.logfile, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self.parse_firewall_log(line.strip())
                    if entry['action']:
                        if entry['action'] == 'BLOCKED':
                            self.blocked_connections.append(entry)
                        else:
                            self.allowed_connections.append(entry)
            
            print(f"{Fore.GREEN}[+] Loaded {len(self.blocked_connections)} blocked connections{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Loaded {len(self.allowed_connections)} allowed connections{Style.RESET_ALL}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Error: Log file not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Note: You may need to configure firewall logging{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading log file: {e}{Style.RESET_ALL}")
            return False
        
        return True
    
    def analyze_blocked_connections(self):
        """Analyze blocked connection patterns"""
        print(f"\n{Fore.CYAN}[*] Analyzing blocked connections...{Style.RESET_ALL}")
        
        if not self.blocked_connections:
            print(f"{Fore.YELLOW}[!] No blocked connections found{Style.RESET_ALL}")
            return
        
        # Top blocked source IPs
        blocked_ips = Counter([e['source_ip'] for e in self.blocked_connections if e['source_ip']])
        if blocked_ips:
            print(f"\n{Fore.YELLOW}Top blocked source IPs:{Style.RESET_ALL}")
            for ip, count in blocked_ips.most_common(10):
                print(f"  {Fore.RED}{ip:15s} - {count} blocks{Style.RESET_ALL}")
        
        # Top blocked destination ports
        blocked_ports = Counter([e['dest_port'] for e in self.blocked_connections if e['dest_port']])
        if blocked_ports:
            print(f"\n{Fore.YELLOW}Top blocked destination ports:{Style.RESET_ALL}")
            for port, count in blocked_ports.most_common(10):
                service = self.get_service_name(port)
                print(f"  {Fore.RED}Port {port:5d} ({service:10s}) - {count} blocks{Style.RESET_ALL}")
        
        # Protocol distribution
        protocols = Counter([e['protocol'] for e in self.blocked_connections if e['protocol']])
        if protocols:
            print(f"\n{Fore.YELLOW}Blocked by protocol:{Style.RESET_ALL}")
            for proto, count in protocols.most_common():
                print(f"  {Fore.CYAN}{proto:6s} - {count} blocks{Style.RESET_ALL}")
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP',
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')
    
    def analyze_firewall_effectiveness(self):
        """Analyze firewall rule effectiveness"""
        print(f"\n{Fore.CYAN}[*] Analyzing firewall effectiveness...{Style.RESET_ALL}")
        
        total = len(self.blocked_connections) + len(self.allowed_connections)
        if total == 0:
            print(f"{Fore.YELLOW}[!] No data to analyze{Style.RESET_ALL}")
            return
        
        block_rate = (len(self.blocked_connections) / total) * 100
        allow_rate = (len(self.allowed_connections) / total) * 100
        
        print(f"\n{Fore.CYAN}Firewall Statistics:{Style.RESET_ALL}")
        print(f"  Total connections: {total}")
        print(f"  {Fore.RED}Blocked: {len(self.blocked_connections)} ({block_rate:.1f}%){Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Allowed: {len(self.allowed_connections)} ({allow_rate:.1f}%){Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate firewall monitoring report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Firewall Monitoring Report{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        self.analyze_blocked_connections()
        self.analyze_firewall_effectiveness()
    
    def analyze(self):
        """Run complete analysis"""
        if not self.load_logs():
            return
        
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='Blue Team Firewall Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python firewall_monitor.py --logfile /var/log/firewall.log
  python firewall_monitor.py --logfile /var/log/iptables.log
        '''
    )
    parser.add_argument('--logfile', required=True, help='Path to firewall log file')
    
    args = parser.parse_args()
    
    try:
        monitor = FirewallMonitor(args.logfile)
        monitor.analyze()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Analysis interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

