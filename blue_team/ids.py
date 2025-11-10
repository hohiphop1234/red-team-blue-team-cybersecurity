#!/usr/bin/env python3
"""
Blue Team Tool: Intrusion Detection System (IDS)
Monitors network traffic for suspicious patterns.

WARNING: Requires root/administrator privileges for packet capture.
"""

import argparse
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
from colorama import init, Fore, Style
import sys

init(autoreset=True)

class IDS:
    def __init__(self, interface=None, threshold=10):
        self.interface = interface
        self.threshold = threshold
        self.connection_counts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.alerts = []
        
    def detect_port_scan(self, packet):
        """Detect potential port scanning activity"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # Track unique ports scanned by source IP
            self.port_scans[src_ip].add((dst_ip, dst_port))
            
            # Alert if scanning multiple ports
            if len(self.port_scans[src_ip]) > self.threshold:
                if not any(a['ip'] == src_ip and a['type'] == 'Port Scan' for a in self.alerts):
                    self.alerts.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'Port Scan',
                        'source_ip': src_ip,
                        'target_ip': dst_ip,
                        'ports_scanned': len(self.port_scans[src_ip]),
                        'severity': 'HIGH'
                    })
                    print(f"{Fore.RED}[ALERT] Port scan detected from {src_ip} "
                          f"({len(self.port_scans[src_ip])} ports scanned){Style.RESET_ALL}")
    
    def detect_syn_flood(self, packet):
        """Detect potential SYN flood attack"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            flags = packet[TCP].flags
            
            # Count SYN packets without ACK (SYN flood indicator)
            if flags == 2:  # SYN flag only
                self.connection_counts[src_ip] += 1
                
                if self.connection_counts[src_ip] > self.threshold * 5:
                    if not any(a['ip'] == src_ip and a['type'] == 'SYN Flood' for a in self.alerts):
                        self.alerts.append({
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'type': 'SYN Flood',
                            'source_ip': src_ip,
                            'syn_count': self.connection_counts[src_ip],
                            'severity': 'HIGH'
                        })
                        print(f"{Fore.RED}[ALERT] Potential SYN flood from {src_ip} "
                              f"({self.connection_counts[src_ip]} SYN packets){Style.RESET_ALL}")
    
    def detect_suspicious_ports(self, packet):
        """Detect connections to suspicious ports"""
        if IP in packet and TCP in packet:
            dst_port = packet[TCP].dport
            src_ip = packet[IP].src
            
            # Common suspicious ports
            suspicious_ports = {
                4444: 'Backdoor/Shell',
                31337: 'Elite/Backdoor',
                12345: 'NetBus',
                54321: 'Back Orifice',
                6667: 'IRC (often used by bots)'
            }
            
            if dst_port in suspicious_ports:
                print(f"{Fore.YELLOW}[WARNING] Connection to suspicious port {dst_port} "
                      f"({suspicious_ports[dst_port]}) from {src_ip}{Style.RESET_ALL}")
                self.alerts.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'Suspicious Port',
                    'source_ip': src_ip,
                    'port': dst_port,
                    'description': suspicious_ports[dst_port],
                    'severity': 'MEDIUM'
                })
    
    def process_packet(self, packet):
        """Process each captured packet"""
        self.detect_port_scan(packet)
        self.detect_syn_flood(packet)
        self.detect_suspicious_ports(packet)
    
    def start(self):
        """Start IDS monitoring"""
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Intrusion Detection System - Starting...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.interface:
            print(f"{Fore.CYAN}[*] Monitoring interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Alert threshold: {self.threshold}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}[!] Error: Root privileges required{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Try: sudo python ids.py{Style.RESET_ALL}")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[*] IDS stopped{Style.RESET_ALL}")
            self.generate_summary()
    
    def generate_summary(self):
        """Generate summary of detected threats"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}IDS Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if not self.alerts:
            print(f"{Fore.GREEN}[+] No threats detected{Style.RESET_ALL}")
        else:
            high_alerts = [a for a in self.alerts if a['severity'] == 'HIGH']
            medium_alerts = [a for a in self.alerts if a['severity'] == 'MEDIUM']
            
            print(f"\n{Fore.RED}HIGH Severity: {len(high_alerts)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}MEDIUM Severity: {len(medium_alerts)}{Style.RESET_ALL}\n")
            
            print(f"{Fore.YELLOW}Alert Details:{Style.RESET_ALL}")
            for alert in self.alerts:
                color = Fore.RED if alert['severity'] == 'HIGH' else Fore.YELLOW
                print(f"{color}[{alert['severity']}] {alert['type']} - {alert['source_ip']} "
                      f"at {alert['timestamp']}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='Blue Team IDS - Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo python ids.py --interface eth0
  sudo python ids.py --interface eth0 --threshold 20
        '''
    )
    parser.add_argument('--interface', help='Network interface to monitor')
    parser.add_argument('--threshold', type=int, default=10, 
                       help='Alert threshold (default: 10)')
    
    args = parser.parse_args()
    
    try:
        ids = IDS(args.interface, args.threshold)
        ids.start()
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

