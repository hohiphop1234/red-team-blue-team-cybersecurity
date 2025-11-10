#!/usr/bin/env python3
"""
Red Team Tool: Network Sniffer
Packet capture and analysis tool for network reconnaissance.

WARNING: Only use on networks you own or have explicit permission to monitor.
Packet sniffing on networks you don't own is illegal.
Requires root/administrator privileges.
"""

import argparse
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, Raw
from colorama import init, Fore, Style
import sys

init(autoreset=True)

class NetworkSniffer:
    def __init__(self, interface=None, filter=None, count=0):
        self.interface = interface
        self.filter = filter
        self.count = count
        self.packet_count = 0
        
    def process_packet(self, packet):
        """Process and display packet information"""
        self.packet_count += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # TCP packets
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                print(f"{Fore.CYAN}[TCP]{Style.RESET_ALL} {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                      f"[Flags: {flags}]")
                
                if Raw in packet:
                    payload = packet[Raw].load[:50]  # First 50 bytes
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if any(keyword in payload_str.lower() for keyword in ['password', 'login', 'user', 'pass']):
                            print(f"{Fore.RED}  [!] Potential credentials in payload:{Style.RESET_ALL}")
                            print(f"  {payload_str[:100]}")
                    except:
                        pass
            
            # UDP packets
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"{Fore.GREEN}[UDP]{Style.RESET_ALL} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # ICMP packets
            elif ICMP in packet:
                print(f"{Fore.YELLOW}[ICMP]{Style.RESET_ALL} {src_ip} -> {dst_ip} "
                      f"[Type: {packet[ICMP].type}]")
        
        # ARP packets
        elif ARP in packet:
            print(f"{Fore.MAGENTA}[ARP]{Style.RESET_ALL} {packet[ARP].psrc} -> {packet[ARP].pdst}")
    
    def start(self):
        """Start packet capture"""
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Network Sniffer - Starting capture...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.interface:
            print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
        if self.filter:
            print(f"{Fore.CYAN}[*] Filter: {self.filter}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                count=self.count,
                prn=self.process_packet,
                store=False
            )
        except PermissionError:
            print(f"{Fore.RED}[!] Error: Root privileges required for packet capture{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Try: sudo python network_sniffer.py{Style.RESET_ALL}")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[*] Capture stopped{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Total packets captured: {self.packet_count}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='Red Team Network Sniffer - Educational Purpose Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo python network_sniffer.py --interface eth0
  sudo python network_sniffer.py --interface eth0 --filter "tcp port 80"
  sudo python network_sniffer.py --interface eth0 --count 100
        '''
    )
    parser.add_argument('--interface', help='Network interface to capture on')
    parser.add_argument('--filter', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    
    args = parser.parse_args()
    
    try:
        sniffer = NetworkSniffer(args.interface, args.filter, args.count)
        sniffer.start()
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

