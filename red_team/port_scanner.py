#!/usr/bin/env python3
"""
Red Team Tool: Port Scanner
Multi-threaded TCP port scanner for network reconnaissance.

WARNING: Only use on systems you own or have explicit permission to test.
Unauthorized port scanning is illegal in many jurisdictions.
"""

import socket
import argparse
import threading
import time
from queue import Queue
from colorama import init, Fore, Style

init(autoreset=True)

class PortScanner:
    def __init__(self, target, ports, timeout=1, threads=100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()
        
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                service = self.get_service(port)
                print(f"{Fore.GREEN}[+] Port {port:5d} OPEN - {service}{Style.RESET_ALL}")
                return True
        except Exception as e:
            pass
        return False
    
    def get_service(self, port):
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')
    
    def worker(self):
        """Worker thread for scanning"""
        while True:
            port = self.queue.get()
            if port is None:
                break
            self.scan_port(port)
            self.queue.task_done()
    
    def scan(self):
        """Start the scan"""
        print(f"{Fore.CYAN}[*] Starting scan of {self.target}...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scanning {len(self.ports)} ports with {self.threads} threads{Style.RESET_ALL}\n")
        
        start_time = time.time()
        
        # Add ports to queue
        for port in self.ports:
            self.queue.put(port)
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        # Wait for completion
        self.queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()
        
        elapsed = time.time() - start_time
        
        # Print summary
        print(f"\n{Fore.CYAN}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Found {len(self.open_ports)} open port(s){Style.RESET_ALL}")
        
        if self.open_ports:
            print(f"\n{Fore.YELLOW}Open Ports:{Style.RESET_ALL}")
            for port in sorted(self.open_ports):
                service = self.get_service(port)
                print(f"  {port:5d}/tcp - {service}")

def parse_ports(port_string):
    """Parse port string (e.g., '80,443,8080' or '1-1000')"""
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(
        description='Red Team Port Scanner - Educational Purpose Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python port_scanner.py --target 192.168.1.1 --ports 1-1000
  python port_scanner.py --target example.com --ports 22,80,443,8080
        '''
    )
    parser.add_argument('--target', required=True, help='Target IP address or hostname')
    parser.add_argument('--ports', required=True, help='Ports to scan (e.g., 1-1000 or 22,80,443)')
    parser.add_argument('--timeout', type=float, default=1, help='Connection timeout (default: 1)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads (default: 100)')
    
    args = parser.parse_args()
    
    try:
        ports = parse_ports(args.ports)
        scanner = PortScanner(args.target, ports, args.timeout, args.threads)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

