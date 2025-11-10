#!/usr/bin/env python3
"""
Shared utilities for Red Team and Blue Team tools
"""

import socket
import ipaddress
from typing import Optional, Tuple

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def parse_port_range(port_string: str) -> list:
    """Parse port range string (e.g., '1-1000' or '22,80,443')"""
    ports = []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def format_bytes(bytes_count: int) -> str:
    """Format bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"

def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """Validate target (IP or hostname)"""
    if is_valid_ip(target):
        return True, target
    
    ip = resolve_hostname(target)
    if ip:
        return True, ip
    
    return False, None

