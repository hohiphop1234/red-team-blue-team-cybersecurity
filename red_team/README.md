# Red Team Tools

This directory contains offensive security tools for penetration testing and vulnerability assessment.

## 🔴 Tools Overview

### 1. Port Scanner (`port_scanner.py`)
Multi-threaded port scanner for network reconnaissance.
- TCP SYN scanning
- Service detection
- Banner grabbing

### 2. Vulnerability Scanner (`vulnerability_scanner.py`)
Scans for common vulnerabilities and misconfigurations.
- HTTP security headers check
- SSL/TLS configuration analysis
- Common vulnerability checks

### 3. Password Cracker (`password_cracker.py`)
Educational password cracking tool.
- Dictionary attacks
- Brute force (limited)
- Hash cracking demonstrations

### 4. Network Sniffer (`network_sniffer.py`)
Packet capture and analysis tool.
- Real-time packet capture
- Protocol analysis
- Traffic pattern detection

## ⚠️ Usage Guidelines

1. **Only test on systems you own or have permission to test**
2. **Document all findings in reports/**
3. **Follow responsible disclosure practices**
4. **Never use these tools maliciously**

## 📝 Example Usage

```bash
# Port scan
python port_scanner.py --target 192.168.1.1 --ports 22,80,443

# Vulnerability scan
python vulnerability_scanner.py --url http://example.com

# Network sniffing (requires root)
sudo python network_sniffer.py --interface eth0
```

## 📊 Reporting

All findings should be documented in `../docs/red_team_reports/` with:
- Vulnerability descriptions
- Proof of concept
- Risk assessment
- Remediation recommendations

