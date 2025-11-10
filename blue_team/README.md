# Blue Team Tools

This directory contains defensive security tools for monitoring, detection, and incident response.

## 🔵 Tools Overview

### 1. Log Analyzer (`log_analyzer.py`)
Analyzes security logs for suspicious activities and patterns.
- Failed login attempts
- Unusual access patterns
- Security event correlation

### 2. IDS (Intrusion Detection System) (`ids.py`)
Monitors network traffic for suspicious patterns.
- Anomaly detection
- Signature-based detection
- Real-time alerting

### 3. Firewall Monitor (`firewall_monitor.py`)
Monitors firewall logs and blocked connections.
- Connection tracking
- Rule effectiveness analysis
- Alert generation

### 4. Threat Detection (`threat_detection.py`)
Pattern-based threat identification system.
- Known attack pattern detection
- Behavioral analysis
- Threat intelligence integration

### 5. Incident Response (`incident_response.py`)
Automated incident response scripts.
- Alert handling
- Evidence collection
- Response automation

## 📊 Monitoring Dashboard

Use the monitoring tools to:
- Track security events in real-time
- Generate security reports
- Identify potential threats
- Respond to incidents

## 📝 Example Usage

```bash
# Analyze authentication logs
python log_analyzer.py --logfile /var/log/auth.log --type auth

# Monitor network traffic
sudo python ids.py --interface eth0 --mode monitor

# Check firewall logs
python firewall_monitor.py --logfile /var/log/firewall.log

# Run threat detection
python threat_detection.py --input network_traffic.pcap
```

## 📈 Reporting

All security events and incidents should be documented in `../docs/blue_team_reports/` with:
- Event timeline
- Impact assessment
- Response actions taken
- Recommendations

