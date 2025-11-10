#!/usr/bin/env python3
"""
Blue Team Tool: Threat Detection
Pattern-based threat identification system.
"""

import argparse
import re
from collections import defaultdict
from colorama import init, Fore, Style

init(autoreset=True)

class ThreatDetection:
    def __init__(self):
        self.threat_patterns = {
            'sql_injection': [
                r"('|(\\')|(;)|(\\;)|(--)|(\\--)|(/\*)|(\\/\*)|(\*/)|(\\\*/)|(\+)|(\\\+)|(\%)|(\\\%))",
                r"(union|select|insert|update|delete|drop|create|alter|exec|execute)",
                r"(\bor\b.*=.*\bor\b)",
                r"(\band\b.*=.*\band\b)"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
                r"onclick\s*=",
                r"<iframe[^>]*>"
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"\.\.%2f",
                r"\.\.%5c",
                r"/etc/passwd",
                r"\\windows\\system32"
            ],
            'command_injection': [
                r"[;&|`]\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
                r"\$\(",
                r"`.*`",
                r"\|.*sh",
                r"\|.*bash"
            ],
            'brute_force': [
                r"failed.*password",
                r"authentication.*failure",
                r"invalid.*user",
                r"login.*failed"
            ]
        }
        
        self.detected_threats = []
    
    def detect_threats(self, text, source=None):
        """Detect threats in text"""
        threats_found = []
        
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    threat = {
                        'type': threat_type.replace('_', ' ').title(),
                        'pattern': pattern,
                        'match': match.group(0),
                        'position': match.start(),
                        'source': source
                    }
                    threats_found.append(threat)
        
        return threats_found
    
    def analyze_file(self, filepath):
        """Analyze a file for threats"""
        print(f"{Fore.CYAN}[*] Analyzing file: {filepath}{Style.RESET_ALL}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    threats = self.detect_threats(line, f"Line {line_num}")
                    if threats:
                        for threat in threats:
                            threat['file'] = filepath
                            threat['line'] = line_num
                            self.detected_threats.append(threat)
                            print(f"{Fore.RED}[THREAT] {threat['type']} detected in {filepath}:{line_num}{Style.RESET_ALL}")
                            print(f"  Pattern: {threat['match']}")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}{Style.RESET_ALL}")
    
    def analyze_text(self, text, source="Input"):
        """Analyze text string for threats"""
        threats = self.detect_threats(text, source)
        self.detected_threats.extend(threats)
        return threats
    
    def generate_report(self):
        """Generate threat detection report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Threat Detection Report{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.detected_threats:
            print(f"{Fore.GREEN}[+] No threats detected{Style.RESET_ALL}")
            return
        
        # Group by threat type
        by_type = defaultdict(list)
        for threat in self.detected_threats:
            by_type[threat['type']].append(threat)
        
        print(f"{Fore.YELLOW}Threats Detected by Type:{Style.RESET_ALL}\n")
        for threat_type, threats in sorted(by_type.items()):
            print(f"{Fore.RED}{threat_type}: {len(threats)} occurrence(s){Style.RESET_ALL}")
            for threat in threats[:5]:  # Show first 5
                location = threat.get('file', threat.get('source', 'Unknown'))
                if 'line' in threat:
                    location += f":{threat['line']}"
                print(f"  - {location}: {threat['match'][:50]}")
            if len(threats) > 5:
                print(f"  ... and {len(threats) - 5} more")
            print()

def main():
    parser = argparse.ArgumentParser(
        description='Blue Team Threat Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python threat_detection.py --file suspicious.log
  python threat_detection.py --text "SELECT * FROM users WHERE id=1 OR 1=1"
        '''
    )
    parser.add_argument('--file', help='File to analyze for threats')
    parser.add_argument('--text', help='Text string to analyze')
    
    args = parser.parse_args()
    
    try:
        detector = ThreatDetection()
        
        if args.file:
            detector.analyze_file(args.file)
        elif args.text:
            threats = detector.analyze_text(args.text)
            if threats:
                print(f"\n{Fore.RED}[!] Threats detected in input text{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No threats detected{Style.RESET_ALL}")
        else:
            parser.print_help()
            return
        
        detector.generate_report()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Analysis interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

