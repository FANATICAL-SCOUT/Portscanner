import socket
import ssl
import requests
import json
import re
import os
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self, target, open_ports, banner_info):
        self.target = target
        self.open_ports = open_ports
        self.banner_info = banner_info
        self.results = {}
        
        # Load vulnerability database (either from file or built-in)
        self.vuln_db = self._load_vuln_database()
    
    def _load_vuln_database(self):
        """Load vulnerability database from file or use built-in definitions"""
        # Try to load from local file if available
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_database.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("[!] Error parsing vulnerability database file, using built-in database")
        
        # Built-in vulnerability database with CVE details
        return {
            'ftp': [
                {'name': 'vsftpd Backdoor', 'versions': ['vsftpd 2.3.4'], 'cve': 'CVE-2011-2523', 
                 'description': 'Backdoor that allows unauthorized access'},
                {'name': 'ProFTPD Arbitrary File Copy', 'versions': ['ProFTPD 1.3.5'], 'cve': 'CVE-2015-3306', 
                 'description': 'Remote command execution via mod_copy module'}
            ],
            'ssh': [
                {'name': 'OpenSSH User Enumeration', 'versions': ['OpenSSH 7.2p2', 'OpenSSH 7.1p1'], 'cve': 'CVE-2016-6210', 
                 'description': 'User enumeration via timing attack'},
                {'name': 'OpenSSH Username Enumeration', 'versions': ['OpenSSH 5.9p1', 'OpenSSH 7.7'], 'cve': 'CVE-2018-15473', 
                 'description': 'Username enumeration via crafted packets'}
            ],
            'http': [
                {'name': 'Apache Struts RCE', 'versions': ['Struts 2.3.5', 'Struts 2.3.31'], 'cve': 'CVE-2017-5638', 
                 'description': 'Remote Code Execution via Content-Type header'},
                {'name': 'Apache HTTP Server Root Access', 'versions': ['Apache 2.4.49'], 'cve': 'CVE-2021-41773', 
                 'description': 'Path traversal and file disclosure vulnerability'}
            ],
            'https': [
                {'name': 'Heartbleed', 'versions': ['OpenSSL 1.0.1', 'OpenSSL 1.0.1f'], 'cve': 'CVE-2014-0160', 
                 'description': 'Memory disclosure vulnerability in OpenSSL'},
                {'name': 'POODLE', 'versions': ['SSLv3'], 'cve': 'CVE-2014-3566', 
                 'description': 'Padding Oracle On Downgraded Legacy Encryption vulnerability'}
            ],
            'smb': [
                {'name': 'EternalBlue', 'versions': ['SMBv1'], 'cve': 'CVE-2017-0144', 
                 'description': 'Remote code execution vulnerability in SMBv1'},
                {'name': 'SambaCry', 'versions': ['Samba 3.5.0', 'Samba 4.5.9'], 'cve': 'CVE-2017-7494', 
                 'description': 'Remote code execution vulnerability in Samba'}
            ],
            'mysql': [
                {'name': 'MySQL Auth Bypass', 'versions': ['MySQL 5.5.', 'MySQL 5.6.'], 'cve': 'CVE-2012-2122', 
                 'description': 'Authentication bypass via timing attack'},
                {'name': 'MySQL Remote Code Execution', 'versions': ['MySQL 5.5.', 'MySQL 5.6.', 'MySQL 5.7.'], 'cve': 'CVE-2016-6662', 
                 'description': 'Remote code execution via malicious configuration'}
            ]
        }
    
    def _check_version_match(self, banner, versions):
        """Check if banner contains any of the vulnerable versions"""
        if not banner:
            return False
            
        for version in versions:
            if version.lower() in banner.lower():
                return True
        return False
    
    def _check_specific_vulnerabilities(self, service, port, banner):
        """Run service-specific vulnerability checks"""
        # This method can be expanded with active vulnerability checks
        
        # Example: Check for specific HTTP vulnerabilities
        if service == 'http' or port in [80, 8080]:
            try:
                # Try to detect Apache Struts vulnerability
                headers = {'Content-Type': '%{#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("X-Vulnerability-Check","CVE-2017-5638")}'}
                resp = requests.get(f"http://{self.target}:{port}/", headers=headers, timeout=3)
                if 'X-Vulnerability-Check' in resp.headers:
                    return [{'name': 'Apache Struts RCE', 'cve': 'CVE-2017-5638', 'confirmed': True}]
            except:
                pass
        
        # Example: Check for Heartbleed in HTTPS services
        elif service == 'https' or port in [443, 8443]:
            # Simplified check - in a real scanner, this would be more complex
            if 'OpenSSL 1.0.1' in banner:
                return [{'name': 'Potential Heartbleed Vulnerability', 'cve': 'CVE-2014-0160', 'confirmed': False}]
        
        return []
    
    def scan(self):
        """Scan for vulnerabilities in detected services"""
        print("\n[*] Starting vulnerability scan...")
        
        for port in self.open_ports:
            service_info = self.banner_info.get(port, {})
            service = service_info.get('service', 'unknown')
            banner = service_info.get('banner', '')
            
            print(f"[*] Checking port {port}/{service} for vulnerabilities...")
            
            # Initialize results for this port
            self.results[port] = {
                'service': service,
                'vulnerabilities': []
            }
            
            # Match service to vulnerability database categories
            categories = []
            if service == 'http' or port in [80, 8080]:
                categories.append('http')
            elif service == 'https' or port in [443, 8443]:
                categories.append('https')
            elif service == 'ftp' or port == 21:
                categories.append('ftp')
            elif service == 'ssh' or port == 22:
                categories.append('ssh')
            elif service == 'mysql' or port == 3306:
                categories.append('mysql')
            elif service in ['netbios-ssn', 'microsoft-ds'] or port in [139, 445]:
                categories.append('smb')
            else:
                # Try to infer service from banner
                if 'SSH' in banner:
                    categories.append('ssh')
                elif 'FTP' in banner:
                    categories.append('ftp')
                elif 'HTTP' in banner:
                    categories.append('http')
            
            # Check for vulnerabilities based on version in banner
            for category in categories:
                vulns = self.vuln_db.get(category, [])
                for vuln in vulns:
                    if self._check_version_match(banner, vuln.get('versions', [])):
                        self.results[port]['vulnerabilities'].append({
                            'name': vuln.get('name', 'Unknown'),
                            'cve': vuln.get('cve', 'Unknown'),
                            'description': vuln.get('description', ''),
                            'confirmed': False  # Version-based detection isn't confirmed
                        })
            
            # Run service-specific vulnerability checks
            specific_vulns = self._check_specific_vulnerabilities(service, port, banner)
            self.results[port]['vulnerabilities'].extend(specific_vulns)
        
        if self.has_vulnerabilities():
            print(f"[+] Found {self.count_vulnerabilities()} potential vulnerabilities")
        else:
            print("[*] No vulnerabilities detected")
            
        return self.results
    
    def has_vulnerabilities(self):
        """Check if any vulnerabilities were found"""
        for port, info in self.results.items():
            if info.get('vulnerabilities', []):
                return True
        return False
    
    def count_vulnerabilities(self):
        """Count total vulnerabilities found"""
        count = 0
        for port, info in self.results.items():
            count += len(info.get('vulnerabilities', []))
        return count
    
    def generate_report(self, output_file=None):
        """Generate a vulnerability report"""
        if not self.results:
            return "No vulnerability scan results available"
            
        report = "="*70 + "\n"
        report += f"VULNERABILITY SCAN REPORT FOR {self.target}\n"
        report += "="*70 + "\n"
        report += f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Total vulnerabilities detected: {self.count_vulnerabilities()}\n"
        report += "-"*70 + "\n\n"
        
        for port in sorted(self.results.keys()):
            info = self.results[port]
            service = info.get('service', 'unknown')
            vulnerabilities = info.get('vulnerabilities', [])
            
            if not vulnerabilities:
                continue
                
            report += f"PORT {port}/{service.upper()}\n"
            report += "-"*50 + "\n"
            
            for vuln in vulnerabilities:
                report += f"  {vuln.get('name', 'Unknown vulnerability')}\n"
                report += f"    CVE: {vuln.get('cve', 'Unknown')}\n"
                if vuln.get('description'):
                    report += f"    Description: {vuln.get('description')}\n"
                report += f"    Confidence: {'High' if vuln.get('confirmed', False) else 'Medium'}\n"
                report += "\n"
                
            report += "\n"
        
        # Save report to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                print(f"[*] Vulnerability report saved to {os.path.abspath(output_file)}")
            except Exception as e:
                print(f"[!] Error saving vulnerability report: {e}")
                
        return report

def scan_target(target, open_ports, banner_info, output_file=None):
    """Main function to scan a target for vulnerabilities"""
    scanner = VulnerabilityScanner(target, open_ports, banner_info)
    results = scanner.scan()
    
    # Generate and print report
    report = scanner.generate_report(output_file)
    print("\n" + report)
    
    return results

# Standalone usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <target> <port1,port2,...>")
        print("Example: python vuln_scanner.py 192.168.1.1 22,80,443")
        sys.exit(1)
        
    target = sys.argv[1]
    
    # Parse ports if provided
    open_ports = []
    banner_info = {}
    
    if len(sys.argv) > 2:
        ports = sys.argv[2].split(',')
        for port in ports:
            try:
                port_num = int(port.strip())
                open_ports.append(port_num)
                
                # Initialize with empty banner info
                try:
                    banner_info[port_num] = {
                        'service': socket.getservbyport(port_num) if port_num < 1024 else "unknown",
                        'banner': "No banner (manual scan)"
                    }
                except OSError:
                    # Service name not found
                    banner_info[port_num] = {
                        'service': "unknown",
                        'banner': "No banner (manual scan)"
                    }
            except ValueError:
                print(f"[!] Invalid port number: {port}")
    
    if not open_ports:
        print("[!] No valid ports provided")
        sys.exit(1)
    
    # Create records directory for reports
    records_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "records")
    if not os.path.exists(records_dir):
        try:
            os.makedirs(records_dir)
        except Exception as e:
            print(f"[!] Could not create records directory: {e}")
    
    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(records_dir, f"vuln_scan_{target}_{timestamp}.txt")
    
    # Run the scan
    scan_target(target, open_ports, banner_info, output_file)