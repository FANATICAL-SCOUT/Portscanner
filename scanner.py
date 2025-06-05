import socket
import sys
import threading
import time
from datetime import datetime
import os
import re
import ssl
import requests
from concurrent.futures import ThreadPoolExecutor

# Import MAC spoofing functionality if available
try:
    from mac_spoofer import get_interface_name, spoof_mac, restore_mac
    MAC_SPOOFING_AVAILABLE = True
except ImportError:
    MAC_SPOOFING_AVAILABLE = False

# Try to import vulnerability scanner
try:
    from vuln_scanner import scan_target
    VULN_SCANNER_AVAILABLE = True
except ImportError:
    VULN_SCANNER_AVAILABLE = False

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, timeout=1, threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.banner_info = {}
        
    def scan_port(self, port):
        """Scan a single port and attempt to grab banner if open"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            
            if result == 0:
                self.open_ports.append(port)
                service = self.get_service_name(port)
                banner = self.grab_banner(s, port)
                if banner:
                    self.banner_info[port] = {
                        'service': service,
                        'banner': banner
                    }
                else:
                    self.banner_info[port] = {
                        'service': service,
                        'banner': "No banner retrieved"
                    }
            s.close()
        except (socket.error, socket.timeout):
            pass
    
    def get_service_name(self, port):
        """Get service name based on port number"""
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
    
    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        service = self.get_service_name(port)
        banner = ""
        
        try:
            # HTTP/HTTPS specific handling
            if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                if service == 'https' or port in [443, 8443]:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock)
                    except:
                        pass
                try:
                    sock.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.target.encode())
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            # FTP specific handling
            elif service == 'ftp' or port == 21:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            # SSH specific handling
            elif service == 'ssh' or port == 22:
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            # Default handling for other services
            else:
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                    
            return banner.strip()
        except:
            return ""
    
    def check_vulnerabilities(self, service, banner):
        """Check if banner indicates a vulnerable service version"""
        vulnerabilities = []
        
        if not banner:
            return vulnerabilities
        
        # Common vulnerable versions based on service type
        if service == 'ftp':
            if 'vsftpd 2.3.4' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: vsftpd 2.3.4 (Backdoor)")
            elif 'proftpd 1.3.5' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: ProFTPD 1.3.5 (RCE)")
        
        elif service == 'ssh':
            if 'openssh 7.2p2' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: OpenSSH 7.2p2 (User enumeration)")
            elif 'openssh 5.9' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: OpenSSH 5.9 (Username enumeration)")
        
        elif service in ['http', 'https']:
            if 'apache 2.4.49' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: Apache 2.4.49 (Path Traversal)")
            elif 'struts' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: Apache Struts (RCE)")
            elif 'openssl/1.0.1' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: OpenSSL 1.0.1 (Heartbleed)")
        
        elif service == 'smb' or port in [139, 445]:
            if 'smbv1' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: SMBv1 (EternalBlue)")
        
        elif service == 'mysql':
            if 'mysql 5.5.' in banner.lower() or 'mysql 5.6.' in banner.lower():
                vulnerabilities.append("Potentially vulnerable: MySQL 5.5/5.6 (Multiple CVEs)")
                
        return vulnerabilities
    
    def run_scan(self, run_vuln_scan=False):
        """Execute the port scan with multiple threads"""
        print(f"[*] Starting port scan on {self.target}")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        start_time = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.scan_port, range(self.start_port, self.end_port + 1))
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            
        end_time = time.time()
        duration = end_time - start_time
        
        # Print regular scan results
        self.print_results(duration)
        
        # Run vulnerability scan if requested and available
        if run_vuln_scan and VULN_SCANNER_AVAILABLE and self.open_ports:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            records_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "records")
            output_file = os.path.join(records_dir, f"vuln_scan_{self.target}_{timestamp}.txt")
            
            # Run vulnerability scan
            print("\n[*] Running vulnerability scan...")
            scan_target(self.target, self.open_ports, self.banner_info, output_file)
        elif run_vuln_scan and not VULN_SCANNER_AVAILABLE:
            print("\n[!] Vulnerability scanner module not available")
    
    def print_results(self, duration):
        """Print scan results in a formatted way and save to a file in the records folder"""
        print("\n" + "="*60)
        print(f"SCAN RESULTS FOR {self.target}")
        print("="*60)
        print(f"Scan completed in {duration:.2f} seconds")
        print(f"Open ports: {len(self.open_ports)}/{self.end_port - self.start_port + 1}")
        print("-"*60)
        
        # Display results to console
        if not self.open_ports:
            print("No open ports found.")
        else:
            for port in sorted(self.open_ports):
                info = self.banner_info.get(port, {})
                service = info.get('service', 'unknown')
                banner = info.get('banner', 'No banner')
                vulnerabilities = info.get('vulnerabilities', [])
                
                print(f"PORT {port}/tcp\tOPEN\t{service}")
                if banner and banner != "No banner retrieved":
                    print(f"  Banner: {banner[:100]}{'...' if len(banner) > 100 else ''}")
                if vulnerabilities:
                    print("  POTENTIAL VULNERABILITIES:")
                    for vuln in vulnerabilities:
                        print(f"    - {vuln}")
                print()
        
        print("="*60)
        
        # Create records directory if it doesn't exist
        records_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "records")
        if not os.path.exists(records_dir):
            try:
                os.makedirs(records_dir)
                print(f"[*] Created records directory: {records_dir}")
            except Exception as e:
                print(f"[!] Could not create records directory: {e}")
                return
        
        # Save results to file in records directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{self.target}_{timestamp}.txt"
        filepath = os.path.join(records_dir, filename)
        
        try:
            with open(filepath, "w") as f:
                f.write(f"SCAN RESULTS FOR {self.target}\n")
                f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Ports scanned: {self.start_port}-{self.end_port}\n")
                f.write(f"Scan duration: {duration:.2f} seconds\n")
                f.write(f"Open ports: {len(self.open_ports)}/{self.end_port - self.start_port + 1}\n")
                f.write("-"*60 + "\n\n")
                
                if not self.open_ports:
                    f.write("No open ports found.\n")
                else:
                    for port in sorted(self.open_ports):
                        info = self.banner_info.get(port, {})
                        service = info.get('service', 'unknown')
                        banner = info.get('banner', 'No banner')
                        vulnerabilities = info.get('vulnerabilities', [])
                        
                        f.write(f"PORT {port}/tcp\tOPEN\t{service}\n")
                        if banner and banner != "No banner retrieved":
                            f.write(f"  Banner: {banner[:100]}{'...' if len(banner) > 100 else ''}\n")
                        if vulnerabilities:
                            f.write("  POTENTIAL VULNERABILITIES:\n")
                            for vuln in vulnerabilities:
                                f.write(f"    - {vuln}\n")
                        f.write("\n")
            
            print(f"[*] Results saved to {os.path.abspath(filepath)}")
        except Exception as e:
            print(f"[!] Error saving results to file: {e}")

def validate_ip(ip):
    """Validate if string is a valid IP address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        # Check each octet
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True
    return False

def resolve_hostname(hostname):
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def main():
    """Main function to run the scanner"""
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target> [start_port] [end_port] [options]")
        print("Example: python scanner.py 192.168.1.1 1 1024")
        print("\nOptions:")
        if MAC_SPOOFING_AVAILABLE:
            print("  --spoof-mac [vendor]    Spoof MAC address (vendors: Apple, Cisco, Microsoft, Samsung, Intel, etc.)")
            print("  --spoof-mac 0           Use random MAC address")
        if VULN_SCANNER_AVAILABLE:
            print("  --vuln-scan             Run vulnerability scan on open ports")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Handle IP or hostname
    if not validate_ip(target):
        print(f"[*] Resolving hostname {target}...")
        ip = resolve_hostname(target)
        if not ip:
            print(f"[!] Could not resolve hostname {target}")
            sys.exit(1)
        print(f"[*] Hostname resolved to {ip}")
        target = ip
    
    # Handle port range
    start_port = 1
    end_port = 1028
    
    # Check for non-option arguments (ports)
    arg_index = 2
    while arg_index < len(sys.argv) and not sys.argv[arg_index].startswith('--'):
        if arg_index == 2:  # Start port
            try:
                start_port = int(sys.argv[arg_index])
            except ValueError:
                print("[!] Invalid start port, using default (1)")
        elif arg_index == 3:  # End port
            try:
                end_port = int(sys.argv[arg_index])
            except ValueError:
                print("[!] Invalid end port, using default (1024)")
        arg_index += 1
    
    # Handle MAC spoofing option
    spoofed_mac = False
    original_mac = None
    interface = None
    
    if MAC_SPOOFING_AVAILABLE:
        for i in range(2, len(sys.argv)):
            if sys.argv[i] == '--spoof-mac':
                vendor = None
                # Check if next argument is provided and not another option
                if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('--'):
                    vendor_arg = sys.argv[i + 1]
                    # Check if it's numeric 0 for random MAC
                    if vendor_arg != '0':
                        vendor = vendor_arg
                    # Skip the vendor argument in the next iteration
                    i += 1
                
                # Fix for MAC spoofing
                try:
                    interface = get_interface_name()
                    if interface:
                        try:
                            result = spoof_mac(interface, vendor=vendor)
                            if isinstance(result, tuple) and len(result) == 2:
                                spoofed_mac, original_mac = result
                            else:
                                spoofed_mac, original_mac = False, None
                        except Exception as e:
                            print(f"[!] Error spoofing MAC address: {e}")
                            spoofed_mac, original_mac = False, None
                    else:
                        print("[!] Could not determine network interface for MAC spoofing")
                except Exception as e:
                    print(f"[!] Error: {e}")
    
    # Create scanner and run
    run_vuln_scan = '--vuln-scan' in sys.argv
    scanner = PortScanner(target, start_port, end_port)
    scanner.run_scan(run_vuln_scan)
    
    # Handle MAC address restoration
    if spoofed_mac and original_mac and interface:
        print(f"[*] Restoring original MAC address {original_mac}...")
        restore_mac(interface, original_mac)
        print("[+] MAC address restored")

if __name__ == "__main__":
    main()
