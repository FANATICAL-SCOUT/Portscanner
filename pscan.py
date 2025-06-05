#!/usr/bin/env python3
"""
Port Scanner Suite - Unified Command Line Interface
Combines port scanning, MAC spoofing, and vulnerability scanning in one tool.
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner with MAC Spoofing and Vulnerability Detection',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Main arguments
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', 
                      help='Port range to scan (e.g., 1-1024, 80,443,8080)')
    
    # Scanner options
    scanner_group = parser.add_argument_group('Scanning Options')
    scanner_group.add_argument('-t', '--timeout', type=float, default=1.0,
                             help='Timeout for port connections in seconds (default: 1.0)')
    scanner_group.add_argument('-T', '--threads', type=int, default=100,
                             help='Number of threads to use (default: 100)')
    scanner_group.add_argument('-D', '--decoy', nargs='?', type=int, const=5, metavar='NUM',
                             help='Use decoy scanning with specified number of decoys (requires root/admin)')
    
    # MAC spoofing options
    mac_group = parser.add_argument_group('MAC Spoofing Options')
    mac_group.add_argument('-m', '--mac', nargs='?', const='random', metavar='VENDOR',
                         help='Spoof MAC address (optional: specify vendor like Apple, Cisco, etc.)')
    mac_group.add_argument('-r', '--restore-mac', action='store_true',
                         help='Restore original MAC address after scan')
    
    # Vulnerability scanning options
    vuln_group = parser.add_argument_group('Vulnerability Scanning Options')
    vuln_group.add_argument('-v', '--vuln-scan', action='store_true',
                          help='Perform vulnerability scanning on open ports')
    vuln_group.add_argument('-o', '--output',
                          help='Custom output file for vulnerability scan results')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle port range/list formatting
    if '-' in args.ports:
        start_port, end_port = map(int, args.ports.split('-'))
        port_args = [str(start_port), str(end_port)]
    else:
        # If comma-separated ports, use default port range and set scan targets later
        port_args = []
    
    # Check for decoy scanning - use a different approach
    if args.decoy is not None:
        # Cross-platform check for admin/root privileges
        is_admin = False
        if os.name == 'nt':  # Windows
            try:
                is_admin = os.getuid() == 0
            except AttributeError:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/Mac
            is_admin = os.getuid() == 0
            
        if not is_admin:
            print("[!] Warning: Decoy scanning requires root/administrator privileges")
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() != 'y':
                print("[!] Exiting...")
                sys.exit(1)
                
        print(f"[*] Using decoy scanning with {args.decoy} decoys")
        decoy_cmd = [sys.executable, "decoy_scanner.py", args.target, args.ports, str(args.decoy), str(args.threads), str(args.timeout)]
        
        try:
            print(f"[*] Executing: {' '.join(decoy_cmd)}")
            subprocess.run(decoy_cmd, check=True)
            
            # If vulnerability scanning is also requested, run it after the scan
            if args.vuln_scan:
                print("\n[*] Running vulnerability scan on results...")
                vuln_cmd = [sys.executable, "vuln_scanner.py", args.target, args.ports]
                if args.output:
                    vuln_cmd.extend(["-o", args.output])
                subprocess.run(vuln_cmd, check=True)
                
            print("\n[+] All operations completed")
            return  # Exit the function early since we've handled everything
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running command: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] Operation interrupted by user")
            sys.exit(1)
    
    # If not using decoy scanning, continue with regular scanning
    # Build the scanner.py command
    cmd = [sys.executable, "scanner.py", args.target]
    
    # Add port range if specified
    if port_args:
        cmd.extend(port_args)
    
    # Add MAC spoofing option if requested
    if args.mac:
        cmd.append("--spoof-mac")
        if args.mac != 'random':
            cmd.append(args.mac)
        else:
            cmd.append("0")  # 0 means random MAC
    
    # Add vulnerability scanning option if requested
    if args.vuln_scan:
        cmd.append("--vuln-scan")
    
    # Execute the command
    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        # Use subprocess to run the scanner with all arguments
        subprocess.run(cmd, check=True)
        
        # If a specific port list was provided, run vulnerability scanner separately
        if not port_args and args.vuln_scan and ',' in args.ports:
            print("\n[*] Running vulnerability scan on specific ports...")
            vuln_cmd = [sys.executable, "vuln_scanner.py", args.target, args.ports]
            if args.output:
                vuln_cmd.extend(["-o", args.output])
            subprocess.run(vuln_cmd, check=True)
            
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running command: {e}")
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
    
    print("\n[+] All operations completed")

if __name__ == "__main__":
    main()