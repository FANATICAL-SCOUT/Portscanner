#!/usr/bin/env python3
"""
Decoy Scanner Module - Performs port scanning with multiple source IP addresses
"""

import sys
import random
import time
import socket
import struct
import os
from datetime import datetime  # Add this if not already present
import threading
from queue import Queue

# Try to import Scapy and set availability flag
try:
    from scapy.all import IP, TCP, sr1, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class DecoyScanner:
    def __init__(self, target, ports, num_decoys=5, timeout=2, threads=100):
        """Initialize decoy scanner
        
        Args:
            target: Target IP address
            ports: List or range of ports to scan
            num_decoys: Number of decoy IPs to use
            timeout: Timeout for responses
            threads: Number of threads to use
        """
        self.target = target
        self.ports = self._parse_ports(ports)
        self.num_decoys = num_decoys
        self.timeout = timeout
        self.threads = min(threads, len(self.ports))
        self.decoys = []
        self.open_ports = []
        self.port_queue = Queue()
        self.print_lock = threading.Lock()
        
        # Disable Scapy verbose output
        if SCAPY_AVAILABLE:
            conf.verb = 0
    
    def _parse_ports(self, ports):
        """Parse port string into list of ports"""
        result = []
        if isinstance(ports, list):
            return ports
        
        # Handle comma-separated list
        if ',' in ports:
            for p in ports.split(','):
                try:
                    result.append(int(p.strip()))
                except ValueError:
                    pass
        # Handle range
        elif '-' in ports:
            try:
                start, end = map(int, ports.split('-'))
                result = list(range(start, end + 1))
            except ValueError:
                pass
        # Handle single port
        else:
            try:
                result = [int(ports)]
            except ValueError:
                pass
                
        return result
    
    def _generate_decoys(self):
        """Generate decoy IP addresses"""
        decoys = []
        
        # Get real IP by making a test connection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            real_ip = s.getsockname()[0]
            s.close()
            decoys.append(real_ip)  # Add real IP to list
        except:
            print("[!] Could not determine real IP, using localhost")
            real_ip = "127.0.0.1"
            decoys.append(real_ip)
        
        # Generate random decoy IPs
        for i in range(self.num_decoys):
            # Generate a random IP that's not private
            while True:
                # Generate all octets
                ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
                # Skip private IP ranges
                if not (ip.startswith("10.") or ip.startswith("192.168.") or 
                       (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)):
                    break
            decoys.append(ip)
        
        # Shuffle the decoys with real IP somewhere in the list
        random.shuffle(decoys)
        
        # Print decoy information
        real_ip_index = decoys.index(real_ip)
        decoy_display = []
        for i, ip in enumerate(decoys):
            if ip == real_ip:
                decoy_display.append(f"ME({ip})")
            else:
                decoy_display.append(ip)
                
        print(f"[*] Using decoys: {', '.join(decoy_display)}")
        return decoys
    
    def _worker(self):
        """Worker thread function for scanning ports"""
        while not self.port_queue.empty():
            try:
                port = self.port_queue.get(block=False)
            except:
                break
                
            # Print port being scanned (with lock to prevent output mixing)
            with self.print_lock:
                # Only show detailed progress for smaller scans
                if len(self.ports) < 100:
                    print(f"[*] Scanning port {port} with decoys... ", end="", flush=True)
            
            if SCAPY_AVAILABLE:
                # Send SYN packets from decoy IPs
                for decoy_ip in self.decoys:
                    try:
                        pkt = IP(src=decoy_ip, dst=self.target)/TCP(dport=port, flags="S")
                        send(pkt, verbose=0)
                    except:
                        pass
            
            # Check if port is open
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    self.open_ports.append(port)
                    with self.print_lock:
                        if len(self.ports) < 100:
                            print("Open!")
                        else:
                            print(f"[+] Port {port} is open")
                    s.close()
                elif len(self.ports) < 100:
                    with self.print_lock:
                        print("Closed")
            except:
                if len(self.ports) < 100:
                    with self.print_lock:
                        print("Error")
            
            # Mark task as done
            self.port_queue.task_done()
        
    def scan(self):
        """Perform multithreaded decoy scan"""
        print(f"[*] Starting multithreaded decoy scan against {self.target}")
        print(f"[*] Scanning {len(self.ports)} ports with {self.num_decoys} decoys using {self.threads} threads")
        
        if not SCAPY_AVAILABLE:
            print("[!] Scapy library not available. Using basic scan mode.")
            print("[!] Install Scapy for full decoy functionality: pip install scapy")
        
        # Generate decoy IPs
        self.decoys = self._generate_decoys()
        
        # Add all ports to the queue
        for port in self.ports:
            self.port_queue.put(port)
        
        # Start timing
        start_time = time.time()
        
        # Create worker threads
        thread_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Total ports for progress calculation
        total_ports = len(self.ports)
        
        # Monitor progress for large scans
        try:
            while not self.port_queue.empty():
                # Calculate progress
                remaining = self.port_queue.qsize()
                completed = total_ports - remaining
                progress = (completed / total_ports) * 100
                
                # Only show progress for large scans
                if total_ports > 100:
                    print(f"[*] Progress: {progress:.1f}% ({completed}/{total_ports}) - Open ports found: {len(self.open_ports)}")
                
                # Wait before updating again
                time.sleep(2)
                
                # Check if threads are still alive
                alive_threads = sum(1 for t in thread_list if t.is_alive())
                if alive_threads == 0 and not self.port_queue.empty():
                    print("[!] All worker threads stopped but scan not complete.")
                    break
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user. Showing partial results.")
        
        # Calculate scan duration
        duration = time.time() - start_time
        
        # Print results
        print(f"\n[+] Scan completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.open_ports)} open ports on {self.target}")
        
        if self.open_ports:
            print("\nPORT     STATE   SERVICE")
            print("------------------------")
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port) if port < 1024 else "unknown"
                except:
                    service = "unknown"
                print(f"{port:<8} open    {service}")
        
        # Save results to file
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            records_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "records")
            if not os.path.exists(records_dir):
                os.makedirs(records_dir)
                
            output_file = os.path.join(records_dir, f"decoy_scan_{self.target}_{timestamp}.txt")
            with open(output_file, 'w') as f:
                f.write(f"# Decoy Scan Results for {self.target}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Ports scanned: {len(self.ports)}\n")
                f.write(f"# Decoys used: {self.num_decoys}\n")
                f.write(f"# Scan duration: {duration:.2f} seconds\n\n")
                
                if self.open_ports:
                    f.write("PORT     STATE   SERVICE\n")
                    f.write("------------------------\n")
                    for port in sorted(self.open_ports):
                        try:
                            service = socket.getservbyport(port) if port < 1024 else "unknown"
                        except:
                            service = "unknown"
                        f.write(f"{port:<8} open    {service}\n")
                
            print(f"[*] Results saved to {output_file}")
        except Exception as e:
            print(f"[!] Could not save results to file: {e}")
        
        return self.open_ports

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target> <ports> [num_decoys] [threads] [timeout]")
        print(f"Example: {sys.argv[0]} 192.168.1.1 80,443,8080 5 100 0.5")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2]
    num_decoys = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 1.0
    
    # Alert if SCAPY is not available
    if not SCAPY_AVAILABLE:
        print("[!] Warning: Scapy library not installed. Decoy functionality will be limited.")
        print("[!] Run 'pip install scapy' for full decoy scanning capabilities.")
    
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
        print("[!] Warning: Not running with administrator/root privileges")
        print("[!] Decoy functionality may be limited")
    
    scanner = DecoyScanner(target, ports, num_decoys, timeout, threads)
    scanner.scan()

if __name__ == "__main__":
    main()