# Advanced Port Scanner (pscan)

A comprehensive network security tool that combines port scanning, service detection, vulnerability assessment, MAC address spoofing, and decoy scanning.

## Features

- Port scanning with customizable threads and timeout
- Banner grabbing and service detection
- Vulnerability scanning with CVE lookup
- MAC address spoofing with vendor selection
- Decoy scanning to evade detection

## Installation

### Method 1: Quick Installation (All Platforms)

```bash
# Install from GitHub
pip install git+https://github.com/yourusername/port-scanner.git
```

### Method 2: Development Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
```

### Method 3: Windows Batch File (No Installation)
For Windows users who prefer not to install:

Download the repository
Run pscan.bat from the project directory

## Usage Examples

```bash
# Basic scan
pscan 192.168.1.1

# Scan specific ports with vulnerability check
pscan 192.168.1.1 -p 22,80,443 -v

# Use decoy scanning with MAC spoofing
pscan 192.168.1.1 -D 5 -m Apple -r

# Full scan with all options
pscan 192.168.1.1 -p 1-1024 -t 1.5 -T 200 -D 5 -m Dell -v -o results.txt
```

## Options

-p, --ports: Port range to scan (e.g., 1-1024, 80,443,8080)
-t, --timeout: Timeout for port connections in seconds (default: 1.0)
-T, --threads: Number of threads to use (default: 100)
-D, --decoy: Use decoy scanning with specified number of decoys
-m, --mac: Spoof MAC address (optional: specify vendor)
-r, --restore-mac: Restore original MAC address after scan
-v, --vuln-scan: Perform vulnerability scanning on open ports
-o, --output: Custom output file for results

## Requirements

Python 3.6+
Scapy (for decoy scanning)
Requests (for vulnerability lookups)
Administrator/root privileges (for MAC spoofing and decoy scanning)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
