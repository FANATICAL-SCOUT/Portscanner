import random
import subprocess
import platform
import os
import time
import sys

# MAC address prefixes for common vendors
MAC_PREFIXES = {
    'Apple': ['00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:0D:93', '00:1E:52', '00:50:E4', '00:17:F2', '28:5A:EB', '34:C0:59'],
    'Cisco': ['00:00:0C', '00:01:42', '00:01:43', '00:01:63', '00:01:64', '00:0A:8A', '00:0E:38', '00:0F:23', '00:13:7F', '00:17:0E'],
    'Microsoft': ['00:03:FF', '00:0D:3A', '00:12:5A', '00:15:5D', '00:17:FA', '00:1D:D8', '00:50:F2', '00:BD:3A', '28:18:78', '3C:83:75'],
    'Samsung': ['00:00:F0', '00:07:AB', '00:12:47', '00:12:FB', '00:15:99', '00:17:C9', '00:1A:8A', '00:21:19', '00:23:39', '00:25:66'],
    'Intel': ['00:02:B3', '00:03:47', '00:04:23', '00:07:E9', '00:0C:F1', '00:0E:0C', '00:13:E8', '00:13:02', '00:15:00', '00:16:76'],
    'AMD': ['00:0C:87', '00:1A:80', '00:20:A6', '00:CF:D4', '40:16:7E', '74:D0:2B', '98:8A:EA', 'E0:69:95', '34:40:B5', '30:85:A9'],
    'Dell': ['00:06:5B', '00:08:74', '00:11:43', '00:12:3F', '00:13:72', '00:14:22', '00:18:8B', '00:1A:A0', '00:21:70', '00:25:64'],
    'HP': ['00:01:E6', '00:01:E7', '00:02:A5', '00:04:EA', '00:08:02', '00:0B:CD', '00:0D:9D', '00:10:83', '00:11:0A', '00:14:C2'],
    'Lenovo': ['00:12:FE', '00:21:CC', '00:24:B6', '60:D9:A0', '70:72:0D', '88:70:8C', 'A0:32:99', 'B4:D4:E2', 'C8:D3:FF', 'EC:47:3C'],
    'Asus': ['00:0C:6E', '00:0E:A6', '00:11:2F', '00:15:F2', '00:17:31', '00:1B:FC', '00:1E:8C', '00:22:15', '00:23:54', '00:26:18'],
    'Nvidia': ['00:04:4B', '00:12:1D', '00:21:A0', '00:AB:CD', '00:E0:B8', '37:86:93', '44:4E:6E', '52:DA:00', '60:EB:69', '98:F7:81'],
    'Huawei': ['00:18:82', '00:1E:10', '00:25:9E', '00:34:FE', '00:5A:13', '00:9A:CD', '00:E0:FC', '00:F8:1C', '08:19:A6', '0C:37:DC'],
    'Sony': ['00:01:4A', '00:13:A9', '00:15:C1', '00:19:63', '00:1A:80', '00:1D:0D', '00:1F:A7', '00:24:BE', '30:39:26', '54:42:49'],
    'LG': ['00:05:C9', '00:0C:29', '00:1C:62', '00:1E:75', '00:1F:6B', '00:1F:E3', '00:21:FB', '00:24:83', '00:26:E2', '00:2A:A8'],
    'Toshiba': ['00:00:39', '00:00:B0', '00:08:CA', '00:0E:7B', '00:0F:3D', '00:0F:4D', '00:12:D4', '00:15:B7', '00:1C:7E', '00:23:54'],
    'IBM': ['00:04:AC', '00:09:6B', '00:0D:60', '00:10:D9', '00:14:5E', '00:17:EF', '00:18:B1', '00:20:35', '00:21:5E', '08:00:5A'],
    'Nokia': ['00:02:EE', '00:0B:6C', '00:0F:BB', '00:10:B3', '00:14:A7', '00:19:2D', '00:19:4F', '00:1A:89', '00:1A:DC', '00:1B:AF'],
    'Amazon': ['00:BB:3A', '34:D2:70', '40:B4:CD', '44:65:0D', '68:37:E9', '74:75:48', '84:D6:D0', 'A0:02:DC', 'B0:FC:0D', 'F0:D2:F1'],
    'Google': ['00:1A:11', '08:9E:08', '20:DF:B9', '3C:5A:B4', '48:D6:D5', '54:60:09', '70:3A:CB', '94:95:A0', 'A4:77:33', 'F4:F5:D8']
}

def get_interface_name():
    """Get the main network interface name based on platform"""
    system = platform.system().lower()
    
    if system == 'windows':
        try:
            # Get active interface through ipconfig
            output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
            for line in output.split('\n'):
                if "Ethernet adapter" in line or "Wireless LAN adapter" in line:
                    adapter = line.split("adapter")[1].strip().rstrip(':')
                    return adapter
            return None
        except:
            return None
    elif system == 'linux':
        for iface in ['eth0', 'wlan0', 'enp0s3', 'ens33']:
            try:
                if b'UP' in subprocess.check_output(['ip', 'link', 'show', iface]):
                    return iface
            except:
                continue
        return None
    elif system == 'darwin':  # macOS
        for iface in ['en0', 'en1']:
            try:
                if subprocess.call(['ifconfig', iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                    return iface
            except:
                continue
        return None
    return None

def generate_random_mac(vendor=None):
    """Generate a random MAC address, optionally using a specific vendor prefix"""
    if vendor and vendor in MAC_PREFIXES:
        # Use vendor prefix
        prefix = random.choice(MAC_PREFIXES[vendor])
        suffix = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(3)])
        return prefix + ':' + suffix
    else:
        # Completely random MAC
        mac = [random.randint(0, 255) for _ in range(6)]
        # Set locally administered bit
        mac[0] = (mac[0] & 0xfc) | 0x02
        return ':'.join([f'{b:02x}' for b in mac])

def spoof_mac(interface, new_mac=None, vendor=None):
    """Spoof the MAC address of a network interface"""
    if not interface:
        print("[!] No network interface found to spoof MAC address")
        return False, None
    
    # Generate a MAC address if none is provided
    if not new_mac:
        new_mac = generate_random_mac(vendor)
    
    original_mac = None
    system = platform.system().lower()
    
    try:
        # Get original MAC first
        if system == 'windows':
            output = subprocess.check_output(f"getmac /v /fo list | findstr {interface}", shell=True).decode('utf-8')
            for line in output.split('\n'):
                if "Physical Address" in line:
                    original_mac = line.split(':')[1].strip()
                    break
        elif system == 'linux':
            output = subprocess.check_output(['ip', 'link', 'show', interface]).decode('utf-8')
            for line in output.split('\n'):
                if 'link/ether' in line:
                    original_mac = line.split()[1].strip()
        elif system == 'darwin':  # macOS
            output = subprocess.check_output(['ifconfig', interface]).decode('utf-8')
            for line in output.split('\n'):
                if 'ether' in line:
                    original_mac = line.split()[1].strip()
        
        # Perform MAC spoofing
        if system == 'windows':
            # For Windows, use the device manager method via PowerShell
            # Create a PowerShell script to change the MAC
            ps_script = f"""
            $adapterName = "{interface}"
            $newMac = "{new_mac.replace(':', '-')}"
            
            # Get network adapter
            $adapter = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {{ $_.NetConnectionID -eq $adapterName }}
            if ($adapter) {{
                $adapterId = $adapter.DeviceID
                
                # Get network adapter configuration
                $config = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {{ $_.Index -eq $adapterId }}
                
                # Disable adapter
                $adapter.Disable() | Out-Null
                Start-Sleep -Seconds 1
                
                # Set registry value for MAC address
                $registryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\$('{{0:D4}}' -f $adapterId)"
                Set-ItemProperty -Path $registryPath -Name "NetworkAddress" -Value $newMac.Replace('-', '') -Type String
                
                # Re-enable adapter
                $adapter.Enable() | Out-Null
                Write-Output "MAC address changed to $newMac"
            }} else {{
                Write-Error "Network adapter '$adapterName' not found"
                exit 1
            }}
            """
            
            # Save the script to a temporary file
            script_path = os.path.join(os.environ.get('TEMP', '.'), 'change_mac.ps1')
            with open(script_path, 'w') as f:
                f.write(ps_script)
            
            # Run the PowerShell script with administrative privileges
            try:
                # Execute with PowerShell
                subprocess.check_output(
                    ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path],
                    shell=True
                )
                time.sleep(2)  # Wait for changes to apply
            finally:
                # Clean up the temporary script
                try:
                    os.remove(script_path)
                except:
                    pass
                
        elif system == 'linux':
            subprocess.call(['ip', 'link', 'set', 'dev', interface, 'down'])
            subprocess.call(['ip', 'link', 'set', 'dev', interface, 'address', new_mac])
            subprocess.call(['ip', 'link', 'set', 'dev', interface, 'up'])
        elif system == 'darwin':  # macOS
            subprocess.call(['sudo', 'ifconfig', interface, 'ether', new_mac])
        
        print(f"[*] MAC address spoofed: {original_mac} -> {new_mac}")
        return True, original_mac
    except subprocess.CalledProcessError as e:
        print(f"[!] Error spoofing MAC address: {e}")
        print("[!] This operation requires administrative/root privileges")
        return False, None
    except Exception as e:
        print(f"[!] Unexpected error during MAC spoofing: {e}")
        return False, None

def restore_mac(interface, original_mac):
    """Restore the original MAC address"""
    if not interface or not original_mac:
        return False
    
    # Simply call spoof_mac with the original MAC
    success, _ = spoof_mac(interface, new_mac=original_mac)
    if success:
        print(f"[*] MAC address restored to original: {original_mac}")
    return success

# Test function if this script is run directly
if __name__ == "__main__":
    print("MAC Address Spoofing Tool")
    print("-" * 30)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python mac_spoofer.py spoof [vendor]  - Spoof MAC with optional vendor")
        print("  python mac_spoofer.py restore         - Restore original MAC")
        print("\nVendors: Apple, Cisco, Microsoft, Samsung, Intel")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    interface = get_interface_name()
    
    if not interface:
        print("[!] No suitable network interface found")
        sys.exit(1)
    
    print(f"[*] Using network interface: {interface}")
    
    if command == "spoof":
        vendor = sys.argv[2] if len(sys.argv) > 2 else None
        success, original = spoof_mac(interface, vendor=vendor)
        if success:
            # Save original MAC for restoration
            try:
                with open(".mac_original", "w") as f:
                    f.write(f"{interface},{original}")
            except:
                print("[!] Warning: Could not save original MAC address")
    
    elif command == "restore":
        # Read saved original MAC
        try:
            if os.path.exists(".mac_original"):
                with open(".mac_original", "r") as f:
                    data = f.read().strip().split(",")
                    if len(data) == 2:
                        interface, original_mac = data
                        restore_mac(interface, original_mac)
                    else:
                        print("[!] Invalid saved MAC data")
            else:
                print("[!] No saved original MAC address found")
        except Exception as e:
            print(f"[!] Error restoring MAC: {e}")