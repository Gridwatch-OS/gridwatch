#!/usr/bin/env python3
"""
================================================================================
GRIDWATCH - Network Security Monitoring Tool (Base Model)
================================================================================
A foundational network security tool that:
1. Pulls live malicious IP lists from threat intelligence sources
2. Scans the local network subnet to discover devices
3. Monitors running processes for connections to known malicious IPs
4. Generates a clean summary report

This base model is designed for contributors to expand upon.
Cross-platform support: Windows and Linux

Dependencies: requests, scapy, psutil
Install with: pip install requests scapy psutil

Authors: Gridwatch Team
License: MIT
================================================================================
"""

# ============================================================================
# IMPORTS
# ============================================================================

import os
import sys
import socket
import platform
import subprocess
import ipaddress
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional

# Third-party imports (required: pip install requests scapy psutil)
try:
    import requests
except ImportError:
    print("[ERROR] 'requests' module not found. Install with: pip install requests")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("[ERROR] 'psutil' module not found. Install with: pip install psutil")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, conf
    # Suppress Scapy warnings for cleaner output
    conf.verb = 0
except ImportError:
    print("[ERROR] 'scapy' module not found. Install with: pip install scapy")
    print("[NOTE] On Windows, you may also need Npcap: https://npcap.com/")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Output file paths - contributors can modify these as needed
BLOCKLIST_FILE = "blocklist.txt"
DEVICES_FILE = "discovered_devices.txt"

# Threat intelligence source URLs
# Using FireHOL level1 list - contains verified malicious IPs
# Contributors can add more sources here (AbuseIPDB, EmergingThreats, etc.)
THREAT_INTEL_URLS = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
]

# Network scanning timeout (seconds)
SCAN_TIMEOUT = 3

# Request timeout for downloading blocklists
REQUEST_TIMEOUT = 30


# ============================================================================
# MODULE 1: THREAT INTELLIGENCE - MALICIOUS IP LIST FETCHER
# ============================================================================
# This module downloads and parses malicious IP lists from threat intel sources.
# Contributors can expand this to support:
# - Additional threat intel feeds (AbuseIPDB API, EmergingThreats, etc.)
# - IP list deduplication across multiple sources
# - Automatic scheduled updates
# - Caching with expiration
# ============================================================================

def fetch_malicious_ips() -> Set[str]:
    """
    Fetches malicious IP addresses from FireHOL threat intelligence feed.
    
    Returns:
        Set[str]: A set of malicious IP addresses (deduplicated)
    
    The FireHOL level1 list contains IPs that are verified to be malicious,
    including known C2 servers, malware distribution points, and attack sources.
    
    Contributors: Add support for additional feeds here (AbuseIPDB, etc.)
    """
    print("\n" + "=" * 60)
    print("[MODULE 1] THREAT INTELLIGENCE - Fetching Malicious IP List")
    print("=" * 60)
    
    malicious_ips: Set[str] = set()
    
    for url in THREAT_INTEL_URLS:
        print(f"\n[*] Fetching from: {url}")
        
        try:
            # Download the threat intel feed
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            # Parse the response - FireHOL format has IPs/CIDRs, one per line
            # Lines starting with # are comments
            lines = response.text.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle CIDR notation (e.g., 192.168.1.0/24)
                # For base model, we extract individual IPs from small subnets
                # and store CIDR notation for larger ones
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        # For small subnets (/24 or smaller), expand to individual IPs
                        # For larger subnets, store the CIDR notation
                        if network.prefixlen >= 24:
                            for ip in network.hosts():
                                malicious_ips.add(str(ip))
                        else:
                            # Store CIDR for larger networks (checked separately)
                            malicious_ips.add(line)
                    except ValueError:
                        continue
                else:
                    # Single IP address
                    try:
                        ipaddress.ip_address(line)
                        malicious_ips.add(line)
                    except ValueError:
                        continue
            
            print(f"[+] Successfully fetched {len(malicious_ips)} malicious IPs/ranges")
            
        except requests.exceptions.Timeout:
            print(f"[!] Timeout while fetching: {url}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching threat intel: {e}")
    
    return malicious_ips


def save_blocklist(malicious_ips: Set[str], filepath: str = BLOCKLIST_FILE) -> int:
    """
    Saves the malicious IP list to a local text file.
    
    Args:
        malicious_ips: Set of malicious IP addresses
        filepath: Output file path
    
    Returns:
        int: Number of IPs saved
    
    Contributors: Add support for different output formats (JSON, CSV, etc.)
    """
    print(f"\n[*] Saving blocklist to: {filepath}")
    
    try:
        with open(filepath, 'w') as f:
            # Write header with timestamp
            f.write(f"# Gridwatch Blocklist\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total entries: {len(malicious_ips)}\n")
            f.write("#" + "=" * 50 + "\n\n")
            
            # Write sorted IPs for easier reading
            for ip in sorted(malicious_ips):
                f.write(f"{ip}\n")
        
        print(f"[+] Saved {len(malicious_ips)} entries to blocklist")
        return len(malicious_ips)
        
    except IOError as e:
        print(f"[!] Error saving blocklist: {e}")
        return 0


def load_blocklist(filepath: str = BLOCKLIST_FILE) -> Set[str]:
    """
    Loads the blocklist from a local file.
    
    Args:
        filepath: Path to the blocklist file
    
    Returns:
        Set[str]: Set of malicious IP addresses
    
    Contributors: Add validation and integrity checking
    """
    malicious_ips: Set[str] = set()
    
    if not os.path.exists(filepath):
        print(f"[!] Blocklist file not found: {filepath}")
        return malicious_ips
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    malicious_ips.add(line)
    except IOError as e:
        print(f"[!] Error loading blocklist: {e}")
    
    return malicious_ips


# ============================================================================
# MODULE 2: NETWORK SCANNER - LOCAL SUBNET DISCOVERY
# ============================================================================
# This module discovers devices on the local network using multiple methods:
# - ARP scanning (preferred, requires root/admin)
# - ICMP ping sweep (fallback method)
#
# Contributors can expand this to support:
# - Port scanning for discovered devices
# - Device fingerprinting and OS detection
# - MAC address vendor lookup
# - Historical device tracking (new device detection)
# ============================================================================

def get_local_subnet() -> Optional[str]:
    """
    Detects the local network subnet.
    
    Returns:
        str: Subnet in CIDR notation (e.g., "192.168.1.0/24") or None
    
    Works on both Windows and Linux by querying network interfaces.
    Contributors: Add support for multiple network interfaces
    """
    print("\n[*] Detecting local network subnet...")
    
    try:
        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
        
        for iface_name, iface_addrs in interfaces.items():
            for addr in iface_addrs:
                # Look for IPv4 addresses
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    
                    # Skip loopback and link-local addresses
                    if ip.startswith('127.') or ip.startswith('169.254.'):
                        continue
                    
                    # Calculate subnet
                    if netmask:
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            subnet = str(network)
                            print(f"[+] Detected subnet: {subnet} (interface: {iface_name})")
                            return subnet
                        except ValueError:
                            continue
        
        print("[!] Could not detect local subnet")
        return None
        
    except Exception as e:
        print(f"[!] Error detecting subnet: {e}")
        return None


def arp_scan(subnet: str) -> List[Dict[str, str]]:
    """
    Performs an ARP scan to discover devices on the network.
    
    Args:
        subnet: Network subnet in CIDR notation
    
    Returns:
        List of dictionaries containing IP and MAC addresses
    
    Note: Requires root/admin privileges on most systems.
    Contributors: Add MAC vendor lookup functionality
    """
    print(f"\n[*] Performing ARP scan on {subnet}...")
    
    discovered_devices = []
    
    try:
        # Create ARP request packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        # Send packet and capture responses
        result = srp(packet, timeout=SCAN_TIMEOUT, verbose=False)[0]
        
        for sent, received in result:
            device = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': resolve_hostname(received.psrc)
            }
            discovered_devices.append(device)
            print(f"    [+] Found: {device['ip']} ({device['hostname']}) - MAC: {device['mac']}")
        
        print(f"[+] ARP scan complete. Found {len(discovered_devices)} devices.")
        
    except PermissionError:
        print("[!] ARP scan requires administrator/root privileges")
        print("[*] Falling back to ping sweep...")
        return ping_sweep(subnet)
    except Exception as e:
        print(f"[!] ARP scan error: {e}")
        print("[*] Falling back to ping sweep...")
        return ping_sweep(subnet)
    
    return discovered_devices


def ping_sweep(subnet: str) -> List[Dict[str, str]]:
    """
    Performs a ping sweep to discover devices (fallback method).
    
    Args:
        subnet: Network subnet in CIDR notation
    
    Returns:
        List of dictionaries containing IP and hostname
    
    This is a fallback when ARP scan is not available.
    Less reliable but works without special privileges.
    """
    print(f"\n[*] Performing ping sweep on {subnet}...")
    
    discovered_devices = []
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        
        # Determine ping command based on OS
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "1000"]
        else:
            ping_cmd = ["ping", "-c", "1", "-W", "1"]
        
        # Ping each host in the subnet (skip network and broadcast addresses)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        print(f"[*] Scanning {total_hosts} potential hosts...")
        
        for i, ip in enumerate(hosts):
            ip_str = str(ip)
            
            # Progress indicator
            if (i + 1) % 50 == 0:
                print(f"    Progress: {i + 1}/{total_hosts} hosts scanned...")
            
            try:
                # Run ping command
                result = subprocess.run(
                    ping_cmd + [ip_str],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                
                if result.returncode == 0:
                    hostname = resolve_hostname(ip_str)
                    device = {
                        'ip': ip_str,
                        'mac': 'N/A (ping sweep)',
                        'hostname': hostname
                    }
                    discovered_devices.append(device)
                    print(f"    [+] Found: {ip_str} ({hostname})")
                    
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue
        
        print(f"[+] Ping sweep complete. Found {len(discovered_devices)} devices.")
        
    except Exception as e:
        print(f"[!] Ping sweep error: {e}")
    
    return discovered_devices


def resolve_hostname(ip: str) -> str:
    """
    Resolves an IP address to its hostname.
    
    Args:
        ip: IP address string
    
    Returns:
        Hostname string or 'Unknown' if resolution fails
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"


def scan_network() -> List[Dict[str, str]]:
    """
    Main network scanning function.
    Detects subnet and scans for devices.
    
    Returns:
        List of discovered devices
    
    Contributors: Add support for scanning specific subnets or IP ranges
    """
    print("\n" + "=" * 60)
    print("[MODULE 2] NETWORK SCANNER - Local Subnet Discovery")
    print("=" * 60)
    
    # Detect local subnet
    subnet = get_local_subnet()
    
    if not subnet:
        print("[!] Cannot scan network: subnet detection failed")
        return []
    
    # Perform ARP scan (falls back to ping sweep if needed)
    devices = arp_scan(subnet)
    
    return devices


def save_devices(devices: List[Dict[str, str]], filepath: str = DEVICES_FILE) -> int:
    """
    Saves discovered devices to a text file.
    
    Args:
        devices: List of device dictionaries
        filepath: Output file path
    
    Returns:
        int: Number of devices saved
    
    Contributors: Add CSV/JSON export options, historical tracking
    """
    print(f"\n[*] Saving device list to: {filepath}")
    
    try:
        with open(filepath, 'w') as f:
            # Write header with timestamp
            f.write(f"# Gridwatch Device Discovery Report\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total devices: {len(devices)}\n")
            f.write("#" + "=" * 50 + "\n\n")
            
            # Write column headers
            f.write(f"{'IP Address':<20} {'Hostname':<30} {'MAC Address'}\n")
            f.write("-" * 70 + "\n")
            
            # Write device entries
            for device in sorted(devices, key=lambda x: ipaddress.ip_address(x['ip'])):
                f.write(f"{device['ip']:<20} {device['hostname']:<30} {device['mac']}\n")
        
        print(f"[+] Saved {len(devices)} devices to file")
        return len(devices)
        
    except IOError as e:
        print(f"[!] Error saving device list: {e}")
        return 0


# ============================================================================
# MODULE 3: PROCESS MONITOR - CONNECTION ANALYZER
# ============================================================================
# This module monitors running processes and their network connections,
# checking against the blocklist for suspicious activity.
#
# Contributors can expand this to support:
# - Real-time continuous monitoring
# - Process whitelisting
# - Automatic process termination
# - Detailed connection logging
# - RAT/spyware behavior detection
# ============================================================================

def check_ip_in_blocklist(ip: str, blocklist: Set[str]) -> bool:
    """
    Checks if an IP address matches any entry in the blocklist.
    
    Args:
        ip: IP address to check
        blocklist: Set of malicious IPs/CIDRs
    
    Returns:
        bool: True if IP is in blocklist
    
    Handles both individual IPs and CIDR ranges.
    """
    # Direct match
    if ip in blocklist:
        return True
    
    # Check against CIDR ranges in blocklist
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in blocklist:
            if '/' in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue
    except ValueError:
        pass
    
    return False


def analyze_process_connections(blocklist: Set[str]) -> List[Dict]:
    """
    Analyzes all running processes for suspicious outbound connections.
    
    Args:
        blocklist: Set of malicious IP addresses
    
    Returns:
        List of suspicious process dictionaries
    
    Each suspicious process entry contains:
    - pid: Process ID
    - name: Process name
    - remote_ip: Destination IP address
    - remote_port: Destination port
    - status: Connection status
    
    Contributors: Add process reputation checking, connection persistence detection
    """
    print("\n" + "=" * 60)
    print("[MODULE 3] PROCESS MONITOR - Analyzing Connections")
    print("=" * 60)
    
    suspicious_processes = []
    analyzed_connections = 0
    
    print("\n[*] Scanning active network connections...")
    
    try:
        # Get all network connections
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            # Only check established outbound connections
            if conn.status == 'ESTABLISHED' and conn.raddr:
                analyzed_connections += 1
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Check if remote IP is in blocklist
                if check_ip_in_blocklist(remote_ip, blocklist):
                    # Get process information
                    try:
                        process = psutil.Process(conn.pid)
                        proc_info = {
                            'pid': conn.pid,
                            'name': process.name(),
                            'exe': process.exe() if hasattr(process, 'exe') else 'N/A',
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'status': conn.status
                        }
                        suspicious_processes.append(proc_info)
                        
                        print(f"\n    [!] SUSPICIOUS CONNECTION DETECTED!")
                        print(f"        Process: {proc_info['name']} (PID: {proc_info['pid']})")
                        print(f"        Destination: {remote_ip}:{remote_port}")
                        print(f"        Status: {conn.status}")
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        suspicious_processes.append({
                            'pid': conn.pid,
                            'name': 'Unknown (Access Denied)',
                            'exe': 'N/A',
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'status': conn.status
                        })
        
        print(f"\n[*] Analyzed {analyzed_connections} active connections")
        
        if suspicious_processes:
            print(f"[!] Found {len(suspicious_processes)} suspicious connection(s)!")
        else:
            print("[+] No suspicious connections detected")
            
    except psutil.AccessDenied:
        print("[!] Access denied. Try running with administrator/root privileges.")
    except Exception as e:
        print(f"[!] Error analyzing connections: {e}")
    
    return suspicious_processes


# ============================================================================
# MODULE 4: REPORTING - SUMMARY GENERATION
# ============================================================================
# This module generates and displays the final summary report.
#
# Contributors can expand this to support:
# - PDF report generation
# - Email alerts
# - Dashboard integration
# - Historical trend analysis
# ============================================================================

def print_summary(
    blocklist_count: int,
    devices_count: int,
    suspicious_processes: List[Dict]
) -> None:
    """
    Prints a clean summary report to the terminal.
    
    Args:
        blocklist_count: Number of IPs in blocklist
        devices_count: Number of discovered devices
        suspicious_processes: List of suspicious process detections
    
    Contributors: Add more detailed statistics, trend analysis
    """
    print("\n")
    print("=" * 60)
    print("           GRIDWATCH SCAN SUMMARY REPORT")
    print("=" * 60)
    print(f"  Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    print(f"  Blocked IPs in database:      {blocklist_count:,}")
    print(f"  Network devices discovered:   {devices_count}")
    print(f"  Suspicious processes found:   {len(suspicious_processes)}")
    print("-" * 60)
    
    # Status indicator
    if suspicious_processes:
        print("\n  [!!!] ALERT: Suspicious activity detected!")
        print("\n  Flagged Processes:")
        for proc in suspicious_processes:
            print(f"    - {proc['name']} (PID {proc['pid']}) → {proc['remote_ip']}:{proc['remote_port']}")
        print("\n  Recommended Action: Investigate flagged processes immediately.")
    else:
        print("\n  [✓] Status: All Clear")
        print("      No suspicious connections detected.")
    
    print("\n" + "=" * 60)
    print("  Output Files:")
    print(f"    - Blocklist:  {BLOCKLIST_FILE}")
    print(f"    - Devices:    {DEVICES_FILE}")
    print("=" * 60)
    print("\n")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main execution function - orchestrates all modules.
    
    Execution flow:
    1. Fetch and save malicious IP blocklist
    2. Scan local network for devices
    3. Check processes against blocklist
    4. Generate summary report
    """
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "         GRIDWATCH - Network Security Monitor".center(58) + "║")
    print("║" + "               Base Model v1.0.0".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")
    print(f"\n  System: {platform.system()} {platform.release()}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Track execution results
    blocklist_count = 0
    devices_count = 0
    suspicious_processes = []
    
    # ========================================
    # STEP 1: Fetch malicious IP blocklist
    # ========================================
    malicious_ips = fetch_malicious_ips()
    if malicious_ips:
        blocklist_count = save_blocklist(malicious_ips)
    else:
        # Try to load existing blocklist
        print("[*] Attempting to load existing blocklist...")
        malicious_ips = load_blocklist()
        blocklist_count = len(malicious_ips)
    
    # ========================================
    # STEP 2: Scan local network
    # ========================================
    devices = scan_network()
    if devices:
        devices_count = save_devices(devices)
    
    # ========================================
    # STEP 3: Check processes against blocklist
    # ========================================
    if malicious_ips:
        suspicious_processes = analyze_process_connections(malicious_ips)
    else:
        print("\n[!] Skipping process analysis: No blocklist available")
    
    # ========================================
    # STEP 4: Generate summary report
    # ========================================
    print_summary(blocklist_count, devices_count, suspicious_processes)
    
    # Return exit code based on findings
    return 1 if suspicious_processes else 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
