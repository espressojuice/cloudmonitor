#!/usr/bin/env python3
"""
CloudMonitor Network Scanner

Core scanning functions for discovering IP cameras and network devices.
"""

import sys
import socket
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Camera manufacturers by MAC OUI (first 3 bytes)
CAMERA_OUI = {
    # Hikvision
    'A0:CF:5B': 'Hikvision', 'C0:56:E3': 'Hikvision', '54:C4:15': 'Hikvision',
    '44:19:B6': 'Hikvision', '18:68:CB': 'Hikvision', 'BC:AD:28': 'Hikvision',
    '28:57:BE': 'Hikvision', 'C4:2F:90': 'Hikvision', '4C:BD:8F': 'Hikvision',
    # Dahua
    '3C:EF:8C': 'Dahua', '90:02:A9': 'Dahua', 'E0:50:8B': 'Dahua',
    '4C:11:BF': 'Dahua', 'A0:BD:1D': 'Dahua', '40:F4:FD': 'Dahua',
    # Axis
    '00:40:8C': 'Axis', 'AC:CC:8E': 'Axis', 'B8:A4:4F': 'Axis',
    # Hanwha/Samsung
    '00:09:18': 'Hanwha', '00:16:6C': 'Samsung', '00:1A:B6': 'Samsung',
    # Vivotek
    '00:02:D1': 'Vivotek', '00:22:F7': 'Vivotek',
    # Bosch
    '00:04:13': 'Bosch', '00:07:5F': 'Bosch',
    # Panasonic
    '00:80:F0': 'Panasonic', '00:B0:C7': 'Panasonic', '04:20:9A': 'Panasonic',
    # Sony
    '00:04:1F': 'Sony', '00:13:A9': 'Sony',
    # Uniview
    '24:24:05': 'Uniview', '24:28:FD': 'Uniview',
    # Reolink
    'EC:71:DB': 'Reolink', '9C:8E:CD': 'Reolink',
    # Amcrest
    '9C:8E:CD': 'Amcrest',
    # Foscam
    '00:62:6E': 'Foscam', 'C0:F6:C2': 'Foscam',
    # TP-Link
    '50:C7:BF': 'TP-Link', '60:32:B1': 'TP-Link',
    # Ubiquiti
    '24:A4:3C': 'Ubiquiti', '80:2A:A8': 'Ubiquiti', 'FC:EC:DA': 'Ubiquiti',
    # Turing
    '7C:D9:A0': 'Turing',
}

# Network infrastructure by MAC OUI
INFRASTRUCTURE_OUI = {
    # Cisco
    '00:00:0C': 'Cisco', '00:1B:D4': 'Cisco', '00:26:CB': 'Cisco',
    # Ubiquiti
    '24:A4:3C': 'Ubiquiti', '80:2A:A8': 'Ubiquiti', 'FC:EC:DA': 'Ubiquiti',
    '74:83:C2': 'Ubiquiti', 'F0:9F:C2': 'Ubiquiti',
    # Netgear
    '00:14:6C': 'Netgear', '00:1F:33': 'Netgear',
    # TP-Link
    '50:C7:BF': 'TP-Link', '60:32:B1': 'TP-Link',
    # Aruba
    '00:0B:86': 'Aruba', '24:DE:C6': 'Aruba',
    # Meraki
    '00:18:0A': 'Meraki', 'AC:17:C8': 'Meraki',
}


def get_local_subnets():
    """Auto-detect local subnets from network interfaces."""
    subnets = []
    try:
        if sys.platform == 'win32':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'IPv4 Address' in line or 'IP Address' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[1].strip().split('(')[0].strip()
                        if ip and not ip.startswith('127.'):
                            subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                            if subnet not in subnets:
                                subnets.append(subnet)
        else:
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            ip = parts[i + 1].split('/')[0]
                            octets = ip.split('.')
                            if len(octets) == 4:
                                subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                                if subnet not in subnets:
                                    subnets.append(subnet)
    except Exception as e:
        logger.error(f"Error detecting subnets: {e}")

    return subnets if subnets else ['192.168.1.0/24']


def get_arp_table():
    """Get ARP table to map IPs to MACs."""
    arp_map = {}
    try:
        if sys.platform == 'win32':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=10)

        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                ip = None
                mac = None
                for part in parts:
                    if part.count('.') == 3 and all(p.isdigit() for p in part.split('.')):
                        ip = part
                    elif part.count(':') == 5 or part.count('-') == 5:
                        mac = part.upper().replace('-', ':')
                if ip and mac and mac != 'FF:FF:FF:FF:FF:FF':
                    arp_map[ip] = mac
    except Exception as e:
        logger.debug(f"Error reading ARP table: {e}")

    return arp_map


def lookup_manufacturer(mac):
    """Look up manufacturer from MAC OUI."""
    if not mac:
        return None, None

    oui = mac.upper()[:8]

    if oui in CAMERA_OUI:
        return CAMERA_OUI[oui], 'camera'
    if oui in INFRASTRUCTURE_OUI:
        return INFRASTRUCTURE_OUI[oui], 'infrastructure'

    return None, None


def check_port(ip, port, timeout=1):
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def ping_host(ip, timeout=1):
    """Ping a host to check if it's alive."""
    try:
        if sys.platform == 'win32':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]

        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except:
        return False


def scan_host(ip, arp_map):
    """Scan a single host for camera/device identification."""
    if not ping_host(ip, timeout=1):
        return None

    mac = arp_map.get(ip)
    manufacturer, device_type = lookup_manufacturer(mac) if mac else (None, None)

    # Check camera-related ports
    ports = {
        'rtsp': check_port(ip, 554, timeout=1),
        'http': check_port(ip, 80, timeout=1),
        'https': check_port(ip, 443, timeout=1),
        'http_alt': check_port(ip, 8080, timeout=1),
    }

    # Determine device type based on ports if not identified by MAC
    if not device_type:
        if ports['rtsp']:
            device_type = 'camera'
        elif any([ports['http'], ports['https'], ports['http_alt']]):
            device_type = 'unknown'

    if not device_type:
        device_type = 'unknown'

    return {
        'ip': ip,
        'mac': mac,
        'manufacturer': manufacturer,
        'device_type': device_type,
        'ports': ports,
        'discovered_at': datetime.now().isoformat()
    }


def expand_cidr(cidr):
    """Expand CIDR notation to list of IPs."""
    if '/' not in cidr:
        return [cidr]

    ip_part, prefix = cidr.split('/')
    prefix = int(prefix)

    if prefix < 24:
        prefix = 24  # Limit to /24 for safety

    ip_parts = [int(x) for x in ip_part.split('.')]
    base_ip = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

    num_hosts = 2 ** (32 - prefix)
    network = base_ip & (0xFFFFFFFF << (32 - prefix))

    ips = []
    for i in range(1, num_hosts - 1):  # Skip network and broadcast
        ip_int = network + i
        ip_str = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
        ips.append(ip_str)

    return ips


def scan_network(subnet, max_workers=50):
    """Scan a single subnet for devices."""
    logger.info(f"Scanning subnet: {subnet}")

    all_ips = expand_cidr(subnet)
    logger.info(f"Scanning {len(all_ips)} IP addresses...")

    # Get current ARP table
    arp_map = get_arp_table()

    devices = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, ip, arp_map): ip for ip in all_ips}

        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)
                logger.info(f"Found: {result['ip']} - {result.get('manufacturer', 'Unknown')} ({result['device_type']})")

    return devices
