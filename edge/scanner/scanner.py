#!/usr/bin/env python3
"""
CloudMonitor Network Scanner

Discovers IP cameras and network devices, generates Gatus config for monitoring.
Runs on startup and periodically (default: hourly).
"""

import os
import sys
import time
import json
import socket
import struct
import logging
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import yaml

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
    # Amcrest (uses Dahua OUIs mostly)
    '9C:8E:CD': 'Amcrest',
    # Foscam
    '00:62:6E': 'Foscam', 'C0:F6:C2': 'Foscam',
    # TP-Link
    '50:C7:BF': 'TP-Link', '60:32:B1': 'TP-Link',
    # Ubiquiti
    '24:A4:3C': 'Ubiquiti', '80:2A:A8': 'Ubiquiti', 'FC:EC:DA': 'Ubiquiti',
    # Turing (uses various OUIs)
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
    # Dell
    '00:14:22': 'Dell', 'D4:BE:D9': 'Dell',
    # HP
    '00:1E:0B': 'HP', '3C:D9:2B': 'HP',
}


def get_local_subnets():
    """Auto-detect local subnets from network interfaces."""
    subnets = []
    try:
        if sys.platform == 'win32':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            # Parse Windows ipconfig - simplified
            lines = result.stdout.split('\n')
            current_ip = None
            for line in lines:
                if 'IPv4 Address' in line or 'IP Address' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_ip = parts[1].strip().split('(')[0].strip()
                        if current_ip and not current_ip.startswith('127.'):
                            # Assume /24 for simplicity
                            subnet = '.'.join(current_ip.split('.')[:3]) + '.0/24'
                            if subnet not in subnets:
                                subnets.append(subnet)
        else:
            # Linux - use ip command
            result = subprocess.run(
                ['ip', '-4', 'addr', 'show'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == 'inet' and i + 1 < len(parts):
                            cidr = parts[i + 1]
                            ip_part = cidr.split('/')[0]
                            # Convert to /24 network
                            octets = ip_part.split('.')
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
                # Look for IP and MAC patterns
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
        'onvif': check_port(ip, 8000, timeout=1),
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


def scan_network(subnets=None, max_workers=50):
    """Scan network for devices."""
    if not subnets:
        subnets = get_local_subnets()

    logger.info(f"Scanning subnets: {subnets}")

    # Refresh ARP table with pings first
    all_ips = []
    for subnet in subnets:
        all_ips.extend(expand_cidr(subnet))

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


def generate_gatus_config(devices, location='edge'):
    """Generate Gatus configuration from discovered devices."""
    cameras = [d for d in devices if d['device_type'] == 'camera']
    infrastructure = [d for d in devices if d['device_type'] == 'infrastructure']

    config = {
        'web': {
            'port': 8080
        },
        'metrics': True,
        'storage': {
            'type': 'memory'
        },
        'endpoints': []
    }

    # Add camera endpoints
    for cam in cameras:
        ip = cam['ip']
        name = cam.get('manufacturer', 'Camera')

        # ICMP ping check
        config['endpoints'].append({
            'name': f"{name} ({ip})",
            'group': f"{location}/cameras",
            'url': f"icmp://{ip}",
            'interval': '30s',
            'conditions': ['[CONNECTED] == true']
        })

        # RTSP port check if available
        if cam.get('ports', {}).get('rtsp'):
            config['endpoints'].append({
                'name': f"{name} RTSP ({ip})",
                'group': f"{location}/cameras",
                'url': f"tcp://{ip}:554",
                'interval': '30s',
                'conditions': ['[CONNECTED] == true']
            })

    # Add infrastructure endpoints
    for infra in infrastructure:
        ip = infra['ip']
        name = infra.get('manufacturer', 'Device')

        config['endpoints'].append({
            'name': f"{name} ({ip})",
            'group': f"{location}/infrastructure",
            'url': f"icmp://{ip}",
            'interval': '60s',
            'conditions': ['[CONNECTED] == true']
        })

    # Add placeholder if no devices found
    if not config['endpoints']:
        config['endpoints'].append({
            'name': 'No devices discovered',
            'group': f"{location}/status",
            'url': 'icmp://127.0.0.1',
            'interval': '60s',
            'conditions': ['[CONNECTED] == true']
        })

    return config


def main():
    parser = argparse.ArgumentParser(description='CloudMonitor Network Scanner')
    parser.add_argument('--output', '-o', default='/config/gatus/config.yaml',
                        help='Output path for Gatus config')
    parser.add_argument('--location', '-l', default=os.environ.get('LOCATION', 'edge'),
                        help='Location name for grouping')
    parser.add_argument('--interval', '-i', type=int,
                        default=int(os.environ.get('SCAN_INTERVAL_HOURS', '1')),
                        help='Scan interval in hours (0 for one-shot)')
    parser.add_argument('--subnets', '-s', nargs='+',
                        help='Subnets to scan (auto-detect if not specified)')
    parser.add_argument('--json', action='store_true',
                        help='Output JSON instead of writing config')
    args = parser.parse_args()

    logger.info(f"CloudMonitor Scanner starting")
    logger.info(f"  Location: {args.location}")
    logger.info(f"  Output: {args.output}")
    logger.info(f"  Interval: {args.interval}h (0=one-shot)")

    while True:
        try:
            # Run scan
            devices = scan_network(args.subnets)

            cameras = [d for d in devices if d['device_type'] == 'camera']
            infra = [d for d in devices if d['device_type'] == 'infrastructure']
            logger.info(f"Scan complete: {len(cameras)} cameras, {len(infra)} infrastructure, {len(devices) - len(cameras) - len(infra)} other")

            if args.json:
                print(json.dumps(devices, indent=2))
                break

            # Generate and write config
            config = generate_gatus_config(devices, args.location)

            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Wrote Gatus config to {args.output}")

            # Signal Gatus to reload (it watches the file, but just in case)
            try:
                subprocess.run(['pkill', '-HUP', 'gatus'], capture_output=True)
            except:
                pass

        except Exception as e:
            logger.error(f"Scan error: {e}")

        if args.interval == 0:
            break

        # Wait for next scan
        next_scan = datetime.now().timestamp() + (args.interval * 3600)
        logger.info(f"Next scan at: {datetime.fromtimestamp(next_scan).strftime('%H:%M:%S')}")
        time.sleep(args.interval * 3600)


if __name__ == '__main__':
    main()
