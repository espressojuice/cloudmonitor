#!/bin/bash
#
# CloudMonitor Edge Installer
# Installs: Scanner + Gatus + vmagent
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/install.sh | sudo bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/cloudmonitor"
REPO_URL="https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge"

# Cloud monitoring server (VictoriaMetrics)
MONITORING_SERVER="178.156.175.240"
VM_AUTH_USER="admin"
VM_AUTH_PASS="WQt4C5PYRg44JCNzv104IWe6"

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       CLOUDMONITOR EDGE INSTALLER${NC}"
echo -e "${BLUE}      Network Camera Monitoring Stack${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run with sudo${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Error: Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}Detected:${NC} $OS"
echo ""

# Step 1: Install Docker
echo -e "${CYAN}[1/4]${NC} Installing Docker..."
if command -v docker &> /dev/null; then
    echo "  Docker already installed"
else
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    echo "  Docker installed"
fi

# Step 2: Create directories
echo -e "${CYAN}[2/4]${NC} Creating directories..."
mkdir -p $INSTALL_DIR/scanner
mkdir -p $INSTALL_DIR/config/vmagent
mkdir -p $INSTALL_DIR/config/gatus
chmod -R 755 $INSTALL_DIR

# Step 3: Create configuration files
echo -e "${CYAN}[3/4]${NC} Creating configuration..."

# Generate location from hostname
DEVICE_LOCATION=$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-')

# Create .env
cat > $INSTALL_DIR/.env << ENVEOF
VERSION=latest
LOCATION=$DEVICE_LOCATION

# Monitoring cloud server
REMOTE_WRITE_URL=http://$MONITORING_SERVER:8428/api/v1/write
VM_AUTH_USER=$VM_AUTH_USER
VM_AUTH_PASS=$VM_AUTH_PASS

# Scanner settings
SCAN_INTERVAL_HOURS=1
ENVEOF

# Create vmagent config
cat > $INSTALL_DIR/config/vmagent/vmagent.yml << 'VMAGENTEOF'
global:
  scrape_interval: 30s
  scrape_timeout: 10s

scrape_configs:
  - job_name: 'gatus'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
VMAGENTEOF

# Create initial gatus config (scanner will overwrite)
cat > $INSTALL_DIR/config/gatus/config.yaml << 'GATUSEOF'
web:
  port: 8080

metrics: true

storage:
  type: memory

endpoints:
  - name: "Scanning network..."
    group: "status"
    url: "icmp://127.0.0.1"
    interval: 60s
    conditions:
      - "[CONNECTED] == true"
GATUSEOF

# Create scanner script
cat > $INSTALL_DIR/scanner/scanner.py << 'SCANNEREOF'
#!/usr/bin/env python3
"""CloudMonitor Network Scanner - Discovers cameras and generates Gatus config."""

import os
import sys
import time
import json
import socket
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CAMERA_OUI = {
    'A0:CF:5B': 'Hikvision', 'C0:56:E3': 'Hikvision', '54:C4:15': 'Hikvision',
    '44:19:B6': 'Hikvision', '18:68:CB': 'Hikvision', 'BC:AD:28': 'Hikvision',
    '3C:EF:8C': 'Dahua', '90:02:A9': 'Dahua', 'E0:50:8B': 'Dahua',
    '00:40:8C': 'Axis', 'AC:CC:8E': 'Axis', 'B8:A4:4F': 'Axis',
    '00:09:18': 'Hanwha', '00:02:D1': 'Vivotek', '00:04:13': 'Bosch',
    '00:80:F0': 'Panasonic', '24:24:05': 'Uniview', 'EC:71:DB': 'Reolink',
    '00:62:6E': 'Foscam', '24:A4:3C': 'Ubiquiti', '7C:D9:A0': 'Turing',
}

INFRASTRUCTURE_OUI = {
    '00:00:0C': 'Cisco', '00:1B:D4': 'Cisco', '24:A4:3C': 'Ubiquiti',
    '80:2A:A8': 'Ubiquiti', '00:14:6C': 'Netgear', '50:C7:BF': 'TP-Link',
    '00:0B:86': 'Aruba', '00:18:0A': 'Meraki',
}

def get_local_subnets():
    subnets = []
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=10)
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
    arp_map = {}
    try:
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=10)
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                ip, mac = parts[0], parts[2].upper()
                if ':' in mac and mac != 'FF:FF:FF:FF:FF:FF':
                    arp_map[ip] = mac
    except:
        pass
    return arp_map

def lookup_manufacturer(mac):
    if not mac:
        return None, None
    oui = mac.upper()[:8]
    if oui in CAMERA_OUI:
        return CAMERA_OUI[oui], 'camera'
    if oui in INFRASTRUCTURE_OUI:
        return INFRASTRUCTURE_OUI[oui], 'infrastructure'
    return None, None

def check_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def ping_host(ip, timeout=1):
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip], capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except:
        return False

def scan_host(ip, arp_map):
    if not ping_host(ip):
        return None
    mac = arp_map.get(ip)
    manufacturer, device_type = lookup_manufacturer(mac) if mac else (None, None)
    ports = {'rtsp': check_port(ip, 554), 'http': check_port(ip, 80)}
    if not device_type:
        device_type = 'camera' if ports['rtsp'] else 'unknown'
    return {'ip': ip, 'mac': mac, 'manufacturer': manufacturer, 'device_type': device_type, 'ports': ports}

def expand_cidr(cidr):
    if '/' not in cidr:
        return [cidr]
    ip_part, prefix = cidr.split('/')
    prefix = min(int(prefix), 24)
    ip_parts = [int(x) for x in ip_part.split('.')]
    base = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
    num_hosts = 2 ** (32 - prefix)
    network = base & (0xFFFFFFFF << (32 - prefix))
    return [f"{(network + i >> 24) & 0xFF}.{(network + i >> 16) & 0xFF}.{(network + i >> 8) & 0xFF}.{(network + i) & 0xFF}" for i in range(1, num_hosts - 1)]

def scan_network(subnets=None):
    if not subnets:
        subnets = get_local_subnets()
    logger.info(f"Scanning: {subnets}")
    all_ips = []
    for subnet in subnets:
        all_ips.extend(expand_cidr(subnet))
    arp_map = get_arp_table()
    devices = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_host, ip, arp_map): ip for ip in all_ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)
                logger.info(f"Found: {result['ip']} - {result.get('manufacturer', 'Unknown')} ({result['device_type']})")
    return devices

def generate_gatus_config(devices, location):
    cameras = [d for d in devices if d['device_type'] == 'camera']
    config = {'web': {'port': 8080}, 'metrics': True, 'storage': {'type': 'memory'}, 'endpoints': []}
    for cam in cameras:
        ip, name = cam['ip'], cam.get('manufacturer', 'Camera')
        config['endpoints'].append({'name': f"{name} ({ip})", 'group': f"{location}/cameras", 'url': f"icmp://{ip}", 'interval': '30s', 'conditions': ['[CONNECTED] == true']})
        if cam.get('ports', {}).get('rtsp'):
            config['endpoints'].append({'name': f"{name} RTSP ({ip})", 'group': f"{location}/cameras", 'url': f"tcp://{ip}:554", 'interval': '30s', 'conditions': ['[CONNECTED] == true']})
    if not config['endpoints']:
        config['endpoints'].append({'name': 'No cameras found', 'group': f"{location}/status", 'url': 'icmp://127.0.0.1', 'interval': '60s', 'conditions': ['[CONNECTED] == true']})
    return config

def main():
    location = os.environ.get('LOCATION', 'edge')
    output = os.environ.get('GATUS_CONFIG', '/config/gatus/config.yaml')
    interval = int(os.environ.get('SCAN_INTERVAL_HOURS', '1'))
    logger.info(f"Scanner starting - Location: {location}, Interval: {interval}h")
    while True:
        try:
            devices = scan_network()
            cameras = [d for d in devices if d['device_type'] == 'camera']
            logger.info(f"Found {len(cameras)} cameras")
            config = generate_gatus_config(devices, location)
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info(f"Wrote config to {output}")
        except Exception as e:
            logger.error(f"Error: {e}")
        if interval == 0:
            break
        time.sleep(interval * 3600)

if __name__ == '__main__':
    main()
SCANNEREOF

# Create scanner Dockerfile
cat > $INSTALL_DIR/scanner/Dockerfile << 'DOCKEREOF'
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping net-tools && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pyyaml
COPY scanner.py .
ENV LOCATION=edge
ENV SCAN_INTERVAL_HOURS=1
ENV GATUS_CONFIG=/config/gatus/config.yaml
CMD ["python", "scanner.py"]
DOCKEREOF

# Create docker-compose.yml
cat > $INSTALL_DIR/docker-compose.yml << 'COMPOSEEOF'
services:
  scanner:
    build: ./scanner
    container_name: cloudmonitor-scanner
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_RAW
    cap_drop:
      - ALL
    environment:
      - LOCATION=${LOCATION:-edge}
      - SCAN_INTERVAL_HOURS=${SCAN_INTERVAL_HOURS:-1}
      - GATUS_CONFIG=/config/gatus/config.yaml
    volumes:
      - gatus-config:/config/gatus
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  gatus:
    image: twinproduction/gatus:v5.7.0
    container_name: cloudmonitor-gatus
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_RAW
    cap_drop:
      - ALL
    volumes:
      - gatus-config:/config:ro
    command: ["--config", "/config/gatus/config.yaml"]
    depends_on:
      - scanner
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 90s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  vmagent:
    image: victoriametrics/vmagent:v1.96.0
    container_name: cloudmonitor-vmagent
    restart: unless-stopped
    network_mode: host
    command:
      - '-promscrape.config=/etc/vmagent/vmagent.yml'
      - '-remoteWrite.url=${REMOTE_WRITE_URL}'
      - '-remoteWrite.basicAuth.username=${VM_AUTH_USER:-admin}'
      - '-remoteWrite.basicAuth.password=${VM_AUTH_PASS}'
      - '-remoteWrite.tmpDataPath=/vmagent-data'
      - '-remoteWrite.maxDiskUsagePerURL=100MB'
    volumes:
      - ./config/vmagent:/etc/vmagent:ro
      - vmagent-data:/vmagent-data
    depends_on:
      - gatus
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8429/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  gatus-config:
  vmagent-data:
COMPOSEEOF

echo "  Configuration created"

# Step 4: Start services
echo -e "${CYAN}[4/4]${NC} Starting services..."
cd $INSTALL_DIR

# Build scanner image
docker compose build --quiet

# Pull other images
docker pull twinproduction/gatus:v5.7.0
docker pull victoriametrics/vmagent:v1.96.0

# Start
docker compose up -d

# Wait and check
sleep 15

SCANNER_OK=false
GATUS_OK=false
VMAGENT_OK=false

docker ps -f name=cloudmonitor-scanner | grep -q cloudmonitor-scanner && SCANNER_OK=true
docker ps -f name=cloudmonitor-gatus | grep -q cloudmonitor-gatus && GATUS_OK=true
docker ps -f name=cloudmonitor-vmagent | grep -q cloudmonitor-vmagent && VMAGENT_OK=true

if $SCANNER_OK; then echo -e "  ${GREEN}✓ Scanner${NC}"; else echo -e "  ${RED}✗ Scanner${NC}"; fi
if $GATUS_OK; then echo -e "  ${GREEN}✓ Gatus${NC}"; else echo -e "  ${YELLOW}✗ Gatus (starting...)${NC}"; fi
if $VMAGENT_OK; then echo -e "  ${GREEN}✓ vmagent${NC}"; else echo -e "  ${YELLOW}✗ vmagent${NC}"; fi

# Create helper commands
cat > /usr/local/bin/cloudmonitor-status << 'CMDEOF'
#!/bin/bash
echo "=== CloudMonitor Status ==="
docker ps -f name=cloudmonitor --format "table {{.Names}}\t{{.Status}}"
echo ""
echo "=== Recent Scanner Logs ==="
docker logs cloudmonitor-scanner --tail 10
CMDEOF
chmod +x /usr/local/bin/cloudmonitor-status

cat > /usr/local/bin/cloudmonitor-scan << 'CMDEOF'
#!/bin/bash
echo "Triggering network scan..."
docker restart cloudmonitor-scanner
CMDEOF
chmod +x /usr/local/bin/cloudmonitor-scan

cat > /usr/local/bin/cloudmonitor-logs << 'CMDEOF'
#!/bin/bash
docker logs cloudmonitor-scanner -f
CMDEOF
chmod +x /usr/local/bin/cloudmonitor-logs

# Get IP
MAIN_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}       CLOUDMONITOR INSTALLED!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${CYAN}Access:${NC}"
echo -e "  Gatus UI:    ${BLUE}http://${MAIN_IP}:8080${NC}"
echo -e "  Grafana:     ${BLUE}http://$MONITORING_SERVER:3000${NC}"
echo ""
echo -e "${CYAN}Commands:${NC}"
echo "  cloudmonitor-status  - Check services"
echo "  cloudmonitor-scan    - Trigger scan now"
echo "  cloudmonitor-logs    - View scanner logs"
echo ""
echo -e "${CYAN}Location:${NC} $DEVICE_LOCATION"
echo ""
