#!/bin/bash
#
# CloudMonitor Edge Installer
# Installs: Scanner UI + Gatus + vmagent
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/install.sh | sudo bash
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="/opt/cloudmonitor"

# Cloud monitoring server
MONITORING_SERVER="178.156.175.240"
VM_AUTH_USER="admin"
VM_AUTH_PASS="WQt4C5PYRg44JCNzv104IWe6"

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       CLOUDMONITOR EDGE INSTALLER${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run with sudo${NC}"
    exit 1
fi

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
chmod -R 755 $INSTALL_DIR

# Step 3: Create configuration
echo -e "${CYAN}[3/4]${NC} Creating configuration..."

DEVICE_LOCATION=$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-')

cat > $INSTALL_DIR/.env << ENVEOF
LOCATION=$DEVICE_LOCATION
REMOTE_WRITE_URL=http://$MONITORING_SERVER:8428/api/v1/write
VM_AUTH_USER=$VM_AUTH_USER
VM_AUTH_PASS=$VM_AUTH_PASS
ENVEOF

cat > $INSTALL_DIR/config/vmagent/vmagent.yml << 'EOF'
global:
  scrape_interval: 30s
  scrape_timeout: 10s

scrape_configs:
  - job_name: 'gatus'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
EOF

# Download scanner files
echo "  Downloading scanner..."
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/scanner/scanner.py -o $INSTALL_DIR/scanner/scanner.py
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/scanner/app.py -o $INSTALL_DIR/scanner/app.py
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/scanner/requirements.txt -o $INSTALL_DIR/scanner/requirements.txt
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/scanner/Dockerfile -o $INSTALL_DIR/scanner/Dockerfile

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
      - GATUS_CONFIG_PATH=/config/gatus/config.yaml
      - MONITORED_FILE=/config/monitored.json
    volumes:
      - config:/config
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
      - config:/config:ro
    command: ["--config", "/config/gatus/config.yaml"]
    depends_on:
      - scanner
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
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
  config:
  vmagent-data:
COMPOSEEOF

echo "  Configuration created"

# Step 4: Start services
echo -e "${CYAN}[4/4]${NC} Starting services..."
cd $INSTALL_DIR

docker compose build --quiet
docker pull twinproduction/gatus:v5.7.0
docker pull victoriametrics/vmagent:v1.96.0
docker compose up -d

sleep 10

# Create helper commands
cat > /usr/local/bin/cloudmonitor-status << 'EOF'
#!/bin/bash
echo "=== CloudMonitor Status ==="
docker ps -f name=cloudmonitor --format "table {{.Names}}\t{{.Status}}"
EOF
chmod +x /usr/local/bin/cloudmonitor-status

cat > /usr/local/bin/cloudmonitor-logs << 'EOF'
#!/bin/bash
docker logs cloudmonitor-scanner -f
EOF
chmod +x /usr/local/bin/cloudmonitor-logs

MAIN_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}       CLOUDMONITOR INSTALLED!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${CYAN}Access:${NC}"
echo -e "  Scanner UI:  ${BLUE}http://${MAIN_IP}:8081${NC}"
echo -e "  Gatus:       ${BLUE}http://${MAIN_IP}:8080${NC}"
echo -e "  Grafana:     ${BLUE}http://$MONITORING_SERVER:3000${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo "  1. Open Scanner UI at http://${MAIN_IP}:8081"
echo "  2. Enter subnet(s) to scan"
echo "  3. Select cameras to monitor"
echo "  4. Click 'Add to Monitoring'"
echo ""
echo -e "${CYAN}Commands:${NC}"
echo "  cloudmonitor-status  - Check services"
echo "  cloudmonitor-logs    - View scanner logs"
echo ""
echo -e "${CYAN}Location:${NC} $DEVICE_LOCATION"
echo ""
