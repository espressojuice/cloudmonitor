# CloudMonitor

Distributed network camera monitoring system with a web UI for manual device selection.

## Overview

CloudMonitor is a **completely separate project** from CamDrop. It provides:
- Network scanning to discover IP cameras and devices
- Manual selection of which devices to monitor (not automatic)
- Push-based metrics from edge to cloud (outbound only)
- Centralized dashboards in Grafana

## Architecture

```
Edge Device (any site)                    Cloud Server (178.156.175.240)
┌─────────────────────────────────┐      ┌──────────────────────────────┐
│                                 │      │                              │
│  Scanner UI (:8081)             │      │  VictoriaMetrics (:8428)     │
│  ├─ Scan subnets                │      │  └─ Time series database     │
│  ├─ Select cameras              │      │                              │
│  └─ Add/remove from monitoring  │      │  Grafana (:3000)             │
│                                 │      │  └─ Dashboards               │
│  Gatus (:8080)                  │      │                              │
│  ├─ ICMP ping checks            │      │                              │
│  ├─ TCP port checks (554)       │      │                              │
│  └─ /metrics endpoint           │      │                              │
│            │                    │      │                              │
│  vmagent (:8429)                │      │                              │
│  └─ Scrapes Gatus ─────────push─────────► VictoriaMetrics            │
│                                 │      │                              │
└─────────────────────────────────┘      └──────────────────────────────┘
```

### Data Flow

1. **Scanner UI** discovers devices on local network via ping + ARP + port scan
2. User **manually selects** cameras to monitor
3. **Gatus** performs health checks (ping, RTSP port 554)
4. **vmagent** scrapes Gatus metrics and pushes to cloud VictoriaMetrics
5. **Grafana** visualizes camera health across all locations

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Push vs Pull | Push (vmagent remote_write) | Edge devices behind NAT, outbound-only traffic |
| Manual vs Auto | Manual selection | User control over what gets monitored |
| Metric storage | VictoriaMetrics | Lightweight, Prometheus-compatible |
| Health checks | Gatus | Simple config, multiple check types |

## Cloud Server

**Server:** 178.156.175.240 (Hetzner)

### Credentials

| Service | URL | Username | Password |
|---------|-----|----------|----------|
| Grafana | http://178.156.175.240:3000 | admin | KLZIZbvSWk4NvRBHLVeI5lii |
| VictoriaMetrics | http://178.156.175.240:8428 | admin | WQt4C5PYRg44JCNzv104IWe6 |

### Cloud Services

```bash
cd /opt/cloudmonitor/cloud
docker compose up -d
```

Services:
- **VictoriaMetrics** - Stores metrics from all edge devices
- **Grafana** - Dashboards for camera health visualization

## Edge Installation

### Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/install.sh | sudo bash
```

### Manual Install

```bash
# Clone repository
git clone https://github.com/espressojuice/cloudmonitor.git /opt/cloudmonitor
cd /opt/cloudmonitor/edge

# Start services
docker compose up -d
```

### Verify Installation

```bash
# Check all containers are running
docker ps -f name=cloudmonitor

# Should show:
# - cloudmonitor-scanner (port 8081)
# - cloudmonitor-gatus (port 8080)
# - cloudmonitor-vmagent (port 8429)
```

## Ports

| Service | Port | Purpose |
|---------|------|---------|
| Scanner UI | 8081 | Web interface for scanning and selection |
| Gatus | 8080 | Health check dashboard + /metrics |
| vmagent | 8429 | Metrics scraper (local only) |
| VictoriaMetrics | 8428 | Time series database (cloud) |
| Grafana | 3000 | Dashboards (cloud) |

## Usage

### 1. Access Scanner UI

Open `http://<edge-ip>:8081` in your browser.

### 2. Scan Network

- Enter subnet(s) in CIDR notation: `192.168.1.0/24, 10.0.0.0/24`
- Or click **Detect** to auto-fill local subnets
- Click **Scan Network** (takes 1-2 minutes per subnet)

### 3. Review Results

The scan results table shows:
- **IP Address** - Device IP
- **MAC Address** - Hardware address
- **Manufacturer** - Detected via MAC OUI (Hikvision, Dahua, etc.)
- **Type** - camera, infrastructure, or unknown
- **Ports** - Open ports (RTSP 554, HTTP 80/443/8080)

Cameras are highlighted with a camera icon.

### 4. Select Devices

Check the boxes next to devices you want to monitor.

### 5. Add to Monitoring

Click **Add Selected to Monitoring** to start health checks.

### 6. View in Grafana

Open Grafana at http://178.156.175.240:3000 to see dashboards.

## File Structure

```
cloudmonitor/
├── edge/
│   ├── scanner/
│   │   ├── app.py           # FastAPI web UI
│   │   ├── scanner.py       # Network scanning functions
│   │   ├── requirements.txt # Python dependencies
│   │   └── Dockerfile       # Scanner container build
│   ├── config/
│   │   └── vmagent/
│   │       └── vmagent.yml  # vmagent scrape config
│   ├── docker-compose.yml   # Edge services
│   └── install.sh           # One-line installer
├── cloud/
│   ├── docker-compose.yml   # Cloud services
│   └── .env.example         # Environment template
└── README.md
```

## Supported Camera Manufacturers

Cameras are identified by MAC address OUI (first 3 bytes):

- Hikvision
- Dahua
- Axis
- Hanwha/Samsung
- Vivotek
- Bosch
- Panasonic
- Sony
- Uniview
- Reolink
- Amcrest
- Foscam
- TP-Link (cameras)
- Ubiquiti
- Turing

## Troubleshooting

### Scanner UI not loading

```bash
# Check container is running
docker ps -f name=cloudmonitor-scanner

# View logs
docker logs cloudmonitor-scanner -f
```

### Metrics not reaching cloud

```bash
# Check vmagent logs
docker logs cloudmonitor-vmagent -f

# Verify remote_write URL in .env
cat /opt/cloudmonitor/.env
```

### Port conflicts

If you have existing gatus/vmagent containers:

```bash
# Stop and remove old containers
docker stop vmagent gatus
docker rm vmagent gatus

# Restart cloudmonitor
cd /opt/cloudmonitor/edge
docker compose down
docker compose up -d
```

### Rebuild after code changes

```bash
cd /opt/cloudmonitor/edge
docker compose build --no-cache scanner
docker compose up -d
```

## Commands

```bash
cloudmonitor-status   # Check service status
cloudmonitor-logs     # View scanner logs
```

## GitHub Repository

https://github.com/espressojuice/cloudmonitor
