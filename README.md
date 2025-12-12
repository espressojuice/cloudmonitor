# CloudMonitor

Distributed network camera monitoring system.

## Architecture

```
Edge Device(s)                          Cloud Server
┌────────────────────┐                  ┌────────────────────┐
│  cloudmonitor-     │                  │  VictoriaMetrics   │
│  scanner           │                  │  (metrics storage) │
│  - Scans network   │                  │                    │
│  - Finds cameras   │                  │  Grafana           │
│  - Generates config│                  │  (dashboards)      │
│                    │                  │                    │
│  cloudmonitor-     │   push metrics   │                    │
│  gatus ──────────────────────────────►│                    │
│  - Health checks   │   (vmagent)      │                    │
│  - Ping + RTSP     │                  │                    │
│                    │                  │                    │
│  cloudmonitor-     │                  │                    │
│  vmagent           │                  │                    │
│  - Scrapes Gatus   │                  │                    │
│  - Pushes to cloud │                  │                    │
└────────────────────┘                  └────────────────────┘
```

## Cloud Setup

1. SSH to your cloud server
2. Clone this repo and go to `cloud/` directory
3. Create `.env` from `.env.example`:
   ```bash
   cp .env.example .env
   # Edit with secure passwords
   ```
4. Start services:
   ```bash
   docker compose up -d
   ```

**Access:**
- Grafana: `http://your-server:3000`
- VictoriaMetrics: `http://your-server:8428`

## Edge Installation

Run on each edge device:

```bash
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/install.sh | sudo bash
```

This installs:
- **Scanner** - Discovers cameras on local network by MAC address + RTSP port
- **Gatus** - Health checks (ping + TCP) for discovered cameras
- **vmagent** - Pushes metrics to central VictoriaMetrics

### Edge Commands

```bash
cloudmonitor-status  # Check service status
cloudmonitor-scan    # Trigger network scan
cloudmonitor-logs    # View scanner logs
```

## Camera Detection

Cameras are identified by:
1. **MAC OUI** - First 3 bytes identify manufacturer (Hikvision, Dahua, Axis, etc.)
2. **RTSP Port** - Port 554 open indicates video streaming device

Supported manufacturers:
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
- TP-Link
- Ubiquiti

## Configuration

### Edge `.env`

```bash
LOCATION=site-name          # Location identifier (shown in Grafana)
SCAN_INTERVAL_HOURS=1       # How often to scan for new cameras
REMOTE_WRITE_URL=http://cloud:8428/api/v1/write
VM_AUTH_USER=admin
VM_AUTH_PASS=your-password
```

### Cloud `.env`

```bash
VM_AUTH_USER=admin
VM_AUTH_PASS=your-password
GRAFANA_PASS=your-password
```

## Ports

| Service | Port | Purpose |
|---------|------|---------|
| Gatus | 8080 | Health check UI + metrics |
| vmagent | 8429 | Metrics scraper |
| VictoriaMetrics | 8428 | Time series database |
| Grafana | 3000 | Dashboards |

## License

MIT
