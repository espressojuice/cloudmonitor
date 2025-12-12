# CloudMonitor

Distributed network camera monitoring with a web UI for manual device selection.

## Features

- **Web UI** for scanning networks and selecting cameras to monitor
- **MAC OUI detection** - Identifies camera manufacturers (Hikvision, Dahua, Axis, etc.)
- **RTSP port scanning** - Detects cameras by open port 554
- **Manual selection** - You choose which devices to monitor, not automatic
- **Push-based metrics** - Edge pushes to central VictoriaMetrics (outbound only)
- **Grafana dashboards** - Visualize camera health across all locations

## Architecture

```
Edge Device                              Cloud Server (178.156.175.240)
┌────────────────────────────────┐      ┌──────────────────────────┐
│  Scanner UI (:8081)            │      │  VictoriaMetrics (:8428) │
│  - Scan subnets                │      │  - Stores metrics        │
│  - Select cameras              │      │                          │
│  - Add to monitoring           │      │  Grafana (:3000)         │
│                                │      │  - Dashboards            │
│  Gatus (:8080)                 │      │                          │
│  - Ping cameras                │      │                          │
│  - Check RTSP ports            │      │                          │
│                    push ──────────────►                          │
│  vmagent                       │      │                          │
│  - Scrape Gatus metrics        │      │                          │
└────────────────────────────────┘      └──────────────────────────┘
```

## Quick Start

### Edge Installation

```bash
curl -fsSL https://raw.githubusercontent.com/espressojuice/cloudmonitor/main/edge/install.sh | sudo bash
```

Then open `http://<edge-ip>:8081` to access the Scanner UI.

### Cloud Setup

SSH to your cloud server:

```bash
cd /opt/cloudmonitor
git clone https://github.com/espressojuice/cloudmonitor.git .
cd cloud
cp .env.example .env
# Edit .env with secure passwords
docker compose up -d
```

## Usage

1. **Open Scanner UI** at `http://<edge-ip>:8081`
2. **Enter subnets** to scan (e.g., `192.168.1.0/24, 10.0.0.0/24`)
3. **Click "Scan Network"** - takes 1-2 minutes per subnet
4. **Review discovered devices** - cameras are highlighted
5. **Select devices** to monitor (checkbox)
6. **Click "Add to Monitoring"**

Gatus will start monitoring the selected devices immediately.

## Ports

| Service | Port | Purpose |
|---------|------|---------|
| Scanner UI | 8081 | Web interface for scanning |
| Gatus | 8080 | Health check dashboard + metrics |
| vmagent | 8429 | Metrics scraper |
| VictoriaMetrics | 8428 | Time series database |
| Grafana | 3000 | Dashboards |

## Supported Camera Manufacturers

Cameras are identified by MAC address OUI:

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
- Ubiquiti

## Configuration

### Edge `.env`

```bash
LOCATION=site-name              # Shows in Grafana grouping
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

## Commands

```bash
cloudmonitor-status   # Check service status
cloudmonitor-logs     # View scanner logs
```

## License

MIT
