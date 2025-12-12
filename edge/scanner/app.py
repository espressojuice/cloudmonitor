#!/usr/bin/env python3
"""
CloudMonitor Scanner Web UI

Web interface for discovering cameras and selecting which to monitor.
"""

import os
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import yaml

# Import scanner functions
from scanner import (
    scan_network, get_local_subnets, expand_cidr,
    CAMERA_OUI, INFRASTRUCTURE_OUI
)

app = FastAPI(title="CloudMonitor Scanner")

# Store scan results and monitored devices
scan_results = []
scan_in_progress = False
monitored_devices = []
locations = []

# Config paths
GATUS_CONFIG_PATH = os.environ.get('GATUS_CONFIG_PATH', '/config/gatus/config.yaml')
MONITORED_FILE = os.environ.get('MONITORED_FILE', '/config/monitored.json')
LOCATIONS_FILE = os.environ.get('LOCATIONS_FILE', '/config/locations.json')
LOCATION = os.environ.get('LOCATION', 'edge')


class ScanRequest(BaseModel):
    subnets: List[str]


class AddDevicesRequest(BaseModel):
    devices: List[dict]
    location: str = "default"


class RemoveDeviceRequest(BaseModel):
    ip: str


class AddLocationRequest(BaseModel):
    name: str


def load_locations():
    """Load locations from file."""
    global locations
    try:
        if os.path.exists(LOCATIONS_FILE):
            with open(LOCATIONS_FILE, 'r') as f:
                locations = json.load(f)
    except Exception as e:
        print(f"Error loading locations: {e}")
        locations = []
    return locations


def save_locations():
    """Save locations to file."""
    try:
        Path(LOCATIONS_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(LOCATIONS_FILE, 'w') as f:
            json.dump(locations, f, indent=2)
    except Exception as e:
        print(f"Error saving locations: {e}")


def load_monitored_devices():
    """Load monitored devices from file."""
    global monitored_devices
    try:
        if os.path.exists(MONITORED_FILE):
            with open(MONITORED_FILE, 'r') as f:
                monitored_devices = json.load(f)
    except Exception as e:
        print(f"Error loading monitored devices: {e}")
        monitored_devices = []
    return monitored_devices


def save_monitored_devices():
    """Save monitored devices to file."""
    try:
        Path(MONITORED_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(MONITORED_FILE, 'w') as f:
            json.dump(monitored_devices, f, indent=2)
    except Exception as e:
        print(f"Error saving monitored devices: {e}")


def generate_gatus_config():
    """Generate Gatus config from monitored devices."""
    config = {
        'web': {'port': 8080},
        'metrics': True,
        'storage': {'type': 'memory'},
        'endpoints': []
    }

    for device in monitored_devices:
        ip = device['ip']
        name = device.get('name') or device.get('manufacturer') or 'Camera'
        location = device.get('location', LOCATION)  # Use device location or fallback to env
        endpoint_name = f"{name} ({ip})"

        # ICMP ping check
        config['endpoints'].append({
            'name': endpoint_name,
            'group': f"{location}/cameras",
            'url': f"icmp://{ip}",
            'interval': '30s',
            'conditions': ['[CONNECTED] == true']
        })

        # RTSP port 554 TCP check (always add for cameras)
        config['endpoints'].append({
            'name': endpoint_name,
            'group': f"{location}/cameras",
            'url': f"tcp://{ip}:554",
            'interval': '30s',
            'conditions': ['[CONNECTED] == true']
        })

    # Add placeholder if no devices
    if not config['endpoints']:
        config['endpoints'].append({
            'name': 'No devices monitored',
            'group': f"{LOCATION}/status",
            'url': 'icmp://127.0.0.1',
            'interval': '60s',
            'conditions': ['[CONNECTED] == true']
        })

    # Write config
    try:
        Path(GATUS_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(GATUS_CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        print(f"Gatus config written to {GATUS_CONFIG_PATH}")
    except Exception as e:
        print(f"Error writing Gatus config: {e}")


# Load data on startup
load_monitored_devices()
load_locations()
generate_gatus_config()  # Regenerate config on startup


@app.get("/", response_class=HTMLResponse)
async def index():
    """Main scanner UI page."""
    subnets = get_local_subnets()
    return HTML_TEMPLATE.replace("{{SUBNETS}}", ", ".join(subnets))


@app.get("/api/subnets")
async def get_subnets():
    """Get detected local subnets."""
    return {"subnets": get_local_subnets()}


@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a network scan."""
    global scan_in_progress, scan_results

    if scan_in_progress:
        raise HTTPException(status_code=409, detail="Scan already in progress")

    scan_in_progress = True
    scan_results = []

    # Run scan in background
    background_tasks.add_task(run_scan, request.subnets)

    return {"status": "started", "subnets": request.subnets}


async def run_scan(subnets: List[str]):
    """Run the actual scan."""
    global scan_in_progress, scan_results
    try:
        # Run scan (this is blocking, but we're in a background task)
        loop = asyncio.get_event_loop()
        for subnet in subnets:
            devices = await loop.run_in_executor(None, scan_network, subnet)
            scan_results.extend(devices)
    finally:
        scan_in_progress = False


@app.get("/api/scan/status")
async def scan_status():
    """Get scan status and results."""
    # Mark which devices are already monitored
    monitored_ips = {d['ip'] for d in monitored_devices}
    results_with_status = []
    for device in scan_results:
        device_copy = device.copy()
        device_copy['monitored'] = device['ip'] in monitored_ips
        results_with_status.append(device_copy)

    return {
        "in_progress": scan_in_progress,
        "results": results_with_status,
        "count": len(scan_results)
    }


@app.get("/api/monitored")
async def get_monitored():
    """Get list of monitored devices."""
    return {"devices": monitored_devices}


@app.post("/api/monitored")
async def add_monitored(request: AddDevicesRequest):
    """Add devices to monitoring."""
    global monitored_devices

    # Add devices that aren't already monitored
    monitored_ips = {d['ip'] for d in monitored_devices}
    for device in request.devices:
        if device['ip'] not in monitored_ips:
            device['added_at'] = datetime.now().isoformat()
            device['location'] = request.location  # Store location with device
            monitored_devices.append(device)
            monitored_ips.add(device['ip'])

    save_monitored_devices()
    generate_gatus_config()

    return {"status": "ok", "count": len(monitored_devices)}


@app.delete("/api/monitored")
async def remove_monitored(request: RemoveDeviceRequest):
    """Remove a device from monitoring."""
    global monitored_devices

    monitored_devices = [d for d in monitored_devices if d['ip'] != request.ip]

    save_monitored_devices()
    generate_gatus_config()

    return {"status": "ok", "count": len(monitored_devices)}


@app.get("/api/locations")
async def get_locations():
    """Get list of locations."""
    return {"locations": locations}


@app.post("/api/locations")
async def add_location(request: AddLocationRequest):
    """Add a new location."""
    global locations

    name = request.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Location name is required")

    if name in locations:
        raise HTTPException(status_code=409, detail="Location already exists")

    locations.append(name)
    save_locations()

    return {"status": "ok", "locations": locations}


@app.delete("/api/locations/{name}")
async def delete_location(name: str):
    """Delete a location."""
    global locations

    if name not in locations:
        raise HTTPException(status_code=404, detail="Location not found")

    locations.remove(name)
    save_locations()

    return {"status": "ok", "locations": locations}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudMonitor - Network Scanner</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { color: #00d4ff; margin-bottom: 10px; }
        .subtitle { color: #888; margin-bottom: 30px; }

        /* Tabs */
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }
        .tab {
            padding: 10px 20px;
            background: #252540;
            border: none;
            color: #888;
            cursor: pointer;
            border-radius: 8px 8px 0 0;
            font-size: 14px;
            transition: all 0.2s;
        }
        .tab:hover { background: #303050; color: #fff; }
        .tab.active { background: #00d4ff; color: #000; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Scan Section */
        .scan-form {
            background: #252540;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .form-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .form-label { color: #888; font-size: 14px; }
        input[type="text"], select {
            background: #1a1a2e;
            border: 1px solid #444;
            color: #fff;
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 14px;
            width: 300px;
        }
        input[type="text"]:focus, select:focus { outline: none; border-color: #00d4ff; }
        select { cursor: pointer; }
        select option { background: #1a1a2e; }
        select option:disabled { color: #666; }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-primary { background: #00d4ff; color: #000; }
        .btn-primary:hover { background: #00b8e6; }
        .btn-primary:disabled { background: #555; color: #888; cursor: not-allowed; }
        .btn-secondary { background: #444; color: #fff; }
        .btn-secondary:hover { background: #555; }
        .btn-success { background: #00c853; color: #fff; }
        .btn-success:hover { background: #00a844; }
        .btn-danger { background: #ff4757; color: #fff; }
        .btn-danger:hover { background: #e8414f; }
        .btn-sm { padding: 6px 12px; font-size: 12px; }

        /* Results Table */
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .results-count { color: #888; }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #252540;
            border-radius: 10px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        th {
            background: #1a1a2e;
            color: #00d4ff;
            font-weight: 500;
            font-size: 13px;
            text-transform: uppercase;
        }
        tr:hover { background: #303050; }
        tr.monitored { background: #1a3a2e; }

        .device-type {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .device-type.camera { background: #00d4ff22; color: #00d4ff; }
        .device-type.infrastructure { background: #ffa50022; color: #ffa500; }
        .device-type.unknown { background: #88888822; color: #888; }

        .status-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
        }
        .status-badge.monitored { background: #00c85322; color: #00c853; }
        .status-badge.rtsp { background: #9c27b022; color: #9c27b0; }

        .checkbox-cell { width: 40px; text-align: center; }
        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        /* Spinner */
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid #333;
            border-top-color: #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        .scanning-status {
            display: flex;
            align-items: center;
            padding: 15px;
            background: #252540;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }
        .empty-state h3 { color: #888; margin-bottom: 10px; }

        /* Actions bar */
        .actions-bar {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #252540;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-top: 1px solid #333;
            transform: translateY(100%);
            transition: transform 0.3s;
        }
        .actions-bar.visible { transform: translateY(0); }
        .selected-count { color: #00d4ff; font-weight: 500; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudMonitor</h1>
        <p class="subtitle">Network Camera Scanner</p>

        <div class="tabs">
            <button class="tab active" onclick="showTab('scan')">Scan Network</button>
            <button class="tab" onclick="showTab('monitored')">Monitored Devices</button>
            <button class="tab" onclick="showTab('locations')">Locations</button>
        </div>

        <!-- Scan Tab -->
        <div id="scan-tab" class="tab-content active">
            <div class="scan-form">
                <div class="form-row" style="margin-bottom: 10px;">
                    <span class="form-label">Location:</span>
                    <select id="location" style="width: 200px;">
                        <option value="" disabled selected>Select Location</option>
                    </select>
                    <input type="text" id="new-location" placeholder="New location name" style="width: 180px;">
                    <button class="btn btn-secondary" onclick="addLocation()">Add Location</button>
                </div>
                <div class="form-row">
                    <span class="form-label">Subnets:</span>
                    <input type="text" id="subnets" value="{{SUBNETS}}" placeholder="192.168.1.0/24, 10.0.0.0/24">
                    <button class="btn btn-secondary" onclick="detectSubnets()" title="Auto-detect local subnets">
                        Detect
                    </button>
                    <button class="btn btn-primary" id="scan-btn" onclick="startScan()">
                        Scan Network
                    </button>
                </div>
            </div>

            <div id="scanning-status" class="scanning-status" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning network... This may take a few minutes.</span>
            </div>

            <div id="scan-results">
                <div class="empty-state">
                    <h3>No scan results</h3>
                    <p>Enter subnet(s) above and click "Scan Network" to discover devices</p>
                </div>
            </div>
        </div>

        <!-- Monitored Tab -->
        <div id="monitored-tab" class="tab-content">
            <div id="monitored-devices">
                <div class="empty-state">
                    <h3>No devices monitored</h3>
                    <p>Scan the network and add devices to start monitoring</p>
                </div>
            </div>
        </div>

        <!-- Locations Tab -->
        <div id="locations-tab" class="tab-content">
            <div class="scan-form">
                <div class="form-row">
                    <span class="form-label">New Location:</span>
                    <input type="text" id="new-location-tab" placeholder="Enter location name" style="width: 250px;">
                    <button class="btn btn-success" onclick="addLocationFromTab()">Add Location</button>
                </div>
            </div>
            <div id="locations-list" style="margin-top: 20px;">
                <div class="empty-state">
                    <h3>No locations</h3>
                    <p>Add a location above to get started</p>
                </div>
            </div>
        </div>
    </div>

    <div id="actions-bar" class="actions-bar">
        <span class="selected-count"><span id="selected-count">0</span> devices selected</span>
        <button class="btn btn-success" onclick="addSelected()">Add to Monitoring</button>
    </div>

    <script>
        let scanResults = [];
        let selectedDevices = new Set();
        let pollInterval = null;

        // Load locations on page load
        document.addEventListener('DOMContentLoaded', loadLocations);

        async function loadLocations() {
            try {
                const resp = await fetch('/api/locations');
                const data = await resp.json();
                renderLocationDropdown(data.locations);
            } catch (e) {
                console.error('Error loading locations:', e);
            }
        }

        function renderLocationDropdown(locationsList) {
            const select = document.getElementById('location');
            const currentValue = select.value;

            // Keep the default disabled option
            select.innerHTML = '<option value="" disabled selected>Select Location</option>';

            // Add all locations
            locationsList.forEach(loc => {
                const option = document.createElement('option');
                option.value = loc;
                option.textContent = loc;
                select.appendChild(option);
            });

            // Restore previous selection if it still exists
            if (currentValue && locationsList.includes(currentValue)) {
                select.value = currentValue;
            }
        }

        async function addLocation() {
            const input = document.getElementById('new-location');
            const name = input.value.trim();

            if (!name) {
                alert('Please enter a location name');
                input.focus();
                return;
            }

            try {
                const resp = await fetch('/api/locations', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });

                if (!resp.ok) {
                    const err = await resp.json();
                    alert(err.detail || 'Error adding location');
                    return;
                }

                const data = await resp.json();
                renderLocationDropdown(data.locations);

                // Select the newly added location
                document.getElementById('location').value = name;

                // Clear the input
                input.value = '';
            } catch (e) {
                alert('Error adding location: ' + e.message);
            }
        }

        async function loadLocationsTab() {
            try {
                const resp = await fetch('/api/locations');
                const data = await resp.json();
                renderLocationsTab(data.locations);
            } catch (e) {
                console.error('Error loading locations:', e);
            }
        }

        function renderLocationsTab(locationsList) {
            const container = document.getElementById('locations-list');

            if (!locationsList.length) {
                container.innerHTML = `
                    <div class="empty-state">
                        <h3>No locations</h3>
                        <p>Add a location above to get started</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="results-header">
                    <span class="results-count">${locationsList.length} location(s)</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Location Name</th>
                            <th style="width: 120px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${locationsList.map(loc => `
                            <tr>
                                <td><strong>${loc}</strong></td>
                                <td>
                                    <button class="btn btn-danger btn-sm" onclick="deleteLocationFromTab('${loc}')">Delete</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        async function addLocationFromTab() {
            const input = document.getElementById('new-location-tab');
            const name = input.value.trim();

            if (!name) {
                alert('Please enter a location name');
                input.focus();
                return;
            }

            try {
                const resp = await fetch('/api/locations', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });

                if (!resp.ok) {
                    const err = await resp.json();
                    alert(err.detail || 'Error adding location');
                    return;
                }

                const data = await resp.json();
                renderLocationsTab(data.locations);
                renderLocationDropdown(data.locations);
                input.value = '';
            } catch (e) {
                alert('Error adding location: ' + e.message);
            }
        }

        async function deleteLocationFromTab(name) {
            if (!confirm(`Delete location "${name}"?`)) return;

            try {
                const resp = await fetch(`/api/locations/${encodeURIComponent(name)}`, {
                    method: 'DELETE'
                });

                if (!resp.ok) {
                    const err = await resp.json();
                    alert(err.detail || 'Error deleting location');
                    return;
                }

                const data = await resp.json();
                renderLocationsTab(data.locations);
                renderLocationDropdown(data.locations);
            } catch (e) {
                alert('Error deleting location: ' + e.message);
            }
        }

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            const tabIndex = tab === 'scan' ? 1 : tab === 'monitored' ? 2 : 3;
            document.querySelector(`.tab:nth-child(${tabIndex})`).classList.add('active');
            document.getElementById(`${tab}-tab`).classList.add('active');

            if (tab === 'monitored') {
                loadMonitored();
            } else if (tab === 'locations') {
                loadLocationsTab();
            }
        }

        async function detectSubnets() {
            try {
                const resp = await fetch('/api/subnets');
                const data = await resp.json();
                document.getElementById('subnets').value = data.subnets.join(', ');
            } catch (e) {
                alert('Error detecting subnets: ' + e.message);
            }
        }

        async function startScan() {
            const subnets = document.getElementById('subnets').value.split(',').map(s => s.trim()).filter(s => s);
            if (!subnets.length) {
                alert('Please enter at least one subnet');
                return;
            }

            document.getElementById('scan-btn').disabled = true;
            document.getElementById('scanning-status').style.display = 'flex';
            selectedDevices.clear();
            updateActionsBar();

            try {
                await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ subnets })
                });

                // Poll for results
                pollInterval = setInterval(checkScanStatus, 2000);
            } catch (e) {
                alert('Error starting scan: ' + e.message);
                document.getElementById('scan-btn').disabled = false;
                document.getElementById('scanning-status').style.display = 'none';
            }
        }

        async function checkScanStatus() {
            try {
                const resp = await fetch('/api/scan/status');
                const data = await resp.json();

                scanResults = data.results;
                renderResults(data.results);

                if (!data.in_progress) {
                    clearInterval(pollInterval);
                    document.getElementById('scan-btn').disabled = false;
                    document.getElementById('scanning-status').style.display = 'none';
                }
            } catch (e) {
                console.error('Error checking scan status:', e);
            }
        }

        function renderResults(results) {
            const container = document.getElementById('scan-results');

            if (!results.length) {
                container.innerHTML = `
                    <div class="empty-state">
                        <h3>No devices found</h3>
                        <p>Try scanning a different subnet</p>
                    </div>
                `;
                return;
            }

            // Sort: cameras first, then by IP
            results.sort((a, b) => {
                if (a.device_type === 'camera' && b.device_type !== 'camera') return -1;
                if (a.device_type !== 'camera' && b.device_type === 'camera') return 1;
                return a.ip.localeCompare(b.ip);
            });

            const cameras = results.filter(d => d.device_type === 'camera');

            container.innerHTML = `
                <div class="results-header">
                    <span class="results-count">${results.length} devices found (${cameras.length} cameras)</span>
                    <label>
                        <input type="checkbox" id="select-all" onchange="toggleSelectAll()"> Select all cameras
                    </label>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th class="checkbox-cell"></th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Manufacturer</th>
                            <th>Type</th>
                            <th>Ports</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(d => `
                            <tr class="${d.monitored ? 'monitored' : ''}">
                                <td class="checkbox-cell">
                                    ${!d.monitored ? `<input type="checkbox"
                                        data-ip="${d.ip}"
                                        ${selectedDevices.has(d.ip) ? 'checked' : ''}
                                        onchange="toggleDevice('${d.ip}')">` : ''}
                                </td>
                                <td>${d.ip}</td>
                                <td>${d.mac || '-'}</td>
                                <td>${d.manufacturer || 'Unknown'}</td>
                                <td><span class="device-type ${d.device_type}">${d.device_type}</span></td>
                                <td>
                                    ${d.ports?.rtsp ? '<span class="status-badge rtsp">RTSP</span>' : ''}
                                    ${d.ports?.http ? '<span class="status-badge">HTTP</span>' : ''}
                                </td>
                                <td>
                                    ${d.monitored ? '<span class="status-badge monitored">Monitored</span>' : '-'}
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        function toggleDevice(ip) {
            if (selectedDevices.has(ip)) {
                selectedDevices.delete(ip);
            } else {
                selectedDevices.add(ip);
            }
            updateActionsBar();
        }

        function toggleSelectAll() {
            const selectAll = document.getElementById('select-all').checked;
            const cameras = scanResults.filter(d => d.device_type === 'camera' && !d.monitored);

            selectedDevices.clear();
            if (selectAll) {
                cameras.forEach(d => selectedDevices.add(d.ip));
            }

            document.querySelectorAll('input[data-ip]').forEach(cb => {
                const device = scanResults.find(d => d.ip === cb.dataset.ip);
                if (device?.device_type === 'camera') {
                    cb.checked = selectAll;
                }
            });

            updateActionsBar();
        }

        function updateActionsBar() {
            const bar = document.getElementById('actions-bar');
            const count = document.getElementById('selected-count');
            count.textContent = selectedDevices.size;
            bar.classList.toggle('visible', selectedDevices.size > 0);
        }

        async function addSelected() {
            const devices = scanResults.filter(d => selectedDevices.has(d.ip));
            if (!devices.length) return;

            const locationSelect = document.getElementById('location');
            const location = locationSelect.value;
            if (!location) {
                alert('Please select a Location before adding devices');
                locationSelect.focus();
                return;
            }

            try {
                await fetch('/api/monitored', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ devices, location })
                });

                // Refresh results
                selectedDevices.clear();
                updateActionsBar();
                await checkScanStatus();

                alert(`Added ${devices.length} device(s) to monitoring at location "${location}"`);
            } catch (e) {
                alert('Error adding devices: ' + e.message);
            }
        }

        async function loadMonitored() {
            try {
                const resp = await fetch('/api/monitored');
                const data = await resp.json();
                renderMonitored(data.devices);
            } catch (e) {
                console.error('Error loading monitored devices:', e);
            }
        }

        function renderMonitored(devices) {
            const container = document.getElementById('monitored-devices');

            if (!devices.length) {
                container.innerHTML = `
                    <div class="empty-state">
                        <h3>No devices monitored</h3>
                        <p>Scan the network and add devices to start monitoring</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="results-header">
                    <span class="results-count">${devices.length} devices monitored</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Location</th>
                            <th>IP Address</th>
                            <th>Name</th>
                            <th>Manufacturer</th>
                            <th>Added</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${devices.map(d => `
                            <tr>
                                <td><strong>${d.location || 'Unknown'}</strong></td>
                                <td>${d.ip}</td>
                                <td>${d.name || '-'}</td>
                                <td>${d.manufacturer || 'Unknown'}</td>
                                <td>${d.added_at ? new Date(d.added_at).toLocaleString() : '-'}</td>
                                <td>
                                    <button class="btn btn-danger btn-sm" onclick="removeDevice('${d.ip}')">Remove</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

        async function removeDevice(ip) {
            if (!confirm(`Remove ${ip} from monitoring?`)) return;

            try {
                await fetch('/api/monitored', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });
                loadMonitored();
            } catch (e) {
                alert('Error removing device: ' + e.message);
            }
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
