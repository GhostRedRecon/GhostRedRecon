GhostRedRecon systemd deployment

Backend service file:
- `deploy/systemd/ghostredrecon-backend.service`

Why this exists:
- `WIFI-MK7` needs real packet-capture privileges for monitor-mode channel control.
- Running the backend from a normal user shell is enough for the SDR-only tabs, but often not enough for `iw dev <iface> set channel ...` and monitor-mode packet workflows.

What the service grants:
- `CAP_NET_ADMIN`
- `CAP_NET_RAW`

Recommended install flow on Kali:

1. Copy the service:
   `sudo cp /home/ghost/Documents/GhostRedRecon/deploy/systemd/ghostredrecon-backend.service /etc/systemd/system/`
2. Reload systemd:
   `sudo systemctl daemon-reload`
3. Enable and start:
   `sudo systemctl enable --now ghostredrecon-backend.service`
4. Check status:
   `sudo systemctl status ghostredrecon-backend.service`
5. Verify backend and WiFi MK7:
   `curl -fsS http://127.0.0.1:8100/health`
   `curl -fsS 'http://127.0.0.1:8100/api/wifi_mk7/status?prepare=true'`

Notes:
- The frontend can still be started with the existing `scripts/start.sh` workflow or your preferred dev server.
- If your Python path differs, update `ExecStart` and `PATH` in the unit file.
- If you want the backend to run as root instead, change `User=` and `Group=` accordingly, but capabilities are the cleaner production path.
