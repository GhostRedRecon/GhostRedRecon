# GhostRedRecon

[![CI](https://github.com/GhostRedRecon/GhostRedRecon/actions/workflows/ci.yml/badge.svg)](https://github.com/GhostRedRecon/GhostRedRecon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#supported-operating-systems)
[![Target](https://img.shields.io/badge/target-Kali%20Linux-557C94.svg)](#installation-on-kali-linux)
[![Use](https://img.shields.io/badge/use-authorized%20labs%20only-red.svg)](#security-and-safety)

**GhostRedRecon** is a local-first Linux red-team reconnaissance console for authorized WiFi, BLE, IoT, and camera assessment workflows. It turns a Kali workstation, an MK7AC WiFi adapter, and an nRF52840 BLE dongle into a browser-based operator console for evidence-backed discovery, validation, and review.

Repository: <https://github.com/GhostRedRecon/GhostRedRecon>

> Educational and authorized use only: GhostRedRecon is for learning, research, lab validation, owned-device testing, and explicitly authorized assessments. Do not use this project for unauthorized access, credential theft, illegal monitoring, network abuse, privacy invasion, or attacks against systems you do not own or have permission to test.

## Why Ethical Hackers Use It

GhostRedRecon is for red-team operators, ethical hackers, wireless lab builders, and cybersecurity engineers who want a practical way to turn raw RF/network signals into reviewable evidence. Instead of jumping between disconnected terminals, packet captures, Bluetooth tools, service probes, and notes, GhostRedRecon gives you a local operator console built around discovery, validation, and evidence.

It is designed for authorized labs and assessments where the interesting question is not just "what is broadcasting?" but "what is it, why do we think that, what evidence supports it, and what should the operator review next?"

Public v1 gives operators a focused toolkit:

- WiFi MK7AC packet-truth hunting for AP/client discovery and evidence review.
- Camera Hunt for WiFi, IP, and cloud-camera lead detection.
- BLE NR5 / BLE NRF workflows for nRF52840-backed Bluetooth discovery and validation.
- Device inventory, identity snapshots, timelines, evidence folders, and operator status panels.
- A React + Vite GUI backed by a local FastAPI runtime.
- Kali Linux installation automation for system tools, Python dependencies, and frontend dependencies.

## Quick Install

Connect the nRF52840 BLE dongle and MK7AC WiFi adapter first, then run:

```bash
git clone https://github.com/GhostRedRecon/GhostRedRecon.git
cd GhostRedRecon
chmod +x scripts/install_kali_dependencies.sh scripts/start.sh scripts/stop.sh
./scripts/install_kali_dependencies.sh
./scripts/start.sh
```

Open the operator console:

```text
http://127.0.0.1:5174
```

If the GUI does not show the connected adapters after installation:

```bash
./scripts/stop.sh
./scripts/start.sh
```

## Feature Status

Some advanced features are intentionally disabled or hidden in public v1. This keeps the first public release focused on workflows that are ready for safer authorized lab use.

| Area | Public v1 Status | Notes |
| --- | --- | --- |
| WiFi MK7 | Enabled | Validated path for monitor-mode WiFi discovery, packet evidence, and Camera Hunt input. |
| Camera Hunt | Enabled | Produces evidence-backed camera leads; treat results as leads until corroborated. |
| BLE NR5 / BLE NRF | Enabled | Built for nRF52840-backed Bluetooth discovery and selected-device validation. |
| SDR HKRF | Source retained, GUI hidden | Reserved for v2.0 validation before public operator exposure. |
| Hunt Drones | Source retained, GUI hidden | Reserved for v2.0 validation before public operator exposure. |
| Runtime evidence export | Local only | Runtime logs, identities, captures, and evidence are ignored for public release hygiene. |

## What GhostRedRecon Can Do

- Start and stop local backend/frontend services for a browser-based operator console.
- Detect connected project hardware such as MK7AC WiFi adapters, Bluetooth adapters, and BLE NRF sensors.
- Collect WiFi AP/client observations through Linux wireless tools and packet capture utilities.
- Rank WiFi targets using exposure, behavior, proximity, persistence, vendor risk, and packet evidence.
- Run Camera Hunt to identify likely cameras using SSID, vendor, hostname, mDNS, DHCP, DNS, TLS SNI, services, cloud hints, and traffic behavior.
- Use BLE NR5 to build a Bluetooth device census, review service hints, and run selected-device hard BLE validation.
- Retain authorized evidence and timeline data for operator review.
- Show dependency, module, identity, and project configuration status in Settings.

## Supported Operating Systems

GhostRedRecon is designed for Linux workstations.

| Platform | Status | Notes |
| --- | --- | --- |
| Kali Linux | Primary target | Best target for wireless, RF, Bluetooth, and packet-capture tooling. |
| Debian 12+ | Manual/supported base | Use equivalent packages; some wireless tools may need manual setup. |
| Ubuntu 22.04+ / 24.04+ | Manual/supported base | Works best when monitor-mode drivers and SDR packages are installed manually. |
| Raspberry Pi OS 64-bit | Experimental | Suitable only for lighter workflows; SDR/WiFi performance depends heavily on hardware. |
| Fedora / Arch / other Linux | Manual setup | Install equivalent packages and verify tool paths manually. |
| macOS / Windows | Not supported | WSL is not a target for hardware capture workflows. |

## Hardware Guidance

| Hardware | Used By | Notes |
| --- | --- | --- |
| HackRF One | Hidden v2.0 SDR HKRF workflows | Source retained for later validation; not exposed in public v1 GUI. |
| MK7AC / monitor-mode WiFi adapter | WiFi MK7, Camera Hunt | Intended WiFi path. Interface defaults to `wlan1` unless overridden. |
| nRF52840 BLE sensor | BLE NR5 / BLE NRF | Used for native Bluetooth discovery and hard BLE validation. |
| Host Bluetooth adapter | BLE host-side validation | Requires BlueZ, rfkill unblock, and working Linux Bluetooth service. |
| Laptop/desktop CPU, 16 GB RAM recommended | Full GUI + backend + captures | More RAM helps when packet captures, Kismet, and frontend dev server run together. |

Important hardware setup note:

- Connect the nRF52840 BLE dongle and MK7AC WiFi adapter before running the installer. The installer and startup checks report currently visible USB/WiFi hardware, so plugging in the adapters first gives the cleanest first-run setup.
- If the GUI does not show the nRF dongle or MK7AC adapter after installation, stop and restart the local services:

  ```bash
  ./scripts/stop.sh
  ./scripts/start.sh
  ```

- If you do not have an MK7AC adapter, use a Linux WiFi adapter that supports monitor mode and packet capture. Set the preferred interface before starting the app, for example:

  ```bash
  WIFI_MK7_PREFERRED_INTERFACE=wlan2 ./scripts/start.sh
  ```

  Some GUI labels and workflow names still refer to MK7AC because that is the validated public v1 WiFi path. If you want the project to present a different adapter as the primary WiFi sensor, update the relevant config/source labels and verify monitor-mode behavior on your hardware.

## Architecture

```text
operator browser
  -> React/Vite GUI
  -> FastAPI backend
  -> integration controllers
  -> Linux tools and hardware sensors
  -> evidence, identities, logs, and runtime state
```

Main directories:

```text
backend/                         FastAPI APIs, RF/session logic, integrations, intel engines
frontend/                        React + Vite operator console
frontend/src/views/              GUI tabs for WiFi MK7, Camera Hunt, BLE NR5, Settings, Manual, and hidden v2 views
frontend/src/components/         Shared GUI components and header
frontend/src/lib/                Frontend API/runtime helpers and branding source
scripts/install_kali_dependencies.sh  Kali/Linux dependency installer and verifier
scripts/start.sh                 Starts backend and frontend locally
scripts/stop.sh                  Stops backend and frontend locally
config/project.config.json       Network, GUI, and runtime project configuration
evidence/                        Runtime evidence output, ignored for release hygiene
logs/                            Runtime logs and PID files, ignored for release hygiene
identities/                      Local identity snapshots
rf_reports/                      Runtime report/evidence outputs used by feature workflows
tests/                           Project test helpers
```

## Dependencies

The Kali installer installs or checks a broad wireless/RF operator stack, including:

```bash
python3 python3-venv python3-pip nodejs npm git curl jq usbutils pciutils wireless-tools iw rfkill aircrack-ng tshark wireshark-common tcpdump bettercap kismet nmap ffmpeg arp-scan avahi-utils v4l-utils rtl-433 hackrf bluez bluez-tools bluetooth ubertooth libcap2-bin
```

Python backend packages installed into `backend/.venv` include:

- `fastapi`
- `uvicorn[standard]`
- `numpy`
- `requests`
- `psutil`
- `scapy`
- `aiofiles`
- `python-multipart`
- `pyserial`
- `pydantic`
- `pyyaml`

Frontend dependencies are installed from `frontend/package.json`:

- `react`
- `react-dom`
- `vite`
- `@vitejs/plugin-react`

## Installation On Kali Linux

Clone the repository:

```bash
git clone https://github.com/GhostRedRecon/GhostRedRecon.git
cd GhostRedRecon
```

Before running the installer, connect the nRF52840 BLE dongle and MK7AC WiFi adapter. If you are using a different monitor-mode WiFi adapter, confirm Linux can see it:

```bash
iw dev
lsusb
```

Run the installer:

```bash
chmod +x scripts/install_kali_dependencies.sh
./scripts/install_kali_dependencies.sh
```

The installer performs these tasks:

- Installs Kali/Linux system dependencies.
- Creates runtime directories for logs, identities, evidence, WiFi Hunt sessions, and reports.
- Builds `backend/.venv` and installs backend Python packages.
- Installs React/Vite frontend dependencies.
- Enables or starts the Linux Bluetooth service where possible.
- Adds the operator user to common capture and hardware groups when available.
- Installs a limited monitor-mode sudoers policy for selected interface commands.
- Validates required command-line tools.
- Checks project config JSON.
- Compiles backend Python files.
- Runs a production frontend build.
- Prints current WiFi/USB hardware visibility.

If group membership changes, log out and back in before using monitor-mode or capture workflows.

After installation, start GhostRedRecon and confirm the adapters appear in Home or Settings. If the GUI does not show the adapter state correctly after plugging in hardware, restart the local services:

```bash
./scripts/stop.sh
./scripts/start.sh
```

## Start And Stop

Start GhostRedRecon:

```bash
./scripts/start.sh
```

Default URLs:

| Service | URL |
| --- | --- |
| Frontend | `http://127.0.0.1:5174` |
| Backend | `http://127.0.0.1:8100` |

Stop GhostRedRecon:

```bash
./scripts/stop.sh
```

The start script reads `config/project.config.json`, writes `frontend/public/config.js`, starts the backend, starts the Vite frontend, and stores PID/log files under `logs/`.

## How To Use GhostRedRecon

| Workflow | Tab | Best For |
| --- | --- | --- |
| WiFi packet hunting | WiFi MK7 | AP/client discovery, target ranking, packet evidence, selected SSID review. |
| Camera discovery | Camera Hunt | Finding likely WiFi/IP/cloud cameras and collecting evidence reasons. |
| Bluetooth validation | BLE NR5 | BLE device census, identity hints, service review, and hard BLE tests. |
| Project health | Settings | Dependency checks, layout controls, identities, and config. |
| Operator guide | Manual | Built-in usage guidance and workflow notes. |

Basic operator flow:

1. Connect only the hardware required for the workflow.
2. Start the app with `./scripts/start.sh`.
3. Open the GUI and confirm hardware status in Home or Settings.
4. Select the correct tab.
5. Start the tab-local session or sensor.
6. Run the sweep, hunt, scan, or audit.
7. Review evidence before making a finding.
8. Stop capture and clear retained results before changing environments.

## Hidden v2.0 Workflows

SDR HKRF and Hunt Drones are retained in source for later validation but hidden from the public v1 GUI. They should not be treated as public v1 release workflows until their hardware tests and operator flows are completed.

## WiFi MK7 Workflow

Use WiFi MK7 as the packet-truth wireless reconnaissance layer.

1. Connect the MK7AC adapter.
2. Confirm Linux can see the adapter:

   ```bash
   iw dev
   lsusb
   ```

3. Open **WiFi MK7**.
4. Confirm adapter readiness and monitor-mode status.
5. Start WiFi Hunt or use the tab-local controls for selected bands and duration.
6. Review AP/client inventory, packet truth, target scoring, vendor risk, channel plan, evidence, and timeline.
7. Select an SSID/client before using selected-target operator actions.
8. Stop Hunt and clear retained results before moving to a new assessment area.

WiFi MK7 does not replace HackRF. It is a native 802.11 packet workflow using Linux wireless tools.

## Camera Hunt Workflow

Use Camera Hunt to separate likely cameras from generic routers, repeaters, and IoT devices.

1. Connect the MK7AC adapter.
2. If testing a lab camera, open the camera live view on the phone/app to generate fresh traffic.
3. Open **Camera Hunt**.
4. Run the camera hunt/audit.
5. Review camera confidence, evidence reasons, vendor/cloud hints, reachable IP services, DNS/SNI, mDNS, DHCP, and packet behavior.
6. Treat a result as a lead until corroborated by camera-specific evidence.
7. Retain or export evidence only for authorized assessment records.

Cloud cameras may not expose local RTSP, ONVIF, or HTTP video. For cloud-only devices, proof may come from vendor infrastructure, live-view timing, DNS/SNI, packet behavior, and device identity evidence rather than a local snapshot.

## BLE NRF Workflow

Use BLE NR5 / BLE NRF for native Bluetooth discovery and validation.

1. Connect the nRF52840 BLE sensor.
2. Ensure Bluetooth is unblocked and BlueZ is running:

   ```bash
   rfkill list
   bluetoothctl show
   ```

3. Open **BLE NR5**.
4. Start the NRF session or run an NRF scan.
5. Select a Bluetooth device from the census or assessment queue.
6. Review identity, vendor hints, services, confidence, risk notes, and timeline.
7. Use **Hard BLE Test** only on a selected device in an authorized lab.
8. Stop or clear the BLE session before moving to a new environment.

Vendor/product labels should be treated as evidence-backed only when decoded identifiers exist. Attack-class detections can still be useful even when vendor identity is unknown.

## Configuration

Primary project config:

```text
config/project.config.json
```

Common environment overrides:

| Variable | Purpose |
| --- | --- |
| `BACKEND_HOST` | Override backend bind host. |
| `BACKEND_PORT` | Override backend port. |
| `FRONTEND_HOST` | Override frontend bind host. |
| `FRONTEND_PORT` | Override frontend port. |
| `WIFI_MK7_PREFERRED_INTERFACE` | Preferred WiFi adapter interface, default `wlan1`. |
| `WIFI_MK7_REQUIRE_PRIVILEGED_BACKEND` | Controls whether backend starts with elevated privileges for WiFi workflows. |
| `TARGET_OPERATOR_USER` | Explicit operator user for installer ownership/group setup. |

Example:

```bash
WIFI_MK7_PREFERRED_INTERFACE=wlan1 ./scripts/start.sh
```

## Logs And Runtime Data

Runtime files are stored locally and should not be committed:

| Path | Purpose |
| --- | --- |
| `logs/` | Backend/frontend logs, PIDs, feature logs. |
| `evidence/` | Authorized assessment evidence and session output. |
| `identities/` | Local identity snapshots. |
| `rf_reports/` | Feature report/evidence outputs. |
| `frontend/dist/` | Generated frontend build output. |
| `frontend/public/config.js` | Generated runtime frontend config. |
| `backend/.venv/` | Local backend Python virtual environment. |
| `frontend/node_modules/` | Local frontend dependencies. |

## Development

Install frontend dependencies manually if needed:

```bash
npm --prefix frontend install
```

Build the frontend:

```bash
npm --prefix frontend run build
```

Compile backend Python files:

```bash
python3 -m compileall backend
```

Import-check the backend:

```bash
python3 -c "import backend.main; print('backend import ok')"
```

Run available tests:

```bash
python3 tests/run_tests.py
```

## Release Hygiene

Before publishing or tagging a public release, remove local runtime artifacts and verify the build:

```bash
find evidence logs -mindepth 1 -delete
find . \
  \( -path './frontend/node_modules' -o -path './frontend/dist' -o -path './backend/.venv' \) -prune -o \
  -type f \( -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' -o -iname '*.hccapx' -o -iname '*.22000' -o -iname '*.hc22000' -o -iname '*handshake*' \) -print
npm --prefix frontend run build
python3 -m compileall backend tests
python3 -m pytest
```

## Security And Safety

- Use GhostRedRecon only on systems, networks, cameras, Bluetooth devices, and RF environments you own or are explicitly authorized to assess.
- Do not use Camera Hunt for privacy invasion or unauthorized surveillance discovery.
- Do not run active validation against third-party networks or devices.
- Do not publish packet captures, camera evidence, identity snapshots, logs, or local runtime artifacts.
- BLE validation should be performed only against owned or approved lab devices.
- Follow local RF, wireless, privacy, and computer misuse laws.

See [SECURITY.md](SECURITY.md) for reporting and safe-use guidance.

## Troubleshooting

| Symptom | What To Check |
| --- | --- |
| Frontend does not open | Check `logs/frontend.log`, port `5174`, and `npm --prefix frontend run build`. |
| Backend is unreachable | Check `logs/backend.log`, port `8100`, and `python3 -c "import backend.main"`. |
| HackRF is connected but not streaming | Run `hackrf_info`, check USB permissions, gain profile, and competing SDR processes. |
| MK7AC scan is empty or hangs | Check `iw dev`, monitor-mode support, NetworkManager interference, stale capture tools, and interface name. |
| BLE NRF shows no devices | Check `rfkill`, BlueZ service, serial permissions, nRF sensor visibility, and local BLE advertising. |
| Camera Hunt lists routers | Require camera-specific evidence such as vendor, hostname, RTSP/ONVIF/media service, cloud domain, or live-view traffic behavior. |

## Contributing

Contributions are welcome when they keep the project local-first, authorized-use focused, evidence-oriented, and practical on Kali/Linux operator workstations. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Support The Project

If GhostRedRecon helps you, you can support development here:

[Support this project - Buy Me a Coffee](https://buymeacoffee.com/navnish)

## Powered By And Thanks

GhostRedRecon exists because the Linux security and open-source wireless communities already built an incredible foundation. Thank you to the maintainers, contributors, researchers, and operators behind these projects.

Special thanks to [Kali Linux](https://www.kali.org/) for being the primary operator platform this project targets. GhostRedRecon is designed to feel natural on Kali because Kali already brings together the wireless, Bluetooth, packet-capture, and security tooling needed for serious authorized lab work.

Runtime and ecosystem projects used by or supported around GhostRedRecon include:

| Project | Role In GhostRedRecon |
| --- | --- |
| [Kali Linux](https://www.kali.org/) | Primary Linux target and operator environment. |
| [Python](https://www.python.org/) | Backend runtime and analysis engine language. |
| [FastAPI](https://fastapi.tiangolo.com/) | Local backend API framework. |
| [Uvicorn](https://www.uvicorn.org/) | ASGI server for the backend runtime. |
| [React](https://react.dev/) | Operator GUI framework. |
| [Vite](https://vite.dev/) | Frontend development and production build tool. |
| [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/) | Frontend dependency and build runtime. |
| [BlueZ](http://www.bluez.org/) | Linux Bluetooth stack used for BLE workflows. |
| [Scapy](https://scapy.net/) | Packet parsing and packet-oriented Python workflows. |
| [Aircrack-ng](https://www.aircrack-ng.org/) | WiFi capture and monitor-mode ecosystem tooling. |
| [Kismet](https://www.kismetwireless.net/) | Wireless discovery and sensor ecosystem. |
| [Bettercap](https://www.bettercap.org/) | Network discovery and assessment ecosystem. |
| [tcpdump](https://www.tcpdump.org/) | Packet capture support. |
| [Wireshark/tshark](https://www.wireshark.org/) | Packet inspection and evidence tooling. |
| [nmap](https://nmap.org/) | Network service discovery. |
| [arp-scan](https://github.com/royhills/arp-scan) | Local network ARP discovery. |
| [HackRF](https://greatscottgadgets.com/hackrf/) | SDR hardware ecosystem used by hidden v2.0 workflows. |
| [GNU Radio](https://www.gnuradio.org/) | SDR and signal-processing ecosystem. |
| [rtl-433](https://github.com/merbanan/rtl_433) | ISM/sub-GHz decoding ecosystem. |
| Linux wireless tools, `iw`, `rfkill`, `usbutils`, `pciutils`, `ffmpeg`, and related packages | Host visibility, capture setup, device checks, and runtime diagnostics. |

These projects belong to their respective authors and maintainers. GhostRedRecon integrates with them but is not affiliated with or endorsed by them unless explicitly stated by those projects.

## License

GhostRedRecon is released under the [MIT License](LICENSE).
