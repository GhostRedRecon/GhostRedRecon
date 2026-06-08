import { Metric, Panel, Pill } from '../components/ui'
import { usePanelPreferences } from '../lib/viewPreferences'

const installSteps = [
  'Run the Kali dependency installer from the project root before first launch.',
  'Connect only the hardware needed for the workflow: MK7AC for WiFi/Camera Hunt and nRF52840 for BLE NRF.',
  'Start the backend and frontend with the project scripts, then open the GUI in the browser.',
  'Check Settings for host diagnostics, optional module readiness, and tool visibility before field use.',
  'Use one active capture workflow at a time when hardware is shared, then stop or clear before changing roles.',
]

const prerequisites = [
  { label: 'Host OS', value: 'Kali Linux', detail: 'Recommended public-release host for wireless and RF tooling' },
  { label: 'Python', value: 'Python 3', detail: 'Required for backend runtime, APIs, and hardware controllers' },
  { label: 'Node.js', value: 'Node + npm', detail: 'Required for Vite + React frontend build and launch' },
  { label: 'Browser', value: 'Desktop browser', detail: 'Use the web GUI for RED TEAM workflows' },
  { label: 'Permissions', value: 'Operator access', detail: 'USB, Bluetooth, WiFi monitor mode, and capture tools need correct host permissions' },
  { label: 'Scope', value: 'Authorized lab only', detail: 'Run scans only where you have explicit permission' },
]

const startupFlow = [
  {
    title: '1. Open the GUI',
    detail: 'The GUI loads in an idle-safe state. A hard refresh returns live sessions to idle so scans do not continue without operator intent.',
  },
  {
    title: '2. Check hardware state',
    detail: 'Use Home and Settings to confirm MK7AC and BLE NRF visibility before starting a workflow.',
  },
  {
    title: '3. Select the correct tab',
    detail: 'Use BLE NR5 for nRF52840 Bluetooth work, WiFi MK7 for packet-truth WiFi, and Camera Hunt for video-device discovery. SDR HKRF and Hunt Drones are hidden for the v1 public release and reserved for v2.0 testing.',
  },
  {
    title: '4. Start session or sensor',
    detail: 'Start only arms the relevant sensor path. It should not run unrelated scans or start other hardware workflows.',
  },
  {
    title: '5. Run the scan or audit',
    detail: 'Use the tab-local Run Sweep, NRF Scan, WiFi Hunt, or Camera Hunt controls to collect fresh results.',
  },
  {
    title: '6. Review evidence',
    detail: 'Inspect scores, packet evidence, identity hints, vendors, services, screenshots/probes, and timelines before drawing conclusions.',
  },
  {
    title: '7. Stop and clear',
    detail: 'Stop active capture before unplugging hardware. Clear retained results when starting a new target environment.',
  },
]

const modeGuides = [
  {
    title: 'RED TEAM mode',
    bullets: [
      'Use for reconnaissance, RF posture mapping, environmental discovery, and authorized offensive validation.',
      'Tables emphasize target leads, fingerprints, evidence, operator actions, and practical next steps.',
      'Public release keeps the GUI focused on red-team workflows only; blue-team-only tabs have been removed.',
    ],
  },
]

const tabGuide = [
  { label: 'Home', detail: 'Runtime overview, connected project hardware, and mission status.' },
  { label: 'BLE NR5', detail: 'Native nRF52840 Bluetooth discovery, identity scoring, GATT/service review, and hard BLE validation workflow.' },
  { label: 'WiFi MK7', detail: 'MK7AC packet-truth WiFi reconnaissance, target ranking, client/AP mapping, live packet evidence, and RED operator actions.' },
  { label: 'Camera Hunt', detail: 'WiFi/IP/cloud camera discovery, camera confidence scoring, service probing, live-view evidence hints, and audit preparation.' },
  { label: 'Settings', detail: 'Dependency checks, feature flags, layout controls, identities, and project configuration.' },
  { label: 'Manual', detail: 'Operator guide for prerequisites, workflows, features, and troubleshooting.' },
]

const toolManuals = [
  {
    id: 'ble-nrf',
    title: 'BLE NRF',
    kicker: 'BLE NR5',
    summary: 'Use BLE NR5 for nRF52840-backed Bluetooth discovery and target validation where decoded BLE evidence matters more than raw RF presence.',
    prerequisites: [
      'nRF52840 BLE sensor connected and visible to the host.',
      'BlueZ host stack available and Bluetooth unblocked on Linux.',
      'Serial permissions configured for the operator user.',
      'Run in an authorized lab or approved assessment area only.',
    ],
    features: [
      'Native BLE device census and assessment queue.',
      'Identity graph, vendor hints, service UUID review, and confidence scoring.',
      'Hard BLE Test action for deeper selected-device validation.',
      'Knowledge and risk intel panel for likely device class and exposure context.',
      'Timeline of BLE observations and retained session state.',
    ],
    workflow: [
      'Open BLE NR5 and confirm the sensor readiness status.',
      'Start the NRF session or run an NRF scan from the command rail or tab controls.',
      'Select a discovered Bluetooth device from the census or queue.',
      'Review identity, services, confidence, and risk notes before taking follow-on action.',
      'Use Hard BLE Test on a selected device when deeper lab validation is required.',
      'Stop or clear the BLE session before moving to a new environment.',
    ],
    notes: [
      'Vendor/product labels should be treated as evidence-backed only when decoded identifiers exist.',
      'Attack-class detections can be valid even when vendor identity is unknown.',
      'If no devices appear, verify BlueZ, rfkill, USB permissions, and that the sensor is not owned by another process.',
    ],
  },
  {
    id: 'wifi-mk7',
    title: 'WiFi MK7',
    kicker: 'WIFI-MK7',
    summary: 'Use WiFi MK7 as the packet-truth WiFi reconnaissance layer for AP/client mapping, target ranking, and evidence-backed WiFi assessment.',
    prerequisites: [
      'MK7AC WiFi adapter connected and visible as a Linux WiFi interface.',
      'Monitor mode-capable driver with `iw`, `airmon-ng`, `airodump-ng`, `tcpdump`, `tshark`, and `kismet` available where possible.',
      'Operator account has capture permissions and can use monitor mode without GUI hangs.',
      'Only scan networks and clients inside the authorized scope.',
    ],
    features: [
      'Adapter readiness detection and monitor-mode orchestration.',
      '2.4 GHz and 5 GHz broad sweeps with packet evidence.',
      'AP/client table, target scoring, environment makeup, vendor risk, anomaly leads, and likely device clusters.',
            'Selected SSID tasking, channel plan, live evidence table, and timeline.',
    ],
    workflow: [
      'Open WiFi MK7 and confirm MK7AC adapter detected.',
      'Start WiFi Hunt or use tab-local sensor controls for the desired bands and duration.',
      'Let the sweep complete without switching adapters or killing capture tools.',
      'Select an SSID/client and review ranking, clients, packet truth, services, and evidence.',
      'Use RED Team operator actions only inside authorized lab scope.',
      'Stop Hunt and clear retained results before starting a new site or test run.',
    ],
    notes: [
      'WiFi MK7 is separate from HackRF and should remain responsive while Linux tools run in the backend.',
      'If scans hang, verify monitor mode, NetworkManager interference, driver support, and stale capture processes.',
      'Large scans should favor bounded durations and retained evidence rather than unbounded packet capture.',
    ],
  },
  {
    id: 'camera-hunt',
    title: 'Camera Hunt',
    kicker: 'Camera Hunt',
    summary: 'Use Camera Hunt to identify likely WiFi/IP/cloud cameras and collect enough evidence to separate real camera leads from generic routers or IoT devices.',
    prerequisites: [
      'MK7AC adapter connected and ready for WiFi packet capture.',
      'LAN reachability for authorized IP/service checks when the camera is on the same network.',
      'Optional phone/live-view activity can help create observable traffic for cloud cameras.',
      'Scope approval for IP probing, service fingerprinting, and evidence collection.',
    ],
    features: [
      'Camera-focused WiFi hunt profile with vendor, SSID, hostname, mDNS, DHCP, DNS, TLS SNI, and service hints.',
      'Confidence scoring intended to reduce router false positives.',
      'IP camera service checks for common web, RTSP, ONVIF, and media endpoints where reachable.',
      'Cloud-camera lead handling through traffic pattern, vendor infrastructure, DNS/SNI, and live-view activity evidence.',
      'Evidence-first output so operators can see why a device is likely a camera.',
    ],
    workflow: [
      'Open Camera Hunt and confirm MK7AC readiness.',
      'If testing a lab camera, start live view on the phone/app to create fresh traffic.',
      'Run Camera Hunt and wait for the sweep/audit to complete.',
      'Review each camera lead for confidence, evidence reasons, vendor/cloud hints, IP services, and packet observations.',
      'Treat generic routers, repeaters, and access points as non-camera unless camera-specific evidence exists.',
      'Export or retain evidence only for authorized assessment records.',
    ],
    notes: [
      'Cloud cameras may not expose local video services; proof may come from vendor/cloud traffic and live-view behavior rather than a local snapshot.',
      'Different manufacturers encrypt differently, so the system should focus on metadata, traffic shape, infrastructure, and reachable management surfaces.',
      'A camera lead without video/image proof should remain a lead until corroborated by service, cloud, or traffic evidence.',
    ],
  },
]

const troubleshooting = [
  {
    label: 'MK7AC scan is slow or stuck',
    detail: 'Check monitor-mode support, NetworkManager interference, stale airodump/tshark/tcpdump processes, and whether the adapter changed interface names.',
  },
  {
    label: 'BLE NRF scan returns no devices',
    detail: 'Check rfkill, BlueZ service state, serial permissions, nRF sensor visibility, and whether the selected environment has active BLE advertising.',
  },
  {
    label: 'Camera Hunt lists routers',
    detail: 'Treat router-like devices as non-camera unless camera-specific evidence exists, such as camera vendor, RTSP/ONVIF/media service, camera hostname, cloud camera domain, or live-view traffic behavior.',
  },
  {
    label: 'Cloud camera has no local video proof',
    detail: 'Review DNS/SNI, vendor infrastructure, timing during live view, and device identity evidence. Many cloud cameras do not expose local unauthenticated video paths.',
  },
]

const wifiMk7ToolStack = [
  { label: 'iw / airmon-ng', detail: 'interface state, channel support, and monitor-mode setup' },
  { label: 'airodump-ng', detail: 'raw WiFi recon, AP/client mapping, and channel observation' },
  { label: 'tshark', detail: 'DHCP, DNS, mDNS, TLS SNI, HTTP, and protocol extraction' },
  { label: 'tcpdump', detail: 'lightweight packet capture and troubleshooting' },
  { label: 'kismet', detail: 'advanced wireless detection and JSON/API workflows' },
  { label: 'nmap', detail: 'authorized IP/service validation for reachable devices' },
  { label: 'masscan', detail: 'bounded high-speed discovery in approved lab ranges' },
]

function ManualSection({ title, children, kicker = 'Manual' }) {
  return (
    <Panel kicker={kicker} title={title} className="dashboard-panel manual-panel">
      {children}
    </Panel>
  )
}

function ManualList({ items }) {
  return (
    <div className="intel-stack">
      {items.map((item, index) => (
        <div key={item} className="advisory-card">
          <strong>{index + 1}. {item}</strong>
        </div>
      ))}
    </div>
  )
}

function ToolManualCard({ tool }) {
  return (
    <ManualSection title={tool.title} kicker={tool.kicker}>
      <div className="manual-copy">{tool.summary}</div>
      <div className="detail-grid">
        <Metric label="Prerequisites" value={tool.prerequisites.length} detail="Host, hardware, and scope checks" />
        <Metric label="Features" value={tool.features.length} detail="Operator capabilities" />
        <Metric label="Workflow" value={tool.workflow.length} detail="Recommended operating steps" />
      </div>
      <div className="dashboard-grid">
        <div className="advisory-card">
          <strong>Prerequisites</strong>
          {tool.prerequisites.map((item) => <div key={item} className="device-meta">{item}</div>)}
        </div>
        <div className="advisory-card">
          <strong>Features</strong>
          {tool.features.map((item) => <div key={item} className="device-meta">{item}</div>)}
        </div>
      </div>
      <div className="dashboard-grid">
        <div className="advisory-card">
          <strong>Workflow</strong>
          {tool.workflow.map((item, index) => <div key={item} className="device-meta">{index + 1}. {item}</div>)}
        </div>
        <div className="advisory-card">
          <strong>Reliability Notes</strong>
          {tool.notes.map((item) => <div key={item} className="device-meta">{item}</div>)}
        </div>
      </div>
    </ManualSection>
  )
}

export default function ManualView() {
  const { isPanelVisible } = usePanelPreferences('MANUAL')

  return (
    <main className="workspace">
      <div className="main-column">
        <section className="metrics-grid compact-metrics">
          <Metric label="Document" value="GhostRedRecon Manual" detail="Web-accessible operator guide" />
          <Metric label="Mode" value="RED TEAM" detail="Public release operator mode" />
          <Metric label="Tools" value="3" detail="BLE NRF, MK7AC, Camera Hunt" />
          <Metric label="Workflow" value="Evidence First" detail="Collect, verify, then act" />
        </section>

        {isPanelVisible('overview') ? (
        <ManualSection title="Overview">
          <div className="manual-copy">
            GhostRedRecon is a Linux RED TEAM operator console for authorized WiFi, BLE, and camera discovery workflows. The v1 public manual is organized around BLE NRF, WiFi MK7, and Camera Hunt. SDR HKRF and Hunt Drones are retained for v2.0 testing but hidden from the public GUI.
          </div>
          <div className="pill-row">
            <Pill text="BLE NRF" tone="cyan" />
            <Pill text="WiFi MK7AC" tone="green" />
            <Pill text="Camera Hunt" tone="amber" />
          </div>
        </ManualSection>
        ) : null}

        {isPanelVisible('coreGuides') ? (
        <section className="dashboard-grid">
          <ManualSection title="Prerequisites">
            <div className="detail-grid">
              {prerequisites.map((item) => (
                <Metric key={item.label} label={item.label} value={item.value} detail={item.detail} />
              ))}
            </div>
          </ManualSection>

          <ManualSection title="Installation And Launch">
            <ManualList items={installSteps} />
          </ManualSection>

          <ManualSection title="Standard Workflow">
            <div className="intel-stack">
              {startupFlow.map((item) => (
                <div key={item.title} className="advisory-card">
                  <strong>{item.title}</strong>
                  <div className="device-meta">{item.detail}</div>
                </div>
              ))}
            </div>
          </ManualSection>

          <ManualSection title="Mode Guide">
            <div className="intel-stack">
              {modeGuides.map((section) => (
                <div key={section.title} className="advisory-card">
                  <strong>{section.title}</strong>
                  {section.bullets.map((bullet) => (
                    <div key={bullet} className="device-meta">{bullet}</div>
                  ))}
                </div>
              ))}
            </div>
          </ManualSection>
        </section>
        ) : null}

        {isPanelVisible('reference') ? (
        <>
          <ManualSection title="Tab Reference" kicker="Operations">
            <div className="intel-stack">
              {tabGuide.map((item) => (
                <div key={item.label} className="intel-row">
                  <span>{item.label}</span>
                  <strong>{item.detail}</strong>
                </div>
              ))}
            </div>
          </ManualSection>

          <section className="dashboard-grid">
            {toolManuals.map((tool) => <ToolManualCard key={tool.id} tool={tool} />)}
          </section>
        </>
        ) : null}

        {isPanelVisible('support') ? (
        <section className="dashboard-grid">
          <ManualSection title="WiFi MK7 Tool Stack" kicker="CLI">
            <div className="intel-stack">
              {wifiMk7ToolStack.map((tool) => (
                <div key={tool.label} className="intel-row">
                  <span>{tool.label}</span>
                  <strong>{tool.detail}</strong>
                </div>
              ))}
            </div>
          </ManualSection>

          <ManualSection title="Troubleshooting" kicker="Support">
            <div className="intel-stack">
              {troubleshooting.map((item) => (
                <div key={item.label} className="advisory-card">
                  <strong>{item.label}</strong>
                  <div className="device-meta">{item.detail}</div>
                </div>
              ))}
            </div>
          </ManualSection>
        </section>
        ) : null}
      </div>
    </main>
  )
}
