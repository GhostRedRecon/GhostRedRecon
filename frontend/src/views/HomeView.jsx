import { useMemo } from 'react'
import { Panel, Pill } from '../components/ui'
import { usePanelPreferences } from '../lib/viewPreferences'

function shortText(value, max = 36) {
  const text = String(value || '').trim()
  if (!text) return '--'
  if (text.length <= max) return text
  return `${text.slice(0, max - 1)}…`
}

function fmtRelative(timestamp) {
  if (!timestamp) return '--'
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - Number(timestamp)))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`
  return `${Math.round(seconds / 3600)}h ago`
}

function healthTone(health = '') {
  const normalized = String(health || '').trim().toUpperCase()
  if (normalized === 'ACTIVE' || normalized === 'HEALTHY' || normalized === 'READY') return 'green'
  if (normalized === 'DEGRADED' || normalized === 'PARTIAL') return 'warning'
  return 'neutral'
}

function cardStateClass(health = '') {
  const normalized = String(health || '').trim().toLowerCase()
  if (normalized === 'active' || normalized === 'healthy' || normalized === 'ready') return 'healthy'
  if (normalized === 'degraded' || normalized === 'partial') return 'degraded'
  return 'idle'
}

function buildConnectedProjectDevices({ system = {}, rfHealth = {}, integrations = {} }) {
  const usbInventory = Array.isArray(system?.connected_hardware) ? system.connected_hardware : []
  const cards = []
  const usedIds = new Set()

  function claimUsb(predicate) {
    const found = usbInventory.find((item) => !usedIds.has(item.id) && predicate(item))
    if (found) usedIds.add(found.id)
    return found
  }

  const sdrFeatureEnabled = false
  const hackrfUsb = claimUsb((item) => /hackrf/i.test(`${item.manufacturer} ${item.product} ${item.descriptor}`))
  if (sdrFeatureEnabled && (rfHealth?.hackrf?.available || hackrfUsb)) {
    cards.push({
      id: 'hackrf',
      name: 'HackRF One',
      manufacturer: hackrfUsb?.manufacturer || 'Great Scott Gadgets',
      firmware: '--',
      health: rfHealth?.sdr_streaming_confirmed ? 'ACTIVE' : (rfHealth?.hackrf?.available ? 'READY' : 'DEGRADED'),
      detail: rfHealth?.hackrf?.detail || 'SDR capture device',
      transport: 'USB',
      path: rfHealth?.hackrf?.path || hackrfUsb?.id || '--',
    })
  }

  const bleSensors = integrations?.bleNr5?.manager?.sensors || []
  bleSensors.forEach((sensor, index) => {
    cards.push({
      id: `ble-nrf-${index}`,
      name: sensor?.usb_descriptor || 'nRF52840 BLE Sensor',
      manufacturer: 'Nordic Semiconductor',
      firmware: sensor?.firmware_mode || '--',
      health: sensor?.collector_ready ? (integrations?.bleNr5?.manager?.active ? 'ACTIVE' : 'READY') : 'DEGRADED',
      detail: sensor?.transport_probe?.detail || sensor?.collector_detail || 'BLE sniffer path',
      transport: 'USB',
      path: (sensor?.serial_paths || []).join(', ') || '--',
    })
  })

  const wifiAdapter = integrations?.wifiMk7?.manager?.adapter
  const wifiUsb = claimUsb((item) => /wireless|802\.11|mt76|mediatek|realtek|rtl|alfa|tp-link|ubiquiti|wifi/i.test(`${item.manufacturer} ${item.product} ${item.descriptor}`))
  if (wifiAdapter?.detected) {
    cards.push({
      id: 'wifi-mk7-adapter',
      name: wifiUsb?.product || wifiAdapter?.monitor_interface || wifiAdapter?.base_interface || 'WiFi Recon Adapter',
      manufacturer: wifiUsb?.manufacturer || 'Linux WiFi Adapter',
      firmware: '--',
      health: integrations?.wifiMk7?.manager?.capture_active ? 'ACTIVE' : 'READY',
      detail: wifiAdapter?.detail || wifiUsb?.descriptor || 'WiFi recon path available',
      transport: wifiUsb?.transport || 'PCIe / USB',
      path: wifiAdapter?.monitor_interface || wifiAdapter?.base_interface || wifiUsb?.id || '--',
    })
  } else if (wifiUsb) {
    cards.push({
      id: 'wifi-mk7-usb-candidate',
      name: wifiUsb.product || 'WiFi Recon Adapter',
      manufacturer: wifiUsb.manufacturer || 'Linux WiFi Adapter',
      firmware: '--',
      health: 'READY',
      detail: wifiUsb.descriptor || 'Linux-visible WiFi adapter connected',
      transport: wifiUsb.transport || 'USB',
      path: wifiUsb.id || '--',
    })
  }

  const bluetoothUsb = claimUsb((item) => /bluetooth|ax211/i.test(`${item.manufacturer} ${item.product} ${item.descriptor}`))
  if (bluetoothUsb) {
    cards.push({
      id: 'bluetooth-host',
      name: bluetoothUsb.product || 'Bluetooth Adapter',
      manufacturer: bluetoothUsb.manufacturer || 'Unknown Manufacturer',
      firmware: '--',
      health: 'READY',
      detail: bluetoothUsb.descriptor || 'Linux-visible Bluetooth interface',
      transport: bluetoothUsb.transport || 'USB',
      path: bluetoothUsb.id || '--',
    })
  }

  usbInventory
    .filter((item) => !usedIds.has(item.id))
    .forEach((item, index) => {
      cards.push({
        id: `usb-${item.id}-${index}`,
        name: item.product || item.descriptor || 'Connected Device',
        manufacturer: item.manufacturer || 'Unknown Manufacturer',
        firmware: '--',
        health: 'READY',
        detail: item.descriptor || 'Connected Linux-visible device',
        transport: item.transport || 'USB',
        path: item.id || '--',
      })
    })

  return cards.filter((item) => item.name && item.health)
}

function summarizeRigHealth(cards = []) {
  const summary = { ACTIVE: 0, READY: 0, DEGRADED: 0, OTHER: 0 }
  cards.forEach((item) => {
    const key = String(item.health || '').toUpperCase()
    if (summary[key] != null) {
      summary[key] += 1
    } else {
      summary.OTHER += 1
    }
  })
  return summary
}

function buildMissionWidgets({ integrations = {}, rfHealth = {} }) {
  return [
    {
      id: 'ble-nrf',
      kicker: 'Bluetooth NRF',
      title: 'BLE NR5 Baseline',
      tone: integrations?.bleNr5?.manager?.active ? 'ACTIVE' : 'READY',
      detail: integrations?.bleNr5?.manager?.active ? 'BLE NRF session active.' : 'Ready for native BLE discovery.',
      lines: ['device census', 'identity graph', 'hard test queue'],
      kind: 'sdr-graph',
    },
    {
      id: 'wifi',
      kicker: 'WiFi Radar',
      title: 'Camera Hunt Sweep',
      tone: integrations?.wifiMk7?.manager?.capture_active ? 'ACTIVE' : 'READY',
      detail: integrations?.wifiMk7?.manager?.capture_active ? 'Packet hunt in progress.' : 'Launch radar-backed WiFi hunt.',
      lines: ['omni sweep', 'capture ring', 'threat bearings'],
      kind: 'radar',
    },
    {
      id: 'vision',
      kicker: 'Surveillance Feed',
      title: 'Visual Hunt Overlay',
      tone: integrations?.wifiMk7?.manager?.capture_active ? 'TRACKING' : 'STANDBY',
      detail: 'Operator surveillance panel for future camera/AI workflows.',
      lines: ['target boxes', 'motion framing', 'evidence timeline'],
      kind: 'surveillance',
    },
  ]
}

export default function HomeView({
    onNavigate,
  system,
  rfHealth,
  error,
  integrations,
}) {
  const { isPanelVisible } = usePanelPreferences('HOME')
  const connectedDevices = useMemo(
    () => buildConnectedProjectDevices({ system, rfHealth, integrations }),
    [system, rfHealth, integrations],
  )
  const rigHealth = useMemo(() => summarizeRigHealth(connectedDevices), [connectedDevices])
  const missionWidgets = useMemo(() => buildMissionWidgets({ integrations, rfHealth }), [integrations, rfHealth])
  const activeCount = rigHealth.ACTIVE + rigHealth.READY

  return (
    <>
      <section className="home-hero-panel">
        <div className="home-hero-copy">
          <span className="panel-kicker">GhostRedRecon Landing Surface</span>
          <h2>Linux operator console for connected recon hardware and toolchain status.</h2>
          <p>
            Home tracks only live connected project hardware and platform posture.
            No scan tables, no host specs, and no tool disclosure are shown here.
          </p>
          <div className="pill-row">
            <Pill text={`${connectedDevices.length} connected devices`} tone="green" />
            <Pill text={`${activeCount} ready paths`} tone="cyan" />
            <Pill text={`${rigHealth.DEGRADED} degraded`} tone={rigHealth.DEGRADED ? 'warning' : 'green'} />
          </div>
        </div>
        <div className="home-team-switch">
          <button type="button" className="home-team-button active red">
            <span>Red Team</span>
            <small>Offensive validation and adversarial posture</small>
          </button>
        </div>
      </section>

      {!!error && <section className="error-banner">{error}</section>}

      <main className="workspace home-hub-layout">
        <div className="main-column">
          {isPanelVisible('runtimeProfile') ? (
            <Panel kicker="Linux Operator Surface" title="Connected Device Matrix" className="command-panel">
              <div className="home-console-shell home-console-shell--large">
                <div className="home-console-grid" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                  <span />
                </div>
                <div className="home-console-scanline" aria-hidden="true" />
                <div className="home-console-orb home-console-orb-a" aria-hidden="true" />
                <div className="home-console-orb home-console-orb-b" aria-hidden="true" />
                <div className="home-console-head">
                  <div>
                    <span className="backend-stage-kicker">operator.home</span>
                    <strong>connected.hardware.console</strong>
                    <div className="home-alive-strip">
                      <span className="home-alive-dot" />
                      <span>platform alive</span>
                      <small>{system?.session_active ? `session active · ${fmtRelative(system?.session_telemetry?.session_started_at)}` : 'idle but armed'}</small>
                    </div>
                  </div>
                  <div className="pill-row">
                    <Pill text={`${connectedDevices.length} connected`} tone="green" />
                    <Pill text={`${activeCount} ready`} tone="cyan" />
                    <Pill text="RED" tone="danger" />
                  </div>
                </div>
                {connectedDevices.length ? (
                  <div className="home-device-grid">
                    {connectedDevices.map((item) => (
                      <div
                        key={item.id}
                        className={`home-device-card ${cardStateClass(item.health)}`}
                      >
                        <div className="home-device-card-head">
                          <strong>{shortText(item.name, 28)}</strong>
                          <Pill text={item.health} tone={healthTone(item.health)} />
                        </div>
                        <div className="home-device-meta">{shortText(item.manufacturer, 34)}</div>
                        <div className="home-device-foot">
                          <span>{shortText(item.transport, 16)}</span>
                          <span>{shortText(item.firmware || '--', 18)}</span>
                        </div>
                        <small>{shortText(item.detail, 72)}</small>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-box">No project hardware is connected. Attach hardware and it will appear here automatically.</div>
                )}
              </div>
            </Panel>
          ) : null}

          <section className="home-widget-grid">
            {missionWidgets.map((widget) => (
              <Panel key={widget.id} kicker={widget.kicker} title={widget.title} className="dashboard-panel">
                <div className={`home-mission-widget ${widget.kind}`}>
                  <div className="home-mission-head">
                    <Pill text={widget.tone} tone={widget.tone === 'ACTIVE' || widget.tone === 'TRACKING' ? 'green' : 'neutral'} />
                    <small>{widget.detail}</small>
                  </div>
                  <div className={`home-mission-canvas ${widget.kind}`} aria-hidden="true">
                    <span />
                    <span />
                    <span />
                    <span />
                  </div>
                  <div className="home-mission-lines">
                    {widget.lines.map((line) => (
                      <span key={line}>{line}</span>
                    ))}
                  </div>
                </div>
              </Panel>
            ))}
          </section>
        </div>

        <aside className="side-column home-hunt-column">
          <Panel kicker="Operator Launch Rail" title="HUNT TOOLS" className="dashboard-panel">
            <div className="home-hunt-tools">
              <button type="button" className="home-hunt-tool" onClick={() => onNavigate?.('WIFI-MK7')}>
                <strong>WIFI HUNT</strong>
                <small>Launch packet-truth WiFi hunt workflow.</small>
              </button>
              <button type="button" className="home-hunt-tool" onClick={() => onNavigate?.('BLE-NR5')}>
                <strong>BLUETOOTH HUNT (NRF)</strong>
                <small>Open native nRF Bluetooth hunt and validation.</small>
              </button>
              <button type="button" className="home-hunt-tool" onClick={() => onNavigate?.('CAMERA-HUNT')}>
                <strong>CAMERA HUNT (WIFI)</strong>
                <small>Go straight to WiFi-backed camera hunt.</small>
              </button>
            </div>
          </Panel>
        </aside>
      </main>

      <section className="home-chat-dock">
        <Panel kicker="Future Operator Control" title="MISSION CHAT CONSOLE" className="command-panel">
          <div className="home-chat-shell">
            <div className="home-chat-stream">
              <div className="home-chat-row system">
                <span>SYSTEM</span>
                <p>GhostRedRecon command layer online. Connected hardware inventory retained.</p>
              </div>
              <div className="home-chat-row analyst">
                <span>OPERATOR</span>
                <p>Future AI workflow placeholder. This area will accept tasking and orchestrate hunts.</p>
              </div>
              <div className="home-chat-row system">
                <span>QUEUE</span>
                <p>Suggested commands: launch WiFi Hunt, baseline BLE NR5, pivot to Camera Hunt.</p>
              </div>
            </div>
            <div className="home-chat-input">
              <div className="home-chat-prompt">ghost@operator&gt;</div>
              <div className="home-chat-field">AI mission console placeholder: natural-language tasking will live here.</div>
              <button type="button" className="home-chat-send" disabled>ARMED</button>
            </div>
          </div>
        </Panel>
      </section>
    </>
  )
}
