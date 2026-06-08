import { useEffect, useState } from 'react'
import { Metric, Panel, Pill } from '../components/ui'
import { API_BASE } from '../lib/runtime'
import {
  TAB_PANEL_DEFINITIONS,
  getResolvedPanelPreferences,
  resetPanelPreferences,
  setPanelPreference,
  usePanelPreferences,
} from '../lib/viewPreferences'

export default function SettingsView({ diagnostics, identities, integrations }) {
  const { isPanelVisible } = usePanelPreferences('SETTINGS')
  const dependencies = diagnostics?.dependencies || {}
  const optionalModules = diagnostics?.optional_modules || {}
  const artifactCounts = diagnostics?.artifacts || {}
  const projectConfig = diagnostics?.project_config || {}
  const activeSdrConfig = diagnostics?.active_sdr_config || {}
  const integrationRows = [
    ['WiFi MK7', integrations?.wifiMk7],
    ['BLE NR5', integrations?.bleNr5],
  ]
  const [panelState, setPanelState] = useState(() => (
    Object.keys(TAB_PANEL_DEFINITIONS).reduce((acc, tabKey) => {
      acc[tabKey] = getResolvedPanelPreferences(tabKey)
      return acc
    }, {})
  ))

  useEffect(() => {
    function refresh() {
      setPanelState(
        Object.keys(TAB_PANEL_DEFINITIONS).reduce((acc, tabKey) => {
          acc[tabKey] = getResolvedPanelPreferences(tabKey)
          return acc
        }, {}),
      )
    }

    window.addEventListener('ghostredrecon:view-panels:changed', refresh)
    window.addEventListener('storage', refresh)
    return () => {
      window.removeEventListener('ghostredrecon:view-panels:changed', refresh)
      window.removeEventListener('storage', refresh)
    }
  }, [])

  function handlePanelToggle(tabKey, panelKey, checked) {
    setPanelPreference(tabKey, panelKey, checked)
    setPanelState((current) => ({
      ...current,
      [tabKey]: {
        ...(current?.[tabKey] || {}),
        [panelKey]: checked,
      },
    }))
  }

  function handleResetPanels(tabKey) {
    resetPanelPreferences(tabKey)
    setPanelState((current) => ({
      ...current,
      [tabKey]: getResolvedPanelPreferences(tabKey),
    }))
  }

  return (
    <main className="workspace category-workspace">
      <div className="main-column">
        <section className="metrics-grid compact-metrics">
          <Metric label="Identities" value={artifactCounts.identities ?? '--'} detail="Identity snapshots" />
        </section>

        {isPanelVisible('deployment') ? (
        <Panel kicker="Runtime" title="Deployment Settings">
          <div className="guidance-list">
            <div className="guidance-item"><strong>Backend API:</strong> {API_BASE}</div>
            <div className="guidance-item"><strong>Frontend:</strong> Vite + React on port 5174</div>
            <div className="guidance-item"><strong>Control Scripts:</strong> `scripts/start.sh`, `scripts/stop.sh`, `scripts/debug.sh`</div>
            <div className="guidance-item"><strong>Current Goal:</strong> stabilize SIGINT categories and backend contract before exposing higher-risk workflows.</div>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('dependencies') ? (
        <Panel kicker="Dependencies" title="Host Diagnostics">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Dependency</th>
                  <th>Status</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(dependencies).map(([key, value]) => (
                  <tr key={key}>
                    <td>{key}</td>
                    <td><Pill text={value?.installed ? 'installed' : 'missing'} tone={value?.installed ? 'green' : 'amber'} /></td>
                    <td>{value?.output || value?.path || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('modules') ? (
        <Panel kicker="Runtime Modules" title="Optional Engine Readiness">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Status</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(optionalModules).map(([key, value]) => (
                  <tr key={key}>
                    <td>{key}</td>
                    <td><Pill text={value?.available ? 'ready' : 'degraded'} tone={value?.available ? 'green' : 'amber'} /></td>
                    <td>{value?.detail || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('integrations') ? (
        <Panel kicker="External Integrations" title="Tool Readiness">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {integrationRows.map(([label, payload]) => {
                  const installed = payload?.status?.installed
                  const running = payload?.process?.running || payload?.manager?.running
                  const status = installed ? (running ? 'running' : 'installed') : 'missing'
                  const detail =
                    payload?.status?.path
                    || payload?.installation_hint
                    || '--'
                  return (
                    <tr key={label}>
                      <td>{label}</td>
                      <td><Pill text={status} tone={installed ? (running ? 'green' : 'cyan') : 'amber'} /></td>
                      <td>{detail}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('wifiMk7Red') ? (
        <Panel kicker="WiFi MK7 RED" title="RED TEAM Operator Profile">
          <div className="guidance-list">
            <div className="guidance-item"><strong>Scoring Model:</strong> weighted target scoring using exposure, device value, proximity, behavior confidence, persistence, and noise penalty.</div>
            <div className="guidance-item"><strong>RED Outputs:</strong> top targets, environment map, vendor risk concentration, anomaly leads, and likely device clusters.</div>
            <div className="guidance-item"><strong>CLI Stack:</strong> `airodump-ng`, `tshark`, `tcpdump`, `kismet`, `nmap`, `masscan` are present on this host. `bettercap` should be installed to complete the recommended operator stack.</div>
            <div className="guidance-item"><strong>Protocol Intelligence:</strong> DHCP hostnames, DNS query names, mDNS, HTTP user agents, TLS SNI, WPS identity, and service exposure are now folded into WiFi MK7 risk and device prediction.</div>
          </div>
        </Panel>
        ) : null}

        {isPanelVisible('layoutControl') ? (
        <Panel kicker="Layout Control" title="Configurable Tab Windows">
          <div className="settings-panel-groups">
            {Object.entries(TAB_PANEL_DEFINITIONS).map(([tabKey, panels]) => (
              <section key={tabKey} className="settings-panel-group">
                <div className="settings-panel-group-head">
                  <strong>{tabKey}</strong>
                  <button className="mini-action" onClick={() => handleResetPanels(tabKey)}>Reset</button>
                </div>
                <div className="settings-toggle-grid">
                  {panels.map((panel) => (
                    <label key={`${tabKey}-${panel.key}`} className="settings-toggle-card">
                      <input
                        type="checkbox"
                        checked={panelState?.[tabKey]?.[panel.key] !== false}
                        onChange={(event) => handlePanelToggle(tabKey, panel.key, event.target.checked)}
                      />
                      <span>{panel.label}</span>
                    </label>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </Panel>
        ) : null}
      </div>
      <div className="side-column">
        {isPanelVisible('projectConfig') ? (
        <Panel kicker="Configuration" title="Loaded Project Config">
          <pre className="json-box">{Object.keys(projectConfig).length ? JSON.stringify(projectConfig, null, 2) : 'Project config unavailable.'}</pre>
        </Panel>
        ) : null}
        {isPanelVisible('identities') ? (
        <Panel kicker="Identities" title="Stored Identity Snapshots">
          <pre className="json-box">{identities?.length ? JSON.stringify(identities.slice(0, 10), null, 2) : 'No identity snapshots found.'}</pre>
        </Panel>
        ) : null}
      </div>
    </main>
  )
}
