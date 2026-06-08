import DeviceList from '../components/DeviceList'
import { Metric, Panel } from '../components/ui'
import { usePanelPreferences } from '../lib/viewPreferences'

export default function DevicesView({ devices, selectedDevice, onSelectDevice }) {
  const { isPanelVisible } = usePanelPreferences('DEVICES')

  return (
    <main className="workspace category-workspace">
      <div className="main-column">
        <section className="metrics-grid compact-metrics">
          <Metric label="Device Entities" value={devices.length} detail="Fused identities" />
          <Metric label="Selected Device" value={selectedDevice?.device_id || '--'} detail="Focused entity" />
        </section>

        {isPanelVisible('inventory') ? (
        <Panel kicker="Fusion Graph" title="Device Inventory">
          <DeviceList devices={devices.slice(0, 30)} onSelect={onSelectDevice} />
        </Panel>
        ) : null}
      </div>

      {isPanelVisible('detail') ? (
      <div className="side-column">
        <Panel kicker="Device Detail" title={selectedDevice?.device_id || 'Selected Device'}>
          <pre className="json-box">{selectedDevice ? JSON.stringify(selectedDevice, null, 2) : 'Select a device to inspect the fused entity payload.'}</pre>
        </Panel>
      </div>
      ) : null}
    </main>
  )
}
