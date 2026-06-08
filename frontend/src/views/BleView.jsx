import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function BleView(props) {
  const config = getCategoryConfigForTab('BLE')
  return (
    <CategoryConsole
      {...props}
      tab="BLE"
      title="Bluetooth / BLE"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Channel"
    />
  )
}
