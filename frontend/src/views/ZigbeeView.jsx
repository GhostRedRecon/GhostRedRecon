import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function ZigbeeView(props) {
  const config = getCategoryConfigForTab('ZIGBEE')

  return (
    <CategoryConsole
      {...props}
      tab="ZIGBEE"
      title="Zigbee"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Channel"
    />
  )
}
