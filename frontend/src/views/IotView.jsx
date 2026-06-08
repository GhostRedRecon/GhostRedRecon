import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function IotView(props) {
  const config = getCategoryConfigForTab('IOT')

  return (
    <CategoryConsole
      {...props}
      tab="IOT"
      title="IoT"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Profile"
    />
  )
}
