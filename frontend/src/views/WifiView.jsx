import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function WifiView(props) {
  const config = getCategoryConfigForTab('WIFI')

  return (
    <CategoryConsole
      {...props}
      tab="WIFI"
      title="WiFi"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Channel"
    />
  )
}
