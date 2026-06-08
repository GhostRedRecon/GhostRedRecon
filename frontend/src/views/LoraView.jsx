import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function LoraView(props) {
  const config = getCategoryConfigForTab('LORA')

  return (
    <CategoryConsole
      {...props}
      tab="LORA"
      title="LoRa"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Profile"
    />
  )
}
