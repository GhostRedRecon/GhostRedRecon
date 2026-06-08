import CategoryConsole from '../components/CategoryConsole'
import { getCategoryConfigForTab } from '../lib/runtime'

export default function SubGhzView(props) {
  const config = getCategoryConfigForTab('SUB-GHZ')

  return (
    <CategoryConsole
      {...props}
      tab="SUB-GHZ"
      title="Sub-GHz"
      subtitle={`Default tune ${config.defaultFrequencyMHz} MHz`}
      config={config}
      focusMetricLabel="Channel"
    />
  )
}
