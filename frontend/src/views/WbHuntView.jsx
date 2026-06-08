import IntegrationWorkbench from '../components/IntegrationWorkbench'

export default function WbHuntView({ onPivot }) {
  return (
    <IntegrationWorkbench
      tabKey="WB-HUNT"
      integrationKey="wb_hunt"
      title="WB Hunt"
      subtitle="HackRF-wide one-pass peak hunt for unknown emitters, suspicious bursts, and RF hotspot discovery."
      onPivot={onPivot}
    />
  )
}
