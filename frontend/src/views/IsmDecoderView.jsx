import IntegrationWorkbench from '../components/IntegrationWorkbench'

export default function IsmDecoderView() {
  return (
    <IntegrationWorkbench
      tabKey="ISM-DECODER"
      integrationKey="rtl433"
      title="433 / 868 Decoder"
      subtitle="rtl_433-driven decode readiness for EU ISM sensors, remotes, alarms, and utility-like devices."
    />
  )
}
