import { Panel, Pill } from './ui'

function formatTime(timestamp) {
  if (!timestamp) return '--'
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleTimeString()
}

export default function RealtimeTopologyRail({
  kicker = 'Realtime Topology',
  title = 'Live Data Flow',
  tone = 'cyan',
  stateLabel = 'READY',
  subtitle = '',
  lastUpdate = null,
  nodes = [],
  edges = [],
}) {
  return (
    <Panel
      kicker={kicker}
      title={title}
      className="topology-rail-panel"
      action={<Pill text={stateLabel} tone={tone} />}
    >
      <div className="topology-rail-head">
        <div className="topology-rail-radar">
          <span className="topology-rail-radar-ring topology-rail-radar-ring-a" />
          <span className="topology-rail-radar-ring topology-rail-radar-ring-b" />
          <span className="topology-rail-radar-dot" />
        </div>
        <div className="topology-rail-meta">
          <strong>{subtitle || 'Live graph is waiting for scan activity.'}</strong>
          <small>Last update {formatTime(lastUpdate)}</small>
        </div>
      </div>

      <div className="topology-lane">
        {nodes.map((node, index) => (
          <div key={`${node.label}-${index}`} className={`topology-node ${node.tone || 'neutral'}${node.active ? ' active' : ''}`}>
            <span>{node.group || 'Node'}</span>
            <strong>{node.label}</strong>
            {node.detail ? <small>{node.detail}</small> : null}
          </div>
        ))}
      </div>

      <div className="topology-edge-list">
        {edges.length ? edges.map((edge, index) => (
          <div key={`${edge.label}-${index}`} className="topology-edge-row">
            <span>{edge.label}</span>
            <strong>{edge.value}</strong>
          </div>
        )) : (
          <div className="empty-box">No topology edges yet.</div>
        )}
      </div>
    </Panel>
  )
}
