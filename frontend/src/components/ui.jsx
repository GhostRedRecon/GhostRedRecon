export function Panel({ title, kicker, action, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <div>
          {kicker ? <div className="panel-kicker">{kicker}</div> : null}
          <h2>{title}</h2>
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

export function Pill({ text, tone = 'neutral' }) {
  return <span className={`pill pill-${tone}`}>{text}</span>
}

export function Metric({ label, value, detail }) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value ?? '--'}</div>
      {detail ? <div className="metric-detail">{detail}</div> : null}
    </div>
  )
}
