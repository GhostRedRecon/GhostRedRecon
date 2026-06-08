import { BRANDING } from '../lib/branding'

export default function HeroHeader({
  statusLine,
  busy,
  eyebrow,
  title,
  operatorMessage,
  blockReason,
  hardwareStatus = [],
  commandRail = {},
  workspaceLabel = '',
  workspaceDetail = '',
  backendState = 'READY',
  apiBase = '',
  contextSummary = [],
}) {
  const actions = commandRail.actions || []
  const primaryNote = commandRail.primaryNote || 'Command actions follow the active hardware path.'
  const notes = commandRail.notes || []
  const headerContext = [
    { label: 'Workspace', value: workspaceLabel || 'HOME', detail: workspaceDetail || 'Operator context' },
    { label: 'Backend', value: backendState, detail: apiBase || '--' },
    ...contextSummary,
  ]

  return (
    <header className="hero command-hero">
      <div className="hero-status-block hero-pane-status">
        <div className="hero-brand-lockup" aria-label={BRANDING.product}>
          <div className="hero-brand-name">{BRANDING.product}</div>
          <div className="hero-brand-tagline">{BRANDING.tagline}</div>
        </div>
        <div className="eyebrow">{eyebrow}</div>
        <div className="hero-title-row">
          <h1>{title}</h1>
          <span className="hero-status-line">{statusLine}</span>
        </div>
        {blockReason ? <div className="hero-inline-alert">{blockReason}</div> : null}
        <div className="hero-hardware-strip">
          {hardwareStatus.map((item) => (
            <div key={item.label} className={`hero-hardware-chip ${item.tone || ''}`}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              {item.detail ? <em>{item.detail}</em> : null}
            </div>
          ))}
        </div>
        <div className="hero-context-strip">
          {headerContext.map((item) => (
            <div key={item.label} className="hero-context-chip">
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              {item.detail ? <em>{item.detail}</em> : null}
            </div>
          ))}
        </div>
      </div>

      <div className={`hero-operator-window hero-pane-guidance ${operatorMessage?.tone || 'info'}`}>
        <div className="hero-operator-head">
          <div className="hero-operator-kicker">Operator Guidance</div>
          <div className="hero-operator-live">
            <span className="hero-operator-pulse" />
            Live
          </div>
        </div>
        <div className="hero-operator-toolbar">
          <div className="mode-switch" aria-label="Operator mode">
            <span className="mode-pill active">RED TEAM</span>
          </div>
        </div>
        <div className="hero-guidance-row">
          <strong>{operatorMessage?.headline || 'Console ready'}</strong>
          <span className="hero-operator-detail">{operatorMessage?.detail || 'Awaiting operator action.'}</span>
        </div>
        <div className="hero-operator-tags">
          {(operatorMessage?.tags || []).map((tag) => (
            <span key={tag} className="hero-operator-tag">{tag}</span>
          ))}
        </div>
      </div>

      <div className="hero-pane-actions">
        <div className="hero-command-surface">
          <div className="hero-command-head">
            <div className="hero-command-kicker">{commandRail.kicker || 'Command Rail'}</div>
            <div className="hero-command-state">{commandRail.state || 'Idle'}</div>
          </div>

          <div className={`hero-actions compact hero-actions-${Math.max(actions.length, 1)}`}>
            {actions.map((action) => (
              <button
                key={action.label}
                disabled={busy || action.disabled}
                onClick={action.onClick}
                className={action.tone === 'primary' ? 'primary' : ''}
              >
                {action.label}
              </button>
            ))}
          </div>

          <div className="hero-command-meta">
            <div className="hero-command-primary-note">{primaryNote}</div>
            <div className="hero-command-notes">
              {notes.map((note) => (
                <span key={note} className="hero-command-note">{note}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </header>
  )
}
