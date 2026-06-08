import React from 'react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, message: '', stack: '' }
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      message: error?.message || 'Unknown UI error',
    }
  }

  componentDidCatch(error, info) {
    this.setState({
      stack: info?.componentStack || '',
      message: error?.message || 'Unknown UI error',
    })
  }

  componentDidUpdate(prevProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false, message: '', stack: '' })
    }
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children
    }

    return (
      <section className="error-boundary-panel">
        <div className="error-boundary-kicker">Operator Fault</div>
        <h2>Tab rendering failed</h2>
        <p>
          The interface caught a frontend error and prevented a blank screen.
          Refresh the page or switch tabs after reviewing the fault details below.
        </p>
        <div className="error-boundary-detail">
          <strong>Error:</strong> {this.state.message}
        </div>
        {this.state.stack ? (
          <pre className="error-boundary-stack">{this.state.stack}</pre>
        ) : null}
      </section>
    )
  }
}
