import { useEffect } from 'react'

export default function SpectrumCanvas({ bins, canvasId = 'spectrum-canvas' }) {
  useEffect(() => {
    const canvas = document.getElementById(canvasId)
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    const width = (canvas.width = canvas.clientWidth)
    const height = (canvas.height = canvas.clientHeight)

    ctx.clearRect(0, 0, width, height)
    ctx.fillStyle = '#031018'
    ctx.fillRect(0, 0, width, height)

    if (!Array.isArray(bins) || !bins.length) return

    const min = Math.min(...bins)
    const max = Math.max(...bins)
    const span = max - min || 1
    const step = width / bins.length

    ctx.beginPath()
    bins.forEach((raw, index) => {
      const normalized = (raw - min) / span
      const x = index * step
      const y = height - normalized * (height - 8) - 4
      if (index === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.strokeStyle = '#2dd4bf'
    ctx.lineWidth = 1.4
    ctx.stroke()
  }, [bins, canvasId])

  return <canvas id={canvasId} className="spectrum-canvas" />
}
