import { fmt } from '../lib/runtime'

function getBrandLead(device) {
  return (
    device.vendor
    || device.brand
    || device.rf_vendor_candidate
    || device.lora_lab_profile_candidates?.[0]?.vendor
    || '--'
  )
}

function getProductLead(device) {
  return (
    device.product
    || device.device_type
    || device.device_category
    || device.lora_device_type_hint
    || device.lora_lab_profile_name
    || device.lora_lab_profile_candidates?.[0]?.profile_name
    || device.device_id
  )
}

export default function DeviceList({ devices, onSelect }) {
  return (
    <div className="device-list">
      {devices.map((device, index) => (
        <button
          key={device.device_id || `device-${index}`}
          className="device-card"
          onClick={() => onSelect(device)}
        >
          <div className="device-title">{fmt(getBrandLead(device))}</div>
          <div className="device-meta device-lead">{fmt(getProductLead(device))}</div>
          <div className="device-meta">{fmt(device.device_id)}</div>
          {device.mac_address ? <div className="device-meta">{fmt(device.mac_address)}</div> : null}
          <div className="device-meta">
            {fmt((device.protocols || []).join(' / ') || device.protocol)}
          </div>
          {device.privacy_state || device.seen_count ? (
            <div className="device-meta">
              {fmt(device.privacy_state || 'privacy unknown')}
              {device.seen_count ? ` · seen ${fmt(device.seen_count)}` : ''}
            </div>
          ) : null}
        </button>
      ))}
      {!devices.length && <div className="empty-box">No fused devices available.</div>}
    </div>
  )
}
