# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/multi_protocol_engine.py
# VERSION:      v1.0.0 (MULTI PROTOCOL FUSION)
# =============================================================================

from backend.intel.ble.ble_decoder_worker import BLEDecoderWorker
from backend.intel.zigbee.zigbee_decoder_worker import ZigbeeDecoderWorker


class MultiProtocolEngine:

    def __init__(self):

        self.ble = BLEDecoderWorker()
        self.zigbee = ZigbeeDecoderWorker()

    def start(self):
        self.ble.start()
        self.zigbee.start()

    def stop(self):
        self.ble.stop()
        self.zigbee.stop()

    def get_events(self):

        events = []
        events += self.ble.get_events()
        events += self.zigbee.get_events()

        return events
