# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         zigbee_role_classifier.py
# VERSION:      v1.0.0 (ZIGBEE ROLE INTELLIGENCE)
# =============================================================================

from collections import defaultdict


class ZigbeeRoleClassifier:
    """
    Zigbee Role Classifier

    Classifies devices into:
    - Coordinator
    - Router
    - End Device
    """

    def __init__(self):

        # Device communication graph
        self.device_peers = defaultdict(set)

        # Activity tracking
        self.device_activity = defaultdict(int)

    # -----------------------------------------------------------------------------
    # PROCESS EVENT
    # -----------------------------------------------------------------------------
    def process_event(self, event):

        src = event.get("src_addr")
        dst = event.get("dst_addr")

        if not src:
            return

        # Track activity
        self.device_activity[src] += 1

        # Track communication graph
        if dst:
            self.device_peers[src].add(dst)
            self.device_peers[dst].add(src)

    # -----------------------------------------------------------------------------
    # CLASSIFY DEVICE
    # -----------------------------------------------------------------------------
    def classify(self, device_id, behavior_profile=None):

        activity = self.device_activity.get(device_id, 0)
        peers = len(self.device_peers.get(device_id, []))

        # ---------------------------------------------------------
        # CLASSIFICATION LOGIC
        # ---------------------------------------------------------

        # 🔥 Coordinator (high activity + many peers)
        if activity > 50 and peers > 5:
            return "coordinator"

        # 🔥 Router (moderate activity + multiple peers)
        elif activity > 20 and peers > 2:
            return "router"

        # 🔥 End Device (low activity or periodic)
        elif behavior_profile:
            if behavior_profile.get("type") in ["low_power_device", "periodic_beacon"]:
                return "end_device"

        # Default
        return "unknown"

    # -----------------------------------------------------------------------------
    # GET ALL ROLES
    # -----------------------------------------------------------------------------
    def get_roles(self, behavior_profiles):

        roles = {}

        for device_id in self.device_activity.keys():
            profile = behavior_profiles.get(device_id)
            roles[device_id] = self.classify(device_id, profile)

        return roles
