# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/intel/phy/rf_protocol_database.py
# VERSION:      v1.0.0 (GLOBAL RF DEVICE INTELLIGENCE DATABASE)
# LAST UPDATED: 2026-03-07
#
# =============================================================================
# ARCHITECTURE
# =============================================================================
#
# HackRF SDR
#   ↓
# SDRController
#   ↓
# LiveFFT
#   ↓
# ReconEngine
#   ↓
# RFProtocolClassifier
#   ↓
# RFProtocolDatabase   ← THIS FILE
#   ↓
# DeviceIdentityEngine
#
# This database provides:
#
#   • RF protocol families
#   • spectrum bands
#   • bandwidth fingerprints
#   • modulation types
#   • device class intelligence
#
# Used for passive RF fingerprinting and device classification.
#
# =============================================================================
# DESIGN PRINCIPLES
# =============================================================================
#
# ✔ Global spectrum coverage (EU / US / Asia)
# ✔ Passive RF intelligence
# ✔ Device-class inference
# ✔ SDR-friendly heuristics
# ✔ Modular protocol definitions
# ✔ Expandable to thousands of devices
#
# =============================================================================
# RESPONSIBILITY
# =============================================================================
#
# This database is responsible for:
#
#   • Protocol family definitions
#   • RF band intelligence
#   • Device classification mapping
#   • Security characteristics
#
# It does NOT perform:
#
#   ✘ signal detection
#   ✘ SDR processing
#   ✘ FFT analysis
#
# =============================================================================


PROTOCOL_FAMILIES = {

# -------------------------------------------------------------------------
# WIFI
# -------------------------------------------------------------------------

"wifi_24ghz": {

    "band_mhz": (2400.0, 2483.5),
    "bandwidth_khz": (15000, 25000),
    "modulation": "OFDM",
    "security": "WPA2/WPA3 AES",

    "devices": [

        "WiFi Router",
        "WiFi Mesh Node",
        "WiFi Access Point",
        "WiFi Camera",
        "WiFi Smart TV",
        "WiFi Laptop",
        "WiFi Smartphone",
        "WiFi Tablet",
        "WiFi Printer",
        "WiFi Smart Speaker",
        "WiFi Smart Display",
        "WiFi Gaming Console",
        "WiFi Robot Vacuum",
        "WiFi Refrigerator",
        "WiFi Microwave",
        "WiFi Washing Machine",
        "WiFi Dishwasher",
        "WiFi Oven",
        "WiFi Air Conditioner",
        "WiFi Smart Thermostat",
        "WiFi Baby Monitor",
        "WiFi Doorbell Camera",
        "WiFi NAS Storage",
        "WiFi Mesh Repeater",
        "WiFi Industrial Gateway",
        "WiFi Smart Monitor",
        "WiFi Digital Signage",
        "WiFi Retail Kiosk",
        "WiFi Smart POS",
        "WiFi Warehouse Scanner"

    ]
},

# -------------------------------------------------------------------------
# BLUETOOTH LE
# -------------------------------------------------------------------------

"bluetooth_le": {

    "band_mhz": (2400.0, 2483.5),
    "bandwidth_khz": (800, 1500),
    "modulation": "GFSK",
    "security": "AES-CCM",

    "devices": [

        "BLE Beacon",
        "BLE Fitness Tracker",
        "BLE Smart Watch",
        "BLE Smart Ring",
        "BLE Asset Tracker",
        "BLE Smart Lock",
        "BLE Smart Scale",
        "BLE Medical Sensor",
        "BLE Thermometer",
        "BLE Glucose Monitor",
        "BLE Blood Pressure Monitor",
        "BLE Pulse Oximeter",
        "BLE Smart Thermostat",
        "BLE Keyboard",
        "BLE Mouse",
        "BLE Game Controller",
        "BLE Smart Tag",
        "BLE Door Sensor",
        "BLE Motion Sensor",
        "BLE Light Controller",
        "BLE Smart Plug",
        "BLE Smart Bulb",
        "BLE Smart Remote",
        "BLE Smart Button",
        "BLE Automotive Sensor",
        "BLE Bike Computer",
        "BLE Hearing Aid",
        "BLE Pet Tracker",
        "BLE Fitness Equipment",
        "BLE Indoor Positioning Beacon"

    ]
},

# -------------------------------------------------------------------------
# ZIGBEE / IEEE 802.15.4
# -------------------------------------------------------------------------

"zigbee": {

    "band_mhz": (2400.0, 2483.5),
    "bandwidth_khz": (1500, 3000),
    "modulation": "DSSS-OQPSK",
    "security": "AES-128",

    "devices": [

        "Zigbee Motion Sensor",
        "Zigbee Door Sensor",
        "Zigbee Window Sensor",
        "Zigbee Smart Plug",
        "Zigbee Temperature Sensor",
        "Zigbee Humidity Sensor",
        "Zigbee Smoke Detector",
        "Zigbee Water Leak Sensor",
        "Zigbee Light Bulb",
        "Zigbee LED Strip",
        "Zigbee Wall Switch",
        "Zigbee Dimmer Switch",
        "Zigbee Smart Lock",
        "Zigbee Garage Controller",
        "Zigbee Hub",
        "Zigbee Router Node",
        "Zigbee Smart Blind",
        "Zigbee Curtain Controller",
        "Zigbee HVAC Controller",
        "Zigbee Irrigation Controller",
        "Zigbee Industrial Sensor",
        "Zigbee Warehouse Sensor",
        "Zigbee Smart Meter Gateway",
        "Zigbee Lighting Controller",
        "Zigbee Smart Thermostat"

    ]
},

# -------------------------------------------------------------------------
# 433 MHz SRD
# -------------------------------------------------------------------------

"srd_433": {

    "band_mhz": (433.05, 434.79),
    "bandwidth_khz": (5, 40),
    "modulation": "OOK / ASK / FSK",
    "security": "Often none or rolling code",

    "devices": [

        "433MHz Door Sensor",
        "433MHz Window Sensor",
        "433MHz Weather Station",
        "433MHz Outdoor Thermometer",
        "433MHz Alarm Sensor",
        "433MHz Motion Detector",
        "433MHz Garage Remote",
        "433MHz Gate Controller",
        "433MHz RF Remote Switch",
        "433MHz Smart Plug",
        "433MHz Power Meter",
        "433MHz Tire Pressure Sensor",
        "433MHz Wireless Doorbell",
        "433MHz Panic Button",
        "433MHz Remote Key Fob",
        "433MHz Security Panel",
        "433MHz Industrial Sensor",
        "433MHz Agriculture Sensor",
        "433MHz Smart Irrigation Node",
        "433MHz RF Light Switch"

    ]
},

# -------------------------------------------------------------------------
# 868 MHz EUROPE ISM
# -------------------------------------------------------------------------

"etsi_868": {

    "band_mhz": (863.0, 870.0),
    "bandwidth_khz": (20, 300),
    "modulation": "FSK / GFSK",
    "security": "Device dependent",

    "devices": [

        "868MHz Smart Meter",
        "868MHz Gas Meter",
        "868MHz Water Meter",
        "868MHz Smart Valve",
        "868MHz Alarm System",
        "868MHz Industrial Sensor",
        "868MHz Parking Sensor",
        "868MHz Environmental Sensor",
        "868MHz Building Sensor",
        "868MHz Warehouse Monitor",
        "868MHz Smart Lighting Node",
        "868MHz HVAC Sensor",
        "868MHz Agriculture Node",
        "868MHz Soil Sensor",
        "868MHz Weather Station",
        "868MHz Flood Sensor",
        "868MHz Structural Monitor",
        "868MHz Smart Grid Sensor",
        "868MHz Pipeline Monitor",
        "868MHz Utility Telemetry Node"

    ]
},

# -------------------------------------------------------------------------
# LORA / LORAWAN
# -------------------------------------------------------------------------

"lora": {

    "bands_mhz": [

        (863.0, 870.0),
        (902.0, 928.0),
        (915.0, 928.0)

    ],

    "bandwidth_khz": (100, 500),
    "modulation": "LoRa Chirp Spread Spectrum",
    "security": "LoRaWAN AES-128",

    "devices": [

        "LoRa Sensor Node",
        "LoRa Gateway",
        "LoRa Tracker",
        "LoRa Agriculture Sensor",
        "LoRa Smart Meter",
        "LoRa Parking Sensor",
        "LoRa Environmental Sensor",
        "LoRa Asset Tracker",
        "LoRa Water Meter",
        "LoRa Industrial Sensor",
        "LoRa Flood Sensor",
        "LoRa Wildlife Tracker",
        "LoRa Soil Moisture Sensor",
        "LoRa Smart City Node",
        "LoRa Street Light Controller",
        "LoRa Pipeline Sensor",
        "LoRa Utility Monitor",
        "LoRa Weather Station",
        "LoRa Fleet Tracker",
        "LoRa Cold Chain Sensor"

    ]
},

# -------------------------------------------------------------------------
# DRONES / ROBOTICS
# -------------------------------------------------------------------------

"drones_robotics": {

    "bands_mhz": [

        (2400, 2500),
        (5725, 5850)

    ],

    "modulation": "FHSS / OFDM / Proprietary",
    "security": "Vendor dependent",

    "devices": [

        "Consumer Drone Controller",
        "Consumer Drone Telemetry",
        "FPV Drone Video",
        "FPV Drone Controller",
        "DJI Drone Link",
        "Autel Drone Link",
        "Parrot Drone Link",
        "Industrial Inspection Drone",
        "Agriculture Drone",
        "Warehouse Robot",
        "Delivery Robot",
        "Autonomous Robot Controller",
        "Remote Robotic Arm",
        "Industrial AGV",
        "Security Patrol Robot",
        "Mining Robot",
        "Construction Robot",
        "Agriculture Rover",
        "Remote Submarine Drone",
        "Search And Rescue Robot"

    ]
}

}
