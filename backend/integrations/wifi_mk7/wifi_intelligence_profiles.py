from __future__ import annotations

CAMERA_VENDORS = (
    "hikvision",
    "dahua",
    "axis",
    "ezviz",
    "tapo",
    "xiaomi",
    "reolink",
    "wyze",
    "ring",
    "arlo",
    "amcrest",
    "imou",
    "lorex",
    "annke",
    "foscam",
    "eufy",
    "vstarcam",
    "uniview",
    "xiongmai",
    "xmeye",
    "yi technology",
    "tuya",
    "tp-link",
    "tplink",
    "tapo",
    "netatmo",
    "ring",
    "nest",
    "google nest",
    "aqara",
    "imilab",
    "360 smart camera",
    "yi home",
    "imou life",
)

CAMERA_HINTS = (
    "cam",
    "camera",
    "ipc",
    "cctv",
    "doorbell",
    "baby",
    "monitor",
    "tapo",
    "reolink",
    "wyze",
    "ezviz",
    "ring",
    "arlo",
    "imou",
    "lorex",
    "annke",
    "foscam",
    "eufy",
    "vstarcam",
    "xmeye",
    "onvif",
    "ipc_",
    "ipcam",
    "pet camera",
    "door camera",
    "doorbell",
    "surveillance",
    "security cam",
    "cam360",
    "indoor cam",
    "outdoor cam",
)

CAMERA_TLS_SIGNATURES = (
    "iotc",
    "iotcplatform",
    "tuya",
    "tuyaeu",
    "smartlife",
    "ezviz",
    "hik-connect",
    "hikvision",
    "dahuatech",
    "imou",
    "reolink",
    "ring",
    "dropcam",
    "nest",
    "googleapis",
    "camera",
    "ipc",
    "ipcam",
    "mihome",
    "mi.com",
    "xiaomi",
)

CAMERA_DISCOVERY_HINTS = (
    "_rtsp._tcp",
    "_onvif._tcp",
    "_camera._tcp",
    "ipcamera",
    "onvif",
    "rtsp",
    "media server",
    "mediaserver",
    "ipc",
)

HIGH_RISK_IMPORT_COUNTRIES = (
    "china",
    "hong kong",
)

ISP_ROUTER_HINTS = (
    "movistar",
    "vodafone",
    "orange",
    "jazztel",
    "masmovil",
    "pepephone",
    "o2wifi",
    "digi",
    "digifibra",
    "livebox",
    "digifibra",
    "fritz",
)

DEFAULT_PASSWORD_HINTS = (
    "admin",
    "password",
    "default",
    "welcome",
    "12345678",
    "123456789",
    "qwerty",
    "wifi1234",
)

SPANISH_ISP_HINTS = (
    "movistar",
    "vodafone",
    "orange",
    "jazztel",
    "masmovil",
    "pepephone",
    "o2wifi",
    "digi",
    "digifibra",
    "livebox",
)

CHINESE_OEM_HINTS = (
    "hikvision",
    "dahua",
    "ezviz",
    "imou",
    "reolink",
    "tuya",
    "smart life",
    "vstarcam",
    "xiongmai",
    "xmeye",
    "tenda",
    "mercusys",
    "xiaomi",
    "mijia",
)

EXTENDER_HINTS = (
    "plus",
    "mesh",
    "ext",
    "extender",
    "repeater",
    "fronthaul",
    "backhaul",
)

ONBOARDING_HINTS = (
    "setup",
    "config",
    "provision",
    "miap",
    "onboard",
    "direct-",
)

VACUUM_HINTS = (
    "roborock",
    "vacuum",
    "roomba",
    "ecovacs",
    "dreame",
)

ROUTER_HINTS = (
    "movistar",
    "vodafone",
    "livebox",
    "router",
    "gateway",
    "tplink",
    "tp-link",
    "asus",
    "fritz",
    "netgear",
    "linksys",
    "miwifi",
    "digifibra",
)

HUB_HINTS = (
    "hub",
    "bridge",
    "smartthings",
    "aqara",
)

PRINTER_HINTS = (
    "printer",
    "hp-",
    "epson",
    "brother",
    "canon",
)

TV_HINTS = (
    "tv",
    "roku",
    "chromecast",
    "firetv",
    "bravia",
    "samsung",
    "lgwebos",
    "appletv",
)

PHONE_VENDORS = (
    "apple",
    "samsung",
    "google",
    "oneplus",
    "xiaomi",
    "huawei",
)

DEVICE_VALUE_SCORES = {
    "WiFi Camera": 95,
    "ISP Router / CPE": 85,
    "Mesh / Extender": 72,
    "IoT Onboarding": 78,
    "Robot Vacuum": 68,
    "Router / AP": 90,
    "IoT Hub": 85,
    "Printer": 75,
    "Smart TV": 60,
    "Phone": 40,
    "Client Device": 50,
    "WiFi Network": 55,
}

PRIORITY_THRESHOLDS = {
    "CRITICAL": 85,
    "HIGH": 70,
    "MEDIUM": 50,
}
