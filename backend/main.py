# =============================================================================
# PROJECT:      GHOSTRECON
# FILE:         backend/main.py
# VERSION:      v21.0.0 (PRODUCTION — VERIFIED API + RUNTIME + DEVICE LAYER)
# UPDATED:      2026-03-22
# =============================================================================

# =============================================================================
# 🧠 ARCHITECTURE OVERVIEW
# =============================================================================
#
#                ┌──────────────────────────────┐
#                │          FastAPI             │
#                │        (THIS FILE)           │
#                └────────────┬─────────────────┘
#                             │
#      ┌──────────────────────┼──────────────────────┐
#      │                      │                      │
#  System API           RF / Live API           Intel API
#      │                      │                      │
#      └────────────── Runtime (DI CORE) ────────────┘
#                             │
#        SDR → FFT → Recon → Signal → DeviceFusion → API
#
# =============================================================================
# 🎯 PURPOSE
# =============================================================================
#
# This file is the ENTRYPOINT of the GhostRecon backend.
#
# Responsibilities:
#   ✔ Initialize Runtime (single system brain)
#   ✔ Inject runtime into FastAPI (app.state.runtime)
#   ✔ Register ALL API routers
#   ✔ Ensure validator compatibility
#   ✔ Provide safe degraded startup if runtime fails
#
# =============================================================================
# 🧩 RESPONSIBILITIES
# =============================================================================
#
# CORE RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Initialize Runtime exactly once
# ✔ Inject runtime into FastAPI state
# ✔ Register all API routers
# ✔ Maintain endpoint consistency across versions
# ✔ Ensure Phase 1 / 2 / 3 validator compatibility
#
# SAFETY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Fail-safe runtime initialization
# ✔ API remains operational even if runtime fails
# ✔ All endpoints return safe fallback values
#
# COMPATIBILITY RESPONSIBILITIES
# -----------------------------------------------------------------------------
# ✔ Preserve all existing routes
# ✔ Preserve router prefixes
# ✔ Preserve validator endpoints
# ✔ Preserve runtime injection behavior
#
# =============================================================================
# ❌ NON-RESPONSIBILITIES
# =============================================================================
#
# ✘ RF processing
# ✘ Signal classification
# ✘ Device fusion logic
# ✘ Runtime orchestration logic
#
# =============================================================================
# ⚙️ DESIGN PRINCIPLES
# =============================================================================
#
# 1. SINGLETON RUNTIME
# -----------------------------------------------------------------------------
# Runtime must exist as a single instance and be injected into FastAPI.
#
# 2. CLEAN ROUTER SEPARATION
# -----------------------------------------------------------------------------
# Each API module is independent and registered here.
#
# 3. FAIL-SAFE STARTUP
# -----------------------------------------------------------------------------
# Runtime failure must NOT crash the API.
#
# 4. VALIDATOR-FIRST DESIGN
# -----------------------------------------------------------------------------
# All required endpoints must be exposed for Phase 1 / 2 / 3 validation.
#
# 5. NON-BREAKING EVOLUTION
# -----------------------------------------------------------------------------
# Future modules (Device Intelligence, Attack Layer) can be added without
# modifying existing API contracts.
#
# =============================================================================
# 📡 API SURFACE
# =============================================================================
#
# System:
#   /api/system/*
#
# RF / Live:
#   /api/rf/*
#   /api/live/*
#
# Intel:
#   /api/intel/*
#
# Device Intelligence (Phase 3):
#   /api/devices
#   /api/devices/top
#   /api/device/{id}
#   /api/devices/summary
#
# Attack:
#   /api/attack/*
#
# =============================================================================
# 🔍 RUNTIME BEHAVIOR
# =============================================================================
#
# Startup:
#   - Runtime is constructed
#   - Injected into app.state.runtime
#   - All routers gain access via request.app.state.runtime
#
# Failure mode:
#   - Runtime fails → app.state.runtime = None
#   - APIs still respond safely
#
# =============================================================================
# 🔄 CHANGES IN v21.0.0
# =============================================================================
#
# ✔ Preserved all existing routes and prefixes
# ✔ Verified device_api integration for Phase 3
# ✔ Ensured runtime injection compatibility with all APIs
# ✔ Added explicit architecture, schema, and behavior documentation
# ✔ Hardened startup safety and logging clarity
# ✔ Confirmed validator endpoint coverage
#
# =============================================================================
# 🧠 IMPORTANT NOTES
# =============================================================================
#
# - This file should remain STABLE across Phase 1 / 2 / 3.
# - New functionality should be added via routers, not here.
# - Runtime wiring must remain centralized.
#
# =============================================================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

# =============================================================================
# RUNTIME
# =============================================================================
from backend.runtime import Runtime

# =============================================================================
# API ROUTERS
# =============================================================================
from backend.api.system_api import router as system_router
from backend.api.rf_api import router as rf_router
from backend.api.rf_api import live_router
from backend.api.intel_api import router as intel_router
from backend.api.attack_api import router as attack_router
from backend.api.device_api import router as device_router
from backend.api.integrations_api import router as integrations_router
from backend.api.wifi_mk7_api import router as wifi_mk7_router
from backend.api.ble_nr5_api import router as ble_nr5_router
from backend.api.hunt_drones_api import router as hunt_drones_router

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ghostrecon")

# =============================================================================
# APP INIT
# =============================================================================
app = FastAPI(
    title="GhostRecon API",
    version="21.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# RUNTIME INITIALIZATION
# =============================================================================
try:
    logger.info("🧠 Initializing Runtime...")

    runtime = Runtime()

    # 🔥 CRITICAL: inject runtime
    app.state.runtime = runtime

    logger.info("✅ Runtime initialized successfully")

except Exception as e:
    logger.error(f"❌ Runtime initialization failed: {e}")

    # Fail-safe degraded mode
    app.state.runtime = None

# =============================================================================
# ROUTER REGISTRATION
# =============================================================================

# System
app.include_router(system_router, prefix="/api/system")

# RF + Spectrum
app.include_router(rf_router)

# Live FFT
app.include_router(live_router)

# Signal / Intel
app.include_router(intel_router)

# Device Intelligence (Phase 3)
app.include_router(device_router)

# Attack Layer
app.include_router(attack_router)

# Tool / Integration Layer
app.include_router(integrations_router)

# Native WiFi MK7 Packet Sensor
app.include_router(wifi_mk7_router)

# Native BLE NR5 Platform
app.include_router(ble_nr5_router)

# Passive Hunt Drones Workspace
app.include_router(hunt_drones_router)

# =============================================================================
# ROOT ENDPOINT
# =============================================================================
@app.get("/")
def root():
    return {
        "service": "GhostRecon",
        "status": "online",
        "version": "v21.0.0",
    }

# =============================================================================
# GLOBAL HEALTH CHECK
# =============================================================================
@app.get("/health")
def health():
    runtime = getattr(app.state, "runtime", None)

    return {
        "status": "ok" if runtime else "degraded",
        "runtime_initialized": runtime is not None,
    }

# =============================================================================
# STARTUP EVENT
# =============================================================================
@app.on_event("startup")
def on_startup():
    logger.info("🚀 GhostRecon backend starting...")

# =============================================================================
# SHUTDOWN EVENT
# =============================================================================
@app.on_event("shutdown")
def on_shutdown():
    logger.info("🛑 GhostRecon shutting down...")
