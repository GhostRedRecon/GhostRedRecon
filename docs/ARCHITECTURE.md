# GhostRedRecon Architecture

## Active Structure

- `backend/`: FastAPI backend, runtime orchestration, integrations, RF/intel layers
- `frontend/`: React/Vite operator console
- `config/`: runtime and feature configuration
- `app/`: compatibility mirror pointing at `backend/`, `frontend/`, and `config/`
- `deploy/`: deployment assets, including the systemd backend unit
- `scripts/`: live startup and system-control scripts
- `scripts/_archive/`: retained non-runtime scripts removed from the active product path
- `tests/`: pytest suite

## Runtime Entry Points

- Backend: `backend/main.py`
- Runtime orchestration: `backend/runtime.py`
- Frontend shell: `frontend/src/App.jsx`
- Frontend API client: `frontend/src/lib/api.js`
- Shared tab registry: `frontend/src/config/tabs.js`

## Tab Configuration

There is now one active tab source of truth:

- `frontend/src/config/tabs.js`

The frontend shell and runtime helpers both consume this file. The old duplicated tab registry in `frontend/src/lib/runtime.js` and `config/project.config.json` was removed.

## Cleanup Policy

The repository is now source-first. Runtime artifacts such as logs, evidence, reports, PCAPs, generated frontend config, caches, and local environments are ignored through `.gitignore` and should not be committed back into the repo.
