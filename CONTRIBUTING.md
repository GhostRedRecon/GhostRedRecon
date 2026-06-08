# Contributing

GhostRedRecon accepts contributions that keep the project local-first, authorized-use focused, and practical on Linux operator workstations.

## Before Opening A Pull Request

- Keep runtime evidence, logs, captures, local identities, databases, and generated build output out of commits.
- Run `python3 -m compileall backend tests`.
- Run `python3 -m pytest`.
- Run `npm --prefix frontend run build`.
- Document any new external system dependency.
- Update `README.md`, `docs/`, or the Manual tab when operator workflows change.

## Safety Requirements

- Do not add workflows intended for unauthorized access, credential theft, privacy invasion, or third-party monitoring.
- Keep active validation features scoped to owned labs or explicitly authorized assessments.
- Do not include real PCAPs, camera media, private MAC/IP inventories, credentials, tokens, or third-party identifiers in issues or pull requests.

## Development Notes

The project is split into a FastAPI backend and React/Vite frontend. Use the existing controller/API/view patterns unless a change genuinely needs a new abstraction.
