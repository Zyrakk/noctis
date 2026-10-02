# Noctis presentation demo

This is an isolated presentation mode. It does not replace or modify the protected dashboard routes.

## Start locally

From the repository root, run:

```bash
cd web && npm ci && npm run dev -- --host 127.0.0.1
```

Open:

```text
http://127.0.0.1:5173/presentation
```

Use Chrome or Chromium at **1920×1080**. The current frontend loads React, icons and charts from the same stack it already uses; Playwright is a local development dependency for the visual QA command:

```bash
cd web && npm run presentation:qa
```

The QA command opens every presentation route, checks desktop and mobile overflow, follows the recording actions and writes desktop screenshots to `docs/presentation/screenshots/`.

## Recommended recording path

1. `/presentation` — overview: noisy signal field and the shrinking useful set.
2. `/presentation/brief` — one synthetic finding with provenance and extracted evidence.
3. `/presentation/correlation` — synthetic shared IOC / temporal overlap path and decision trail.
4. `/presentation/architecture` — the documented five-layer pipeline and human-verification loop.
5. `/presentation/lessons` — pause, empirical noise estimate and documented rebuild direction.

The visible **SYNTHETIC DEMO DATA · PRESENTATION SAFE** badge stays on every view. The existing dashboard remains available at `/` and `/dashboard` when its normal backend and credentials are present.
