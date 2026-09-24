# SentinelAPI local MVP

This folder started as static HTML. The current MVP adds a FastAPI scanner and a deliberately vulnerable API that bind to loopback and allow scans only against the configured loopback origin. Findings come from HTTP responses from that sandbox; scan history is held in memory and resets when the scanner restarts.

## Run the local demo

Install dependencies once:

```powershell
python -m pip install -r requirements.txt
```

Open two terminals in this folder and run:

```powershell
python -m uvicorn vulnerable_api.main:app --host 127.0.0.1 --port 8001
```

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then open `main.html` in a browser and choose **Scan your API**. The default OpenAPI URL is `http://127.0.0.1:8001/openapi.json`. To serve the site over HTTP instead, use `python -m http.server 5500 --bind 127.0.0.1`; the API CORS allowlist currently accepts the file origin and local UI port 5500.

Configure the backend base URL in `assets/js/config.js`. Configure additional local sandbox origins with `SENTINELAPI_ALLOWED_ORIGINS` as a comma-separated list. The service validates literal loopback hosts without DNS lookups, rejects non-loopback addresses and unconfigured origins, bounds response sizes, and does not follow redirects. Do not expose either service to a public network.

## MVP checks and boundaries

- OpenAPI 3.x and Swagger 2.0 JSON or YAML ingestion (YAML requires PyYAML).
- Endpoint discovery capped at 250 operations; only GET/HEAD operations are actively tested.
- BOLA uses authenticated user-a/user-b contexts against recognized user-resource paths and requires the returned object to identify the requested other user before reporting. Unsupported resource shapes are skipped.
- Exposure checks look for non-empty password, password hash, token, API key, secret, SSN, internal role, and internal notes fields. Values are redacted in evidence.
- Authentication checks probe documented or path-identified protected GET resources without credentials and report only a non-empty 2xx response. Public health endpoints are excluded.
- Rate limiting uses four requests on a rate-limit endpoint when present (otherwise a non-health GET endpoint), inspecting 429, Retry-After, and X-RateLimit/RateLimit headers. A positive result is explicitly marked heuristic.
- Findings are heuristic and require human review. Persistent storage, real user credential management, broader BOLA parameter inference, and production target support are not included.
