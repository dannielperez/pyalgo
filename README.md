# pyalgo

Small Python helpers for **Algo** SIP endpoints (IP speakers, horns, and paging
adapters — 8180/8186/8188/8301, etc.).

Algo devices run a LuCI/UCI (OpenWrt-derived) web stack. This package wraps the
parts we need to audit and (eventually) reconfigure SIP registration fleet-wide,
alongside the sibling `pyakuvox` / `pyfanvil` wrappers.

## Two interfaces

Algo devices expose **two** control surfaces; pyalgo wraps both:

1. **Official RESTful API** (`AlgoRestClient`, firmware >= 3.3) — the clean path.
   `https://{ip}/api/`, HTTP Basic (or HMAC-SHA256) auth, `GET /api/settings/{key}`
   / `PUT /api/settings`, plus `/api/info/*` and `/api/controls/*`. This is the
   right way to read/write SIP registration and drive door/page/tone controls.
   The API must be **enabled** first (Advanced Settings → Admin → RESTful API);
   a disabled API returns HTTP 403 even with valid credentials.
2. **LuCI web UI** (`AlgoClient`) — `POST /index.lua` nonce login, live status via
   `/ajax-status.json`, and a CSRF-checked write primitive (`control_action`).
   Used to read status without the REST API and to *enable* the REST API.

### RESTful API (preferred)

```python
from pyalgo import AlgoRestClient, SIP_SERVER_PRIMARY

api = AlgoRestClient("192.0.2.5", password="...")
api.get_setting(SIP_SERVER_PRIMARY)                 # "192.0.2.10"
api.set_sip_servers("192.0.2.10", secondary="backup.example.com")  # repoint
api.status()                                        # registration/call state
api.page(extension="123")                           # one-way page
```

Canonical SIP keys are exported as constants: `SIP_SERVER_PRIMARY`,
`SIP_SERVER_SECONDARY`, `SIP_AUTH_ID`, `SIP_AUTH_PASSWORD`, `SIP_EXTENSION`,
`SIP_PROXY_ADDRESS`, `SIP_PROXY_PORT`.

### LuCI web UI (status without REST, or to enable REST)

```python
from pyalgo import AlgoClient, identify

print(identify("192.0.2.5"))          # AlgoDevice(model="8186", is_algo=True, ...)
algo = AlgoClient("192.0.2.5", password="...")
st = algo.status()                     # parses /ajax-status.json
print(st.primary_registration.extension, st.primary_registration.state)  # 100 Successful
```

## Verified live

Against an Algo 8186 IP horn (firmware 5.3.4): `identify` → LuCI `login` →
`status` returns the registration (`ext 100`, `Successful`, `Single proxy mode`).
The RESTful API layer is built to the official Algo REST guide; live use requires
the API to be enabled on the device first.

## Not done yet

- **Auto-enable the REST API** via the LuCI admin page (the exact UCI enable key
  + admin-page action varies by model — capture per model, then wire into
  `AlgoClient.control_action`).
- **ONVIF audio-out.** Some speakers are also provisioned into a TVT NVR via the
  NVR's speaker/ONVIF section; that path is separate from SIP registration and is
  not covered here.

This package is intentionally generic. Site-specific inventory, credentials, and
migration ordering live outside the package (in `unique-audit/data`).

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

## License

[MIT](LICENSE).
