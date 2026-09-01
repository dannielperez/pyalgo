# Consumer contract replay fixtures

Sanitized Algo response shapes used to pin the SDK's public API surface. They
contain no credentials, customer names, real network addresses, or device
identifiers.

- `ajax_status_8186.json` is a captured `GET /ajax-status.json` live-status
  payload (LuCI web client), sourced from the same live capture already used
  by `tests/test_status.py`.
- `rest_sip_registration.json` is the per-key `{"<key>": "value"}` envelope
  returned by the official RESTful API's `GET /api/settings/{key}`.
- `landing_page_8186.html` is the unauthenticated landing page used by both
  `identify()` and `AlgoClient.login()`'s CSRF nonce scrape.

The values use synthetic identifiers while preserving the vendor field names
and structure the parsers must accept. Tests replay these files entirely
in-process; they never contact a device.
