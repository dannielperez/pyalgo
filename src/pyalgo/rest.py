"""Algo official RESTful API client (firmware >= 3.3).

Reference: Algo RESTful API Guide (docs.algosolutions.com/docs/restful-api-guide).

  * Base:   ``https://{ip}/api/``  (HTTPS, port 443)
  * Auth:   HTTP Basic ``admin:<api password>`` (HMAC-SHA256 also supported —
            see :func:`hmac_authorization`). All values are returned as strings.
  * Read:   ``GET  /api/settings/{key}``    -> ``{"{key}": "value"}``
  * Write:  ``PUT  /api/settings``          body ``{"{key}": "value", ...}``
  * Status: ``GET  /api/info/status`` / ``GET /api/info/about``
  * Control:``POST /api/controls/...``      (door, tone, call/page, reboot, ...)

The API must first be **enabled** on the device (Advanced Settings -> Admin ->
RESTful API). A disabled API returns HTTP 403 even with valid credentials; use
the LuCI :class:`~pyalgo.client.AlgoClient` to enable it, then this client.

SIP registration keys (from the provisioning guide):
    sip.server.primary, sip.server.secondary, sip.auth.id, sip.auth.password,
    sip.extension, sip.proxy.address, sip.proxy.port
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac

import requests

# Canonical SIP setting keys, so callers don't hard-code strings.
SIP_SERVER_PRIMARY = "sip.server.primary"
SIP_SERVER_SECONDARY = "sip.server.secondary"
SIP_AUTH_ID = "sip.auth.id"
SIP_AUTH_PASSWORD = "sip.auth.password"
SIP_EXTENSION = "sip.extension"
SIP_PROXY_ADDRESS = "sip.proxy.address"
SIP_PROXY_PORT = "sip.proxy.port"


class AlgoRestError(RuntimeError):
    pass


def hmac_authorization(secret: str, method: str, uri: str, timestamp: str,
                       nonce: str, *, content_md5: str = "",
                       content_type: str = "") -> str:
    """Build the ``Authorization: hmac admin:{nonce}:{digest}`` header value.

    Input string is ``METHOD:URI:[CONTENT_MD5:CONTENT_TYPE:]TIMESTAMP:NONCE``
    (the content fields are included only when there is a JSON payload).
    """
    if content_md5 or content_type:
        msg = f"{method}:{uri}:{content_md5}:{content_type}:{timestamp}:{nonce}"
    else:
        msg = f"{method}:{uri}:{timestamp}:{nonce}"
    digest = _hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"hmac admin:{nonce}:{digest}"


class AlgoRestClient:
    """Client for the Algo RESTful API using HTTP Basic auth.

    Usage::

        api = AlgoRestClient("192.0.2.5", password="...")
        api.get_setting("sip.server.primary")            # -> "192.0.2.10"
        api.set_settings({"sip.server.primary": "192.0.2.10",
                          "sip.server.secondary": "backup.example.com"})
        api.page(extension="123")
    """

    def __init__(self, host: str, password: str, *, username: str = "admin",
                 verify_ssl: bool = False, timeout: float = 8.0) -> None:
        self.host = host
        self._timeout = timeout
        self._base = f"https://{host}/api"
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.auth = (username, password)
        self._session.headers["Content-Type"] = "application/json"

    def _req(self, method: str, path: str, **kw) -> requests.Response:
        r = self._session.request(method, f"{self._base}{path}",
                                  timeout=self._timeout, **kw)
        if r.status_code == 403:
            raise AlgoRestError(
                f"{self.host}: 403 — RESTful API disabled or bad credentials "
                "(enable it via Advanced Settings -> Admin)"
            )
        if r.status_code >= 400:
            raise AlgoRestError(f"{self.host}: {method} {path} HTTP {r.status_code}")
        return r

    # ── settings ────────────────────────────────────────────────────
    def get_setting(self, key: str) -> str:
        r = self._req("GET", f"/settings/{key}")
        return r.json().get(key, "")

    def set_settings(self, values: dict[str, str]) -> None:
        """PUT one or more settings. Values are coerced to strings."""
        payload = {k: str(v) for k, v in values.items()}
        self._req("PUT", "/settings", json=payload)

    # ── info ────────────────────────────────────────────────────────
    def status(self) -> dict:
        return self._req("GET", "/info/status").json()

    def about(self) -> dict:
        return self._req("GET", "/info/about").json()

    # ── SIP registration convenience ────────────────────────────────
    def get_sip_registration(self) -> dict[str, str]:
        keys = [SIP_SERVER_PRIMARY, SIP_SERVER_SECONDARY, SIP_EXTENSION,
                SIP_AUTH_ID, SIP_PROXY_ADDRESS, SIP_PROXY_PORT]
        return {k: self.get_setting(k) for k in keys}

    def set_sip_servers(self, primary: str, secondary: str | None = None,
                        primary_port: str | None = None) -> None:
        """Point the speaker's SIP registration at a new primary (+ optional
        secondary/backup) server — the core fleet-repoint operation."""
        vals = {SIP_SERVER_PRIMARY: primary}
        if secondary is not None:
            vals[SIP_SERVER_SECONDARY] = secondary
        if primary_port is not None:
            vals[SIP_PROXY_PORT] = primary_port
        self.set_settings(vals)

    # ── controls ────────────────────────────────────────────────────
    def page(self, extension: str) -> None:
        self._req("POST", "/controls/call/page", json={"extension": extension})

    def door_unlock(self, doorid: str = "local", duration: str | None = None) -> None:
        if duration is not None:
            self._req("POST", "/controls/door/munlock",
                      json={"doorid": doorid, "duration": str(duration)})
        else:
            self._req("POST", "/controls/door/unlock", json={"doorid": doorid})

    def reboot(self) -> None:
        self._req("POST", "/controls/reboot")


def basic_auth_header(username: str, password: str) -> str:
    """``Authorization: Basic ...`` value, for callers not using requests.auth."""
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
