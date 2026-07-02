"""HTTP client for Algo SIP endpoints (LuCI/UCI web stack).

Verified live against an Algo 8186 IP horn (firmware 5.3.4):

  * Login   — ``POST /index.lua`` with ``pwd=<plaintext>`` + ``nonce=<csrf>``.
    The ``nonce`` is a per-page CSRF token scraped from the login form's
    ``<input name="nonce" value="...">``; it is NOT a password hash. On success
    the response sets a session cookie which authorises the rest of the API.
  * Status  — ``GET /ajax-status.json`` → live registration/call/network state
    (see :mod:`pyalgo.status`).
  * Config  — the web UI is LuCI (OpenWrt UCI). Full-config export/import goes
    through ``/control/download.lua`` / the upload counterpart; those require a
    session ``id`` token whose derivation is still being finalised — see
    :meth:`AlgoClient.export_config`. Until then, prefer per-field UCI writes on
    the relevant settings page.

Intentionally generic: no site inventory or credentials live here. Disruptive
writes are explicit and easy to dry-run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import requests

from .status import AlgoStatus, parse_status

_NONCE_RE = re.compile(r'name="nonce"\s+value="([0-9a-fA-F]+)"')


class AlgoError(RuntimeError):
    """Base error for Algo client operations."""


class AlgoAuthError(AlgoError):
    """Login failed (bad password, or no nonce/session returned)."""


@dataclass
class AlgoDevice:
    """Unauthenticated fingerprint of a host (mirrors pyakuvox.identify)."""

    host: str
    reachable: bool = False
    is_algo: bool = False
    model: str = ""      # e.g. "8186"
    title: str = ""      # raw <title> text, e.g. "Algo 8186"


_TITLE_RE = re.compile(r"<title>([^<]*)</title>", re.IGNORECASE)
_ALGO_TITLE_RE = re.compile(r"Algo\s+(\w+)", re.IGNORECASE)


def identify(host: str, *, timeout: float = 5.0, verify_ssl: bool = False) -> AlgoDevice:
    """Best-effort, unauthenticated: is ``host`` an Algo endpoint, and which model?

    Algo serves an ``<title>Algo <model></title>`` landing page. Falls back to
    HTTP if HTTPS is unavailable.
    """
    dev = AlgoDevice(host=host)
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}/", timeout=timeout, verify=verify_ssl)
        except requests.RequestException:
            continue
        dev.reachable = True
        m = _TITLE_RE.search(r.text or "")
        if m:
            dev.title = m.group(1).strip()
            am = _ALGO_TITLE_RE.search(dev.title)
            if am:
                dev.is_algo = True
                dev.model = am.group(1)
        break
    return dev


class AlgoClient:
    """Session client for one Algo endpoint.

    Usage::

        algo = AlgoClient("192.0.2.5", password="...")
        algo.login()
        st = algo.status()
        print(st.primary_registration.extension, st.primary_registration.state)
    """

    def __init__(
        self,
        host: str,
        password: str,
        *,
        use_ssl: bool = False,
        verify_ssl: bool = False,
        timeout: float = 8.0,
    ) -> None:
        self.host = host
        self._password = password
        self._scheme = "https" if use_ssl else "http"
        self._verify = verify_ssl
        self._timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._logged_in = False

    @property
    def base_url(self) -> str:
        return f"{self._scheme}://{self.host}"

    def _get(self, path: str, **kw) -> requests.Response:
        return self._session.get(f"{self.base_url}{path}", timeout=self._timeout, **kw)

    def _post(self, path: str, **kw) -> requests.Response:
        return self._session.post(f"{self.base_url}{path}", timeout=self._timeout, **kw)

    def _fetch_nonce(self, path: str = "/") -> str:
        r = self._get(path)
        m = _NONCE_RE.search(r.text or "")
        if not m:
            raise AlgoAuthError(f"{self.host}: no CSRF nonce on {path}")
        return m.group(1)

    def login(self) -> None:
        """Authenticate; raises AlgoAuthError on failure."""
        nonce = self._fetch_nonce("/")
        r = self._post(
            "/index.lua",
            data={"pwd": self._password, "nonce": nonce},
            allow_redirects=True,
        )
        # A rejected password re-renders the login form with an "Invalid" notice
        # and no privileged content. Confirm auth positively via the status feed.
        if r.status_code != 200:
            raise AlgoAuthError(f"{self.host}: login HTTP {r.status_code}")
        probe = self._get("/ajax-status.json")
        if probe.status_code != 200 or not probe.text.strip().startswith("["):
            raise AlgoAuthError(f"{self.host}: login rejected (bad password?)")
        self._logged_in = True

    def status(self) -> AlgoStatus:
        """Return parsed live status (login first)."""
        if not self._logged_in:
            self.login()
        r = self._get("/ajax-status.json")
        if r.status_code != 200:
            raise AlgoError(f"{self.host}: status HTTP {r.status_code}")
        return parse_status(r.text)

    def current_nonce(self, path: str = "/") -> str:
        """Expose a fresh CSRF nonce for callers building UCI form writes."""
        if not self._logged_in:
            self.login()
        return self._fetch_nonce(path)

    _CSRF_RE = re.compile(r"""apweb\[['"]csrf['"]\]\s*=\s*['"]([^'"]+)['"]""")

    def read_csrf(self, page: str) -> str:
        """Scrape the per-page CSRF token (``apweb['csrf']``).

        Algo settings writes are CSRF-protected: the token is injected into each
        settings page's HTML, NOT the landing page. Fetch the specific settings
        page (e.g. ``sip.lua``) and read its token before posting an action.
        """
        if not self._logged_in:
            self.login()
        r = self._get(f"/{page.lstrip('/')}")
        m = self._CSRF_RE.search(r.text or "")
        if not m:
            raise AlgoError(f"{self.host}: no csrf token on {page}")
        return m.group(1)

    def control_action(self, page: str, action: str, params: dict | None = None,
                       csrf: str | None = None) -> str:
        """POST a LuCI control action — the confirmed Algo write primitive.

        Verified shape (from the firmware's ``prod.js``): a settings write is
        ``POST /<page>.lua`` with a urlencoded body
        ``action=<action>&<k=v>...&csrf.token=<token>``. Example (volume/gain)::

            POST /test.lua   action=setgain&gain=26&csrf.token=<csrf>

        ``page`` is the .lua handler (without extension), ``csrf`` defaults to a
        token scraped from that page. The exact (page, action, field) tuple for
        SIP registration must be captured from the target model's SIP settings
        page — it is not hard-coded here because it varies by model/firmware.
        """
        page = page[:-4] if page.endswith(".lua") else page
        if csrf is None:
            csrf = self.read_csrf(f"{page}.lua")
        body = {"action": action, **(params or {}), "csrf.token": csrf}
        r = self._post(f"/{page}.lua", data=body)
        if r.status_code != 200:
            raise AlgoError(f"{self.host}: {page}.lua action={action} HTTP {r.status_code}")
        return r.text

    def export_config(self) -> str:
        """Download the full UCI config export.

        NOTE (v0.1): ``/control/download.lua`` requires a session ``id`` token
        (Lua raises ``attempt to concatenate local 'id'`` without it). Prefer
        :meth:`control_action` for per-field writes until the export token is
        mapped. This method is a placeholder so the call site is stable.
        """
        raise NotImplementedError(
            "config export pending: /control/download.lua needs the session id token"
        )
