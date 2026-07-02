"""Parsers for the Algo web UI status feed.

Algo SIP endpoints (8180/8186/8188/8301 IP speakers & horns, 8301 paging
adapter, ...) expose a live status document at ``GET /ajax-status.json`` once a
session cookie is set. It is a JSON array of ``[label, value]`` pairs, e.g.::

    [["Device Name","siphorn-000001"],
     ["SIP Registration","Page, Successful, 100;"],
     ["Call Status","Idle"],
     ["Proxy Status","Single proxy mode"],
     ["MAC","00:22:ee:00:00:01"],
     ["IPv4","192.0.2.5/24, Gateway: 192.0.2.1"], ...]

This module turns that into a typed :class:`AlgoStatus`. The parsers are pure
(no I/O) so they are trivially unit-testable against captured fixtures.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# Algo's IEEE OUI. Handy for telling an Algo speaker apart from an Akuvox door
# station (OUI 0c:11:xx) or Ubiquiti gear on the same intercom subnet.
ALGO_OUI = "00:22:ee"


@dataclass
class SipRegistration:
    """One SIP account's registration state as reported by the speaker."""

    account: str = ""          # e.g. "Page" / "Main"
    state: str = ""            # "Successful", "Connecting", "Rejected", "No Account", ...
    extension: str = ""        # e.g. "100"

    @property
    def registered(self) -> bool:
        return self.state.strip().lower() == "successful"


@dataclass
class AlgoStatus:
    device_name: str = ""
    mac: str = ""
    ipv4: str = ""
    gateway: str = ""
    call_status: str = ""
    proxy_status: str = ""
    provisioning_status: str = ""
    registrations: list[SipRegistration] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)

    @property
    def is_algo(self) -> bool:
        return self.mac.lower().startswith(ALGO_OUI)

    @property
    def primary_registration(self) -> SipRegistration | None:
        return self.registrations[0] if self.registrations else None


def parse_sip_registration(value: str) -> list[SipRegistration]:
    """Parse the ``SIP Registration`` status value.

    Format is one or more ``;``-separated accounts, each
    ``<account>, <state>[, <extension>]``. A bare ``No Account`` entry has no
    extension. Example: ``"Page, Successful, 100;"`` or
    ``"Main, No Account;BK1, Rejected, 100;"``.
    """
    out: list[SipRegistration] = []
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        cols = [c.strip() for c in chunk.split(",")]
        reg = SipRegistration(account=cols[0] if cols else "")
        if len(cols) >= 2:
            reg.state = cols[1]
        if len(cols) >= 3:
            reg.extension = cols[2]
        out.append(reg)
    return out


def parse_status(body: str | list) -> AlgoStatus:
    """Parse ``/ajax-status.json`` (raw text or already-decoded list)."""
    data = json.loads(body) if isinstance(body, str) else body
    kv: dict[str, str] = {}
    for row in data:
        if isinstance(row, (list, tuple)) and len(row) >= 2:
            kv[str(row[0])] = str(row[1])

    st = AlgoStatus(raw=kv)
    st.device_name = kv.get("Device Name", "")
    st.mac = kv.get("MAC", "")
    st.call_status = kv.get("Call Status", "")
    st.proxy_status = kv.get("Proxy Status", "")
    st.provisioning_status = kv.get("Provisioning Status", "")
    ipv4 = kv.get("IPv4", "")
    if ipv4:
        st.ipv4 = ipv4.split(",")[0].strip()
        if "Gateway:" in ipv4:
            st.gateway = ipv4.split("Gateway:", 1)[1].strip()
    if "SIP Registration" in kv:
        st.registrations = parse_sip_registration(kv["SIP Registration"])
    return st
