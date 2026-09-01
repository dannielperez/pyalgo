"""Consumer-contract tests for pyalgo's public API (roadmap L3, issue #1452).

Pins the exact names, exception hierarchy, and parsed shapes that
``uniqueos/devices/services/algo_sdk.py`` imports, replayed against recorded
sanitized fixtures. All transport is in-process; no live device is contacted.

See ``fixtures/consumer_contracts/README.md`` for fixture provenance.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pyalgo
from pyalgo import (
    AlgoAuthError,
    AlgoClient,
    AlgoDevice,
    AlgoError,
    AlgoRestClient,
    AlgoRestError,
    AlgoStatus,
    identify,
    parse_status,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "consumer_contracts"


def _json_fixture(name: str) -> dict | list:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _text_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class _FakeResponse:
    """Minimal stand-in for ``requests.Response`` covering what the SDK reads."""

    def __init__(
        self,
        *,
        text: str = "",
        json_body: dict | None = None,
        status_code: int = 200,
    ) -> None:
        self.text = text
        self._json = json_body
        self.status_code = status_code

    def json(self) -> dict:
        return self._json if self._json is not None else {}


class TestPublicApiContract:
    """Pin the exact names and error hierarchy consumed by algo_sdk.py."""

    def test_consumer_critical_names_are_exported(self) -> None:
        required = {
            "AlgoClient",
            "AlgoRestClient",
            "AlgoDevice",
            "AlgoError",
            "AlgoAuthError",
            "AlgoRestError",
            "AlgoStatus",
            "parse_status",
            "identify",
        }
        assert required <= set(pyalgo.__all__)
        assert all(getattr(pyalgo, name) is not None for name in required)

    def test_auth_error_extends_base_error(self) -> None:
        assert issubclass(AlgoAuthError, AlgoError)

    def test_rest_error_is_a_distinct_hierarchy(self) -> None:
        # The RESTful client raises its own error type, independent of the LuCI
        # client's AlgoError hierarchy — callers must catch both explicitly.
        assert not issubclass(AlgoRestError, AlgoError)
        assert issubclass(AlgoRestError, RuntimeError)


class TestStatusReplay:
    """Replay a recorded ``/ajax-status.json`` payload through parse_status."""

    def test_ajax_status_replay_returns_typed_status(self) -> None:
        payload = _json_fixture("ajax_status_8186.json")

        status = parse_status(payload)

        assert isinstance(status, AlgoStatus)
        assert status.device_name == "siphorn-000001"
        assert status.mac == "00:22:ee:00:00:01"
        assert status.is_algo is True
        assert status.ipv4 == "192.0.2.5/24"
        assert status.gateway == "192.0.2.1"
        assert status.call_status == "Idle"
        registration = status.primary_registration
        assert registration is not None
        assert registration.account == "Page"
        assert registration.state == "Successful"
        assert registration.extension == "100"
        assert registration.registered is True

    def test_client_status_replays_through_get(self) -> None:
        client = AlgoClient("device.example.invalid", "synthetic-password")
        client._logged_in = True
        recorded_text = json.dumps(_json_fixture("ajax_status_8186.json"))
        client._get = lambda path, **kw: _FakeResponse(text=recorded_text)

        status = client.status()

        assert status.device_name == "siphorn-000001"
        assert status.is_algo is True


class TestIdentifyReplay:
    """Replay the unauthenticated landing page through identify()."""

    def test_identify_returns_typed_device(self, monkeypatch) -> None:
        html = _text_fixture("landing_page_8186.html")

        def fake_get(url: str, timeout: float, verify: bool):
            return SimpleNamespace(text=html)

        monkeypatch.setattr("pyalgo.client.requests.get", fake_get)

        device = identify("device.example.invalid")

        assert isinstance(device, AlgoDevice)
        assert device.reachable is True
        assert device.is_algo is True
        assert device.model == "8186"
        assert device.title == "Algo 8186"


class TestRestSettingsReplay:
    """Replay the RESTful API's per-key settings envelope."""

    def test_get_sip_registration_replays_typed_mapping(self, monkeypatch) -> None:
        recorded = _json_fixture("rest_sip_registration.json")
        api = AlgoRestClient("device.example.invalid", "synthetic-password")

        def fake_req(method: str, path: str, **kw):
            key = path.rsplit("/", 1)[-1]
            return _FakeResponse(json_body={key: recorded[key]})

        api._req = fake_req

        registration = api.get_sip_registration()

        assert registration == {
            pyalgo.SIP_SERVER_PRIMARY: recorded["sip.server.primary"],
            pyalgo.SIP_SERVER_SECONDARY: recorded["sip.server.secondary"],
            pyalgo.SIP_EXTENSION: recorded["sip.extension"],
            pyalgo.SIP_AUTH_ID: recorded["sip.auth.id"],
            pyalgo.SIP_PROXY_ADDRESS: recorded["sip.proxy.address"],
            pyalgo.SIP_PROXY_PORT: recorded["sip.proxy.port"],
        }

    def test_forbidden_response_raises_rest_error(self) -> None:
        api = AlgoRestClient("device.example.invalid", "synthetic-password")
        api._session.request = lambda *a, **kw: _FakeResponse(status_code=403)

        try:
            api.get_setting(pyalgo.SIP_SERVER_PRIMARY)
        except AlgoRestError:
            pass
        else:
            raise AssertionError("expected AlgoRestError on HTTP 403")
