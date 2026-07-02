"""Unit tests for the Algo RESTful API client (pure — no network)."""

import base64

from pyalgo import (
    SIP_SERVER_PRIMARY,
    SIP_SERVER_SECONDARY,
    basic_auth_header,
    hmac_authorization,
)
from pyalgo.rest import AlgoRestClient


def test_basic_auth_header_matches_doc_example():
    # Doc example: admin:algo -> Basic YWRtaW46YWxnbw==
    assert basic_auth_header("admin", "algo") == "Basic YWRtaW46YWxnbw=="
    raw = base64.b64decode("YWRtaW46YWxnbw==").decode()
    assert raw == "admin:algo"


def test_hmac_input_with_and_without_payload():
    # With payload: METHOD:URI:CONTENT_MD5:CONTENT_TYPE:TIMESTAMP:NONCE
    h1 = hmac_authorization("secret", "POST", "/api/controls/tone/start",
                            "1600", "abc", content_md5="md5", content_type="application/json")
    # Without payload: METHOD:URI:TIMESTAMP:NONCE
    h2 = hmac_authorization("secret", "GET", "/api/info/about", "1600", "abc")
    assert h1.startswith("hmac admin:abc:")
    assert h2.startswith("hmac admin:abc:")
    assert h1 != h2  # payload fields change the digest


def test_base_url_and_sip_keys():
    api = AlgoRestClient("10.0.0.9", "pw")
    assert api._base == "https://10.0.0.9/api"
    assert SIP_SERVER_PRIMARY == "sip.server.primary"
    assert SIP_SERVER_SECONDARY == "sip.server.secondary"


def test_set_settings_coerces_to_strings(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {}

    def fake_req(method, url, timeout=None, **kw):
        captured["method"] = method
        captured["url"] = url
        captured["json"] = kw.get("json")
        return FakeResp()

    api = AlgoRestClient("10.0.0.9", "pw")
    monkeypatch.setattr(api._session, "request", fake_req)
    api.set_sip_servers("192.0.2.10", secondary="backup.example.com")
    assert captured["method"] == "PUT"
    assert captured["url"].endswith("/api/settings")
    assert captured["json"] == {
        "sip.server.primary": "192.0.2.10",
        "sip.server.secondary": "backup.example.com",
    }
