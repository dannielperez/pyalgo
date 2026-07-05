"""Login rejection detection (regression: bad password must NOT read as logged-in)."""
from pyalgo.client import _login_rejected


def test_rejected_login_page_detected():
    html = ('<div class="error"><b>Invalid Password</b>Please use the correct password.</div>'
            '<form action="/index.lua"><input type="password" name="pwd"/></form>')
    assert _login_rejected(html) is True


def test_alt_wording_detected():
    assert _login_rejected("Please use the correct password.") is True


def test_authenticated_page_not_flagged():
    html = "<title>Status</title><a href='/control/shsip.lua'>SIP</a> logged in content"
    assert _login_rejected(html) is False


def test_empty_not_flagged():
    assert _login_rejected("") is False
    assert _login_rejected(None) is False
