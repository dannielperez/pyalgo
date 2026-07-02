"""Unit tests for the Algo status parsers (pure, no I/O)."""

from pyalgo import (
    ALGO_OUI,
    parse_sip_registration,
    parse_status,
)

# Captured live from an Algo 8186 (firmware 5.3.4), a paging speaker.
LIVE_8186 = (
    '[["Device Name","siphorn-000001"],'
    '["SIP Registration","Page, Successful, 100;"],'
    '["Call Status","Idle"],'
    '["Proxy Status","Single proxy mode"],'
    '["Provisioning Status","None Found"],'
    '["MAC","00:22:ee:00:00:01"],'
    '["System Integrity","Updating..."],'
    '["IPv4","192.0.2.5/24, Gateway: 192.0.2.1"],'
    '["IPv6","Not Available"]]'
)


def test_parse_live_8186():
    st = parse_status(LIVE_8186)
    assert st.device_name == "siphorn-000001"
    assert st.mac == "00:22:ee:00:00:01"
    assert st.is_algo
    assert st.ipv4 == "192.0.2.5/24"
    assert st.gateway == "192.0.2.1"
    reg = st.primary_registration
    assert reg is not None
    assert reg.account == "Page"
    assert reg.extension == "100"
    assert reg.state == "Successful"
    assert reg.registered is True


def test_oui_identifies_algo_vs_akuvox():
    algo = parse_status('[["MAC","00:22:ee:aa:bb:cc"]]')
    akuvox = parse_status('[["MAC","0c:11:05:aa:bb:cc"]]')
    assert algo.is_algo is True
    assert akuvox.is_algo is False
    assert ALGO_OUI == "00:22:ee"


def test_parse_multi_account_registration():
    regs = parse_sip_registration("Main, No Account;BK1, Rejected, 100;")
    assert len(regs) == 2
    assert regs[0].account == "Main"
    assert regs[0].state == "No Account"
    assert regs[0].extension == ""
    assert regs[0].registered is False
    assert regs[1].account == "BK1"
    assert regs[1].state == "Rejected"
    assert regs[1].extension == "100"


def test_parse_accepts_decoded_list():
    st = parse_status([["Device Name", "x"], ["MAC", "00:22:EE:00:00:01"]])
    assert st.device_name == "x"
    assert st.is_algo is True  # case-insensitive OUI match


def test_empty_registration_is_safe():
    st = parse_status('[["Call Status","Idle"]]')
    assert st.registrations == []
    assert st.primary_registration is None


def test_form_parser_via_client():
    """AlgoClient.form_fields parses inputs, checked radios, selected options."""
    from pyalgo import AlgoClient
    html = (
        '<form action="/control/admin.lua" method="post">'
        '<input name="admin.devname" value="siphorn">'
        '<input type="radio" name="admin.web.api" value="1">'
        '<input type="radio" name="admin.web.api" value="0" checked>'
        '<input type="password" name="api.admin.pwd" value="algo">'
        '<select name="admin.web.timeout"><option value="60">60</option>'
        '<option value="3600" selected>3600</option></select>'
        '<input type="hidden" name="csrf.token" value="abc123">'
        '<input type="submit" name="save" value="Save"></form>'
    )
    c = AlgoClient("192.0.2.5", "pw")
    c._logged_in = True
    c._get = lambda path, **kw: type("R", (), {"text": html})()
    f = c.form_fields("/control/admin.lua")
    assert f["admin.devname"] == "siphorn"
    assert f["admin.web.api"] == "0"        # only the checked radio
    assert f["api.admin.pwd"] == "algo"
    assert f["admin.web.timeout"] == "3600"  # selected option
    assert f["csrf.token"] == "abc123"
    assert "save" not in f                    # submit excluded
