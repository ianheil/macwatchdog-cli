from macwatchdog.audit.profiles import _risk_flags


def test_risk_flags_detects_root_certificate():
    payload = [{"PayloadType": "com.apple.security.pkcs12", "PayloadDisplayName": "Root CA"}]
    risks = _risk_flags(payload)
    assert "Certificate payload" in risks
    assert "Root certificate" in risks


def test_risk_flags_detects_vpn():
    payload = [{"PayloadType": "com.apple.vpn.managed"}]
    risks = _risk_flags(payload)
    assert "VPN" in risks


def test_risk_flags_empty_payload():
    assert _risk_flags([]) == []
