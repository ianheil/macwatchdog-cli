from macwatchdog.severity import Severity, severity_for


def test_severity_ordering():
    assert Severity.OK < Severity.INFO < Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_for_legacy_statuses():
    assert severity_for("OK") is Severity.OK
    assert severity_for("ALERT") is Severity.MEDIUM
    assert severity_for("ERROR") is Severity.ERROR
    assert severity_for("SUGGESTION") is Severity.LOW
    assert severity_for("UNKNOWN") is Severity.LOW
    assert severity_for("SKIPPED") is Severity.INFO


def test_severity_for_unknown_status_defaults_to_info():
    assert severity_for("NOT_A_STATUS") is Severity.INFO
