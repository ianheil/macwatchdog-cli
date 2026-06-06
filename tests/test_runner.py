from macwatchdog.audit import RegisteredCheck
from macwatchdog.result import CheckResult
from macwatchdog.runner import render_report, run_checks


def test_run_checks_groups_by_category():
    probe_a = RegisteredCheck("A", lambda: CheckResult(label="A", status="OK"), "Cat1")
    probe_b = RegisteredCheck("B", lambda: CheckResult(label="B", status="INFO"), "Cat2")
    probe_c = RegisteredCheck(
        "C",
        lambda: [CheckResult(label="C1", status="OK"), CheckResult(label="C2", status="INFO")],
        "Cat1",
    )
    report = run_checks([probe_a, probe_b, probe_c])
    assert set(report.keys()) == {"Cat1", "Cat2"}
    assert [r.label for r in report["Cat1"]] == ["A", "C1", "C2"]
    assert [r.label for r in report["Cat2"]] == ["B"]


def test_run_checks_catches_exceptions():
    def boom():
        raise RuntimeError("nope")

    probe = RegisteredCheck("boom", boom, "Boom")
    report = run_checks([probe])
    assert report["Boom"][0].status == "ERROR"
    assert "RuntimeError" in str(report["Boom"][0].info)


def test_render_report_smoke(capsys):
    probe = RegisteredCheck(
        "silent-ok",
        lambda: CheckResult(label="silent-ok", status="OK"),
        "Cat",
    )
    render_report(run_checks([probe]))
    # Smoke: ensure something was rendered to stdout or stderr.
    out = capsys.readouterr()
    assert "Cat" in out.out or "silent-ok" in out.out
