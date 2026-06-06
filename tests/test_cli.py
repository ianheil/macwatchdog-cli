from typer.testing import CliRunner

from macwatchdog.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "macWatchdog" in result.stdout


def test_list_checks():
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "MDM Enrollment" in result.stdout


def test_check_requires_selection():
    result = runner.invoke(app, ["check"])
    assert result.exit_code == 2
