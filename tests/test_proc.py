import sys

from macwatchdog.proc import run


def test_run_returns_stdout_on_success():
    result = run(["/bin/echo", "hi"], timeout=5)
    assert result.ok
    assert result.stdout.strip() == "hi"
    assert result.returncode == 0


def test_run_flags_missing_binary():
    result = run(["this-binary-should-not-exist-xyz"], timeout=1)
    assert result.missing
    assert not result.ok


def test_run_honours_timeout():
    result = run([sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.2)
    assert result.timed_out
    assert not result.ok
