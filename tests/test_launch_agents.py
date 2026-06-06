import os

from macwatchdog.audit.launch_agents import _is_apple_agent


def test_apple_agent_detection():
    assert _is_apple_agent("com.apple.Example.plist")
    assert not _is_apple_agent("com.acme.helper.plist")
