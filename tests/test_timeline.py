from macwatchdog import timeline


def test_log_event_writes_jsonl():
    timeline.log_event("snapshot.created", path="/tmp/foo")
    timeline.log_event("ports.closed", port="8080", pid=1234)
    events = timeline.read_events()
    assert len(events) == 2
    assert events[0]["event"] == "snapshot.created"
    assert events[1]["port"] == "8080"


def test_format_and_clear():
    timeline.log_event("test.event", detail="x")
    formatted = timeline.format_events(timeline.read_events())
    assert "test.event" in formatted
    timeline.clear()
    assert timeline.read_events() == []
