from macwatchdog.applescript import quote


def test_quote_wraps_and_escapes_quotes():
    assert quote('simple') == '"simple"'
    assert quote('a "b"') == r'"a \"b\""'
    assert quote('a\\b') == r'"a\\b"'
    assert quote('') == '""'


def test_quote_preserves_unicode():
    assert quote("naïve") == '"naïve"'
