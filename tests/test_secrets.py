from spidercob_sentinel.secrets import scan_secrets


def test_detects_aws_key_and_maps_line_number():
    content = "x = 1\nAWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
    findings = scan_secrets("fake.py", content)

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "SECRET"
    assert f.type == "aws_access_key"
    assert f.line == 2
    assert f.severity == "CRITICAL"
    assert "rotate" in f.remediation.lower()


def test_no_false_positive_on_clean_file():
    content = "def add(a, b):\n    return a + b\n"
    assert scan_secrets("fake.py", content) == []
