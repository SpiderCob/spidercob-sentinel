from spidercob_sentinel.remediation import get_remediation


def test_exact_match():
    assert "parameteris" in get_remediation("sql_injection").lower()


def test_nosql_checked_before_generic_sql_substring():
    # "nosql" contains "sql" — must not fall through to the sql_injection entry.
    assert get_remediation("nosql_injection") == get_remediation("mongo_injection")
    assert "operators" in get_remediation("nosql_injection").lower()


def test_check_id_keyword_fallback():
    # A CWE label alone ("Improperly Controlled Modification...") has no
    # obvious keyword, but a Semgrep check_id folded into the lookup key does.
    assert "parameteris" in get_remediation(
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes "
        "semgrep_rules.python.django.security.injection.tainted-sql-string"
    ).lower()


def test_unknown_type_falls_back_to_default():
    assert get_remediation("totally_made_up_type_xyz") == get_remediation("default")
