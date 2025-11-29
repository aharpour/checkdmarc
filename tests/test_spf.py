import pytest

from checkdmarc import spf as spf_mod


def _mock_query_dns_factory(mapper):
    """
    Create a mock for checkdmarc.spf.query_dns that returns results based on
    (domain, rrtype) tuples from the provided mapper dict.
    """

    def _mock_query_dns(domain, rrtype, **kwargs):
        key = (domain, rrtype)
        return mapper.get(key, [])

    return _mock_query_dns


def test_query_spf_record_prefers_txt_and_warns_on_spf_rrtype(monkeypatch):
    domain = "example.com"
    # Provide an SPF RRtype and a valid TXT record with SPF
    mapper = {
        (domain, "SPF"): ["v=spf1 +all"],
        (domain, "TXT"): [
            "not spf",
            '"v=spf1 -all"',  # valid SPF in TXT
        ],
    }
    monkeypatch.setattr(spf_mod, "query_dns", _mock_query_dns_factory(mapper))

    out = spf_mod.query_spf_record(domain)
    assert out["record"] == "v=spf1 -all"
    # Warn that SPF RRtype is deprecated and present
    assert any(
        "SPF type DNS records found" in w for w in out.get("warnings", [])
    )


def test_query_spf_record_multiple_spf_txt_raises(monkeypatch):
    domain = "multi.example"
    mapper = {
        (domain, "SPF"): [],
        (domain, "TXT"): [
            '"v=spf1 -all"',
            '"v=spf1 +all"',
        ],
    }
    monkeypatch.setattr(spf_mod, "query_dns", _mock_query_dns_factory(mapper))

    with pytest.raises(spf_mod.MultipleSPFRTXTRecords):
        spf_mod.query_spf_record(domain)


def test_query_spf_record_undecodable_raises(monkeypatch):
    domain = "badtxt.example"
    mapper = {
        (domain, "SPF"): [],
        (domain, "TXT"): ["Undecodable characters"],
    }
    monkeypatch.setattr(spf_mod, "query_dns", _mock_query_dns_factory(mapper))

    with pytest.raises(spf_mod.UndecodableCharactersInTXTRecord):
        spf_mod.query_spf_record(domain)


def test_query_spf_record_size_warnings(monkeypatch):
    domain = "big.example"
    # Create two large quoted chunks so that each chunk > 255 and total > 512
    chunk1 = "a" * 300
    chunk2 = "b" * 300
    record = f'"v=spf1" "{chunk1}" "{chunk2}"'
    mapper = {
        (domain, "SPF"): [],
        (domain, "TXT"): [record],
    }
    monkeypatch.setattr(spf_mod, "query_dns", _mock_query_dns_factory(mapper))

    out = spf_mod.query_spf_record(domain)
    warnings = "\n".join(out.get("warnings", []))
    # Should warn about chunk >255
    assert ">255" in warnings
    # Should warn that total is >512 bytes
    assert "> 512 bytes" in warnings
    # Quotes must be removed in the returned record
    assert '"' not in out["record"]
    assert out["record"].startswith("v=spf1")


def test_parse_spf_record_after_all_truncation_and_warning():
    record = "v=spf1 -all include:example.org"
    out = spf_mod.parse_spf_record(record, "example.org")
    # After-all warning should be present
    assert any("after the all mechanism is ignored" in w for w in out["warnings"]) 
    # Parsed should end up with all = fail
    assert out["parsed"]["all"] == "fail"


def test_parse_spf_record_invalid_ip4_raises():
    with pytest.raises(spf_mod.SPFSyntaxError):
        spf_mod.parse_spf_record("v=spf1 ip4:not_an_ip -all", "example.org")


def test_parse_spf_record_exp_modifier_fetches_txt(monkeypatch):
    # exp= is a modifier and should set parsed["exp"] to the first TXT value
    monkeypatch.setattr(spf_mod, "get_txt_records", lambda *a, **k: ["explain", "other"]) 
    out = spf_mod.parse_spf_record("v=spf1 exp=_spf-exp.example -all", "example.org")
    assert out["parsed"]["exp"] == "explain"


def test_parse_spf_record_too_many_dns_lookups_exists_raises():
    # 11 exists mechanisms -> >10 lookups
    record = "v=spf1 " + " ".join(["exists:a" for _ in range(11)])
    with pytest.raises(spf_mod.SPFTooManyDNSLookups):
        spf_mod.parse_spf_record(record, "example.org")


def test_parse_spf_record_too_many_dns_lookups_ignore_sets_error():
    record = "v=spf1 " + " ".join(["exists:a" for _ in range(11)])
    out = spf_mod.parse_spf_record(record, "example.org", ignore_too_many_lookups=True)
    assert out.get("error")
    assert out["dns_lookups"] > 10


def test_parse_spf_record_include_loop_detected(monkeypatch):
    # a.example includes b.example and b.example includes a.example
    def _mock_query_spf_record(domain, **kwargs):
        mapping = {
            "a.example": {"record": "v=spf1 include:b.example -all", "warnings": []},
            "b.example": {"record": "v=spf1 include:a.example -all", "warnings": []},
        }
        return mapping[domain]

    monkeypatch.setattr(spf_mod, "query_spf_record", _mock_query_spf_record)

    with pytest.raises(spf_mod.SPFIncludeLoop):
        spf_mod.parse_spf_record("v=spf1 include:a.example -all", "root.example")


def test_check_spf_integration_simple(monkeypatch):
    # Provide a minimal record and ensure valid True, no lookups
    def _mock_query_spf_record(domain, **kwargs):
        return {"record": "v=spf1 -all", "warnings": []}

    monkeypatch.setattr(spf_mod, "query_spf_record", _mock_query_spf_record)

    out = spf_mod.check_spf("example.org")
    assert out["valid"] is True
    assert out["record"] == "v=spf1 -all"
    assert out["dns_lookups"] == 0
    assert out["void_dns_lookups"] == 0
    assert out["parsed"]["all"] == "fail"


def test_check_spf_sets_error_on_too_many_lookups(monkeypatch):
    # Build a record with too many exists lookups
    record = "v=spf1 " + " ".join(["exists:a" for _ in range(11)])

    def _mock_query_spf_record(domain, **kwargs):
        return {"record": record, "warnings": []}

    monkeypatch.setattr(spf_mod, "query_spf_record", _mock_query_spf_record)

    out = spf_mod.check_spf("example.org")
    assert out["valid"] is False
    assert "error" in out
    assert "DNS lookups" in out["error"]
