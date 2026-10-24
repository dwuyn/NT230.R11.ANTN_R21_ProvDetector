from src.ingest.parse_provninja import parse_paragraph


def test_parse_paragraph():
    parsed = parse_paragraph("JAVA.EXE READ_WRITE 172.16.157.129:443")
    assert parsed is not None
    assert parsed["edges"] == [("JAVA.EXE", "READ_WRITE", "172.16.157.129:443")]
    assert parsed["nodes"] == ["JAVA.EXE", "172.16.157.129:443"]


def test_parse_paragraph_rejects_short_or_malformed():
    assert parse_paragraph("JAVA.EXE READ_WRITE") is None
    assert parse_paragraph("a b c") is None
