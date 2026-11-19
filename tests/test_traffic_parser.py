from app.tools.traffic_parser import parse_traffic_text


def test_parse_traffic_text(tmp_path):
    traffic_log = tmp_path / "mitm_stream.log"
    traffic_log.write_text(
        "\n".join(
            [
                "10:00:00.123 client connect",
                "10:00:01.001 GET https://api.example.com/v1/init HTTP/1.1",
                "10:00:02.002 POST https://ads.example.com/collect HTTP/1.1",
                "ignore this line",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    records = parse_traffic_text(str(traffic_log))
    assert len(records) == 2
    assert records[0]["method"] == "GET"
    assert records[0]["host"] == "api.example.com"
    assert records[1]["path"] == "/collect"
