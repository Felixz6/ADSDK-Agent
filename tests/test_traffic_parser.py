import json

from app.tools.traffic_parser import parse_traffic_text, parse_traffic_to_summary_json


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


def test_parse_traffic_to_summary_json(tmp_path):
    traffic_log = tmp_path / "mitm_stream.log"
    traffic_log.write_text(
        "\n".join(
            [
                "10:00:01.001 GET https://api.example.com/v1/init HTTP/1.1",
                "10:00:02.002 POST https://ads.example.com/collect HTTP/1.1",
                "10:00:03.003 GET https://api.example.com/v1/config HTTP/1.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    summary_json = tmp_path / "traffic_summary.json"

    summary = parse_traffic_to_summary_json(str(traffic_log), str(summary_json))
    assert summary["total_requests"] == 3
    assert summary["top_hosts"][0]["host"] == "api.example.com"
    assert summary_json.exists()

    payload = json.loads(summary_json.read_text(encoding="utf-8"))
    assert payload["total_requests"] == 3
