from pathlib import Path

from app.tools.sdk_fingerprint import (
    KNOWLEDGE_BASE_PATH,
    load_sdk_knowledge_base,
    scan_for_sdks,
)
from app.analyzers.sdk_intelligence import correlate_sdk_evidence


def test_knowledge_base_has_required_categories_and_sdks():
    entries = load_sdk_knowledge_base()
    categories = {entry["category"] for entry in entries}
    names = {entry["name"] for entry in entries}
    assert {"advertising", "analytics", "push", "attribution", "location", "social"} <= categories
    assert {"AdMob", "Unity Ads", "Firebase Analytics", "AppsFlyer", "Adjust"} <= names
    assert KNOWLEDGE_BASE_PATH.is_file()


def test_domain_match_is_static_evidence(tmp_path: Path):
    smali = tmp_path / "unpacked" / "smali"
    smali.mkdir(parents=True)
    (smali / "Config.smali").write_text(
        'const-string v0, "https://appsflyersdk.com/collect"',
        encoding="utf-8",
    )
    hits = scan_for_sdks(str(tmp_path / "unpacked"))
    appsflyer = next(hit for hit in hits if hit["sdk_name"] == "AppsFlyer")
    assert appsflyer["static_only"] is True
    assert appsflyer["dynamic_correlated"] is False
    assert appsflyer["evidence"][0]["source_type"] == "domain"


def test_dynamic_network_evidence_is_correlated_without_claiming_static_presence():
    hits = correlate_sdk_evidence(
        [],
        {
            "traffic_summary": {
                "top_hosts": [{"host": "t.appsflyersdk.com", "count": 1}],
                "sample_requests": [],
            }
        },
    )
    appsflyer = next(hit for hit in hits if hit["sdk_name"] == "AppsFlyer")
    assert appsflyer["static_only"] is False
    assert appsflyer["dynamic_correlated"] is True
    assert appsflyer["evidence"][0]["source_type"] == "network"
