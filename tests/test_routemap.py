"""Unit tests for the route map module, using small fake GeoIP databases."""

from email.message import EmailMessage

import forensight.routemap as routemap
from forensight.ingest import load_email

FAKE_CITY = {
    "8.8.8.8": {"city": {"names": {"en": "Mountain View"}},
                "country": {"names": {"en": "United States"}},
                "location": {"latitude": 37.4, "longitude": -122.1}},
    "1.1.1.1": {"country": {"names": {"en": "Australia"}},
                "location": {"latitude": -33.5, "longitude": 151.0}},
}


class FakeDB:
    def __init__(self, records):
        self.records = records

    def get(self, ip):
        return self.records.get(ip)

    def close(self):
        pass


def make_email(tmp_path):
    msg = EmailMessage()
    msg["Received"] = "from mx.example (mx.example [1.1.1.1]) by inbox.example; Mon, 12 Oct 2026 10:00:05 +0000"
    msg["Received"] = "from relay (relay [10.0.0.5]) by mx.example; Mon, 12 Oct 2026 10:00:03 +0000"
    msg["Received"] = "from sender (sender [8.8.8.8]) by relay; Mon, 12 Oct 2026 10:00:01 +0000"
    msg["From"] = "a@example.com"
    msg.set_content("test")
    path = tmp_path / "route.eml"
    path.write_bytes(bytes(msg))
    return load_email(path)


def test_locate_handles_missing_fields():
    info = routemap.locate("1.1.1.1", FakeDB(FAKE_CITY), None)
    assert info["country"] == "Australia"
    assert info["city"] == "-" and info["organization"] == "-"


def test_build_route_skips_private_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(routemap, "_open", lambda path: FakeDB(FAKE_CITY))
    monkeypatch.setattr(routemap, "ASN_DB", tmp_path / "missing.mmdb")
    points = routemap.build_route(make_email(tmp_path))
    assert [p.ip for p in points] == ["8.8.8.8", "1.1.1.1"]      # 10.0.0.5 is private


def test_draw_map_creates_html(tmp_path, monkeypatch):
    monkeypatch.setattr(routemap, "_open", lambda path: FakeDB(FAKE_CITY))
    monkeypatch.setattr(routemap, "ASN_DB", tmp_path / "missing.mmdb")
    points = routemap.build_route(make_email(tmp_path))
    html = routemap.draw_map(points, "test", tmp_path / "map.html")
    content = html.read_text()
    assert "Mountain View" in content and "antPath" in content
