"""
Forensight - Email route map module.

Places every public IP address in an email's delivery path on an interactive
world map, using offline GeoIP databases (no IP address is sent to any online
service):
  - DB-IP "IP to City Lite"  -> city, country, latitude and longitude
  - DB-IP "IP to ASN Lite"   -> the organization that owns the IP (e.g. Google)
IP geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0.
"""

import sys
from dataclasses import dataclass
from pathlib import Path

import folium
import maxminddb
from folium.plugins import AntPath

from forensight.headers import _is_public, parse_received
from forensight.ingest import EmailEvidence, load_email

GEOIP_DIR = Path("~/geoip").expanduser()
CITY_DB = GEOIP_DIR / "dbip-city-lite.mmdb"
ASN_DB = GEOIP_DIR / "dbip-asn-lite.mmdb"
OUTPUT_DIR = Path("output")


@dataclass
class RoutePoint:
    hop: int
    host: str
    ip: str
    city: str
    country: str
    organization: str
    latitude: float | None
    longitude: float | None
    time: str


def _open(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"GeoIP database not found: {path} (see the setup step)")
    return maxminddb.open_database(str(path))


def locate(ip: str, city_db, asn_db) -> dict:
    """Look up one IP in the offline databases. Missing fields become '-' or None."""
    city = city_db.get(ip) or {}
    asn = (asn_db.get(ip) or {}) if asn_db else {}
    location = city.get("location", {})
    return {
        "city": city.get("city", {}).get("names", {}).get("en", "-"),
        "country": city.get("country", {}).get("names", {}).get("en", "-"),
        "organization": asn.get("autonomous_system_organization", "-"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
    }


def build_route(evidence: EmailEvidence) -> list:
    """One point per hop that has a public IP, in delivery order (sender first)."""
    city_db, asn_db = _open(CITY_DB), (_open(ASN_DB) if ASN_DB.is_file() else None)
    points = []
    try:
        for hop in parse_received(evidence):
            public = [ip for ip in hop.ips if _is_public(ip)]
            if not public:
                continue
            info = locate(public[0], city_db, asn_db)
            points.append(RoutePoint(
                hop=hop.index, host=hop.from_host, ip=public[0],
                time=hop.timestamp.isoformat() if hop.timestamp else "?", **info))
    finally:
        city_db.close()
        if asn_db:
            asn_db.close()
    return points


def draw_map(points: list, title: str, output: Path) -> Path:
    """Write an interactive HTML map with numbered hops and an animated route line."""
    located = [p for p in points if p.latitude is not None]
    center = [located[0].latitude, located[0].longitude] if located else [20, 0]
    fmap = folium.Map(location=center, zoom_start=2, tiles=None)
    # Esri tiles also load when the map is opened as a local file (file://), which the
    # OpenStreetMap servers block. Two styles are offered; switch with the layer button.
    folium.TileLayer("Esri.WorldStreetMap", name="Street map").add_to(fmap)
    folium.TileLayer("Esri.WorldImagery", name="Satellite").add_to(fmap)
    folium.LayerControl().add_to(fmap)
    for i, p in enumerate(located):
        color = "red" if i == 0 else ("green" if i == len(located) - 1 else "blue")
        role = "Origin" if i == 0 else ("Last hop" if i == len(located) - 1 else "Relay")
        popup = (f"<b>{role} - hop {p.hop}</b><br>Host: {p.host}<br>IP: {p.ip}<br>"
                 f"Location: {p.city}, {p.country}<br>Organization: {p.organization}<br>"
                 f"Time: {p.time}")
        folium.Marker([p.latitude, p.longitude], popup=folium.Popup(popup, max_width=350),
                      tooltip=f"Hop {p.hop}: {p.country}",
                      icon=folium.Icon(color=color, icon="envelope")).add_to(fmap)
    if len(located) > 1:
        AntPath([[p.latitude, p.longitude] for p in located], delay=800, weight=4).add_to(fmap)
    fmap.get_root().html.add_child(folium.Element(
        f"<h3 style='position:fixed;top:10px;left:60px;z-index:999;background:white;"
        f"padding:6px 12px;border-radius:6px;font-family:sans-serif'>Forensight route map: "
        f"{title}</h3>"))
    output.parent.mkdir(parents=True, exist_ok=True)
    fmap.save(str(output))
    return output


def format_report(points: list, map_file: Path) -> str:
    out = ["=" * 60, "FORENSIGHT - Email Route Map", "=" * 60,
           f"{'Hop':<5}{'IP address':<18}{'Location':<28}Organization"]
    for p in points:
        location = f"{p.city}, {p.country}"[:27]
        out.append(f"{p.hop:<5}{p.ip:<18}{location:<28}{p.organization[:30]}")
    if not points:
        out.append("No public IP addresses found in the delivery path.")
    out += ["-" * 60, f"Interactive map saved to: {map_file}",
            "IP geolocation by DB-IP (db-ip.com), CC BY 4.0", "=" * 60]
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m forensight.routemap <email.eml>")
        sys.exit(1)
    ev = load_email(sys.argv[1])
    route = build_route(ev)
    html = draw_map(route, ev.path.name, OUTPUT_DIR / f"route_{ev.path.stem}.html")
    print(format_report(route, html))
