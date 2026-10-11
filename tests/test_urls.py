"""Unit tests for the URL and QR-code forensics module (no real URLs are visited)."""

from email.message import EmailMessage

import cv2

from forensight.ingest import load_email
from forensight.urls import Link, analyze_link, analyze_urls, decode_qr_codes


def titles(link):
    return {f.title for f in analyze_link(link)}


def make_qr_png(text: str) -> bytes:
    qr = cv2.QRCodeEncoder.create().encode(text)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    return cv2.imencode(".png", qr)[1].tobytes()


def test_deceptive_link_text():
    link = Link("https://evil-site.ru/login", "HTML link", "www.paypal.com")
    assert "Deceptive link text" in titles(link)


def test_matching_link_text_is_not_deceptive():
    link = Link("https://www.paypal.com/signin", "HTML link", "paypal.com")
    assert "Deceptive link text" not in titles(link)


def test_at_trick():
    assert "'@' trick in URL" in titles(Link("http://paypal.com@evil.ru/x", "Plain text"))


def test_email_in_query_is_not_at_trick():
    assert "'@' trick in URL" not in titles(Link("https://shop.com/?mail=a@b.com", "Plain text"))


def test_ip_shortener_and_free_hosting():
    assert "Link uses an IP address" in titles(Link("http://45.33.32.156/a", "Plain text"))
    assert "URL shortener hides the destination" in titles(Link("https://bit.ly/abc", "Plain text"))
    assert "Link to a free hosting platform" in titles(Link("https://x.web.app/", "Plain text"))


def test_lookalike_link_domain():
    assert any(t.startswith("Lookalike link domain")
               for t in titles(Link("https://paypa1.com/login", "HTML link")))


def test_qr_code_decoding():
    assert decode_qr_codes(make_qr_png("https://evil.example/pay")) == ["https://evil.example/pay"]
    assert decode_qr_codes(b"") == []
    assert decode_qr_codes(b"not an image") == []


def test_quishing_email(tmp_path):
    msg = EmailMessage()
    msg["From"] = "it@company.test"
    msg["Subject"] = "Scan to keep your mailbox"
    msg.set_content("Scan the code below.")
    msg.add_attachment(make_qr_png("https://login-0ffice365.example/verify"),
                       maintype="image", subtype="png", filename="qr.png")
    path = tmp_path / "quishing.eml"
    path.write_bytes(bytes(msg))
    links, images, findings = analyze_urls(load_email(path))
    assert images == 1
    assert links[0].source == "QR code"
    assert "URL hidden in a QR code (quishing)" in {f.title for f in findings}
