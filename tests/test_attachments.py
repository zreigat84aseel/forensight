"""Unit tests for the attachment forensics module (attachments are never executed)."""

import io
import zipfile
from email.message import EmailMessage

import pytest

from forensight.attachments import analyze_attachments, detect_type
from forensight.ingest import load_email


def analyze(tmp_path, filename, data, maintype="application", subtype="octet-stream"):
    """Build an email with one attachment and return the set of finding titles."""
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg.set_content("See attachment.")
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    path = tmp_path / "test.eml"
    path.write_bytes(bytes(msg))
    attachment = analyze_attachments(load_email(path))[0]
    return attachment, {f.title for f in attachment.findings}


@pytest.mark.parametrize("data, expected", [
    (b"%PDF-1.7 ...", "pdf"),
    (b"MZ\x90\x00", "exe"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n", "png"),
    (b"", "empty"),
    (b"<?xml version='1.0'?><plist><dict><key>PayloadType</key></dict></plist>", "mobileconfig"),
    (b"<html><body>hi</body></html>", "html"),
])
def test_detect_type(data, expected):
    assert detect_type(data) == expected


def test_executable_disguised_as_pdf(tmp_path):
    att, titles = analyze(tmp_path, "invoice.pdf", b"MZ" + b"\x00" * 100)
    assert att.true_type == "exe"
    assert "File type does not match extension" in titles


def test_double_extension(tmp_path):
    _, titles = analyze(tmp_path, "invoice.pdf.exe", b"MZ" + b"\x00" * 100)
    assert {"Double extension", "Executable or script attachment"} <= titles


def test_right_to_left_override(tmp_path):
    _, titles = analyze(tmp_path, "invoice\u202efdp.exe", b"MZ" + b"\x00" * 100)
    assert "Right-to-left override in file name" in titles


def test_html_smuggling_and_credential_page(tmp_path):
    page = b"<html><script>var b = atob('UEs=');</script><form><input type='password'></form></html>"
    _, titles = analyze(tmp_path, "payment.html", page, "text", "html")
    assert "HTML attachment decodes or builds a file in the browser" in titles
    assert "HTML attachment contains a password field" in titles


def test_archive_with_executable(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("document.scr", b"MZ")
    _, titles = analyze(tmp_path, "documents.zip", buffer.getvalue())
    assert "Archive contains executable files" in titles


def test_pdf_javascript_and_links(tmp_path):
    pdf = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\n" \
          b"<< /URI (https://bit.ly/abc) >>\n%%EOF"
    _, titles = analyze(tmp_path, "report.pdf", pdf, "application", "pdf")
    assert "PDF contains JavaScript" in titles
    assert "URL shortener hides the destination" in titles


def test_clean_image_has_no_findings(tmp_path):
    _, titles = analyze(tmp_path, "logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, "image", "png")
    assert titles == set()
